// Copyright ⓒ 2024-2025 Peter Morgan <peter.james.morgan@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{
    collections::HashMap,
    error,
    fmt::Debug,
    future::Future,
    io,
    marker::PhantomData,
    mem::size_of,
    net::SocketAddr,
    num::{NonZeroU32, NonZeroUsize},
    sync::Arc,
    time::{Duration, SystemTime},
};

use bytes::Bytes;
use nanoid::nanoid;
use opentelemetry::KeyValue;
use rama::{
    Context, Layer, Service,
    layer::limit::policy::{Policy, PolicyOutput, PolicyResult, UnlimitedPolicy},
};
use socket2::{SockRef, TcpKeepalive};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, Interest},
    net::{TcpListener, TcpStream},
    sync::{AcquireError, OwnedSemaphorePermit, Semaphore},
    task::{Id, JoinError, JoinSet},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, instrument};

use crate::{BYTES_RECEIVED, BYTES_SENT, Error, REQUEST_DURATION, REQUEST_SIZE, RESPONSE_SIZE};

/// Bytes occupied by Kafka's signed frame-length prefix.
const FRAME_LENGTH_PREFIX_BYTES: usize = size_of::<i32>();

/// Minimum Kafka request body: API key, API version, and correlation ID.
const MINIMUM_REQUEST_BODY_BYTES: usize = size_of::<i16>() * 2 + size_of::<i32>();

/// Bytes in the length prefix and fixed Kafka request header fields.
const REQUEST_HEAD_BYTES: usize = FRAME_LENGTH_PREFIX_BYTES + MINIMUM_REQUEST_BODY_BYTES;

/// Minimum Kafka response body: correlation ID.
const MINIMUM_RESPONSE_BODY_BYTES: usize = size_of::<i32>();

/// Largest socket buffer request which socket2 can pass to `setsockopt`
/// without narrowing the value to a negative platform `c_int`.
const MAXIMUM_SOCKET_BUFFER_BYTES: usize = i32::MAX as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FrameLength {
    declared: i32,
    body: usize,
    complete: usize,
}

impl FrameLength {
    fn request(
        encoded: [u8; FRAME_LENGTH_PREFIX_BYTES],
        maximum: Option<usize>,
    ) -> Result<Self, Error> {
        Self::bounded(encoded, maximum)?.with_minimum(MINIMUM_REQUEST_BODY_BYTES)
    }

    fn response(encoded: [u8; FRAME_LENGTH_PREFIX_BYTES]) -> Result<Self, Error> {
        Self::bounded(encoded, None)?.with_minimum(MINIMUM_RESPONSE_BODY_BYTES)
    }

    /// Validate the common length prefix without assuming the payload's framing grammar.
    ///
    /// Kafka request frames require a fixed API/version/correlation head, but SASL handshake v0
    /// tokens are only length-prefixed and may be shorter. Connection-local framing state chooses
    /// the grammar after this peer-controlled signed value is checked for conversion, bounds,
    /// prefix addition, allocation, and reading.
    fn bounded(
        encoded: [u8; FRAME_LENGTH_PREFIX_BYTES],
        maximum: Option<usize>,
    ) -> Result<Self, Error> {
        let declared = i32::from_be_bytes(encoded);
        let body = usize::try_from(declared).map_err(|_| Error::InvalidFrameLength { declared })?;

        if let Some(maximum) = maximum
            && body > maximum
        {
            return Err(Error::FrameTooBig {
                declared: body,
                maximum,
            });
        }

        body.checked_add(FRAME_LENGTH_PREFIX_BYTES)
            .map(|complete| Self {
                declared,
                body,
                complete,
            })
            .ok_or(Error::FrameLengthOverflow { declared })
    }

    fn with_minimum(self, minimum: usize) -> Result<Self, Error> {
        if self.body < minimum {
            Err(Error::FrameTooShort {
                declared: self.body,
                minimum,
            })
        } else {
            Ok(self)
        }
    }
}

/// The allocation-free portion of an incoming Kafka request.
///
/// This head is read and validated before storage for the complete frame is
/// allocated. `body_len` excludes Kafka's four-byte signed length prefix.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RequestHead {
    pub(crate) body_len: usize,
    pub(crate) api_key: i16,
    pub(crate) api_version: i16,
    pub(crate) correlation_id: i32,
}

/// A complete Kafka frame coupled to the guard that admitted its body.
///
/// The guard is deliberately private: downstream services can inspect or map
/// the payload, but cannot construct an admitted frame, replace its guard, or
/// detach the guard from the frame.
///
/// ```compile_fail
/// # use bytes::Bytes;
/// # use tansu_service::{AdmittedFrame, RequestHead};
/// let frame = AdmittedFrame {
///     head: todo!(),
///     payload: Bytes::new(),
///     lease: (),
/// };
/// ```
#[derive(Debug)]
pub struct AdmittedFrame<L, T = Bytes> {
    pub(crate) head: RequestHead,
    pub(crate) payload: T,
    pub(crate) lease: L,
}

/// A request admission guard whose existing reservation can be adjusted.
///
/// This is intentionally narrower than exposing `&mut L`: applications can
/// shrink or otherwise reconcile the reservation after decoding while the
/// envelope remains the sole owner of the original guard.
pub trait AdmissionLease {
    /// The typed adjustment accepted by this lease implementation.
    type Adjustment;

    /// Failure to apply an adjustment.
    type Error;

    /// Apply an adjustment to this same lease in place.
    fn adjust(&mut self, adjustment: Self::Adjustment) -> Result<(), Self::Error>;
}

/// An admission lease that can lend restricted proof of its reservation.
///
/// An admitted service may need to pass the resource reservation to a
/// zero-copy sink while it borrows the request payload. Returning only the
/// application-defined evidence keeps that lifetime proof tied to the
/// envelope without exposing the lease itself for replacement or extraction.
///
/// This is a separate, additive trait so existing admission policies that do
/// not need to expose evidence retain their current API and behavior.
pub trait AdmissionEvidence: AdmissionLease {
    /// The restricted proof lent by the lease.
    type Evidence: ?Sized;

    /// Borrow evidence that remains valid exactly while this lease is alive.
    fn evidence(&self) -> &Self::Evidence;
}

impl<L, T> AdmittedFrame<L, T> {
    /// Return the fixed request head associated with this payload.
    pub fn head(&self) -> &RequestHead {
        &self.head
    }

    /// Borrow the admitted request payload.
    pub fn payload(&self) -> &T {
        &self.payload
    }

    /// Transform only the payload while preserving the request head and guard.
    pub fn map_payload<U>(self, map: impl FnOnce(T) -> U) -> AdmittedFrame<L, U> {
        AdmittedFrame {
            head: self.head,
            payload: map(self.payload),
            lease: self.lease,
        }
    }

    /// Consume this request to create its reply without exposing or replacing
    /// the admission guard.
    pub fn reply<U>(self, payload: U) -> AdmittedReply<L, U> {
        AdmittedReply::from_frame(self, payload)
    }
}

impl<L, T> AdmittedFrame<L, T>
where
    L: AdmissionLease,
{
    /// Adjust the reservation owned by this frame without exposing the guard.
    pub fn adjust_lease(&mut self, adjustment: L::Adjustment) -> Result<(), L::Error> {
        self.lease.adjust(adjustment)
    }
}

impl<L, T> AdmittedFrame<L, T>
where
    L: AdmissionEvidence,
{
    /// Borrow the restricted evidence owned by this frame's admission lease.
    ///
    /// The lease remains private so callers can prove that admitted resources
    /// stay reserved without gaining a way to replace or detach the guard.
    pub fn evidence(&self) -> &L::Evidence {
        self.lease.evidence()
    }

    /// Borrow the payload and its admission evidence for one shared lifetime.
    ///
    /// Returning these disjoint borrows together supports zero-copy consumers
    /// that require both frame bytes and proof that their resources remain
    /// charged. Neither borrow can outlive the admitted envelope.
    ///
    /// ```compile_fail
    /// # use tansu_service::{AdmissionEvidence, AdmittedFrame};
    /// fn detach_evidence<'a, L, T>(frame: AdmittedFrame<L, T>) -> &'a L::Evidence
    /// where
    ///     L: AdmissionEvidence,
    /// {
    ///     frame.payload_and_evidence().1
    /// }
    /// ```
    pub fn payload_and_evidence(&self) -> (&T, &L::Evidence) {
        (&self.payload, self.lease.evidence())
    }
}

/// A Kafka reply coupled to the guard from the request that produced it.
///
/// There is no public constructor or parts accessor. A reply can only be
/// produced by consuming an [`AdmittedFrame`], which prevents callers from
/// substituting a different admission guard.
#[derive(Debug)]
pub struct AdmittedReply<L, T = Bytes> {
    pub(crate) head: RequestHead,
    pub(crate) payload: T,
    pub(crate) lease: L,
}

/// The wire action selected after an admitted request has been handled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Reply {
    /// Write one complete length-prefixed Kafka response frame.
    Frame(Bytes),

    /// Complete the request without writing protocol bytes.
    NoResponse,
}

impl<L, T> AdmittedReply<L, T> {
    pub(crate) fn from_frame<U>(frame: AdmittedFrame<L, U>, payload: T) -> Self {
        Self {
            head: frame.head,
            payload,
            lease: frame.lease,
        }
    }

    /// Return the fixed head from the request that owns this reply.
    pub fn head(&self) -> &RequestHead {
        &self.head
    }

    /// Borrow the reply payload.
    pub fn payload(&self) -> &T {
        &self.payload
    }

    /// Transform only the payload while preserving the request head and guard.
    pub fn map_payload<U>(self, map: impl FnOnce(T) -> U) -> AdmittedReply<L, U> {
        AdmittedReply {
            head: self.head,
            payload: map(self.payload),
            lease: self.lease,
        }
    }
}

impl<L, T> AdmittedReply<L, T>
where
    L: AdmissionLease,
{
    /// Adjust the reservation owned by this reply without exposing its guard.
    ///
    /// Request handling may release a large decoded payload before the much
    /// smaller response is written. Reconciling the same lease at that phase
    /// boundary keeps accounting precise while the transport still owns the
    /// proof, and does not permit callers to replace or extract the guard.
    pub fn adjust_lease(&mut self, adjustment: L::Adjustment) -> Result<(), L::Error> {
        self.lease.adjust(adjustment)
    }
}

/// Failure of the request-admitted TCP runtime.
#[derive(Debug, thiserror::Error)]
pub enum RequestAdmissionError<P, S>
where
    P: error::Error + 'static,
    S: error::Error + 'static,
{
    /// Reading or writing the connection failed.
    #[error("request transport I/O failed")]
    Io(#[from] io::Error),

    /// The request head or declared frame length was malformed.
    #[error("invalid Kafka request frame")]
    Frame(#[source] Error),

    /// A bounded protocol I/O phase did not complete before its deadline.
    #[error("Kafka {phase} exceeded its {timeout:?} deadline")]
    Timeout {
        /// Protocol phase which failed to make bounded progress.
        phase: ProtocolIoPhase,
        /// Caller-configured deadline for that phase.
        timeout: Duration,
    },

    /// The peer disconnected while its request was still awaiting admission.
    #[error("peer disconnected while request admission was pending")]
    Disconnected(#[source] AdmissionDisconnect),

    /// The configured disconnect observer could not inspect its transport.
    #[error("request-admission disconnect monitor failed")]
    DisconnectMonitor(#[source] io::Error),

    /// Request admission explicitly aborted.
    #[error("request admission policy aborted")]
    Policy(#[source] P),

    /// The admitted request service failed fatally.
    #[error("admitted request service failed")]
    Service(#[source] S),
}

/// A non-consuming peer disconnect observed while admission was pending.
#[derive(Debug, thiserror::Error)]
pub enum AdmissionDisconnect {
    /// The peer closed its sending direction cleanly.
    #[error("peer closed its sending direction")]
    Closed,

    /// The socket reported a peer-side failure such as a reset.
    #[error("peer socket failed")]
    Socket(#[source] io::Error),

    /// The reactor reported an error after the socket error was already cleared.
    #[error("peer socket reported error readiness")]
    ErrorReady,
}

/// Observe transport disconnects without consuming protocol bytes.
///
/// A generic [`AsyncReadExt`] implementation cannot promise this property:
/// probing it would remove bytes that the admitted request must later read.
/// This additive seam lets raw TCP, TLS, or another transport provide its own
/// non-consuming signal while the default runtime performs no observation.
pub trait AdmissionDisconnectMonitor<Stream> {
    /// Wait until `stream` disconnects, or fail to inspect the transport.
    fn disconnected(
        &self,
        stream: &Stream,
    ) -> impl Future<Output = Result<AdmissionDisconnect, io::Error>> + Send;
}

/// Default admission behavior which does not inspect a generic stream.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct NoopAdmissionDisconnectMonitor;

impl<Stream> AdmissionDisconnectMonitor<Stream> for NoopAdmissionDisconnectMonitor
where
    Stream: Sync,
{
    async fn disconnected(&self, _stream: &Stream) -> Result<AdmissionDisconnect, io::Error> {
        std::future::pending().await
    }
}

/// Non-consuming disconnect observation for a raw Tokio TCP stream.
///
/// Read readiness may mean that request body bytes are already queued rather
/// than that the peer has disconnected. The positive probe interval prevents
/// repeatedly polling that level-triggered readiness at full speed while a
/// capacity policy remains pending. No interval is supplied by default:
/// callers must select one for their latency and wake-up budget.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TcpAdmissionDisconnectMonitor {
    probe_interval: Duration,
}

impl TcpAdmissionDisconnectMonitor {
    /// Configure how often queued readable bytes are rechecked for a hangup.
    pub fn new(probe_interval: Duration) -> Result<Self, TcpTransportConfigError> {
        Ok(Self {
            probe_interval: checked_duration("admission disconnect probe", probe_interval)?,
        })
    }

    /// Return the positive interval between inconclusive readiness probes.
    pub fn probe_interval(&self) -> Duration {
        self.probe_interval
    }
}

impl AdmissionDisconnectMonitor<TcpStream> for TcpAdmissionDisconnectMonitor {
    async fn disconnected(&self, stream: &TcpStream) -> Result<AdmissionDisconnect, io::Error> {
        let mut probes = tokio::time::interval(self.probe_interval);
        probes.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            // Readable Kafka bytes are level-triggered. Pacing before each
            // readiness inspection prevents a hot loop while still allowing
            // Tokio's reactor to add a later READ_CLOSED or ERROR state.
            _ = probes.tick().await;
            let ready = stream.ready(Interest::READABLE | Interest::ERROR).await?;
            if let Some(error) = stream.take_error()? {
                return Ok(AdmissionDisconnect::Socket(error));
            }
            if ready.is_read_closed() {
                return Ok(AdmissionDisconnect::Closed);
            }
            if ready.is_error() {
                return Ok(AdmissionDisconnect::ErrorReady);
            }
        }
    }
}

/// A separately bounded Kafka protocol I/O phase.
///
/// Admission is deliberately absent: resource-policy waits remain governed by
/// capacity becoming available, while these phases bound work controlled by a
/// connected peer or by a stalled socket.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProtocolIoPhase {
    /// The eight fixed request-header bytes after the length prefix.
    FixedRequestHeader,
    /// The admitted request body following the twelve-byte request head.
    RequestBody,
    /// Writing and flushing one complete protocol response.
    ResponseWrite,
}

impl std::fmt::Display for ProtocolIoPhase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let description = match self {
            Self::FixedRequestHeader => "fixed request header read",
            Self::RequestBody => "request body read",
            Self::ResponseWrite => "response write and flush",
        };
        formatter.write_str(description)
    }
}

impl RequestHead {
    fn decode(
        encoded: [u8; REQUEST_HEAD_BYTES],
        maximum_frame_size: Option<usize>,
    ) -> Result<(Self, FrameLength), Error> {
        let length = FrameLength::request(
            encoded[..FRAME_LENGTH_PREFIX_BYTES]
                .try_into()
                .expect("the request head contains a complete length prefix"),
            maximum_frame_size,
        )?;
        let api_key = i16::from_be_bytes(
            encoded[4..6]
                .try_into()
                .expect("the request head contains a complete API key"),
        );
        let api_version = i16::from_be_bytes(
            encoded[6..8]
                .try_into()
                .expect("the request head contains a complete API version"),
        );
        let correlation_id = i32::from_be_bytes(
            encoded[8..12]
                .try_into()
                .expect("the request head contains a complete correlation ID"),
        );

        Ok((
            Self {
                body_len: length.body,
                api_key,
                api_version,
                correlation_id,
            },
            length,
        ))
    }

    /// Return the declared Kafka request body length, excluding its prefix.
    pub fn body_len(&self) -> usize {
        self.body_len
    }

    /// Return the signed Kafka API key without interpreting whether it is known.
    pub fn api_key(&self) -> i16 {
        self.api_key
    }

    /// Return the requested Kafka API version without route validation.
    pub fn api_version(&self) -> i16 {
        self.api_version
    }

    /// Return the correlation ID copied into the corresponding response.
    pub fn correlation_id(&self) -> i32 {
        self.correlation_id
    }
}

/// The addresses associated with an accepted TCP connection.
///
/// A [`TcpListenerService`] passes this value to its make-connection service
/// exactly once per accepted socket. The returned service then owns that
/// socket's protocol lifetime.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConnectionInfo {
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

impl ConnectionInfo {
    /// Return the address on which this connection was accepted.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Return the remote address of this connection.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

/// Invalid bounded TCP transport configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TcpTransportConfigError {
    /// A receive or send buffer was configured as zero bytes.
    #[error("TCP {option} socket buffer must contain at least one byte")]
    ZeroSocketBuffer {
        /// Socket option being configured.
        option: &'static str,
    },
    /// A receive or send buffer cannot be represented by the socket API.
    #[error(
        "TCP {option} socket buffer of {requested} bytes exceeds the platform option limit of {maximum} bytes"
    )]
    SocketBufferTooLarge {
        /// Socket option being configured.
        option: &'static str,
        /// Caller-requested byte count.
        requested: usize,
        /// Greatest safely representable byte count.
        maximum: usize,
    },
    /// A duration which must establish a finite positive bound was zero.
    #[error("TCP {option} duration must be greater than zero")]
    ZeroDuration {
        /// Transport option being configured.
        option: &'static str,
    },
    /// A keepalive probe count which must establish a finite positive bound was zero.
    #[error("TCP keepalive retries must be greater than zero")]
    ZeroKeepaliveRetries,
}

/// TCP keepalive policy for one accepted connection.
///
/// The idle period is required. Probe interval and retry count are optional so
/// callers can retain platform defaults explicitly. If a configured option is
/// unsupported by the target, socket setup fails instead of silently weakening
/// the requested dead-peer bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpKeepaliveConfig {
    idle: Duration,
    interval: Option<Duration>,
    retries: Option<NonZeroU32>,
}

impl TcpKeepaliveConfig {
    /// Create a keepalive policy which starts probing after `idle`.
    pub fn new(idle: Duration) -> Result<Self, TcpTransportConfigError> {
        if idle.is_zero() {
            return Err(TcpTransportConfigError::ZeroDuration {
                option: "keepalive idle",
            });
        }

        Ok(Self {
            idle,
            interval: None,
            retries: None,
        })
    }

    /// Set the positive interval between keepalive probes.
    pub fn with_interval(mut self, interval: Duration) -> Result<Self, TcpTransportConfigError> {
        if interval.is_zero() {
            return Err(TcpTransportConfigError::ZeroDuration {
                option: "keepalive interval",
            });
        }
        self.interval = Some(interval);
        Ok(self)
    }

    /// Set the positive number of unanswered probes allowed before disconnect.
    pub fn with_retries(mut self, retries: u32) -> Result<Self, TcpTransportConfigError> {
        self.retries =
            Some(NonZeroU32::new(retries).ok_or(TcpTransportConfigError::ZeroKeepaliveRetries)?);
        Ok(self)
    }

    /// Return the idle period before the first keepalive probe.
    pub fn idle(&self) -> Duration {
        self.idle
    }

    /// Return the configured probe interval, or `None` to retain the platform default.
    pub fn interval(&self) -> Option<Duration> {
        self.interval
    }

    /// Return the configured probe count, or `None` to retain the platform default.
    pub fn retries(&self) -> Option<NonZeroU32> {
        self.retries
    }
}

/// Bounded transport policy applied to each accepted TCP connection.
///
/// `Default` leaves every operating-system and connection lifetime default
/// unchanged. Explicit values are installed after admission and acceptance but
/// before constructing connection-local protocol services.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TcpTransportConfig {
    nodelay: Option<bool>,
    receive_buffer_size: Option<NonZeroUsize>,
    send_buffer_size: Option<NonZeroUsize>,
    keepalive: Option<TcpKeepaliveConfig>,
    idle_timeout: Option<Duration>,
    request_head_timeout: Option<Duration>,
    body_read_timeout: Option<Duration>,
    response_write_timeout: Option<Duration>,
}

impl TcpTransportConfig {
    /// Enable or disable Nagle's algorithm for accepted connections.
    ///
    /// Kafka interleaves large Produce frames with small latency-sensitive
    /// control and authentication exchanges. `true` requests `TCP_NODELAY` so
    /// those short responses are not held for packet coalescing or a delayed
    /// acknowledgement. This is a latency policy, not a memory bound;
    /// `Default` leaves the operating-system setting unchanged.
    pub fn with_nodelay(mut self, nodelay: bool) -> Self {
        self.nodelay = Some(nodelay);
        self
    }

    /// Request a positive kernel receive-buffer size.
    ///
    /// Operating systems may clamp or account for this request differently;
    /// this value is the exact input supplied to the socket API.
    pub fn with_receive_buffer_size(
        mut self,
        size: usize,
    ) -> Result<Self, TcpTransportConfigError> {
        self.receive_buffer_size = Some(checked_socket_buffer("receive", size)?);
        Ok(self)
    }

    /// Request a positive kernel send-buffer size.
    ///
    /// Operating systems may clamp or account for this request differently;
    /// this value is the exact input supplied to the socket API.
    pub fn with_send_buffer_size(mut self, size: usize) -> Result<Self, TcpTransportConfigError> {
        self.send_buffer_size = Some(checked_socket_buffer("send", size)?);
        Ok(self)
    }

    /// Enable TCP keepalive using the supplied bounded probe policy.
    pub fn with_keepalive(mut self, keepalive: TcpKeepaliveConfig) -> Self {
        self.keepalive = Some(keepalive);
        self
    }

    /// Close a connection which supplies no next frame prefix within `timeout`.
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Result<Self, TcpTransportConfigError> {
        if timeout.is_zero() {
            return Err(TcpTransportConfigError::ZeroDuration {
                option: "connection idle timeout",
            });
        }
        self.idle_timeout = Some(timeout);
        Ok(self)
    }

    /// Bound reading the fixed request-header bytes after the length prefix.
    pub fn with_request_head_timeout(
        mut self,
        timeout: Duration,
    ) -> Result<Self, TcpTransportConfigError> {
        self.request_head_timeout = Some(checked_duration("fixed request header", timeout)?);
        Ok(self)
    }

    /// Bound reading a request body after its fixed header has been validated.
    ///
    /// In the admitted runtime this clock begins only after the request policy
    /// grants a lease, so time spent waiting for capacity cannot consume a
    /// peer-controlled I/O deadline.
    pub fn with_body_read_timeout(
        mut self,
        timeout: Duration,
    ) -> Result<Self, TcpTransportConfigError> {
        self.body_read_timeout = Some(checked_duration("request body read", timeout)?);
        Ok(self)
    }

    /// Bound writing and flushing one complete response frame.
    pub fn with_response_write_timeout(
        mut self,
        timeout: Duration,
    ) -> Result<Self, TcpTransportConfigError> {
        self.response_write_timeout = Some(checked_duration("response write", timeout)?);
        Ok(self)
    }

    /// Return the requested `TCP_NODELAY` setting.
    pub fn nodelay(&self) -> Option<bool> {
        self.nodelay
    }

    /// Return the requested receive-buffer size.
    pub fn receive_buffer_size(&self) -> Option<NonZeroUsize> {
        self.receive_buffer_size
    }

    /// Return the requested send-buffer size.
    pub fn send_buffer_size(&self) -> Option<NonZeroUsize> {
        self.send_buffer_size
    }

    /// Return the configured keepalive policy.
    pub fn keepalive(&self) -> Option<TcpKeepaliveConfig> {
        self.keepalive
    }

    /// Return the idle period allowed while awaiting the next frame prefix.
    pub fn idle_timeout(&self) -> Option<Duration> {
        self.idle_timeout
    }

    /// Return the deadline for the fixed request header after its length prefix.
    pub fn request_head_timeout(&self) -> Option<Duration> {
        self.request_head_timeout
    }

    /// Return the deadline for reading a validated request body.
    pub fn body_read_timeout(&self) -> Option<Duration> {
        self.body_read_timeout
    }

    /// Return the deadline for writing and flushing one response.
    pub fn response_write_timeout(&self) -> Option<Duration> {
        self.response_write_timeout
    }
}

fn checked_duration(
    option: &'static str,
    duration: Duration,
) -> Result<Duration, TcpTransportConfigError> {
    if duration.is_zero() {
        Err(TcpTransportConfigError::ZeroDuration { option })
    } else {
        Ok(duration)
    }
}

fn checked_socket_buffer(
    option: &'static str,
    size: usize,
) -> Result<NonZeroUsize, TcpTransportConfigError> {
    let size =
        NonZeroUsize::new(size).ok_or(TcpTransportConfigError::ZeroSocketBuffer { option })?;
    if size.get() > MAXIMUM_SOCKET_BUFFER_BYTES {
        return Err(TcpTransportConfigError::SocketBufferTooLarge {
            option,
            requested: size.get(),
            maximum: MAXIMUM_SOCKET_BUFFER_BYTES,
        });
    }
    Ok(size)
}

trait SocketOptionTarget {
    fn set_nodelay(&self, nodelay: bool) -> io::Result<()>;
    fn set_receive_buffer_size(&self, size: NonZeroUsize) -> io::Result<()>;
    fn set_send_buffer_size(&self, size: NonZeroUsize) -> io::Result<()>;
    fn set_keepalive(&self, keepalive: TcpKeepaliveConfig) -> io::Result<()>;
}

impl SocketOptionTarget for TcpStream {
    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        TcpStream::set_nodelay(self, nodelay)
    }

    fn set_receive_buffer_size(&self, size: NonZeroUsize) -> io::Result<()> {
        SockRef::from(self).set_recv_buffer_size(size.get())
    }

    fn set_send_buffer_size(&self, size: NonZeroUsize) -> io::Result<()> {
        SockRef::from(self).set_send_buffer_size(size.get())
    }

    fn set_keepalive(&self, keepalive: TcpKeepaliveConfig) -> io::Result<()> {
        let socket_keepalive = TcpKeepalive::new().with_time(keepalive.idle());
        let socket_keepalive = apply_keepalive_interval(socket_keepalive, keepalive.interval())?;
        let socket_keepalive = apply_keepalive_retries(socket_keepalive, keepalive.retries())?;
        SockRef::from(self).set_tcp_keepalive(&socket_keepalive)
    }
}

impl TcpTransportConfig {
    fn apply<T>(&self, socket: &T) -> io::Result<()>
    where
        T: SocketOptionTarget,
    {
        if let Some(nodelay) = self.nodelay {
            socket.set_nodelay(nodelay)?;
        }
        if let Some(size) = self.receive_buffer_size {
            socket.set_receive_buffer_size(size)?;
        }
        if let Some(size) = self.send_buffer_size {
            socket.set_send_buffer_size(size)?;
        }
        if let Some(keepalive) = self.keepalive {
            socket.set_keepalive(keepalive)?;
        }
        Ok(())
    }
}

#[cfg(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "illumos",
    target_os = "ios",
    target_os = "visionos",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "windows",
    target_os = "cygwin",
    all(target_os = "wasi", not(target_env = "p1")),
))]
fn apply_keepalive_interval(
    keepalive: TcpKeepalive,
    interval: Option<Duration>,
) -> io::Result<TcpKeepalive> {
    Ok(match interval {
        Some(interval) => keepalive.with_interval(interval),
        None => keepalive,
    })
}

#[cfg(not(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "illumos",
    target_os = "ios",
    target_os = "visionos",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "windows",
    target_os = "cygwin",
    all(target_os = "wasi", not(target_env = "p1")),
)))]
fn apply_keepalive_interval(
    keepalive: TcpKeepalive,
    interval: Option<Duration>,
) -> io::Result<TcpKeepalive> {
    if interval.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TCP keepalive interval is not supported on this target",
        ));
    }
    Ok(keepalive)
}

#[cfg(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "illumos",
    target_os = "ios",
    target_os = "visionos",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "cygwin",
    target_os = "windows",
    all(target_os = "wasi", not(target_env = "p1")),
))]
fn apply_keepalive_retries(
    keepalive: TcpKeepalive,
    retries: Option<NonZeroU32>,
) -> io::Result<TcpKeepalive> {
    Ok(match retries {
        Some(retries) => keepalive.with_retries(retries.get()),
        None => keepalive,
    })
}

#[cfg(not(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "illumos",
    target_os = "ios",
    target_os = "visionos",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "cygwin",
    target_os = "windows",
    all(target_os = "wasi", not(target_env = "p1")),
)))]
fn apply_keepalive_retries(
    keepalive: TcpKeepalive,
    retries: Option<NonZeroU32>,
) -> io::Result<TcpKeepalive> {
    if retries.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TCP keepalive retries are not supported on this target",
        ));
    }
    Ok(keepalive)
}

fn configure_admitted_socket<T, Guard>(
    config: TcpTransportConfig,
    socket: &T,
    guard: Guard,
) -> io::Result<Guard>
where
    T: SocketOptionTarget,
{
    config.apply(socket)?;
    Ok(guard)
}

/// A make-connection service that clones one connection service per socket.
///
/// [`TcpListenerLayer`] uses this adapter to preserve its convenient layering
/// API. Applications that need connection-local state can instead construct a
/// [`TcpListenerService`] with their own `Service<State, ConnectionInfo>`.
#[derive(Clone, Debug)]
pub struct CloneConnectionService<S> {
    inner: S,
}

impl<S> CloneConnectionService<S> {
    /// Create an adapter that clones `inner` for every accepted connection.
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<State, S> Service<State, ConnectionInfo> for CloneConnectionService<S>
where
    S: Clone + Send + Sync + 'static,
    State: Send + Sync + 'static,
{
    type Response = S;
    type Error = Error;

    async fn serve(
        &self,
        _ctx: Context<State>,
        _req: ConnectionInfo,
    ) -> Result<Self::Response, Self::Error> {
        Ok(self.inner.clone())
    }
}

/// The policy input emitted before the listener accepts its next connection.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct AcceptIntent;

/// An error returned by the TCP listener runtime.
#[derive(Debug, thiserror::Error)]
pub enum TcpListenerError<E>
where
    E: error::Error + 'static,
{
    /// The listening socket failed.
    #[error("TCP listener I/O failed")]
    Io(#[from] io::Error),

    /// The connection policy aborted an accept intent.
    #[error("connection policy aborted accept intent")]
    Policy(#[source] E),

    /// Caller and listener attempted to install competing transport policies.
    #[error("TCP transport configuration already exists in the connection context")]
    TransportContextAlreadyConfigured,
}

/// A Rama limit policy with a fixed concurrent-connection limit.
#[derive(Clone, Debug)]
pub struct FixedConnectionPolicy {
    permits: Arc<Semaphore>,
}

impl FixedConnectionPolicy {
    /// Create a policy with `limit` concurrent connection guards.
    pub fn new(limit: NonZeroUsize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(limit.get())),
        }
    }

    /// Return the number of leases that can be acquired immediately.
    pub fn available_permits(&self) -> usize {
        self.permits.available_permits()
    }
}

/// An owned lease for one admitted connection.
#[derive(Debug)]
pub struct FixedConnectionLease {
    _permit: OwnedSemaphorePermit,
}

impl<State> Policy<State, AcceptIntent> for FixedConnectionPolicy
where
    State: Clone + Send + Sync + 'static,
{
    type Guard = FixedConnectionLease;
    type Error = AcquireError;

    async fn check(
        &self,
        ctx: Context<State>,
        request: AcceptIntent,
    ) -> PolicyResult<State, AcceptIntent, Self::Guard, Self::Error> {
        match self.permits.clone().acquire_owned().await {
            Ok(permit) => PolicyResult {
                ctx,
                request,
                output: PolicyOutput::Ready(FixedConnectionLease { _permit: permit }),
            },
            Err(error) => PolicyResult {
                ctx,
                request,
                output: PolicyOutput::Abort(error),
            },
        }
    }
}

/// A [`Layer`] that listens for TCP connections.
#[derive(Clone, Debug)]
pub struct TcpListenerLayer<P = UnlimitedPolicy> {
    cancellation: CancellationToken,
    policy: P,
    transport: TcpTransportConfig,
}

impl Default for TcpListenerLayer {
    fn default() -> Self {
        Self {
            cancellation: CancellationToken::new(),
            policy: UnlimitedPolicy::new(),
            transport: TcpTransportConfig::default(),
        }
    }
}

impl TcpListenerLayer {
    pub fn new(cancellation: CancellationToken) -> Self {
        Self {
            cancellation,
            policy: UnlimitedPolicy::new(),
            transport: TcpTransportConfig::default(),
        }
    }
}

impl<P> TcpListenerLayer<P> {
    /// Use the Rama limit `policy` before accepting each connection.
    pub fn with_policy<Q>(self, policy: Q) -> TcpListenerLayer<Q> {
        TcpListenerLayer {
            cancellation: self.cancellation,
            policy,
            transport: self.transport,
        }
    }

    /// Apply a bounded transport policy to every admitted socket.
    pub fn with_transport_config(mut self, transport: TcpTransportConfig) -> Self {
        self.transport = transport;
        self
    }
}

impl<S, P> Layer<S> for TcpListenerLayer<P>
where
    P: Clone,
{
    type Service = TcpListenerService<CloneConnectionService<S>, P>;

    fn layer(&self, inner: S) -> Self::Service {
        TcpListenerService::new(
            self.cancellation.clone(),
            CloneConnectionService::new(inner),
        )
        .with_policy(self.policy.clone())
        .with_transport_config(self.transport)
    }
}

/// A reusable TCP listener runtime.
///
/// `M` is a Rama `Service<State, ConnectionInfo>` which creates one service
/// for each accepted socket. The listener owns all spawned connection tasks,
/// reaps completed tasks while it is running, and aborts and reaps outstanding
/// tasks when its cancellation token is cancelled.
///
/// The admission policy runs before `accept`, so an exhausted policy leaves
/// sockets in the kernel backlog on every target. The listener can hold one
/// prospective connection guard while waiting for a socket; that guard becomes
/// the accepted connection's guard without replacement.
#[derive(Clone)]
pub struct TcpListenerService<M, P = UnlimitedPolicy> {
    cancellation: CancellationToken,
    make_connection: M,
    policy: P,
    transport: TcpTransportConfig,
}

impl<M> TcpListenerService<M> {
    /// Create a listener runtime using `make_connection` as its per-socket
    /// service factory.
    pub fn new(cancellation: CancellationToken, make_connection: M) -> Self {
        Self {
            cancellation,
            make_connection,
            policy: UnlimitedPolicy::new(),
            transport: TcpTransportConfig::default(),
        }
    }
}

impl<M, P> TcpListenerService<M, P> {
    /// Use the Rama limit `policy` before accepting each connection.
    pub fn with_policy<Q>(self, policy: Q) -> TcpListenerService<M, Q> {
        TcpListenerService {
            cancellation: self.cancellation,
            make_connection: self.make_connection,
            policy,
            transport: self.transport,
        }
    }

    /// Apply a bounded transport policy to every admitted socket.
    pub fn with_transport_config(mut self, transport: TcpTransportConfig) -> Self {
        self.transport = transport;
        self
    }
}

impl<M, P> Debug for TcpListenerService<M, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct(stringify!(TcpListenerService))
            .field("transport", &self.transport)
            .finish()
    }
}

impl<M, P> TcpListenerService<M, P> {
    fn reap<State>(joined: Result<(Id, ()), JoinError>, leases: &mut HashMap<Id, P::Guard>)
    where
        P: Policy<State, AcceptIntent>,
    {
        let id = match &joined {
            Ok((id, ())) => *id,
            Err(error) => error.id(),
        };
        let lease = leases
            .remove(&id)
            .expect("every listener-owned task has one connection lease");
        drop(lease);
        debug!(?joined);
    }

    async fn admit<State>(
        &self,
        mut ctx: Context<State>,
        connections: &mut JoinSet<()>,
        leases: &mut HashMap<Id, P::Guard>,
    ) -> Result<Option<(Context<State>, P::Guard)>, P::Error>
    where
        P: Policy<State, AcceptIntent>,
        State: Clone + Send + Sync + 'static,
    {
        let mut request = AcceptIntent;

        loop {
            let check = self.policy.check(ctx, request);
            tokio::pin!(check);
            let result = loop {
                tokio::select! {
                    result = &mut check => break result,
                    joined = connections.join_next_with_id(), if !connections.is_empty() => {
                        let joined = joined.expect("a non-empty join set has a task to reap");
                        Self::reap::<State>(joined, leases);
                    }
                    () = self.cancellation.cancelled() => return Ok(None),
                }
            };
            ctx = result.ctx;
            request = result.request;

            match result.output {
                PolicyOutput::Ready(guard) => return Ok(Some((ctx, guard))),
                PolicyOutput::Retry => continue,
                PolicyOutput::Abort(error) => return Err(error),
            }
        }
    }
}

impl<State, M, S, P> Service<State, TcpListener> for TcpListenerService<M, P>
where
    M: Service<State, ConnectionInfo, Response = S>,
    M::Error: Debug,
    S: Service<State, TcpStream>,
    S::Response: Debug,
    S::Error: Debug,
    P: Policy<State, AcceptIntent>,
    P::Error: error::Error + 'static,
    State: Clone + Send + Sync + 'static,
{
    type Response = ();
    type Error = TcpListenerError<P::Error>;

    #[instrument(skip(ctx, req))]
    async fn serve(
        &self,
        ctx: Context<State>,
        req: TcpListener,
    ) -> Result<Self::Response, Self::Error> {
        let mut connections = JoinSet::new();
        let mut leases = HashMap::new();

        let result = 'listener: loop {
            let Some((mut connection_ctx, lease)) =
                (match self.admit(ctx.clone(), &mut connections, &mut leases).await {
                    Ok(admission) => admission,
                    Err(error) => break 'listener Err(TcpListenerError::Policy(error)),
                })
            else {
                break Ok(());
            };

            let (stream, peer_addr) = loop {
                tokio::select! {
                    accepted = req.accept() => match accepted {
                        Ok(accepted) => break accepted,
                        Err(error) => break 'listener Err(TcpListenerError::Io(error)),
                    },
                    joined = connections.join_next_with_id(), if !connections.is_empty() => {
                        let joined = joined.expect("a non-empty join set has a task to reap");
                        Self::reap::<State>(joined, &mut leases);
                    }
                    () = self.cancellation.cancelled() => break 'listener Ok(()),
                }
            };
            if connection_ctx.get::<TcpTransportConfig>().is_some() {
                break 'listener Err(TcpListenerError::TransportContextAlreadyConfigured);
            }
            let lease = match configure_admitted_socket(self.transport, &stream, lease) {
                Ok(lease) => lease,
                Err(error) => break 'listener Err(TcpListenerError::Io(error)),
            };
            assert!(
                connection_ctx.insert(self.transport).is_none(),
                "transport configuration absence was checked immediately before insertion"
            );
            let connection = ConnectionInfo {
                local_addr: match stream.local_addr() {
                    Ok(local_addr) => local_addr,
                    Err(error) => break 'listener Err(TcpListenerError::Io(error)),
                },
                peer_addr,
            };
            debug!(?connection);

            let service = match tokio::select! {
                result = self.make_connection.serve(connection_ctx.clone(), connection) => result,
                () = self.cancellation.cancelled() => break 'listener Ok(()),
            } {
                Ok(service) => service,
                Err(error) => {
                    error!(
                        ?connection,
                        ?error,
                        "unable to construct connection service"
                    );
                    continue;
                }
            };
            let connection_task = connections.spawn(async move {
                match service.serve(connection_ctx, stream).await {
                    Err(error) => debug!(?connection, ?error),
                    Ok(response) => debug!(?connection, ?response),
                }
            });
            assert!(
                leases.insert(connection_task.id(), lease).is_none(),
                "task identifiers are unique among listener-owned connections"
            );
        };

        connections.abort_all();
        while let Some(joined) = connections.join_next_with_id().await {
            Self::reap::<State>(joined, &mut leases);
        }
        assert!(
            leases.is_empty(),
            "all connection leases are released by task reaping"
        );

        result
    }
}

/// A [context state][`Context#method.state`] state used by [`TcpContextLayer`] and [`TcpContextService`]
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub struct TcpContext {
    cluster_id: Option<String>,
    maximum_frame_size: Option<usize>,
}

impl TcpContext {
    pub fn cluster_id(self, cluster_id: Option<String>) -> Self {
        Self { cluster_id, ..self }
    }

    /// Set the maximum Kafka request body size, excluding the four-byte frame prefix.
    pub fn maximum_frame_size(self, maximum_frame_size: Option<usize>) -> Self {
        Self {
            maximum_frame_size,
            ..self
        }
    }
}

/// A [`Layer`] that injects the [`TcpContext`] into the service [`Context`] state
#[derive(Clone, Debug, Default)]
pub struct TcpContextLayer {
    state: TcpContext,
}

impl TcpContextLayer {
    pub fn new(state: TcpContext) -> Self {
        Self { state }
    }
}

impl<S> Layer<S> for TcpContextLayer {
    type Service = TcpContextService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            state: self.state.clone(),
        }
    }
}

/// A [`Service`] that requires the [`TcpContext`] as the service [`Context`] state
#[derive(Clone)]
pub struct TcpContextService<S> {
    inner: S,
    state: TcpContext,
}

impl<S> Debug for TcpContextService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct(stringify!(TcpContextService)).finish()
    }
}

impl<State, S> Service<State, TcpStream> for TcpContextService<S>
where
    S: Service<TcpContext, TcpStream>,
    S::Error: From<io::Error>,
    State: Clone + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    #[instrument(skip_all, fields(peer = %req.peer_addr()?))]
    async fn serve(
        &self,
        ctx: Context<State>,
        req: TcpStream,
    ) -> Result<Self::Response, Self::Error> {
        let (ctx, _) = ctx.swap_state(self.state.clone());

        self.inner.serve(ctx, req).await
    }
}

/// A [`Service`] writing [`Bytes`] into a [`TcpStream`], responding with a length delimited frame of [`Bytes`]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BytesTcpService;

impl Service<TcpStream, Bytes> for BytesTcpService {
    type Response = Bytes;
    type Error = Error;

    #[instrument(skip(ctx, req))]
    async fn serve(
        &self,
        mut ctx: Context<TcpStream>,
        req: Bytes,
    ) -> Result<Self::Response, Self::Error> {
        let stream = ctx.state_mut();

        stream.write_all(&req[..]).await?;
        BYTES_SENT.add(req.len() as u64, &[]);

        let mut size = [0u8; FRAME_LENGTH_PREFIX_BYTES];
        _ = stream.read_exact(&mut size).await?;

        let length = FrameLength::response(size)?;
        let mut buffer: Vec<u8> = vec![0u8; length.complete];
        buffer[0..size.len()].copy_from_slice(&size[..]);
        _ = stream
            .read_exact(&mut buffer[FRAME_LENGTH_PREFIX_BYTES..])
            .await?;
        BYTES_RECEIVED.add(buffer.len() as u64, &[]);

        Ok(Bytes::from(buffer))
    }
}

/// A [`Layer`] receiving [`Bytes`] from a [`TcpStream`]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TcpBytesLayer<State = ()> {
    _state: PhantomData<State>,
}

impl<S, State> Layer<S> for TcpBytesLayer<State> {
    type Service = TcpBytesService<S, State>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            _state: PhantomData,
        }
    }
}

impl<State> TcpBytesLayer<State> {
    /// Admit requests with `policy` after reading their fixed head and before
    /// allocating or reading the remaining body.
    pub fn with_request_policy<P>(self, policy: P) -> AdmittedTcpBytesLayer<State, P> {
        AdmittedTcpBytesLayer::new(policy)
    }
}

/// A [`Service`] receiving [`Bytes`] from a [`TcpStream`], calling an inner [`Service`] and sending [`Bytes`] into the [`TcpStream`]
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TcpBytesService<S, State> {
    inner: S,
    _state: PhantomData<State>,
}

impl<S, State> Debug for TcpBytesService<S, State> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct(stringify!(TcpBytesService)).finish()
    }
}

impl<S, State> TcpBytesService<S, State> {
    fn elapsed_millis(&self, start: SystemTime) -> u64 {
        start
            .elapsed()
            .map_or(0, |duration| duration.as_millis() as u64)
    }
}

/// A [`Layer`] that admits a Kafka request after its fixed head is read and
/// before storage for the complete frame is allocated.
#[derive(Clone, Debug)]
pub struct AdmittedTcpBytesLayer<State, P, M = NoopAdmissionDisconnectMonitor> {
    policy: P,
    disconnect_monitor: M,
    _state: PhantomData<State>,
}

impl<State, P> AdmittedTcpBytesLayer<State, P> {
    /// Create an admitted TCP byte layer using the Rama request `policy`.
    pub fn new(policy: P) -> Self {
        Self {
            policy,
            disconnect_monitor: NoopAdmissionDisconnectMonitor,
            _state: PhantomData,
        }
    }
}

impl<State, P, M> AdmittedTcpBytesLayer<State, P, M> {
    /// Observe pending-admission disconnects using a transport-specific monitor.
    pub fn with_disconnect_monitor<N>(
        self,
        disconnect_monitor: N,
    ) -> AdmittedTcpBytesLayer<State, P, N> {
        AdmittedTcpBytesLayer {
            policy: self.policy,
            disconnect_monitor,
            _state: PhantomData,
        }
    }
}

impl<S, State, P, M> Layer<S> for AdmittedTcpBytesLayer<State, P, M>
where
    P: Clone,
    M: Clone,
{
    type Service = AdmittedTcpBytesService<S, State, P, M>;

    fn layer(&self, inner: S) -> Self::Service {
        AdmittedTcpBytesService {
            inner,
            policy: self.policy.clone(),
            disconnect_monitor: self.disconnect_monitor.clone(),
            _state: PhantomData,
        }
    }
}

/// A TCP connection service whose request bodies are guarded by a Rama policy.
#[derive(Clone, Debug)]
pub struct AdmittedTcpBytesService<S, State, P, M = NoopAdmissionDisconnectMonitor> {
    inner: S,
    policy: P,
    disconnect_monitor: M,
    _state: PhantomData<State>,
}

#[derive(Debug, thiserror::Error)]
enum ReadHeadError {
    #[error("request head I/O failed")]
    Io(#[from] io::Error),

    #[error("invalid Kafka request head")]
    Frame(#[from] Error),

    #[error("Kafka {phase} exceeded its {timeout:?} deadline")]
    Timeout {
        phase: ProtocolIoPhase,
        timeout: Duration,
    },
}

impl<S, State, P, M> AdmittedTcpBytesService<S, State, P, M> {
    async fn read_head<R>(
        &self,
        stream: &mut R,
        maximum_frame_size: Option<usize>,
        transport: TcpTransportConfig,
    ) -> Result<(RequestHead, FrameLength, [u8; REQUEST_HEAD_BYTES]), ReadHeadError>
    where
        R: AsyncReadExt + Unpin,
    {
        let mut encoded = [0u8; REQUEST_HEAD_BYTES];
        let read = stream.read_exact(&mut encoded[..FRAME_LENGTH_PREFIX_BYTES]);
        if let Some(timeout) = transport.idle_timeout() {
            _ = tokio::time::timeout(timeout, read)
                .await
                .map_err(|_| ReadHeadError::Frame(Error::ConnectionIdleTimeout { timeout }))??;
        } else {
            _ = read.await?;
        }

        let length_prefix = encoded[..FRAME_LENGTH_PREFIX_BYTES]
            .try_into()
            .expect("the request head contains a complete length prefix");
        // This error is converted by `request`; keeping I/O separate here
        // makes it impossible to confuse a policy rejection with malformed
        // wire input.
        let length = FrameLength::request(length_prefix, maximum_frame_size)?;

        let read = stream.read_exact(&mut encoded[FRAME_LENGTH_PREFIX_BYTES..]);
        if let Some(timeout) = transport.request_head_timeout() {
            _ = tokio::time::timeout(timeout, read).await.map_err(|_| {
                ReadHeadError::Timeout {
                    phase: ProtocolIoPhase::FixedRequestHeader,
                    timeout,
                }
            })??;
        } else {
            _ = read.await?;
        }
        let (head, _) = RequestHead::decode(encoded, maximum_frame_size)?;
        Ok((head, length, encoded))
    }

    async fn admit(
        &self,
        mut ctx: Context<State>,
        mut request: RequestHead,
    ) -> Result<(Context<State>, RequestHead, P::Guard), P::Error>
    where
        P: Policy<State, RequestHead>,
        State: Clone + Send + Sync + 'static,
    {
        loop {
            let result = self.policy.check(ctx, request).await;
            ctx = result.ctx;
            request = result.request;

            match result.output {
                PolicyOutput::Ready(guard) => return Ok((ctx, request, guard)),
                PolicyOutput::Retry => continue,
                PolicyOutput::Abort(error) => return Err(error),
            }
        }
    }

    async fn request<R>(
        &self,
        stream: &mut R,
        maximum_frame_size: Option<usize>,
        transport: TcpTransportConfig,
        ctx: Context<State>,
    ) -> Result<(), RequestAdmissionError<P::Error, S::Error>>
    where
        S: Service<State, AdmittedFrame<P::Guard>, Response = AdmittedReply<P::Guard, Reply>>,
        P: Policy<State, RequestHead>,
        P::Error: error::Error + 'static,
        S::Error: error::Error + 'static,
        State: Clone + Send + Sync + 'static,
        R: AsyncReadExt + AsyncWriteExt + Unpin,
        M: AdmissionDisconnectMonitor<R>,
    {
        let (wire_head, length, encoded_head) = self
            .read_head(stream, maximum_frame_size, transport)
            .await
            .map_err(|error| match error {
                ReadHeadError::Io(error) => RequestAdmissionError::Io(error),
                ReadHeadError::Frame(error) => RequestAdmissionError::Frame(error),
                ReadHeadError::Timeout { phase, timeout } => {
                    RequestAdmissionError::Timeout { phase, timeout }
                }
            })?;
        let admitted = {
            let admission = self.admit(ctx, wire_head);
            let disconnect = self.disconnect_monitor.disconnected(&*stream);
            tokio::pin!(admission, disconnect);
            tokio::select! {
                result = &mut admission => result.map_err(RequestAdmissionError::Policy)?,
                result = &mut disconnect => match result {
                    Ok(disconnect) => {
                        return Err(RequestAdmissionError::Disconnected(disconnect));
                    }
                    Err(error) => {
                        return Err(RequestAdmissionError::DisconnectMonitor(error));
                    }
                },
            }
        };
        let (ctx, admitted_head, lease) = admitted;

        // A Rama policy may carry a request through retries, but changing the
        // protocol identity would separate admission from the bytes it guards.
        if admitted_head != wire_head {
            return Err(RequestAdmissionError::Frame(Error::Message(
                "request policy changed the Kafka request head".into(),
            )));
        }

        let mut request = vec![0u8; length.complete];
        request[..REQUEST_HEAD_BYTES].copy_from_slice(&encoded_head);
        let read = stream.read_exact(&mut request[REQUEST_HEAD_BYTES..]);
        if let Some(timeout) = transport.body_read_timeout() {
            _ = tokio::time::timeout(timeout, read).await.map_err(|_| {
                RequestAdmissionError::Timeout {
                    phase: ProtocolIoPhase::RequestBody,
                    timeout,
                }
            })??;
        } else {
            _ = read.await?;
        }
        BYTES_RECEIVED.add(request.len() as u64, &[]);

        let reply = self
            .inner
            .serve(
                ctx,
                AdmittedFrame {
                    head: wire_head,
                    payload: Bytes::from(request),
                    lease,
                },
            )
            .await
            .map_err(RequestAdmissionError::Service)?;

        let AdmittedReply { payload, lease, .. } = reply;
        let _lease = lease;
        if let Reply::Frame(payload) = payload {
            let write = async {
                stream.write_all(&payload).await?;
                stream.flush().await
            };
            if let Some(timeout) = transport.response_write_timeout() {
                tokio::time::timeout(timeout, write).await.map_err(|_| {
                    RequestAdmissionError::Timeout {
                        phase: ProtocolIoPhase::ResponseWrite,
                        timeout,
                    }
                })??;
            } else {
                write.await?;
            }
            BYTES_SENT.add(payload.len() as u64, &[]);
        }
        Ok(())
    }
}

impl<S, State, P, M, Stream> Service<TcpContext, Stream> for AdmittedTcpBytesService<S, State, P, M>
where
    S: Service<State, AdmittedFrame<P::Guard>, Response = AdmittedReply<P::Guard, Reply>>,
    P: Policy<State, RequestHead>,
    P::Error: error::Error + 'static,
    S::Error: error::Error + 'static,
    State: Clone + Default + Send + Sync + 'static,
    Stream: AsyncReadExt + AsyncWriteExt + Unpin + Send + Sync + 'static,
    M: AdmissionDisconnectMonitor<Stream> + Send + Sync + 'static,
{
    type Response = ();
    type Error = RequestAdmissionError<P::Error, S::Error>;

    async fn serve(
        &self,
        ctx: Context<TcpContext>,
        mut stream: Stream,
    ) -> Result<Self::Response, Self::Error> {
        let maximum_frame_size = ctx.state().maximum_frame_size;
        let transport = ctx.get::<TcpTransportConfig>().copied().unwrap_or_default();
        let (ctx, _) = ctx.swap_state(State::default());

        loop {
            self.request(&mut stream, maximum_frame_size, transport, ctx.clone())
                .await?;
        }
    }
}

impl<S, State> TcpBytesService<S, State>
where
    S: Service<State, Bytes, Response = Bytes>,
    S::Error: From<Error> + From<io::Error> + Debug,
    State: Clone + Default + Send + Sync + 'static,
{
    #[instrument(skip_all)]
    async fn wait<R>(
        &self,
        req: &mut R,
        maximum_frame_size: Option<usize>,
        transport: TcpTransportConfig,
    ) -> Result<(RequestHead, FrameLength, [u8; REQUEST_HEAD_BYTES]), S::Error>
    where
        R: AsyncReadExt + Unpin,
    {
        let mut head = [0u8; REQUEST_HEAD_BYTES];

        let read = req.read_exact(&mut head[..FRAME_LENGTH_PREFIX_BYTES]);
        if let Some(timeout) = transport.idle_timeout() {
            _ = tokio::time::timeout(timeout, read)
                .await
                .map_err(|_| Error::ConnectionIdleTimeout { timeout })?
                .inspect_err(|err| debug!(?err))?;
        } else {
            _ = read.await.inspect_err(|err| debug!(?err))?;
        }

        // Validate the declared body before reading even the fixed request
        // header. In particular, an oversized declaration never controls an
        // allocation or causes additional body bytes to be consumed.
        _ = FrameLength::request(
            head[..FRAME_LENGTH_PREFIX_BYTES]
                .try_into()
                .expect("the request head contains a complete length prefix"),
            maximum_frame_size,
        )?;

        let read = req.read_exact(&mut head[FRAME_LENGTH_PREFIX_BYTES..]);
        if let Some(timeout) = transport.request_head_timeout() {
            _ = tokio::time::timeout(timeout, read)
                .await
                .map_err(|_| Error::ProtocolIoTimeout {
                    phase: ProtocolIoPhase::FixedRequestHeader,
                    timeout,
                })?
                .inspect_err(|err| debug!(?err))?;
        } else {
            _ = read.await.inspect_err(|err| debug!(?err))?;
        }

        RequestHead::decode(head, maximum_frame_size)
            .map(|(request_head, length)| (request_head, length, head))
            .map_err(Into::into)
    }

    #[instrument(skip_all)]
    async fn read<R>(
        &self,
        req: &mut R,
        length: FrameLength,
        head: [u8; REQUEST_HEAD_BYTES],
        timeout: Option<Duration>,
    ) -> Result<Bytes, S::Error>
    where
        R: AsyncReadExt + Unpin,
    {
        let mut request: Vec<u8> = vec![0u8; length.complete];

        request[..REQUEST_HEAD_BYTES].copy_from_slice(&head);

        let read = req.read_exact(&mut request[REQUEST_HEAD_BYTES..]);
        if let Some(timeout) = timeout {
            _ = tokio::time::timeout(timeout, read)
                .await
                .map_err(|_| Error::ProtocolIoTimeout {
                    phase: ProtocolIoPhase::RequestBody,
                    timeout,
                })?
                .inspect_err(|err| error!(?err))?;
        } else {
            _ = read.await.inspect_err(|err| error!(?err))?;
        }
        BYTES_RECEIVED.add(request.len() as u64, &[]);

        Ok(Bytes::from(request))
    }

    #[instrument(skip_all)]
    async fn process(
        &self,
        attributes: &[KeyValue],
        ctx: Context<TcpContext>,
        request: Bytes,
    ) -> Result<Bytes, S::Error> {
        REQUEST_SIZE.record(request.len() as u64, attributes);

        let (ctx, _) = ctx.swap_state(State::default());
        let request_start = SystemTime::now();

        self.inner
            .serve(ctx, request)
            .await
            .inspect_err(|err| error!(?err))
            .inspect(|response| {
                RESPONSE_SIZE.record(response.len() as u64, attributes);

                let elapsed_millis = self.elapsed_millis(request_start);

                REQUEST_DURATION.record(elapsed_millis, attributes);
            })
    }

    #[instrument(skip_all)]
    async fn write<W>(
        &self,
        req: &mut W,
        frame: Bytes,
        timeout: Option<Duration>,
    ) -> Result<(), S::Error>
    where
        W: AsyncWriteExt + Unpin,
    {
        let write = async {
            req.write_all(&frame).await.inspect_err(|err| error!(?err))?;
            req.flush().await
        };
        let result: io::Result<()> = if let Some(timeout) = timeout {
            tokio::time::timeout(timeout, write)
                .await
                .map_err(|_| Error::ProtocolIoTimeout {
                    phase: ProtocolIoPhase::ResponseWrite,
                    timeout,
                })?
        } else {
            write.await
        };
        result?;
        BYTES_SENT.add(frame.len() as u64, &[]);
        Ok(())
    }

    #[instrument(skip_all, fields(id = nanoid!()))]
    async fn req<R>(
        &self,
        req: &mut R,
        maximum_frame_size: Option<usize>,
        transport: TcpTransportConfig,
        attributes: &[KeyValue],
        ctx: Context<TcpContext>,
    ) -> Result<(), S::Error>
    where
        R: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let (_head, length, encoded_head) = self.wait(req, maximum_frame_size, transport).await?;
        let request = self
            .read(req, length, encoded_head, transport.body_read_timeout())
            .await?;
        let response = self.process(attributes, ctx, request).await?;
        self.write(req, response, transport.response_write_timeout())
            .await
    }
}

impl<S, State, Stream> Service<TcpContext, Stream> for TcpBytesService<S, State>
where
    S: Service<State, Bytes, Response = Bytes>,
    S::Error: From<Error> + From<io::Error> + Debug,
    State: Clone + Default + Send + Sync + 'static,
    Stream: AsyncReadExt + AsyncWriteExt + Unpin + Send + Sync + 'static,
{
    type Response = ();

    type Error = S::Error;

    #[instrument(skip(ctx, req))]
    async fn serve(
        &self,
        ctx: Context<TcpContext>,
        mut req: Stream,
    ) -> Result<Self::Response, Self::Error> {
        let attributes = {
            let state = ctx.state();

            let mut attributes = vec![];

            if let Some(cluster_id) = state.cluster_id.clone() {
                attributes.push(KeyValue::new("cluster_id", cluster_id))
            }

            attributes
        };

        let maximum_frame_size = ctx.state().maximum_frame_size;
        let transport = ctx.get::<TcpTransportConfig>().copied().unwrap_or_default();

        loop {
            let ctx = ctx.clone();
            let attributes = attributes.clone();

            self.req(
                &mut req,
                maximum_frame_size,
                transport,
                &attributes[..],
                ctx,
            )
            .await?
        }
    }
}

/// A [`Layer`] that handles and responds with [`Bytes`]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BytesLayer;

impl<S> Layer<S> for BytesLayer {
    type Service = BytesService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service { inner }
    }
}

/// A [`Service`] that handles and responds with [`Bytes`]
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BytesService<S> {
    inner: S,
}

impl<S> Debug for BytesService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct(stringify!(BytesService)).finish()
    }
}

impl<S, State> Service<State, Bytes> for BytesService<S>
where
    S: Service<State, Bytes, Response = Bytes>,
    State: Clone + Send + Sync + 'static,
{
    type Response = Bytes;
    type Error = S::Error;

    #[instrument(skip_all)]
    async fn serve(&self, ctx: Context<State>, req: Bytes) -> Result<Self::Response, Self::Error> {
        debug!(request_length = req.len());
        self.inner
            .serve(ctx, req)
            .await
            .inspect(|response| debug!(response_length = response.len()))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        num::{NonZeroU32, NonZeroUsize},
        ptr,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use rama::{
        Context, Layer as _, Service as _,
        layer::limit::policy::{Policy, PolicyOutput, PolicyResult},
    };
    use tansu_sans_io::{
        ApiKey as _, Body, Frame, Header, ProduceRequest, ProduceResponse,
        produce_response::TopicProduceResponse,
    };
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _, duplex},
        net::{TcpListener, TcpStream},
        sync::{Semaphore, mpsc, oneshot},
        time::{Duration, advance, timeout},
    };
    use tokio_util::sync::CancellationToken;

    use super::{
        AcceptIntent, AdmissionDisconnect, AdmissionDisconnectMonitor, AdmissionEvidence,
        AdmissionLease, AdmittedFrame, AdmittedReply, ConnectionInfo, FixedConnectionPolicy,
        FrameLength, ProtocolIoPhase, Reply, RequestAdmissionError, RequestHead,
        SocketOptionTarget, TcpAdmissionDisconnectMonitor, TcpBytesLayer, TcpContext,
        TcpKeepaliveConfig, TcpListenerService, TcpTransportConfig, TcpTransportConfigError,
        configure_admitted_socket,
    };
    use crate::{BytesFrameLayer, Error};

    #[derive(Clone, Debug)]
    struct EchoService {
        calls: Arc<AtomicUsize>,
    }

    #[derive(Clone, Debug)]
    struct RequestPolicy {
        gate: Arc<Semaphore>,
        started: mpsc::UnboundedSender<RequestHead>,
        drops: Arc<AtomicUsize>,
        abort: bool,
    }

    #[derive(Clone, Debug)]
    struct PendingCancellationPolicy {
        started: mpsc::UnboundedSender<()>,
        cancelled: Arc<AtomicUsize>,
    }

    impl Policy<(), RequestHead> for PendingCancellationPolicy {
        type Guard = RequestLease;
        type Error = io::Error;

        async fn check(
            &self,
            _ctx: Context<()>,
            _request: RequestHead,
        ) -> PolicyResult<(), RequestHead, Self::Guard, Self::Error> {
            let cancellation = DropProbe(self.cancelled.clone());
            self.started.send(()).unwrap();
            std::future::pending::<()>().await;
            drop(cancellation);
            unreachable!("the cancellation policy never resolves")
        }
    }

    #[derive(Clone, Debug)]
    struct PendingCancellationMonitor {
        started: mpsc::UnboundedSender<()>,
        cancelled: Arc<AtomicUsize>,
    }

    impl<Stream> AdmissionDisconnectMonitor<Stream> for PendingCancellationMonitor
    where
        Stream: Sync,
    {
        async fn disconnected(&self, _stream: &Stream) -> Result<AdmissionDisconnect, io::Error> {
            let cancellation = DropProbe(self.cancelled.clone());
            self.started.send(()).unwrap();
            std::future::pending::<()>().await;
            drop(cancellation);
            unreachable!("the cancellation monitor never resolves")
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct FailingDisconnectMonitor;

    impl<Stream> AdmissionDisconnectMonitor<Stream> for FailingDisconnectMonitor
    where
        Stream: Sync,
    {
        async fn disconnected(&self, _stream: &Stream) -> Result<AdmissionDisconnect, io::Error> {
            Err(io::Error::other("injected disconnect probe failure"))
        }
    }

    #[derive(Debug)]
    struct RequestLease {
        id: usize,
        drops: Arc<AtomicUsize>,
    }

    #[derive(Debug)]
    struct AdjustableLease {
        identity: usize,
        reservation: usize,
    }

    #[derive(Debug)]
    struct ReservationEvidence {
        identity: usize,
    }

    #[derive(Debug)]
    struct EvidenceLease {
        reservation: Arc<ReservationEvidence>,
    }

    #[derive(Debug)]
    struct PhaseLease {
        identity: Arc<()>,
        reservation: usize,
    }

    impl AdmissionLease for AdjustableLease {
        type Adjustment = usize;
        type Error = std::convert::Infallible;

        fn adjust(&mut self, adjustment: Self::Adjustment) -> Result<(), Self::Error> {
            self.reservation = adjustment;
            Ok(())
        }
    }

    impl AdmissionLease for EvidenceLease {
        type Adjustment = ();
        type Error = std::convert::Infallible;

        fn adjust(&mut self, _adjustment: Self::Adjustment) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl AdmissionEvidence for EvidenceLease {
        type Evidence = ReservationEvidence;

        fn evidence(&self) -> &Self::Evidence {
            &self.reservation
        }
    }

    impl AdmissionLease for PhaseLease {
        type Adjustment = usize;
        type Error = std::convert::Infallible;

        fn adjust(&mut self, adjustment: Self::Adjustment) -> Result<(), Self::Error> {
            self.reservation = adjustment;
            Ok(())
        }
    }

    impl Drop for RequestLease {
        fn drop(&mut self) {
            _ = self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Policy<(), RequestHead> for RequestPolicy {
        type Guard = RequestLease;
        type Error = io::Error;

        async fn check(
            &self,
            ctx: Context<()>,
            request: RequestHead,
        ) -> PolicyResult<(), RequestHead, Self::Guard, Self::Error> {
            self.started.send(request).unwrap();
            let output = if self.abort {
                PolicyOutput::Abort(io::Error::other("request denied"))
            } else {
                match self.gate.clone().acquire_owned().await {
                    Ok(permit) => {
                        permit.forget();
                        PolicyOutput::Ready(RequestLease {
                            id: request.correlation_id() as usize,
                            drops: self.drops.clone(),
                        })
                    }
                    Err(error) => PolicyOutput::Abort(io::Error::other(error.to_string())),
                }
            };
            PolicyResult {
                ctx,
                request,
                output,
            }
        }
    }

    #[derive(Clone, Debug)]
    struct AdmittedEchoService {
        observed_lease: mpsc::UnboundedSender<usize>,
        fail: bool,
    }

    #[derive(Clone, Debug)]
    struct ProduceSequenceService {
        calls: Arc<AtomicUsize>,
        handled: mpsc::UnboundedSender<i32>,
    }

    impl rama::Service<(), Frame> for ProduceSequenceService {
        type Response = Frame;
        type Error = Error;

        async fn serve(
            &self,
            _ctx: Context<()>,
            req: Frame,
        ) -> Result<Self::Response, Self::Error> {
            let correlation_id = req.correlation_id()?;
            self.handled.send(correlation_id).unwrap();
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(Error::Message("first produce failed".into()));
            }

            Ok(Frame {
                size: 0,
                header: Header::Response { correlation_id },
                body: Body::ProduceResponse(
                    ProduceResponse::default()
                        .responses(Some(Vec::<TopicProduceResponse>::new()))
                        .throttle_time_ms(Some(0)),
                ),
            })
        }
    }

    fn encoded_produce(acks: i16, correlation_id: i32) -> bytes::Bytes {
        Frame::request(
            Header::Request {
                api_key: ProduceRequest::KEY,
                api_version: 3,
                correlation_id,
                client_id: Some("test".into()),
            },
            Body::ProduceRequest(
                ProduceRequest::default()
                    .acks(acks)
                    .timeout_ms(1_000)
                    .topic_data(Some(Vec::new())),
            ),
        )
        .unwrap()
    }

    impl rama::Service<(), AdmittedFrame<RequestLease>> for AdmittedEchoService {
        type Response = AdmittedReply<RequestLease, Reply>;
        type Error = Error;

        async fn serve(
            &self,
            _ctx: Context<()>,
            req: AdmittedFrame<RequestLease>,
        ) -> Result<Self::Response, Self::Error> {
            self.observed_lease.send(req.lease.id).unwrap();
            if self.fail {
                Err(Error::Message("handler failed".into()))
            } else {
                let payload = req.payload().clone();
                Ok(req.reply(Reply::Frame(payload)))
            }
        }
    }

    #[derive(Clone, Debug)]
    struct MakeConnection {
        calls: Arc<AtomicUsize>,
        started: mpsc::UnboundedSender<ConnectionInfo>,
        drops: Arc<AtomicUsize>,
    }

    impl rama::Service<(), ConnectionInfo> for MakeConnection {
        type Response = PendingConnection;
        type Error = Error;

        async fn serve(
            &self,
            _ctx: Context<()>,
            connection: ConnectionInfo,
        ) -> Result<Self::Response, Self::Error> {
            _ = self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(PendingConnection {
                connection,
                started: self.started.clone(),
                drops: self.drops.clone(),
            })
        }
    }

    #[derive(Debug)]
    struct PendingConnection {
        connection: ConnectionInfo,
        started: mpsc::UnboundedSender<ConnectionInfo>,
        drops: Arc<AtomicUsize>,
    }

    impl rama::Service<(), TcpStream> for PendingConnection {
        type Response = ();
        type Error = Error;

        async fn serve(
            &self,
            _ctx: Context<()>,
            _stream: TcpStream,
        ) -> Result<Self::Response, Self::Error> {
            struct DropCount(Arc<AtomicUsize>);

            impl Drop for DropCount {
                fn drop(&mut self) {
                    _ = self.0.fetch_add(1, Ordering::SeqCst);
                }
            }

            let _drop_count = DropCount(self.drops.clone());
            self.started.send(self.connection).unwrap();
            std::future::pending().await
        }
    }

    #[derive(Clone, Debug)]
    struct MakeByteConnection {
        started: mpsc::UnboundedSender<ConnectionInfo>,
    }

    impl rama::Service<(), ConnectionInfo> for MakeByteConnection {
        type Response = ByteConnection;
        type Error = Error;

        async fn serve(
            &self,
            _ctx: Context<()>,
            connection: ConnectionInfo,
        ) -> Result<Self::Response, Self::Error> {
            Ok(ByteConnection {
                connection,
                started: self.started.clone(),
            })
        }
    }

    #[derive(Debug)]
    struct ByteConnection {
        connection: ConnectionInfo,
        started: mpsc::UnboundedSender<ConnectionInfo>,
    }

    impl rama::Service<(), TcpStream> for ByteConnection {
        type Response = ();
        type Error = Error;

        async fn serve(
            &self,
            _ctx: Context<()>,
            mut stream: TcpStream,
        ) -> Result<Self::Response, Self::Error> {
            self.started.send(self.connection).unwrap();
            _ = stream.read_u8().await?;
            Ok(())
        }
    }

    #[derive(Clone, Debug)]
    struct GatedPolicy {
        gate: Arc<Semaphore>,
        started: mpsc::UnboundedSender<()>,
        ready: mpsc::UnboundedSender<()>,
        dropped: mpsc::UnboundedSender<()>,
        drops: Arc<AtomicUsize>,
    }

    #[derive(Debug)]
    struct CountingLease {
        dropped: mpsc::UnboundedSender<()>,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for CountingLease {
        fn drop(&mut self) {
            _ = self.drops.fetch_add(1, Ordering::SeqCst);
            self.dropped.send(()).unwrap();
        }
    }

    impl Policy<(), AcceptIntent> for GatedPolicy {
        type Guard = CountingLease;
        type Error = io::Error;

        async fn check(
            &self,
            ctx: Context<()>,
            request: AcceptIntent,
        ) -> PolicyResult<(), AcceptIntent, Self::Guard, Self::Error> {
            self.started.send(()).unwrap();
            let output = match self.gate.clone().acquire_owned().await {
                Ok(permit) => {
                    permit.forget();
                    self.ready.send(()).unwrap();
                    PolicyOutput::Ready(CountingLease {
                        dropped: self.dropped.clone(),
                        drops: self.drops.clone(),
                    })
                }
                Err(error) => PolicyOutput::Abort(io::Error::other(error.to_string())),
            };
            PolicyResult {
                ctx,
                request,
                output,
            }
        }
    }

    #[derive(Clone, Debug)]
    struct RejectConnection {
        calls: Arc<AtomicUsize>,
    }

    impl rama::Service<(), ConnectionInfo> for RejectConnection {
        type Response = PendingConnection;
        type Error = Error;

        async fn serve(
            &self,
            _ctx: Context<()>,
            _connection: ConnectionInfo,
        ) -> Result<Self::Response, Self::Error> {
            _ = self.calls.fetch_add(1, Ordering::SeqCst);
            Err(Error::Message("factory rejected connection".into()))
        }
    }

    impl rama::Service<(), bytes::Bytes> for EchoService {
        type Response = bytes::Bytes;
        type Error = Error;

        async fn serve(
            &self,
            _ctx: Context<()>,
            req: bytes::Bytes,
        ) -> Result<Self::Response, Self::Error> {
            _ = self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(req)
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SocketCall {
        NoDelay(bool),
        ReceiveBuffer(NonZeroUsize),
        SendBuffer(NonZeroUsize),
        Keepalive(TcpKeepaliveConfig),
    }

    #[derive(Debug, Default)]
    struct RecordingSocket {
        calls: Mutex<Vec<SocketCall>>,
        fail_on_call: Option<usize>,
    }

    impl RecordingSocket {
        fn failing_on(call: usize) -> Self {
            Self {
                calls: Mutex::default(),
                fail_on_call: Some(call),
            }
        }

        fn record(&self, call: SocketCall) -> io::Result<()> {
            let mut calls = self.calls.lock().unwrap();
            calls.push(call);
            if self.fail_on_call == Some(calls.len()) {
                Err(io::Error::other("injected socket option failure"))
            } else {
                Ok(())
            }
        }
    }

    impl SocketOptionTarget for RecordingSocket {
        fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
            self.record(SocketCall::NoDelay(nodelay))
        }

        fn set_receive_buffer_size(&self, size: NonZeroUsize) -> io::Result<()> {
            self.record(SocketCall::ReceiveBuffer(size))
        }

        fn set_send_buffer_size(&self, size: NonZeroUsize) -> io::Result<()> {
            self.record(SocketCall::SendBuffer(size))
        }

        fn set_keepalive(&self, keepalive: TcpKeepaliveConfig) -> io::Result<()> {
            self.record(SocketCall::Keepalive(keepalive))
        }
    }

    #[derive(Debug)]
    struct DropProbe(Arc<AtomicUsize>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            _ = self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn bounded_transport_config() -> TcpTransportConfig {
        let keepalive = TcpKeepaliveConfig::new(Duration::from_secs(60))
            .unwrap()
            .with_interval(Duration::from_secs(30))
            .unwrap()
            .with_retries(3)
            .unwrap();
        TcpTransportConfig::default()
            .with_nodelay(true)
            .with_receive_buffer_size(256 * 1024)
            .unwrap()
            .with_send_buffer_size(128 * 1024)
            .unwrap()
            .with_keepalive(keepalive)
            .with_idle_timeout(Duration::from_secs(5 * 60))
            .unwrap()
            .with_request_head_timeout(Duration::from_secs(10))
            .unwrap()
            .with_body_read_timeout(Duration::from_secs(30))
            .unwrap()
            .with_response_write_timeout(Duration::from_secs(30))
            .unwrap()
    }

    #[test]
    fn bounded_transport_configuration_round_trips_without_hidden_defaults() {
        let config = bounded_transport_config();

        assert_eq!(Some(true), config.nodelay());
        assert_eq!(
            Some(NonZeroUsize::new(256 * 1024).unwrap()),
            config.receive_buffer_size()
        );
        assert_eq!(
            Some(NonZeroUsize::new(128 * 1024).unwrap()),
            config.send_buffer_size()
        );
        assert_eq!(Duration::from_secs(60), config.keepalive().unwrap().idle());
        assert_eq!(
            Some(Duration::from_secs(30)),
            config.keepalive().unwrap().interval()
        );
        assert_eq!(
            Some(NonZeroU32::new(3).unwrap()),
            config.keepalive().unwrap().retries()
        );
        assert_eq!(Some(Duration::from_secs(5 * 60)), config.idle_timeout());
        assert_eq!(Some(Duration::from_secs(10)), config.request_head_timeout());
        assert_eq!(Some(Duration::from_secs(30)), config.body_read_timeout());
        assert_eq!(
            Some(Duration::from_secs(30)),
            config.response_write_timeout()
        );
        assert_eq!(TcpTransportConfig::default(), TcpTransportConfig::default());
    }

    #[test]
    fn bounded_transport_configuration_rejects_values_which_do_not_bound_resources() {
        assert!(matches!(
            TcpTransportConfig::default().with_receive_buffer_size(0),
            Err(TcpTransportConfigError::ZeroSocketBuffer { option: "receive" })
        ));
        assert!(matches!(
            TcpTransportConfig::default().with_send_buffer_size(i32::MAX as usize + 1),
            Err(TcpTransportConfigError::SocketBufferTooLarge { option: "send", .. })
        ));
        assert!(matches!(
            TcpKeepaliveConfig::new(Duration::ZERO),
            Err(TcpTransportConfigError::ZeroDuration { .. })
        ));
        assert!(matches!(
            TcpKeepaliveConfig::new(Duration::from_secs(1))
                .unwrap()
                .with_retries(0),
            Err(TcpTransportConfigError::ZeroKeepaliveRetries)
        ));
        assert!(matches!(
            TcpTransportConfig::default().with_idle_timeout(Duration::ZERO),
            Err(TcpTransportConfigError::ZeroDuration { .. })
        ));
        assert!(matches!(
            TcpTransportConfig::default().with_request_head_timeout(Duration::ZERO),
            Err(TcpTransportConfigError::ZeroDuration {
                option: "fixed request header"
            })
        ));
        assert!(matches!(
            TcpTransportConfig::default().with_body_read_timeout(Duration::ZERO),
            Err(TcpTransportConfigError::ZeroDuration {
                option: "request body read"
            })
        ));
        assert!(matches!(
            TcpTransportConfig::default().with_response_write_timeout(Duration::ZERO),
            Err(TcpTransportConfigError::ZeroDuration {
                option: "response write"
            })
        ));
        assert!(matches!(
            TcpAdmissionDisconnectMonitor::new(Duration::ZERO),
            Err(TcpTransportConfigError::ZeroDuration {
                option: "admission disconnect probe"
            })
        ));
    }

    #[test]
    fn socket_options_are_applied_exactly_once_in_declared_order() {
        let config = bounded_transport_config();
        let socket = RecordingSocket::default();

        config.apply(&socket).unwrap();

        assert_eq!(
            vec![
                SocketCall::NoDelay(true),
                SocketCall::ReceiveBuffer(NonZeroUsize::new(256 * 1024).unwrap()),
                SocketCall::SendBuffer(NonZeroUsize::new(128 * 1024).unwrap()),
                SocketCall::Keepalive(config.keepalive().unwrap()),
            ],
            *socket.calls.lock().unwrap()
        );
    }

    #[test]
    fn socket_setup_failure_releases_admission_guard() {
        let drops = Arc::new(AtomicUsize::new(0));
        let socket = RecordingSocket::failing_on(2);

        let result = configure_admitted_socket(
            bounded_transport_config(),
            &socket,
            DropProbe(drops.clone()),
        );

        assert!(result.is_err());
        assert_eq!(1, drops.load(Ordering::SeqCst));
        assert_eq!(2, socket.calls.lock().unwrap().len());
    }

    #[tokio::test(start_paused = true)]
    async fn idle_timeout_expires_only_while_waiting_for_the_next_frame_prefix() {
        let calls = Arc::new(AtomicUsize::new(0));
        let service = TcpBytesLayer::<()>::default().into_layer(EchoService { calls });
        let (_client, server) = duplex(64);
        let mut ctx = Context::with_state(TcpContext::default());
        assert!(
            ctx.insert(
                TcpTransportConfig::default()
                    .with_idle_timeout(Duration::from_secs(30))
                    .unwrap(),
            )
            .is_none()
        );

        let connection = tokio::spawn(async move { service.serve(ctx, server).await });
        tokio::task::yield_now().await;
        advance(Duration::from_secs(29)).await;
        assert!(!connection.is_finished());
        advance(Duration::from_secs(1)).await;

        assert!(matches!(
            connection.await.unwrap(),
            Err(Error::ConnectionIdleTimeout { timeout }) if timeout == Duration::from_secs(30)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn admitted_runtime_expires_only_while_waiting_for_the_next_frame_prefix() {
        let drops = Arc::new(AtomicUsize::new(0));
        let (started_tx, _started_rx) = mpsc::unbounded_channel();
        let (observed_tx, _observed_rx) = mpsc::unbounded_channel();
        let service = TcpBytesLayer::<()>::default()
            .with_request_policy(RequestPolicy {
                gate: Arc::new(Semaphore::new(1)),
                started: started_tx,
                drops,
                abort: false,
            })
            .into_layer(AdmittedEchoService {
                observed_lease: observed_tx,
                fail: false,
            });
        let (_client, server) = duplex(64);
        let mut ctx = Context::with_state(TcpContext::default());
        assert!(
            ctx.insert(
                TcpTransportConfig::default()
                    .with_idle_timeout(Duration::from_secs(30))
                    .unwrap(),
            )
            .is_none()
        );

        let connection = tokio::spawn(async move { service.serve(ctx, server).await });
        tokio::task::yield_now().await;
        advance(Duration::from_secs(29)).await;
        assert!(!connection.is_finished());
        advance(Duration::from_secs(1)).await;

        assert!(matches!(
            connection.await.unwrap(),
            Err(RequestAdmissionError::Frame(Error::ConnectionIdleTimeout { timeout }))
                if timeout == Duration::from_secs(30)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn request_head_deadline_starts_after_the_validated_length_prefix() {
        let calls = Arc::new(AtomicUsize::new(0));
        let service = TcpBytesLayer::<()>::default().into_layer(EchoService { calls });
        let (mut client, server) = duplex(64);
        let mut ctx = Context::with_state(TcpContext::default());
        assert!(
            ctx.insert(
                TcpTransportConfig::default()
                    .with_request_head_timeout(Duration::from_secs(10))
                    .unwrap(),
            )
            .is_none()
        );

        let connection = tokio::spawn(async move { service.serve(ctx, server).await });

        // Waiting for the four-byte prefix is governed only by the independent
        // idle policy, so the fixed-head deadline is not running yet.
        advance(Duration::from_secs(60)).await;
        assert!(!connection.is_finished());

        client.write_all(&8_i32.to_be_bytes()).await.unwrap();
        tokio::task::yield_now().await;
        advance(Duration::from_secs(9)).await;
        assert!(!connection.is_finished());
        advance(Duration::from_secs(1)).await;

        assert!(matches!(
            connection.await.unwrap(),
            Err(Error::ProtocolIoTimeout {
                phase: ProtocolIoPhase::FixedRequestHeader,
                timeout,
            }) if timeout == Duration::from_secs(10)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn legacy_runtime_bounds_request_body_reads() {
        let calls = Arc::new(AtomicUsize::new(0));
        let service = TcpBytesLayer::<()>::default().into_layer(EchoService { calls });
        let (mut client, server) = duplex(64);
        let mut ctx = Context::with_state(TcpContext::default().maximum_frame_size(Some(64)));
        assert!(
            ctx.insert(
                TcpTransportConfig::default()
                    .with_body_read_timeout(Duration::from_secs(30))
                    .unwrap(),
            )
            .is_none()
        );
        client
            .write_all(&[0, 0, 0, 64, 0, 3, 0, 1, 0, 0, 0, 41])
            .await
            .unwrap();

        let connection = tokio::spawn(async move { service.serve(ctx, server).await });
        tokio::task::yield_now().await;
        advance(Duration::from_secs(29)).await;
        assert!(!connection.is_finished());
        advance(Duration::from_secs(1)).await;

        assert!(matches!(
            connection.await.unwrap(),
            Err(Error::ProtocolIoTimeout {
                phase: ProtocolIoPhase::RequestBody,
                timeout,
            }) if timeout == Duration::from_secs(30)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn legacy_runtime_bounds_the_complete_response_write_and_flush() {
        let calls = Arc::new(AtomicUsize::new(0));
        let service = TcpBytesLayer::<()>::default().into_layer(EchoService {
            calls: calls.clone(),
        });
        let (mut client, server) = duplex(16);
        let mut request = vec![0u8; 68];
        request[..4].copy_from_slice(&64_i32.to_be_bytes());
        request[4..6].copy_from_slice(&3_i16.to_be_bytes());
        request[6..8].copy_from_slice(&1_i16.to_be_bytes());
        request[8..12].copy_from_slice(&73_i32.to_be_bytes());
        let mut ctx = Context::with_state(TcpContext::default().maximum_frame_size(Some(64)));
        assert!(
            ctx.insert(
                TcpTransportConfig::default()
                    .with_response_write_timeout(Duration::from_secs(30))
                    .unwrap(),
            )
            .is_none()
        );

        let connection = tokio::spawn(async move { service.serve(ctx, server).await });
        let writer = tokio::spawn(async move {
            client.write_all(&request).await.unwrap();
            client
        });
        while calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        let _client = writer.await.unwrap();

        advance(Duration::from_secs(29)).await;
        assert!(!connection.is_finished());
        advance(Duration::from_secs(1)).await;

        assert!(matches!(
            connection.await.unwrap(),
            Err(Error::ProtocolIoTimeout {
                phase: ProtocolIoPhase::ResponseWrite,
                timeout,
            }) if timeout == Duration::from_secs(30)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn admitted_body_deadline_excludes_policy_wait_and_releases_lease_once() {
        let gate = Arc::new(Semaphore::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let (started_tx, mut started_rx) = mpsc::unbounded_channel();
        let (observed_tx, _observed_rx) = mpsc::unbounded_channel();
        let service = TcpBytesLayer::<()>::default()
            .with_request_policy(RequestPolicy {
                gate: gate.clone(),
                started: started_tx,
                drops: drops.clone(),
                abort: false,
            })
            .into_layer(AdmittedEchoService {
                observed_lease: observed_tx,
                fail: false,
            });
        let (mut client, server) = duplex(64);
        let mut ctx = Context::with_state(TcpContext::default().maximum_frame_size(Some(64)));
        assert!(
            ctx.insert(
                TcpTransportConfig::default()
                    .with_body_read_timeout(Duration::from_secs(30))
                    .unwrap(),
            )
            .is_none()
        );
        client
            .write_all(&[0, 0, 0, 64, 0, 3, 0, 1, 0, 0, 0, 41])
            .await
            .unwrap();

        let connection = tokio::spawn(async move { service.serve(ctx, server).await });
        _ = started_rx.recv().await.unwrap();

        // Capacity waits are intentionally unbounded and do not spend a
        // client-I/O budget before the request owns its reservation.
        advance(Duration::from_secs(300)).await;
        assert!(!connection.is_finished());
        assert_eq!(0, drops.load(Ordering::SeqCst));

        gate.add_permits(1);
        tokio::task::yield_now().await;
        advance(Duration::from_secs(29)).await;
        assert!(!connection.is_finished());
        advance(Duration::from_secs(1)).await;

        assert!(matches!(
            connection.await.unwrap(),
            Err(RequestAdmissionError::Timeout {
                phase: ProtocolIoPhase::RequestBody,
                timeout,
            }) if timeout == Duration::from_secs(30)
        ));
        assert_eq!(1, drops.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn admitted_response_deadline_covers_write_and_flush_and_releases_lease_once() {
        let drops = Arc::new(AtomicUsize::new(0));
        let (started_tx, _started_rx) = mpsc::unbounded_channel();
        let (observed_tx, mut observed_rx) = mpsc::unbounded_channel();
        let service = TcpBytesLayer::<()>::default()
            .with_request_policy(RequestPolicy {
                gate: Arc::new(Semaphore::new(1)),
                started: started_tx,
                drops: drops.clone(),
                abort: false,
            })
            .into_layer(AdmittedEchoService {
                observed_lease: observed_tx,
                fail: false,
            });
        let (mut client, server) = duplex(16);
        let mut request = vec![0u8; 68];
        request[..4].copy_from_slice(&64_i32.to_be_bytes());
        request[4..6].copy_from_slice(&3_i16.to_be_bytes());
        request[6..8].copy_from_slice(&1_i16.to_be_bytes());
        request[8..12].copy_from_slice(&73_i32.to_be_bytes());
        let mut ctx = Context::with_state(TcpContext::default().maximum_frame_size(Some(64)));
        assert!(
            ctx.insert(
                TcpTransportConfig::default()
                    .with_response_write_timeout(Duration::from_secs(30))
                    .unwrap(),
            )
            .is_none()
        );

        let connection = tokio::spawn(async move { service.serve(ctx, server).await });
        let writer = tokio::spawn(async move {
            client.write_all(&request).await.unwrap();
            client
        });
        assert_eq!(73, observed_rx.recv().await.unwrap());
        // Retain the peer without reading: dropping it would turn this into an
        // immediate broken pipe instead of exercising the configured bound.
        let _client = writer.await.unwrap();

        tokio::task::yield_now().await;
        advance(Duration::from_secs(29)).await;
        assert!(!connection.is_finished());
        advance(Duration::from_secs(1)).await;

        assert!(matches!(
            connection.await.unwrap(),
            Err(RequestAdmissionError::Timeout {
                phase: ProtocolIoPhase::ResponseWrite,
                timeout,
            }) if timeout == Duration::from_secs(30)
        ));
        assert_eq!(1, drops.load(Ordering::SeqCst));
    }

    #[test]
    fn request_length_rejects_negative_declaration() {
        assert!(matches!(
            FrameLength::request((-1_i32).to_be_bytes(), Some(8)),
            Err(Error::InvalidFrameLength { declared: -1 })
        ));
    }

    #[test]
    fn request_length_rejects_structurally_short_declaration() {
        assert!(matches!(
            FrameLength::request(7_i32.to_be_bytes(), Some(8)),
            Err(Error::FrameTooShort {
                declared: 7,
                minimum: 8,
            })
        ));
    }

    #[test]
    fn common_length_validation_accepts_short_opaque_tokens() {
        assert_eq!(
            FrameLength {
                declared: 1,
                body: 1,
                complete: 5,
            },
            FrameLength::bounded(1_i32.to_be_bytes(), Some(1)).unwrap()
        );
        assert!(matches!(
            FrameLength::request(1_i32.to_be_bytes(), Some(1)),
            Err(Error::FrameTooShort {
                declared: 1,
                minimum: 8,
            })
        ));
    }

    #[test]
    fn request_length_enforces_body_byte_limit_boundaries() {
        let maximum = 9;

        assert_eq!(
            FrameLength {
                declared: 8,
                body: 8,
                complete: 12,
            },
            FrameLength::request(8_i32.to_be_bytes(), Some(maximum)).unwrap()
        );
        assert_eq!(
            FrameLength {
                declared: 9,
                body: 9,
                complete: 13,
            },
            FrameLength::request(9_i32.to_be_bytes(), Some(maximum)).unwrap()
        );
        assert!(matches!(
            FrameLength::request(10_i32.to_be_bytes(), Some(maximum)),
            Err(Error::FrameTooBig {
                declared: 10,
                maximum: 9,
            })
        ));
    }

    #[test]
    fn request_head_exposes_fixed_fields_without_interpreting_the_api() {
        let encoded = [0, 0, 0, 8, 0x7f, 0xff, 0xff, 0xfe, 0, 0, 0, 42];
        let (head, length) = RequestHead::decode(encoded, Some(8)).unwrap();

        assert_eq!(8, head.body_len());
        assert_eq!(i16::MAX, head.api_key());
        assert_eq!(-2, head.api_version());
        assert_eq!(42, head.correlation_id());
        assert_eq!(12, length.complete);
    }

    #[test]
    fn admitted_frame_adjusts_the_original_lease_without_exposing_it() {
        let mut frame = AdmittedFrame {
            head: RequestHead {
                body_len: 8,
                api_key: 3,
                api_version: 1,
                correlation_id: 42,
            },
            payload: bytes::Bytes::new(),
            lease: AdjustableLease {
                identity: 91,
                reservation: 1_024,
            },
        };

        frame.adjust_lease(128).unwrap();
        let reply = frame.map_payload(|_| ()).reply(Reply::NoResponse);
        assert_eq!(91, reply.lease.identity);
        assert_eq!(128, reply.lease.reservation);
    }

    #[test]
    fn admitted_frame_lends_payload_and_exact_lease_evidence() {
        let reservation = Arc::new(ReservationEvidence { identity: 91 });
        let expected_evidence = Arc::as_ptr(&reservation);
        let frame = AdmittedFrame {
            head: RequestHead {
                body_len: 8,
                api_key: 3,
                api_version: 1,
                correlation_id: 42,
            },
            payload: bytes::Bytes::from_static(b"admitted"),
            lease: EvidenceLease {
                reservation: reservation.clone(),
            },
        };

        let (payload, evidence) = frame.payload_and_evidence();
        assert_eq!(b"admitted".as_slice(), payload.as_ref());
        assert_eq!(91, evidence.identity);
        assert_eq!(expected_evidence, ptr::from_ref(evidence));
        assert_eq!(ptr::from_ref(frame.evidence()), ptr::from_ref(evidence));
    }

    #[test]
    fn admitted_reply_reconciles_the_same_lease_after_request_payload_drop() {
        let payload_drops = Arc::new(AtomicUsize::new(0));
        let identity = Arc::new(());
        let expected_identity = Arc::as_ptr(&identity);
        let frame = AdmittedFrame {
            head: RequestHead {
                body_len: 8,
                api_key: 3,
                api_version: 1,
                correlation_id: 42,
            },
            payload: DropProbe(payload_drops.clone()),
            lease: PhaseLease {
                identity: identity.clone(),
                reservation: 1_024,
            },
        };

        let mut reply = frame.reply(Reply::NoResponse);
        assert_eq!(1, payload_drops.load(Ordering::SeqCst));
        reply.adjust_lease(128).unwrap();

        // This destructuring is the private hand-off used by the transport.
        // The stable token proves adjustment did not substitute the lease.
        let AdmittedReply { lease, .. } = reply;
        assert_eq!(expected_identity, Arc::as_ptr(&lease.identity));
        assert_eq!(128, lease.reservation);
    }

    #[tokio::test]
    async fn rejected_length_never_enters_inner_service() {
        let calls = Arc::new(AtomicUsize::new(0));
        let service = TcpBytesLayer::<()>::default().into_layer(EchoService {
            calls: calls.clone(),
        });
        let (mut client, server) = duplex(32);
        client.write_all(&10_i32.to_be_bytes()).await.unwrap();

        let result = service
            .serve(
                Context::with_state(TcpContext::default().maximum_frame_size(Some(9))),
                server,
            )
            .await;

        assert!(matches!(
            result,
            Err(Error::FrameTooBig {
                declared: 10,
                maximum: 9,
            })
        ));
        assert_eq!(0, calls.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn ordinary_request_round_trip_is_byte_identical() {
        let calls = Arc::new(AtomicUsize::new(0));
        let service = TcpBytesLayer::<()>::default().into_layer(EchoService {
            calls: calls.clone(),
        });
        let (mut client, server) = duplex(64);
        let request = [0, 0, 0, 8, 0, 3, 0, 1, 0, 0, 0, 42];

        let server = tokio::spawn(async move {
            service
                .serve(
                    Context::with_state(TcpContext::default().maximum_frame_size(Some(8))),
                    server,
                )
                .await
        });

        client.write_all(&request).await.unwrap();
        let mut response = [0; 12];
        _ = client.read_exact(&mut response).await.unwrap();
        assert_eq!(request, response);
        assert_eq!(1, calls.load(Ordering::SeqCst));

        client.shutdown().await.unwrap();
        assert!(matches!(server.await.unwrap(), Err(Error::Io(_))));
    }

    #[tokio::test]
    async fn fragmented_request_head_is_reassembled_before_dispatch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let service = TcpBytesLayer::<()>::default().into_layer(EchoService {
            calls: calls.clone(),
        });
        let (mut client, server) = duplex(64);
        let request = [0, 0, 0, 8, 0, 3, 0, 1, 0, 0, 0, 42];

        let server = tokio::spawn(async move {
            service
                .serve(
                    Context::with_state(TcpContext::default().maximum_frame_size(Some(8))),
                    server,
                )
                .await
        });

        for byte in request {
            client.write_all(&[byte]).await.unwrap();
            tokio::task::yield_now().await;
        }
        let mut response = [0; 12];
        _ = client.read_exact(&mut response).await.unwrap();
        assert_eq!(request, response);
        assert_eq!(1, calls.load(Ordering::SeqCst));

        client.shutdown().await.unwrap();
        assert!(matches!(server.await.unwrap(), Err(Error::Io(_))));
    }

    #[tokio::test]
    async fn pending_request_policy_stops_body_reads_before_allocation() {
        let gate = Arc::new(Semaphore::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let (started_tx, mut started_rx) = mpsc::unbounded_channel();
        let (observed_tx, mut observed_rx) = mpsc::unbounded_channel();
        let service = TcpBytesLayer::<()>::default()
            .with_request_policy(RequestPolicy {
                gate: gate.clone(),
                started: started_tx,
                drops: drops.clone(),
                abort: false,
            })
            .into_layer(AdmittedEchoService {
                observed_lease: observed_tx,
                fail: false,
            });
        let (mut client, server) = duplex(16);
        let mut request = vec![0u8; 68];
        request[..4].copy_from_slice(&64_i32.to_be_bytes());
        request[4..6].copy_from_slice(&3_i16.to_be_bytes());
        request[6..8].copy_from_slice(&1_i16.to_be_bytes());
        request[8..12].copy_from_slice(&41_i32.to_be_bytes());

        let server = tokio::spawn(async move {
            service
                .serve(
                    Context::with_state(TcpContext::default().maximum_frame_size(Some(64))),
                    server,
                )
                .await
        });
        let writer = tokio::spawn(async move {
            client.write_all(&request).await.unwrap();
            let mut response = vec![0u8; request.len()];
            _ = client.read_exact(&mut response).await.unwrap();
            response
        });

        let head = timeout(Duration::from_secs(1), started_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(64, head.body_len());
        assert!(
            timeout(Duration::from_millis(50), observed_rx.recv())
                .await
                .is_err()
        );
        assert!(!writer.is_finished());
        assert_eq!(0, drops.load(Ordering::SeqCst));

        gate.add_permits(1);
        assert_eq!(41, observed_rx.recv().await.unwrap());
        let response = writer.await.unwrap();
        assert_eq!(64_i32.to_be_bytes(), response[..4]);
        assert_eq!(1, drops.load(Ordering::SeqCst));
        assert!(matches!(
            server.await.unwrap(),
            Err(RequestAdmissionError::Io(_))
        ));
    }

    #[tokio::test]
    async fn tcp_monitor_observes_fin_behind_queued_bytes_without_consuming_the_body() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(local_addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();

        let gate = Arc::new(Semaphore::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let (started_tx, mut started_rx) = mpsc::unbounded_channel();
        let (observed_tx, _observed_rx) = mpsc::unbounded_channel();
        let monitor = TcpAdmissionDisconnectMonitor::new(Duration::from_millis(50)).unwrap();
        assert_eq!(Duration::from_millis(50), monitor.probe_interval());
        let service = TcpBytesLayer::<()>::default()
            .with_request_policy(RequestPolicy {
                gate,
                started: started_tx,
                drops: drops.clone(),
                abort: false,
            })
            .with_disconnect_monitor(monitor)
            .into_layer(AdmittedEchoService {
                observed_lease: observed_tx,
                fail: false,
            });

        let mut request = vec![0xA5; 68];
        request[..4].copy_from_slice(&64_i32.to_be_bytes());
        request[4..6].copy_from_slice(&3_i16.to_be_bytes());
        request[6..8].copy_from_slice(&1_i16.to_be_bytes());
        request[8..12].copy_from_slice(&91_i32.to_be_bytes());
        client.write_all(&request).await.unwrap();

        let result = {
            let admission = service.request(
                &mut server,
                Some(64),
                TcpTransportConfig::default(),
                Context::with_state(()),
            );
            tokio::pin!(admission);

            // Readable body bytes must not create a hot readiness loop or
            // complete admission observation while the peer remains open.
            let pending = timeout(Duration::from_millis(125), &mut admission);
            tokio::pin!(pending);
            let mut policy_started = false;
            let pending_result = loop {
                tokio::select! {
                    result = &mut pending => break result,
                    started = started_rx.recv(), if !policy_started => {
                        let _started = started.unwrap();
                        policy_started = true;
                    }
                }
            };
            assert!(policy_started);
            assert!(pending_result.is_err());

            client.shutdown().await.unwrap();
            timeout(Duration::from_secs(1), admission)
                .await
                .expect("FIN must finish pending-admission observation")
        };

        assert!(matches!(
            result,
            Err(RequestAdmissionError::Disconnected(
                AdmissionDisconnect::Closed
            ))
        ));
        assert_eq!(0, drops.load(Ordering::SeqCst));

        let mut unread_body = vec![0u8; request.len() - 12];
        _ = timeout(Duration::from_secs(1), server.read_exact(&mut unread_body))
            .await
            .expect("the queued body must remain readable")
            .unwrap();
        assert_eq!(&request[12..], unread_body.as_slice());
    }

    #[tokio::test]
    async fn disconnect_monitor_failure_is_typed_and_never_creates_a_lease() {
        let drops = Arc::new(AtomicUsize::new(0));
        let (started_tx, _started_rx) = mpsc::unbounded_channel();
        let (observed_tx, _observed_rx) = mpsc::unbounded_channel();
        let service = TcpBytesLayer::<()>::default()
            .with_request_policy(RequestPolicy {
                gate: Arc::new(Semaphore::new(0)),
                started: started_tx,
                drops: drops.clone(),
                abort: false,
            })
            .with_disconnect_monitor(FailingDisconnectMonitor)
            .into_layer(AdmittedEchoService {
                observed_lease: observed_tx,
                fail: false,
            });
        let (mut client, server) = duplex(64);
        client
            .write_all(&[0, 0, 0, 8, 0, 3, 0, 1, 0, 0, 0, 9])
            .await
            .unwrap();

        assert!(matches!(
            service
                .serve(Context::with_state(TcpContext::default()), server)
                .await,
            Err(RequestAdmissionError::DisconnectMonitor(error))
                if error.to_string() == "injected disconnect probe failure"
        ));
        assert_eq!(0, drops.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn cancelling_admission_drops_both_pending_futures_without_a_lease() {
        let policy_cancelled = Arc::new(AtomicUsize::new(0));
        let monitor_cancelled = Arc::new(AtomicUsize::new(0));
        let (policy_started_tx, mut policy_started_rx) = mpsc::unbounded_channel();
        let (monitor_started_tx, mut monitor_started_rx) = mpsc::unbounded_channel();
        let (observed_tx, _observed_rx) = mpsc::unbounded_channel();
        let service = TcpBytesLayer::<()>::default()
            .with_request_policy(PendingCancellationPolicy {
                started: policy_started_tx,
                cancelled: policy_cancelled.clone(),
            })
            .with_disconnect_monitor(PendingCancellationMonitor {
                started: monitor_started_tx,
                cancelled: monitor_cancelled.clone(),
            })
            .into_layer(AdmittedEchoService {
                observed_lease: observed_tx,
                fail: false,
            });
        let (mut client, server) = duplex(64);
        client
            .write_all(&[0, 0, 0, 8, 0, 3, 0, 1, 0, 0, 0, 9])
            .await
            .unwrap();

        let connection = tokio::spawn(async move {
            service
                .serve(Context::with_state(TcpContext::default()), server)
                .await
        });
        policy_started_rx.recv().await.unwrap();
        monitor_started_rx.recv().await.unwrap();
        connection.abort();
        assert!(connection.await.unwrap_err().is_cancelled());

        assert_eq!(1, policy_cancelled.load(Ordering::SeqCst));
        assert_eq!(1, monitor_cancelled.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn request_policy_abort_is_distinct_from_a_protocol_denial() {
        let drops = Arc::new(AtomicUsize::new(0));
        let (started_tx, _started_rx) = mpsc::unbounded_channel();
        let (observed_tx, _observed_rx) = mpsc::unbounded_channel();
        let service = TcpBytesLayer::<()>::default()
            .with_request_policy(RequestPolicy {
                gate: Arc::new(Semaphore::new(1)),
                started: started_tx,
                drops,
                abort: true,
            })
            .into_layer(AdmittedEchoService {
                observed_lease: observed_tx,
                fail: false,
            });
        let (mut client, server) = duplex(32);
        client
            .write_all(&[0, 0, 0, 8, 0x7f, 0xff, 0, 1, 0, 0, 0, 9])
            .await
            .unwrap();

        assert!(matches!(
            service
                .serve(
                    Context::with_state(TcpContext::default().maximum_frame_size(Some(8))),
                    server,
                )
                .await,
            Err(RequestAdmissionError::Policy(_))
        ));
    }

    #[tokio::test]
    async fn fatal_handler_error_drops_the_exact_request_lease_once() {
        let drops = Arc::new(AtomicUsize::new(0));
        let (started_tx, _started_rx) = mpsc::unbounded_channel();
        let (observed_tx, mut observed_rx) = mpsc::unbounded_channel();
        let service = TcpBytesLayer::<()>::default()
            .with_request_policy(RequestPolicy {
                gate: Arc::new(Semaphore::new(1)),
                started: started_tx,
                drops: drops.clone(),
                abort: false,
            })
            .into_layer(AdmittedEchoService {
                observed_lease: observed_tx,
                fail: true,
            });
        let (mut client, server) = duplex(32);
        client
            .write_all(&[0, 0, 0, 8, 0, 3, 0, 1, 0, 0, 0, 73])
            .await
            .unwrap();

        assert!(matches!(
            service
                .serve(
                    Context::with_state(TcpContext::default().maximum_frame_size(Some(8))),
                    server,
                )
                .await,
            Err(RequestAdmissionError::Service(Error::Message(message)))
                if message == "handler failed"
        ));
        assert_eq!(73, observed_rx.recv().await.unwrap());
        assert_eq!(1, drops.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn produce_acks_zero_writes_nothing_and_preserves_stream_alignment() {
        let drops = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let (started_tx, _started_rx) = mpsc::unbounded_channel();
        let (handled_tx, mut handled_rx) = mpsc::unbounded_channel();
        let service = TcpBytesLayer::<()>::default()
            .with_request_policy(RequestPolicy {
                gate: Arc::new(Semaphore::new(2)),
                started: started_tx,
                drops: drops.clone(),
                abort: false,
            })
            .into_layer(
                BytesFrameLayer::default().into_layer(ProduceSequenceService {
                    calls: calls.clone(),
                    handled: handled_tx,
                }),
            );
        let (mut client, server) = duplex(512);
        let server = tokio::spawn(async move {
            service
                .serve(
                    Context::with_state(TcpContext::default().maximum_frame_size(Some(256))),
                    server,
                )
                .await
        });

        client.write_all(&encoded_produce(0, 101)).await.unwrap();
        assert_eq!(101, handled_rx.recv().await.unwrap());
        assert!(
            timeout(Duration::from_millis(50), client.read_u8())
                .await
                .is_err()
        );
        assert_eq!(1, drops.load(Ordering::SeqCst));

        client.write_all(&encoded_produce(1, 102)).await.unwrap();
        assert_eq!(102, handled_rx.recv().await.unwrap());
        let mut prefix = [0u8; 4];
        _ = client.read_exact(&mut prefix).await.unwrap();
        let body_len = usize::try_from(i32::from_be_bytes(prefix)).unwrap();
        let mut response = vec![0u8; body_len + prefix.len()];
        response[..prefix.len()].copy_from_slice(&prefix);
        _ = client
            .read_exact(&mut response[prefix.len()..])
            .await
            .unwrap();
        let response =
            Frame::response_from_bytes(bytes::Bytes::from(response), ProduceRequest::KEY, 3)
                .unwrap();
        assert_eq!(102, response.correlation_id().unwrap());
        assert_eq!(2, calls.load(Ordering::SeqCst));
        assert_eq!(2, drops.load(Ordering::SeqCst));

        client.shutdown().await.unwrap();
        assert!(matches!(
            server.await.unwrap(),
            Err(RequestAdmissionError::Io(_))
        ));
    }

    #[tokio::test]
    async fn listener_builds_each_connection_once_and_reaps_on_cancellation() {
        let cancellation = CancellationToken::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let (started_tx, mut started_rx) = mpsc::unbounded_channel();
        let make_connection = MakeConnection {
            calls: calls.clone(),
            started: started_tx,
            drops: drops.clone(),
        };
        let service = TcpListenerService::new(cancellation.clone(), make_connection);
        let (finished_tx, finished_rx) = oneshot::channel();

        let _listener_task = tokio::spawn(async move {
            let result = service.serve(Context::default(), listener).await;
            finished_tx.send(result).unwrap();
        });

        let first = TcpStream::connect(local_addr).await.unwrap();
        let second = TcpStream::connect(local_addr).await.unwrap();
        let first_info = timeout(Duration::from_secs(1), started_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let second_info = timeout(Duration::from_secs(1), started_rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(local_addr, first_info.local_addr());
        assert_eq!(local_addr, second_info.local_addr());
        assert_eq!(2, calls.load(Ordering::SeqCst));
        assert_eq!(0, drops.load(Ordering::SeqCst));

        cancellation.cancel();
        timeout(Duration::from_secs(1), finished_rx)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(2, drops.load(Ordering::SeqCst));

        drop((first, second));
    }

    #[tokio::test]
    async fn connection_limit_leaves_excess_socket_in_kernel_backlog() {
        let cancellation = CancellationToken::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let (started_tx, mut started_rx) = mpsc::unbounded_channel();
        let policy = FixedConnectionPolicy::new(NonZeroUsize::MIN);
        let service = TcpListenerService::new(
            cancellation.clone(),
            MakeByteConnection {
                started: started_tx,
            },
        )
        .with_policy(policy.clone());
        let (finished_tx, finished_rx) = oneshot::channel();
        let _listener_task = tokio::spawn(async move {
            let result = service.serve(Context::default(), listener).await;
            finished_tx.send(result).unwrap();
        });

        let mut first = TcpStream::connect(local_addr).await.unwrap();
        _ = timeout(Duration::from_secs(1), started_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(0, policy.available_permits());

        let second = timeout(Duration::from_secs(1), TcpStream::connect(local_addr))
            .await
            .unwrap()
            .unwrap();
        assert!(
            timeout(Duration::from_millis(50), started_rx.recv())
                .await
                .is_err()
        );

        first.write_u8(1).await.unwrap();
        _ = timeout(Duration::from_secs(1), started_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(0, policy.available_permits());

        cancellation.cancel();
        timeout(Duration::from_secs(1), finished_rx)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(1, policy.available_permits());

        drop((first, second));
    }

    #[tokio::test]
    async fn cancellation_drops_prospective_connection_guard_once() {
        let cancellation = CancellationToken::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let service_drops = Arc::new(AtomicUsize::new(0));
        let (connection_tx, _connection_rx) = mpsc::unbounded_channel();
        let (admission_tx, mut admission_rx) = mpsc::unbounded_channel();
        let (ready_tx, mut ready_rx) = mpsc::unbounded_channel();
        let (dropped_tx, mut dropped_rx) = mpsc::unbounded_channel();
        let lease_drops = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Semaphore::new(0));
        let service = TcpListenerService::new(
            cancellation.clone(),
            MakeConnection {
                calls: calls.clone(),
                started: connection_tx,
                drops: service_drops,
            },
        )
        .with_policy(GatedPolicy {
            gate: gate.clone(),
            started: admission_tx,
            ready: ready_tx,
            dropped: dropped_tx,
            drops: lease_drops.clone(),
        });
        let (finished_tx, finished_rx) = oneshot::channel();
        let _listener_task = tokio::spawn(async move {
            let result = service.serve(Context::default(), listener).await;
            finished_tx.send(result).unwrap();
        });

        timeout(Duration::from_secs(1), admission_rx.recv())
            .await
            .unwrap()
            .unwrap();
        gate.add_permits(1);
        timeout(Duration::from_secs(1), ready_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(0, lease_drops.load(Ordering::SeqCst));

        cancellation.cancel();
        timeout(Duration::from_secs(1), dropped_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(1, lease_drops.load(Ordering::SeqCst));
        assert_eq!(0, calls.load(Ordering::SeqCst));

        timeout(Duration::from_secs(1), finished_rx)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(1, lease_drops.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn competing_transport_context_fails_before_factory_and_releases_guard() {
        let cancellation = CancellationToken::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let service_drops = Arc::new(AtomicUsize::new(0));
        let (connection_tx, _connection_rx) = mpsc::unbounded_channel();
        let (admission_tx, mut admission_rx) = mpsc::unbounded_channel();
        let (ready_tx, mut ready_rx) = mpsc::unbounded_channel();
        let (dropped_tx, mut dropped_rx) = mpsc::unbounded_channel();
        let lease_drops = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Semaphore::new(0));
        let service = TcpListenerService::new(
            cancellation,
            MakeConnection {
                calls: calls.clone(),
                started: connection_tx,
                drops: service_drops,
            },
        )
        .with_policy(GatedPolicy {
            gate: gate.clone(),
            started: admission_tx,
            ready: ready_tx,
            dropped: dropped_tx,
            drops: lease_drops.clone(),
        });
        let mut ctx = Context::default();
        assert!(ctx.insert(TcpTransportConfig::default()).is_none());
        let (finished_tx, finished_rx) = oneshot::channel();
        let _listener_task = tokio::spawn(async move {
            let result = service.serve(ctx, listener).await;
            finished_tx.send(result).unwrap();
        });

        let client = TcpStream::connect(local_addr).await.unwrap();
        timeout(Duration::from_secs(1), admission_rx.recv())
            .await
            .unwrap()
            .unwrap();
        gate.add_permits(1);
        timeout(Duration::from_secs(1), ready_rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert!(matches!(
            timeout(Duration::from_secs(1), finished_rx)
                .await
                .unwrap()
                .unwrap(),
            Err(super::TcpListenerError::TransportContextAlreadyConfigured)
        ));
        timeout(Duration::from_secs(1), dropped_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(1, lease_drops.load(Ordering::SeqCst));
        assert_eq!(0, calls.load(Ordering::SeqCst));
        drop(client);
    }

    #[tokio::test]
    async fn factory_failure_drops_admission_lease_once() {
        let cancellation = CancellationToken::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let (admission_tx, mut admission_rx) = mpsc::unbounded_channel();
        let (ready_tx, mut ready_rx) = mpsc::unbounded_channel();
        let (dropped_tx, mut dropped_rx) = mpsc::unbounded_channel();
        let lease_drops = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Semaphore::new(0));
        let service = TcpListenerService::new(
            cancellation.clone(),
            RejectConnection {
                calls: calls.clone(),
            },
        )
        .with_policy(GatedPolicy {
            gate: gate.clone(),
            started: admission_tx,
            ready: ready_tx,
            dropped: dropped_tx,
            drops: lease_drops.clone(),
        });
        let (finished_tx, finished_rx) = oneshot::channel();
        let _listener_task = tokio::spawn(async move {
            let result = service.serve(Context::default(), listener).await;
            finished_tx.send(result).unwrap();
        });

        let client = TcpStream::connect(local_addr).await.unwrap();
        timeout(Duration::from_secs(1), admission_rx.recv())
            .await
            .unwrap()
            .unwrap();
        gate.add_permits(1);
        timeout(Duration::from_secs(1), ready_rx.recv())
            .await
            .unwrap()
            .unwrap();

        timeout(Duration::from_secs(1), dropped_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(1, calls.load(Ordering::SeqCst));
        assert_eq!(1, lease_drops.load(Ordering::SeqCst));

        cancellation.cancel();
        timeout(Duration::from_secs(1), finished_rx)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(1, lease_drops.load(Ordering::SeqCst));

        drop(client);
    }
}
