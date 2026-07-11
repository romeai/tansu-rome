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
    collections::HashMap, error, fmt::Debug, io, marker::PhantomData, mem::size_of,
    net::SocketAddr, num::NonZeroUsize, sync::Arc, time::SystemTime,
};

use bytes::Bytes;
use nanoid::nanoid;
use opentelemetry::KeyValue;
use rama::{
    Context, Layer, Service,
    layer::limit::policy::{Policy, PolicyOutput, PolicyResult, UnlimitedPolicy},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufWriter},
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
        Self::decode(encoded, MINIMUM_REQUEST_BODY_BYTES, maximum)
    }

    fn response(encoded: [u8; FRAME_LENGTH_PREFIX_BYTES]) -> Result<Self, Error> {
        Self::decode(encoded, MINIMUM_RESPONSE_BODY_BYTES, None)
    }

    fn decode(
        encoded: [u8; FRAME_LENGTH_PREFIX_BYTES],
        minimum: usize,
        maximum: Option<usize>,
    ) -> Result<Self, Error> {
        let declared = i32::from_be_bytes(encoded);
        let body = usize::try_from(declared).map_err(|_| Error::InvalidFrameLength { declared })?;

        if body < minimum {
            return Err(Error::FrameTooShort {
                declared: body,
                minimum,
            });
        }

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
}

/// The allocation-free portion of an incoming Kafka request.
///
/// This head is read and validated before storage for the complete frame is
/// allocated. `body_len` excludes Kafka's four-byte signed length prefix.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RequestHead {
    body_len: usize,
    api_key: i16,
    api_version: i16,
    correlation_id: i32,
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

    /// Request admission explicitly aborted.
    #[error("request admission policy aborted")]
    Policy(#[source] P),

    /// The admitted request service failed fatally.
    #[error("admitted request service failed")]
    Service(#[source] S),
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
}

impl Default for TcpListenerLayer {
    fn default() -> Self {
        Self {
            cancellation: CancellationToken::new(),
            policy: UnlimitedPolicy::new(),
        }
    }
}

impl TcpListenerLayer {
    pub fn new(cancellation: CancellationToken) -> Self {
        Self {
            cancellation,
            policy: UnlimitedPolicy::new(),
        }
    }
}

impl<P> TcpListenerLayer<P> {
    /// Use the Rama limit `policy` before accepting each connection.
    pub fn with_policy<Q>(self, policy: Q) -> TcpListenerLayer<Q> {
        TcpListenerLayer {
            cancellation: self.cancellation,
            policy,
        }
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
}

impl<M> TcpListenerService<M> {
    /// Create a listener runtime using `make_connection` as its per-socket
    /// service factory.
    pub fn new(cancellation: CancellationToken, make_connection: M) -> Self {
        Self {
            cancellation,
            make_connection,
            policy: UnlimitedPolicy::new(),
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
        }
    }
}

impl<M, P> Debug for TcpListenerService<M, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct(stringify!(TcpListenerService)).finish()
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
            let Some((connection_ctx, lease)) =
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
pub struct AdmittedTcpBytesLayer<State, P> {
    policy: P,
    _state: PhantomData<State>,
}

impl<State, P> AdmittedTcpBytesLayer<State, P> {
    /// Create an admitted TCP byte layer using the Rama request `policy`.
    pub fn new(policy: P) -> Self {
        Self {
            policy,
            _state: PhantomData,
        }
    }
}

impl<S, State, P> Layer<S> for AdmittedTcpBytesLayer<State, P>
where
    P: Clone,
{
    type Service = AdmittedTcpBytesService<S, State, P>;

    fn layer(&self, inner: S) -> Self::Service {
        AdmittedTcpBytesService {
            inner,
            policy: self.policy.clone(),
            _state: PhantomData,
        }
    }
}

/// A TCP connection service whose request bodies are guarded by a Rama policy.
#[derive(Clone, Debug)]
pub struct AdmittedTcpBytesService<S, State, P> {
    inner: S,
    policy: P,
    _state: PhantomData<State>,
}

#[derive(Debug, thiserror::Error)]
enum ReadHeadError {
    #[error("request head I/O failed")]
    Io(#[from] io::Error),

    #[error("invalid Kafka request head")]
    Frame(#[from] Error),
}

impl<S, State, P> AdmittedTcpBytesService<S, State, P> {
    async fn read_head<R>(
        &self,
        stream: &mut R,
        maximum_frame_size: Option<usize>,
    ) -> Result<(RequestHead, FrameLength, [u8; REQUEST_HEAD_BYTES]), ReadHeadError>
    where
        R: AsyncReadExt + Unpin,
    {
        let mut encoded = [0u8; REQUEST_HEAD_BYTES];
        _ = stream
            .read_exact(&mut encoded[..FRAME_LENGTH_PREFIX_BYTES])
            .await?;

        let length_prefix = encoded[..FRAME_LENGTH_PREFIX_BYTES]
            .try_into()
            .expect("the request head contains a complete length prefix");
        // This error is converted by `request`; keeping I/O separate here
        // makes it impossible to confuse a policy rejection with malformed
        // wire input.
        let length = FrameLength::request(length_prefix, maximum_frame_size)?;

        _ = stream
            .read_exact(&mut encoded[FRAME_LENGTH_PREFIX_BYTES..])
            .await?;
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
        ctx: Context<State>,
    ) -> Result<(), RequestAdmissionError<P::Error, S::Error>>
    where
        S: Service<State, AdmittedFrame<P::Guard>, Response = AdmittedReply<P::Guard>>,
        P: Policy<State, RequestHead>,
        P::Error: error::Error + 'static,
        S::Error: error::Error + 'static,
        State: Clone + Send + Sync + 'static,
        R: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let (wire_head, length, encoded_head) = self
            .read_head(stream, maximum_frame_size)
            .await
            .map_err(|error| match error {
                ReadHeadError::Io(error) => RequestAdmissionError::Io(error),
                ReadHeadError::Frame(error) => RequestAdmissionError::Frame(error),
            })?;
        let (ctx, admitted_head, lease) = self
            .admit(ctx, wire_head)
            .await
            .map_err(RequestAdmissionError::Policy)?;

        // A Rama policy may carry a request through retries, but changing the
        // protocol identity would separate admission from the bytes it guards.
        if admitted_head != wire_head {
            return Err(RequestAdmissionError::Frame(Error::Message(
                "request policy changed the Kafka request head".into(),
            )));
        }

        let mut request = vec![0u8; length.complete];
        request[..REQUEST_HEAD_BYTES].copy_from_slice(&encoded_head);
        _ = stream
            .read_exact(&mut request[REQUEST_HEAD_BYTES..])
            .await?;
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
        let mut writer = BufWriter::new(stream);
        writer.write_all(&payload).await?;
        BYTES_SENT.add(payload.len() as u64, &[]);
        writer.flush().await?;
        Ok(())
    }
}

impl<S, State, P, Stream> Service<TcpContext, Stream> for AdmittedTcpBytesService<S, State, P>
where
    S: Service<State, AdmittedFrame<P::Guard>, Response = AdmittedReply<P::Guard>>,
    P: Policy<State, RequestHead>,
    P::Error: error::Error + 'static,
    S::Error: error::Error + 'static,
    State: Clone + Default + Send + Sync + 'static,
    Stream: AsyncReadExt + AsyncWriteExt + Unpin + Send + Sync + 'static,
{
    type Response = ();
    type Error = RequestAdmissionError<P::Error, S::Error>;

    async fn serve(
        &self,
        ctx: Context<TcpContext>,
        mut stream: Stream,
    ) -> Result<Self::Response, Self::Error> {
        let maximum_frame_size = ctx.state().maximum_frame_size;
        let (ctx, _) = ctx.swap_state(State::default());

        loop {
            self.request(&mut stream, maximum_frame_size, ctx.clone())
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
    ) -> Result<(RequestHead, FrameLength, [u8; REQUEST_HEAD_BYTES]), S::Error>
    where
        R: AsyncReadExt + Unpin,
    {
        let mut head = [0u8; REQUEST_HEAD_BYTES];

        _ = req
            .read_exact(&mut head[..FRAME_LENGTH_PREFIX_BYTES])
            .await
            .inspect_err(|err| debug!(?err))?;

        // Validate the declared body before reading even the fixed request
        // header. In particular, an oversized declaration never controls an
        // allocation or causes additional body bytes to be consumed.
        _ = FrameLength::request(
            head[..FRAME_LENGTH_PREFIX_BYTES]
                .try_into()
                .expect("the request head contains a complete length prefix"),
            maximum_frame_size,
        )?;

        _ = req
            .read_exact(&mut head[FRAME_LENGTH_PREFIX_BYTES..])
            .await
            .inspect_err(|err| debug!(?err))?;

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
    ) -> Result<Bytes, S::Error>
    where
        R: AsyncReadExt + Unpin,
    {
        let mut request: Vec<u8> = vec![0u8; length.complete];

        request[..REQUEST_HEAD_BYTES].copy_from_slice(&head);

        _ = req
            .read_exact(&mut request[REQUEST_HEAD_BYTES..])
            .await
            .inspect_err(|err| error!(?err))?;
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
    async fn write<W>(&self, req: &mut W, frame: Bytes) -> Result<(), S::Error>
    where
        W: AsyncWriteExt + Unpin,
    {
        let mut w = BufWriter::new(req);
        w.write_all(&frame).await.inspect_err(|err| error!(?err))?;
        BYTES_SENT.add(frame.len() as u64, &[]);
        w.flush().await.map_err(Into::into)
    }

    #[instrument(skip_all, fields(id = nanoid!()))]
    async fn req<R>(
        &self,
        req: &mut R,
        maximum_frame_size: Option<usize>,
        attributes: &[KeyValue],
        ctx: Context<TcpContext>,
    ) -> Result<(), S::Error>
    where
        R: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let (_head, length, encoded_head) = self.wait(req, maximum_frame_size).await?;
        let request = self.read(req, length, encoded_head).await?;
        let response = self.process(attributes, ctx, request).await?;
        self.write(req, response).await
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

        loop {
            let ctx = ctx.clone();
            let attributes = attributes.clone();

            self.req(&mut req, maximum_frame_size, &attributes[..], ctx)
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
    use std::num::NonZeroUsize;
    use std::{
        io,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use rama::{
        Context, Layer as _, Service as _,
        layer::limit::policy::{Policy, PolicyOutput, PolicyResult},
    };
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _, duplex},
        net::{TcpListener, TcpStream},
        sync::{Semaphore, mpsc, oneshot},
        time::{Duration, timeout},
    };
    use tokio_util::sync::CancellationToken;

    use super::{
        AcceptIntent, AdmissionLease, AdmittedFrame, AdmittedReply, ConnectionInfo,
        FixedConnectionPolicy, FrameLength, RequestAdmissionError, RequestHead, TcpBytesLayer,
        TcpContext, TcpListenerService,
    };
    use crate::Error;

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

    impl AdmissionLease for AdjustableLease {
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

    impl rama::Service<(), AdmittedFrame<RequestLease>> for AdmittedEchoService {
        type Response = AdmittedReply<RequestLease>;
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
                Ok(req.reply(payload))
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
        let reply = frame.map_payload(|_| ()).reply(bytes::Bytes::new());
        assert_eq!(91, reply.lease.identity);
        assert_eq!(128, reply.lease.reservation);
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
