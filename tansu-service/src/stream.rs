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

use std::{fmt::Debug, io, marker::PhantomData, mem::size_of, net::SocketAddr, time::SystemTime};

use bytes::Bytes;
use nanoid::nanoid;
use opentelemetry::KeyValue;
use rama::{Context, Layer, Service};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufWriter},
    net::{TcpListener, TcpStream},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, instrument};

use crate::{BYTES_RECEIVED, BYTES_SENT, Error, REQUEST_DURATION, REQUEST_SIZE, RESPONSE_SIZE};

/// Bytes occupied by Kafka's signed frame-length prefix.
const FRAME_LENGTH_PREFIX_BYTES: usize = size_of::<i32>();

/// Minimum Kafka request body: API key, API version, and correlation ID.
const MINIMUM_REQUEST_BODY_BYTES: usize = size_of::<i16>() * 2 + size_of::<i32>();

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

/// A [`Layer`] that listens for TCP connections.
#[derive(Clone, Debug, Default)]
pub struct TcpListenerLayer {
    cancellation: CancellationToken,
}

impl TcpListenerLayer {
    pub fn new(cancellation: CancellationToken) -> Self {
        Self { cancellation }
    }
}

impl<S> Layer<S> for TcpListenerLayer {
    type Service = TcpListenerService<CloneConnectionService<S>>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service::new(
            self.cancellation.clone(),
            CloneConnectionService::new(inner),
        )
    }
}

/// A reusable TCP listener runtime.
///
/// `M` is a Rama `Service<State, ConnectionInfo>` which creates one service
/// for each accepted socket. The listener owns all spawned connection tasks,
/// reaps completed tasks while it is running, and aborts and reaps outstanding
/// tasks when its cancellation token is cancelled.
#[derive(Clone)]
pub struct TcpListenerService<M> {
    cancellation: CancellationToken,
    make_connection: M,
}

impl<M> TcpListenerService<M> {
    /// Create a listener runtime using `make_connection` as its per-socket
    /// service factory.
    pub fn new(cancellation: CancellationToken, make_connection: M) -> Self {
        Self {
            cancellation,
            make_connection,
        }
    }
}

impl<M> Debug for TcpListenerService<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct(stringify!(TcpListenerService)).finish()
    }
}

impl<State, M, S> Service<State, TcpListener> for TcpListenerService<M>
where
    M: Service<State, ConnectionInfo, Response = S>,
    M::Error: Debug,
    S: Service<State, TcpStream>,
    S::Response: Debug,
    S::Error: Debug + From<io::Error>,
    State: Clone + Send + Sync + 'static,
{
    type Response = ();
    type Error = S::Error;

    #[instrument(skip(ctx, req))]
    async fn serve(
        &self,
        ctx: Context<State>,
        req: TcpListener,
    ) -> Result<Self::Response, Self::Error> {
        let mut connections = JoinSet::new();

        loop {
            tokio::select! {
                accepted = req.accept() => {
                    let (stream, peer_addr) = accepted?;
                    let connection = ConnectionInfo {
                        local_addr: stream.local_addr()?,
                        peer_addr,
                    };
                    debug!(?connection);

                    let service = match self
                        .make_connection
                        .serve(ctx.clone(), connection)
                        .await
                    {
                        Ok(service) => service,
                        Err(error) => {
                            error!(?connection, ?error, "unable to construct connection service");
                            continue;
                        }
                    };
                    let connection_ctx = ctx.clone();

                    let _connection_task = connections.spawn(async move {
                        match service.serve(connection_ctx, stream).await {
                            Err(error) => debug!(?connection, ?error),
                            Ok(response) => debug!(?connection, ?response),
                        }
                    });
                }

                joined = connections.join_next(), if !connections.is_empty() => {
                    debug!(?joined);
                }

                () = self.cancellation.cancelled() => {
                    debug!("TCP listener cancellation requested");
                    break;
                }
            }
        }

        connections.shutdown().await;
        Ok(())
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
    ) -> Result<FrameLength, S::Error>
    where
        R: AsyncReadExt + Unpin,
    {
        let mut size = [0u8; FRAME_LENGTH_PREFIX_BYTES];

        _ = req
            .read_exact(&mut size)
            .await
            .inspect_err(|err| debug!(?err))?;

        FrameLength::request(size, maximum_frame_size).map_err(Into::into)
    }

    #[instrument(skip_all)]
    async fn read<R>(&self, req: &mut R, length: FrameLength) -> Result<Bytes, S::Error>
    where
        R: AsyncReadExt + Unpin,
    {
        let mut request: Vec<u8> = vec![0u8; length.complete];

        request[0..FRAME_LENGTH_PREFIX_BYTES].copy_from_slice(&length.declared.to_be_bytes());

        _ = req
            .read_exact(&mut request[FRAME_LENGTH_PREFIX_BYTES..])
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
        let length = self.wait(req, maximum_frame_size).await?;
        let request = self.read(req, length).await?;
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
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use rama::{Context, Layer as _, Service as _};
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _, duplex},
        net::{TcpListener, TcpStream},
        sync::{mpsc, oneshot},
        time::{Duration, timeout},
    };
    use tokio_util::sync::CancellationToken;

    use super::{ConnectionInfo, FrameLength, TcpBytesLayer, TcpContext, TcpListenerService};
    use crate::Error;

    #[derive(Clone, Debug)]
    struct EchoService {
        calls: Arc<AtomicUsize>,
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
}
