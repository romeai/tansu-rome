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
    error::{self},
    fmt::Debug,
    io,
    marker::PhantomData,
    mem::size_of,
    time::SystemTime,
};

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

/// A [`Layer`] that listens for TCP connections
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
    type Service = TcpListenerService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            cancellation: self.cancellation.clone(),
            inner,
        }
    }
}

/// A [`Service`] that listens for TCP connections
#[derive(Clone, Default)]
pub struct TcpListenerService<S> {
    cancellation: CancellationToken,
    inner: S,
}

impl<S> Debug for TcpListenerService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct(stringify!(TcpListenerService)).finish()
    }
}

impl<State, S> Service<State, TcpListener> for TcpListenerService<S>
where
    S: Service<State, TcpStream> + Clone,
    S::Response: Debug,
    S::Error: error::Error,
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
        let mut set = JoinSet::new();

        loop {
            tokio::select! {
                Ok((stream, addr)) = req.accept() => {
                    debug!(?req, ?stream, %addr);

                    let service = self.inner.clone();
                    let ctx = ctx.clone();

                    let handle = set.spawn(async move {
                            match service.serve(ctx, stream).await {
                                Err(error) => {
                                    debug!(%addr, %error);
                                },

                                Ok(response) => {
                                    debug!(%addr, ?response)
                                }
                        }
                    });

                    debug!(?handle);
                    continue;
                }

                v = set.join_next(), if !set.is_empty() => {
                    debug!(?v);
                }

                cancelled = self.cancellation.cancelled() => {
                    debug!(?cancelled);
                    break;
                }
            }
        }

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
        debug!(req = ?&req[..]);
        self.inner
            .serve(ctx, req)
            .await
            .inspect(|response| debug!(response = ?&response[..]))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use rama::{Context, Layer as _, Service as _};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, duplex};

    use super::{FrameLength, TcpBytesLayer, TcpContext};
    use crate::Error;

    #[derive(Clone, Debug)]
    struct EchoService {
        calls: Arc<AtomicUsize>,
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
}
