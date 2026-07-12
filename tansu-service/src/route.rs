// Copyright ⓒ 2024-2025 Peter Morgan <peter.james.morgan@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Route metadata and services selected from an admitted Kafka request head.

use std::{
    collections::BTreeMap,
    mem::size_of,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use rama::{Context, Service, service::BoxService};
use rsasl::config::SASLConfig;
use tansu_auth::{Authentication, SaslAuthenticateService, SaslLimits};
use tansu_sans_io::{
    ApiKey as _, ApiVersionsRequest, Body, DecodeLimits, Frame, Header, ProduceRequest,
    RootMessageMeta, SaslAuthenticateRequest, SaslHandshakeRequest,
};

use crate::{AdmittedFrame, AdmittedReply, Error, Reply, RequestHead};

/// Caller-supplied limits for decoding one admitted owned request.
///
/// The route builder's limits remain the process-wide default. Admission
/// layers can install this value when a request's reservation was calculated
/// from a narrower, request-derived decode bound.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RequestDecodeLimits(DecodeLimits);

impl RequestDecodeLimits {
    /// Validate and retain the limits frozen into a request's admission plan.
    pub fn new(limits: DecodeLimits) -> Result<Self, Error> {
        limits.validate()?;
        Ok(Self(limits))
    }

    /// Return the limits that the owned decoder must enforce for this request.
    pub fn limits(self) -> DecodeLimits {
        self.0
    }
}
/// Whether a route is callable before the connection has a verified identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RouteAuthentication {
    /// The route participates in discovery or authentication itself.
    Anonymous,
    /// The route requires a positively verified connection identity.
    Authenticated,
}

/// The bounded resource policy selected before a request body is allocated.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RouteAdmissionClass {
    /// Produce has payload-sensitive indexing, codec, and publication costs.
    Produce,
    /// Authentication has token and cumulative transcript bounds.
    Authentication,
    /// Standard Kafka APIs use the caller's bounded control-request policy.
    Standard,
}

/// The representation constructed after a route has admitted its body.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RouteDecodeStrategy {
    /// The handler receives the one admitted frame allocation.
    Raw,
    /// The handler receives Tansu's generated owned request model.
    Owned,
}

/// Immutable facts shared by discovery, admission, authentication, and dispatch.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RouteMetadata {
    api_key: i16,
    min_version: i16,
    max_version: i16,
    authentication: RouteAuthentication,
    admission: RouteAdmissionClass,
    decode: RouteDecodeStrategy,
}

impl RouteMetadata {
    fn for_api(api_key: i16, decode: RouteDecodeStrategy) -> Result<Self, Error> {
        let meta = RootMessageMeta::messages()
            .requests()
            .get(&api_key)
            .ok_or(Error::UnknownRouteApiKey(api_key))?;
        let authentication = if matches!(
            api_key,
            key if key == ApiVersionsRequest::KEY
                || key == SaslHandshakeRequest::KEY
                || key == SaslAuthenticateRequest::KEY
        ) {
            RouteAuthentication::Anonymous
        } else {
            RouteAuthentication::Authenticated
        };
        let admission = if api_key == ProduceRequest::KEY {
            RouteAdmissionClass::Produce
        } else if matches!(
            api_key,
            key if key == SaslHandshakeRequest::KEY || key == SaslAuthenticateRequest::KEY
        ) {
            RouteAdmissionClass::Authentication
        } else {
            RouteAdmissionClass::Standard
        };
        Ok(Self {
            api_key,
            min_version: meta.version.valid.start,
            max_version: meta.version.valid.end,
            authentication,
            admission,
            decode,
        })
    }

    /// Return the Kafka API key which indexes this entry.
    pub fn api_key(self) -> i16 {
        self.api_key
    }

    /// Return the inclusive minimum callable version.
    pub fn min_version(self) -> i16 {
        self.min_version
    }

    /// Return the inclusive maximum callable version.
    pub fn max_version(self) -> i16 {
        self.max_version
    }

    /// Return the connection authentication requirement.
    pub fn authentication(self) -> RouteAuthentication {
        self.authentication
    }

    /// Return the resource class selected before body allocation.
    pub fn admission(self) -> RouteAdmissionClass {
        self.admission
    }

    /// Return the request representation constructed for the handler.
    pub fn decode(self) -> RouteDecodeStrategy {
        self.decode
    }

    fn accepts(self, version: i16) -> bool {
        (self.min_version..=self.max_version).contains(&version)
    }
}

struct RouteEntry<State, E, L> {
    metadata: RouteMetadata,
    service: BoxService<State, AdmittedFrame<L, Bytes>, AdmittedReply<L, Reply>, E>,
}

/// One immutable registry for callable versions, admission, and dispatch.
pub struct AdmittedRouteService<State, E, L> {
    routes: Arc<BTreeMap<i16, RouteEntry<State, E, L>>>,
}

/// Mutable authentication identity owned by exactly one Kafka connection.
#[derive(Clone)]
pub struct RouteSession {
    authentication: Option<Authentication>,
    // Transport admission and route dispatch must observe one framing mode for
    // this socket. The shared lock connects those layers without sharing the
    // mutable transcript or identity with any other accepted connection.
    framing: Arc<Mutex<ConnectionFraming>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionFraming {
    Kafka,
    OpaqueSaslV0,
}

pub(crate) enum OpaqueSaslV0Outcome {
    Continue(Bytes),
    Authenticated(Bytes),
    Failed(Bytes),
}

impl std::fmt::Debug for RouteSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RouteSession")
            .field("sasl_configured", &self.authentication.is_some())
            .field("authenticated", &self.is_authenticated())
            .finish()
    }
}

impl RouteSession {
    /// Create a connection for which the route gate does not require SASL.
    pub fn anonymous() -> Self {
        Self {
            authentication: None,
            framing: Arc::new(Mutex::new(ConnectionFraming::Kafka)),
        }
    }

    /// Create fresh bounded SASL protocol state for one connection.
    pub fn sasl(config: Arc<SASLConfig>, limits: SaslLimits) -> Self {
        Self {
            authentication: Some(Authentication::server_with_limits(config, limits)),
            framing: Arc::new(Mutex::new(ConnectionFraming::Kafka)),
        }
    }

    /// Return whether this connection has a positively verified identity.
    pub fn is_authenticated(&self) -> bool {
        self.authentication
            .as_ref()
            .is_none_or(Authentication::is_authenticated)
    }

    /// Check one registry entry against this connection's identity.
    pub fn permits(&self, metadata: RouteMetadata) -> bool {
        metadata.authentication == RouteAuthentication::Anonymous || self.is_authenticated()
    }

    pub(crate) fn expects_opaque_sasl_v0(&self) -> Result<bool, Error> {
        self.framing
            .lock()
            .map(|mode| *mode == ConnectionFraming::OpaqueSaslV0)
            .map_err(Into::into)
    }

    pub(crate) fn maximum_sasl_token_size(&self) -> Option<usize> {
        self.authentication
            .as_ref()
            .map(Authentication::limits)
            .map(|limits| limits.maximum_token_size())
    }

    fn begin_opaque_sasl_v0(&self) -> Result<(), Error> {
        let Some(authentication) = &self.authentication else {
            return Ok(());
        };
        if authentication.is_exchanging()? {
            // A v0 handshake removes the Kafka request head from subsequent
            // tokens. The transport remains in this grammar until the
            // verifier supplies a positive identity; every terminal failure
            // ends the connection instead of returning to Kafka framing.
            *self.framing.lock()? = ConnectionFraming::OpaqueSaslV0;
        }
        Ok(())
    }

    pub(crate) async fn authenticate_opaque_sasl_v0<State>(
        &self,
        mut ctx: Context<State>,
        token: Bytes,
    ) -> Result<OpaqueSaslV0Outcome, Error>
    where
        State: Send + Sync + 'static,
    {
        let authentication = self.authentication.clone().ok_or_else(|| {
            Error::Message("opaque SASL mode requires authentication state".into())
        })?;
        assert!(ctx.insert(authentication.clone()).is_none());
        let response = SaslAuthenticateService::default()
            .serve(ctx, SaslAuthenticateRequest::default().auth_bytes(token))
            .await?;
        let token = response.auth_bytes;
        if response.error_code != i16::from(tansu_sans_io::ErrorCode::None) {
            return Ok(OpaqueSaslV0Outcome::Failed(token));
        }
        if authentication.is_authenticated() {
            *self.framing.lock()? = ConnectionFraming::Kafka;
            Ok(OpaqueSaslV0Outcome::Authenticated(token))
        } else {
            Ok(OpaqueSaslV0Outcome::Continue(token))
        }
    }

    #[cfg(test)]
    pub(crate) fn force_opaque_sasl_v0_for_transport_test(&self) {
        *self.framing.lock().expect("test framing lock") = ConnectionFraming::OpaqueSaslV0;
    }
}

/// A shared immutable registry paired with one connection-local identity.
pub struct AdmittedConnectionRouteService<State, E, L> {
    routes: AdmittedRouteService<State, E, L>,
    session: RouteSession,
}

impl<State, E, L> Clone for AdmittedConnectionRouteService<State, E, L> {
    fn clone(&self) -> Self {
        Self {
            routes: self.routes.clone(),
            session: self.session.clone(),
        }
    }
}

impl<State, E, L> std::fmt::Debug for AdmittedConnectionRouteService<State, E, L> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmittedConnectionRouteService")
            .field("routes", &self.routes)
            .field("session", &self.session)
            .finish()
    }
}

impl<State, E, L> Clone for AdmittedRouteService<State, E, L> {
    fn clone(&self) -> Self {
        Self {
            routes: Arc::clone(&self.routes),
        }
    }
}

impl<State, E, L> std::fmt::Debug for AdmittedRouteService<State, E, L> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmittedRouteService")
            .field("api_keys", &self.routes.keys())
            .finish()
    }
}

impl<State, E, L> AdmittedRouteService<State, E, L> {
    /// Pair process-wide routes with fresh connection-local authentication.
    ///
    /// Routes are immutable process state, while authentication contains a
    /// mutable transcript and verified peer identity. Sharing the latter would
    /// authorize unrelated sockets.
    pub fn for_connection(
        &self,
        session: RouteSession,
    ) -> AdmittedConnectionRouteService<State, E, L> {
        AdmittedConnectionRouteService {
            routes: self.clone(),
            session,
        }
    }

    /// Return the entry selected by a validated request head.
    ///
    /// Route selection uses the fixed head because each handler owns its
    /// representation. Produce can borrow the admitted frame while standard
    /// services construct bounded owned models only after this lookup.
    pub fn metadata(&self, head: &RequestHead) -> Result<RouteMetadata, Error> {
        let metadata = self
            .routes
            .get(&head.api_key())
            .map(|entry| entry.metadata)
            .ok_or(Error::UnknownRouteApiKey(head.api_key()))?;
        if !metadata.accepts(head.api_version()) {
            return Err(Error::UnsupportedRouteVersion {
                api_key: head.api_key(),
                api_version: head.api_version(),
                minimum: metadata.min_version,
                maximum: metadata.max_version,
            });
        }
        Ok(metadata)
    }

    /// Iterate the deterministic final route surface.
    pub fn entries(&self) -> impl ExactSizeIterator<Item = RouteMetadata> + '_ {
        self.routes.values().map(|entry| entry.metadata)
    }
}

impl<State, E, L> Service<State, AdmittedFrame<L, Bytes>>
    for AdmittedConnectionRouteService<State, E, L>
where
    State: Clone + Send + Sync + 'static,
    E: std::error::Error + From<Error> + From<tansu_sans_io::Error> + Send + Sync + 'static,
    L: Send + 'static,
{
    type Response = AdmittedReply<L, Reply>;
    type Error = E;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        request: AdmittedFrame<L, Bytes>,
    ) -> Result<Self::Response, Self::Error> {
        let metadata = self.routes.metadata(request.head()).map_err(E::from)?;
        if !self.session.permits(metadata) {
            return Err(tansu_sans_io::Error::NotAuthenticated.into());
        }
        if let Some(authentication) = self.session.authentication.clone() {
            assert!(ctx.insert(authentication).is_none());
        }
        let enters_opaque_sasl_v0 = request.head().api_key() == SaslHandshakeRequest::KEY
            && request.head().api_version() == 0;
        let reply = self.routes.serve_admitted(ctx, request).await?;
        if enters_opaque_sasl_v0 {
            self.session.begin_opaque_sasl_v0().map_err(E::from)?;
        }
        Ok(reply)
    }
}

impl<State, E, L> AdmittedRouteService<State, E, L>
where
    State: Clone + Send + Sync + 'static,
    E: std::error::Error + From<Error> + Send + Sync + 'static,
    L: Send + 'static,
{
    async fn serve_admitted(
        &self,
        ctx: Context<State>,
        request: AdmittedFrame<L, Bytes>,
    ) -> Result<AdmittedReply<L, Reply>, E> {
        let metadata = self.metadata(request.head()).map_err(E::from)?;
        self.routes
            .get(&metadata.api_key)
            .expect("route metadata came from the same immutable registry")
            .service
            .serve(ctx, request)
            .await
    }
}

/// Builds one admitted registry and supports typed replacement of owned routes.
pub struct AdmittedRouteBuilder<State, E, L> {
    routes: BTreeMap<i16, RouteEntry<State, E, L>>,
    decode_limits: DecodeLimits,
}

impl<State, E, L> std::fmt::Debug for AdmittedRouteBuilder<State, E, L> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmittedRouteBuilder")
            .field("api_keys", &self.routes.keys())
            .field("decode_limits", &self.decode_limits)
            .finish()
    }
}

impl<State, E, L> AdmittedRouteBuilder<State, E, L>
where
    State: Clone + Send + Sync + 'static,
    E: std::error::Error
        + From<tansu_sans_io::Error>
        + From<tokio::task::JoinError>
        + Send
        + Sync
        + 'static,
    L: Send + 'static,
{
    pub(crate) fn from_owned_routes(
        routes: BTreeMap<i16, BoxService<State, Frame, Frame, E>>,
        decode_limits: DecodeLimits,
    ) -> Result<Self, Error> {
        let mut builder = Self {
            routes: BTreeMap::new(),
            decode_limits,
        };
        for (api_key, service) in routes {
            builder.insert_owned(api_key, service)?;
        }
        Ok(builder)
    }

    fn insert_owned(
        &mut self,
        api_key: i16,
        service: BoxService<State, Frame, Frame, E>,
    ) -> Result<(), Error> {
        let metadata = RouteMetadata::for_api(api_key, RouteDecodeStrategy::Owned)?;
        let service = OwnedAdmittedRoute {
            service,
            decode_limits: self.decode_limits,
        };
        let entry = RouteEntry {
            metadata,
            service: service.boxed(),
        };
        self.routes
            .insert(api_key, entry)
            .map_or(Ok(()), |_| Err(Error::DuplicateRoute(api_key)))
    }

    /// Replace one standard owned route with an admitted raw-byte service.
    ///
    /// The existing entry supplies the version, authentication, and admission
    /// metadata. A replacement therefore cannot leave a callable shadow or
    /// restate a version range which differs from discovery.
    pub fn replace_raw<Q, S>(mut self, service: S) -> Result<Self, Error>
    where
        Q: tansu_sans_io::Request,
        S: Service<State, AdmittedFrame<L, Bytes>, Response = AdmittedReply<L, Reply>, Error = E>
            + Send
            + Sync
            + 'static,
    {
        let mut entry = self
            .routes
            .remove(&Q::KEY)
            .ok_or(Error::UnknownRouteApiKey(Q::KEY))?;
        entry.metadata.decode = RouteDecodeStrategy::Raw;
        entry.service = service.boxed();
        assert!(self.routes.insert(Q::KEY, entry).is_none());
        Ok(self)
    }

    /// Build the immutable final registry.
    pub fn build(self) -> AdmittedRouteService<State, E, L> {
        AdmittedRouteService {
            routes: Arc::new(self.routes),
        }
    }
}

struct OwnedAdmittedRoute<State, E> {
    service: BoxService<State, Frame, Frame, E>,
    decode_limits: DecodeLimits,
}

impl<State, E, L> Service<State, AdmittedFrame<L, Bytes>> for OwnedAdmittedRoute<State, E>
where
    State: Clone + Send + Sync + 'static,
    E: std::error::Error
        + From<tansu_sans_io::Error>
        + From<tokio::task::JoinError>
        + Send
        + Sync
        + 'static,
    L: Send + 'static,
{
    type Response = AdmittedReply<L, Reply>;
    type Error = E;

    async fn serve(
        &self,
        ctx: Context<State>,
        request: AdmittedFrame<L, Bytes>,
    ) -> Result<Self::Response, Self::Error> {
        let encoded = request.payload().clone();
        let limits = ctx
            .get::<RequestDecodeLimits>()
            .copied()
            .map_or(self.decode_limits, RequestDecodeLimits::limits);
        let frame = tokio::task::spawn_blocking(move || {
            Frame::request_from_bytes_with_limits(encoded, limits)
        })
        .await??;
        let api_key = frame.api_key()?;
        let api_version = frame.api_version()?;
        let correlation_id = frame.correlation_id()?;
        if request.head().api_key() != api_key
            || request.head().api_version() != api_version
            || request.head().correlation_id() != correlation_id
        {
            return Err(tansu_sans_io::Error::Message(
                "decoded request identity differs from its admitted head".into(),
            )
            .into());
        }
        let no_response = matches!(&frame.body, Body::ProduceRequest(produce) if produce.acks == 0);
        let response = self.service.serve(ctx, frame).await;
        if no_response {
            return Ok(request.reply(Reply::NoResponse));
        }
        let Frame { body, .. } = response?;
        let encoded = tokio::task::spawn_blocking(move || {
            Frame::response(
                Header::Response { correlation_id },
                body,
                api_key,
                api_version,
            )
        })
        .await??;
        Ok(request.reply(Reply::Frame(encoded)))
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use rama::{Context, Layer as _, Service as _, service::BoxService};
    use rsasl::callback::SessionCallback;
    use tansu_auth::{SaslHandshakeService, configuration_with_callback_for};
    use tansu_sans_io::{
        ApiKey as _, ApiVersionsRequest, Body, DecodeLimits, Header, MetadataRequest,
        MetadataResponse, SaslHandshakeRequest, ScramMechanism,
    };

    use super::{
        AdmittedRouteService, OpaqueSaslV0Outcome, RequestDecodeLimits, RouteAdmissionClass,
        RouteDecodeStrategy, RouteMetadata, RouteSession,
    };
    use crate::{
        AdmittedFrame, AdmittedReply, Error, FrameRouteService, Reply, RequestLayer,
        ResponseService, stream::REQUEST_HEAD_BYTES,
    };

    fn metadata_route() -> BoxService<(), tansu_sans_io::Frame, tansu_sans_io::Frame, Error> {
        let service =
            RequestLayer::<MetadataRequest>::new().into_layer(ResponseService::new(|_, _| {
                Ok::<_, Error>(
                    MetadataResponse::default()
                        .brokers(Some(Vec::new()))
                        .topics(Some(Vec::new()))
                        .cluster_id(Some("route-test".into()))
                        .controller_id(Some(1))
                        .throttle_time_ms(Some(0))
                        .cluster_authorized_operations(Some(-1)),
                )
            }));
        service.into()
    }

    fn request_head(api_key: i16, api_version: i16) -> crate::RequestHead {
        let mut encoded = [0u8; REQUEST_HEAD_BYTES];
        encoded[..4].copy_from_slice(&8i32.to_be_bytes());
        encoded[4..6].copy_from_slice(&api_key.to_be_bytes());
        encoded[6..8].copy_from_slice(&api_version.to_be_bytes());
        encoded[8..12].copy_from_slice(&17i32.to_be_bytes());
        crate::RequestHead::decode(encoded, Some(8)).unwrap().0
    }

    #[derive(Clone, Copy)]
    struct RawRoute;

    impl rama::Service<(), AdmittedFrame<(), Bytes>> for RawRoute {
        type Response = AdmittedReply<(), Reply>;
        type Error = Error;

        async fn serve(
            &self,
            _ctx: Context<()>,
            request: AdmittedFrame<(), Bytes>,
        ) -> Result<Self::Response, Self::Error> {
            Ok(request.reply(Reply::NoResponse))
        }
    }

    fn entries(routes: &AdmittedRouteService<(), Error, ()>) -> Vec<RouteMetadata> {
        routes.entries().collect()
    }

    #[derive(Clone, Copy, Debug)]
    struct NoopCallback;

    impl SessionCallback for NoopCallback {}

    #[tokio::test]
    async fn successful_v0_negotiation_selects_connection_local_opaque_framing() {
        let config = configuration_with_callback_for(NoopCallback, ScramMechanism::Scram256)
            .expect("SCRAM configuration");
        let session = RouteSession::sasl(config, tansu_auth::SaslLimits::default());
        let mut ctx = Context::default();
        assert!(
            ctx.insert(session.authentication.clone().unwrap())
                .is_none()
        );
        let response = SaslHandshakeService
            .serve(
                ctx,
                SaslHandshakeRequest::default().mechanism("SCRAM-SHA-256".into()),
            )
            .await
            .unwrap();
        assert_eq!(
            i16::from(tansu_sans_io::ErrorCode::None),
            response.error_code
        );
        assert!(
            session
                .authentication
                .as_ref()
                .unwrap()
                .is_exchanging()
                .unwrap()
        );
        assert!(!session.expects_opaque_sasl_v0().unwrap());

        session.begin_opaque_sasl_v0().unwrap();
        assert!(session.expects_opaque_sasl_v0().unwrap());

        let outcome = session
            .authenticate_opaque_sasl_v0(Context::default(), Bytes::from_static(b"malformed"))
            .await
            .unwrap();
        assert!(matches!(outcome, OpaqueSaslV0Outcome::Failed(_)));
        assert!(session.expects_opaque_sasl_v0().unwrap());
    }

    #[tokio::test]
    async fn raw_replacement_retains_one_metadata_entry_and_skips_owned_decode() {
        let routes = FrameRouteService::<(), Error>::builder()
            .with_route(MetadataRequest::KEY, metadata_route())
            .unwrap()
            .into_admitted()
            .unwrap()
            .replace_raw::<MetadataRequest, _>(RawRoute)
            .unwrap()
            .build();

        let metadata = entries(&routes)
            .into_iter()
            .find(|entry| entry.api_key() == MetadataRequest::KEY)
            .unwrap();
        assert_eq!(RouteDecodeStrategy::Raw, metadata.decode());
        assert_eq!(RouteAdmissionClass::Standard, metadata.admission());
        assert_eq!(
            1,
            routes
                .entries()
                .filter(|entry| entry.api_key() == MetadataRequest::KEY)
                .count()
        );

        // The bytes contain only the fixed head and cannot decode as Metadata.
        // Success proves raw dispatch never entered the owned Frame decoder.
        let head = request_head(MetadataRequest::KEY, 0);
        let reply = routes
            .for_connection(RouteSession::anonymous())
            .serve(
                Context::default(),
                AdmittedFrame {
                    head,
                    payload: Bytes::from_static(&[0, 0, 0, 8, 0, 3, 0, 0, 0, 0, 0, 17]),
                    lease: (),
                },
            )
            .await
            .unwrap();
        assert_eq!(&Reply::NoResponse, reply.payload());
    }

    #[tokio::test]
    async fn owned_decode_uses_the_request_context_limit() {
        let routes = FrameRouteService::<(), Error>::builder()
            .with_route(MetadataRequest::KEY, metadata_route())
            .unwrap()
            .into_admitted::<()>()
            .unwrap()
            .build();
        let encoded = tansu_sans_io::Frame::request(
            Header::Request {
                api_key: MetadataRequest::KEY,
                api_version: 12,
                correlation_id: 17,
                client_id: Some("request-limit-test".into()),
            },
            Body::MetadataRequest(
                MetadataRequest::default()
                    .topics(Some(Vec::new()))
                    .allow_auto_topic_creation(Some(false))
                    .include_cluster_authorized_operations(Some(false))
                    .include_topic_authorized_operations(Some(false)),
            ),
        )
        .unwrap();
        let head = crate::RequestHead::decode(
            encoded[..REQUEST_HEAD_BYTES].try_into().unwrap(),
            Some(encoded.len() - size_of::<i32>()),
        )
        .unwrap()
        .0;
        let mut limits = DecodeLimits::default();
        limits.max_frame_bytes = encoded.len() - 1;
        let mut ctx = Context::default();
        assert!(
            ctx.insert(RequestDecodeLimits::new(limits).unwrap())
                .is_none()
        );

        let error = routes
            .for_connection(RouteSession::anonymous())
            .serve(
                ctx,
                AdmittedFrame {
                    head,
                    payload: encoded,
                    lease: (),
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            Error::Protocol(tansu_sans_io::Error::DecodeLimitExceeded {
                kind: tansu_sans_io::DecodeLimit::FrameBytes,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn discovery_and_dispatch_share_the_same_version_metadata() {
        let routes = FrameRouteService::<(), Error>::builder()
            .with_route(MetadataRequest::KEY, metadata_route())
            .unwrap()
            .into_admitted::<()>()
            .unwrap()
            .build();
        let entries = entries(&routes);
        let encoded = tansu_sans_io::Frame::request(
            Header::Request {
                api_key: ApiVersionsRequest::KEY,
                api_version: 4,
                correlation_id: 17,
                client_id: Some("discovery-test".into()),
            },
            Body::ApiVersionsRequest(
                ApiVersionsRequest::default()
                    .client_software_name(Some("tansu-service-test".into()))
                    .client_software_version(Some("1".into())),
            ),
        )
        .unwrap();
        let head = crate::RequestHead::decode(
            encoded[..REQUEST_HEAD_BYTES].try_into().unwrap(),
            Some(encoded.len() - size_of::<i32>()),
        )
        .unwrap()
        .0;
        let reply = routes
            .for_connection(RouteSession::anonymous())
            .serve(
                Context::default(),
                AdmittedFrame {
                    head,
                    payload: encoded,
                    lease: (),
                },
            )
            .await
            .unwrap();
        let Reply::Frame(encoded) = reply.payload() else {
            panic!("ApiVersions must produce a protocol response")
        };
        let frame =
            tansu_sans_io::Frame::response_from_bytes(encoded.clone(), ApiVersionsRequest::KEY, 4)
                .unwrap();
        let discovery = tansu_sans_io::ApiVersionsResponse::try_from(frame.body).unwrap();
        let advertised = discovery.api_keys.unwrap();

        assert_eq!(entries.len(), advertised.len());
        for entry in entries {
            let version = advertised
                .iter()
                .find(|version| version.api_key == entry.api_key())
                .unwrap();
            assert_eq!(entry.min_version(), version.min_version);
            assert_eq!(entry.max_version(), version.max_version);
        }
        assert!(
            routes
                .metadata(&request_head(ApiVersionsRequest::KEY, 4))
                .is_ok()
        );
        assert!(matches!(
            routes.metadata(&request_head(MetadataRequest::KEY, i16::MAX)),
            Err(Error::UnsupportedRouteVersion { .. })
        ));
    }
}
