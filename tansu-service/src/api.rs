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

use std::{collections::BTreeMap, marker::PhantomData, sync::Arc};

use rama::{Context, Service, service::BoxService};
use tansu_sans_io::{
    ApiKey, ApiVersionsRequest, ApiVersionsResponse, Body, ErrorCode, Frame, Header,
    RootMessageMeta, api_versions_response::ApiVersion,
};

use crate::{AdmittedFrame, AdmittedReply, Error};

/// An [`ApiVersionsResponse`] [`Service`] with a supported set of API and versions from [`RootMessageMeta`].
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ApiVersionsService<E> {
    supported: Vec<i16>,
    error: PhantomData<E>,
}

impl<State, E> Service<State, ApiVersionsRequest> for ApiVersionsService<E>
where
    State: Clone + Send + Sync + 'static,
    E: std::error::Error + Send + Sync + 'static,
{
    type Response = ApiVersionsResponse;
    type Error = E;

    async fn serve(
        &self,
        _ctx: Context<State>,
        _req: ApiVersionsRequest,
    ) -> Result<Self::Response, Self::Error> {
        Ok::<_, E>(
            ApiVersionsResponse::default()
                .finalized_features(Some([].into()))
                .finalized_features_epoch(Some(-1))
                .supported_features(Some([].into()))
                .zk_migration_ready(Some(false))
                .error_code(ErrorCode::None.into())
                .api_keys(Some(
                    RootMessageMeta::messages()
                        .requests()
                        .iter()
                        .filter(|(api_key, _)| self.supported.contains(api_key))
                        .map(|(_, meta)| {
                            ApiVersion::default()
                                .api_key(meta.api_key)
                                .min_version(meta.version.valid.start)
                                .max_version(meta.version.valid.end)
                        })
                        .collect(),
                ))
                .throttle_time_ms(Some(0)),
        )
    }
}

impl<State, E> Service<State, Body> for ApiVersionsService<E>
where
    State: Clone + Send + Sync + 'static,
    E: std::error::Error + From<tansu_sans_io::Error> + Send + Sync + 'static,
{
    type Response = Body;
    type Error = E;

    async fn serve(&self, ctx: Context<State>, req: Body) -> Result<Self::Response, Self::Error> {
        let req = ApiVersionsRequest::try_from(req)?;
        self.serve(ctx, req).await.map(Into::into)
    }
}

impl<State, E> Service<State, Frame> for ApiVersionsService<E>
where
    State: Clone + Send + Sync + 'static,
    E: std::error::Error + From<tansu_sans_io::Error> + Send + Sync + 'static,
{
    type Response = Frame;
    type Error = E;

    async fn serve(&self, ctx: Context<State>, req: Frame) -> Result<Self::Response, Self::Error> {
        let correlation_id = req.correlation_id()?;
        self.serve(ctx, req.body).await.map(|body| Frame {
            size: 0,
            header: Header::Response { correlation_id },
            body,
        })
    }
}

/// Route [`Frame`] to a [`Service`] via [API key][`Frame#method.api_key`]
///
/// A simple example that routes [`MetadataRequest`][`tansu_sans_io::MetadataRequest`]
/// and [`CreateTopicsRequest`][`tansu_sans_io::CreateTopicsRequest`].
/// [`ApiVersionsRequest`][`tansu_sans_io::ApiVersionsRequest`] is created by the
///  builder including both of the implemented services using the version ranges
///  from [`RootMessageMeta`][`tansu_sans_io::RootMessageMeta`].
///
/// ```
/// # use rama::Layer as _;
/// # use tansu_sans_io::{CreateTopicsRequest, CreateTopicsResponse, MetadataRequest, MetadataResponse};
/// # use tansu_service::{Error, FrameRouteService, RequestLayer, ResponseService};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Error> {
/// let router = FrameRouteService::<(), Error>::builder()
///     .with_service(
///         RequestLayer::<MetadataRequest>::new().into_layer(ResponseService::new(|_, _| {
///             Ok(MetadataResponse::default()
///                 .brokers(Some([].into()))
///                 .topics(Some([].into()))
///                 .cluster_id(Some("tansu".into()))
///                 .controller_id(Some(111))
///                 .throttle_time_ms(Some(0))
///                 .cluster_authorized_operations(Some(-1)))
///         })),
///     )
///     .and_then(|builder| {
///         builder.with_service(RequestLayer::<CreateTopicsRequest>::new().into_layer(
///             ResponseService::new(|_, _| {
///                 Ok(CreateTopicsResponse::default()
///                     .throttle_time_ms(Some(0))
///                     .topics(Some([].into())))
///             }),
///         ))
///     })
///     .and_then(|builder| builder.build())?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Default)]
pub struct FrameRouteService<State = (), E = Error> {
    routes: Arc<BTreeMap<i16, BoxService<State, Frame, Frame, E>>>,
}

impl<State, E> FrameRouteService<State, E>
where
    State: Clone + Send + Sync + 'static,
    E: std::error::Error + From<tansu_sans_io::Error> + From<Error> + Send + Sync + 'static,
{
    pub fn new(routes: Arc<BTreeMap<i16, BoxService<State, Frame, Frame, E>>>) -> Self {
        Self { routes }
    }

    pub fn builder() -> FrameRouteBuilder<State, E> {
        FrameRouteBuilder::<State, E>::new()
    }
}

impl<State, E> Service<State, Frame> for FrameRouteService<State, E>
where
    State: Clone + Send + Sync + 'static,
    E: std::error::Error + From<tansu_sans_io::Error> + From<Error> + Send + Sync + 'static,
{
    type Response = Frame;
    type Error = E;

    async fn serve(&self, ctx: Context<State>, req: Frame) -> Result<Self::Response, Self::Error> {
        let api_key = req.api_key()?;

        if let Some(service) = self.routes.get(&api_key) {
            service.serve(ctx, req).await
        } else {
            Err(E::from(Error::UnknownServiceFrame(Box::new(req))))
        }
    }
}

impl<State, E, L> Service<State, AdmittedFrame<L, Frame>> for FrameRouteService<State, E>
where
    State: Clone + Send + Sync + 'static,
    E: std::error::Error + From<tansu_sans_io::Error> + From<Error> + Send + Sync + 'static,
    L: Send + 'static,
{
    type Response = AdmittedReply<L, Frame>;
    type Error = E;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: AdmittedFrame<L, Frame>,
    ) -> Result<Self::Response, Self::Error> {
        let api_key = req.payload.api_key()?;
        let Some(service) = self.routes.get(&api_key) else {
            return Err(E::from(Error::UnknownServiceFrame(Box::new(req.payload))));
        };

        let AdmittedFrame {
            head,
            payload,
            lease,
        } = req;
        service
            .serve(ctx, payload)
            .await
            .map(|payload| AdmittedReply {
                head,
                payload,
                lease,
            })
    }
}

/// A [`Frame`] route builder providing an [`ApiVersionsResponse`] for all available routes
#[derive(Debug)]
pub struct FrameRouteBuilder<State, E> {
    routes: BTreeMap<i16, BoxService<State, Frame, Frame, E>>,
}

impl<State, E> FrameRouteBuilder<State, E>
where
    State: Clone + Send + Sync + 'static,
    E: std::error::Error + From<tansu_sans_io::Error> + Send + Sync + 'static,
{
    fn new() -> Self {
        Self {
            routes: BTreeMap::new(),
        }
    }

    pub fn with_service<S>(self, service: S) -> Result<Self, Error>
    where
        S: Into<BoxService<State, Frame, Frame, E>> + ApiKey,
    {
        self.with_route(S::KEY, service.into())
    }

    pub fn with_route(
        mut self,
        api_key: i16,
        service: BoxService<State, Frame, Frame, E>,
    ) -> Result<Self, Error> {
        self.routes
            .insert(api_key, service)
            .map_or(Ok(self), |_existing| Err(Error::DuplicateRoute(api_key)))
    }

    pub fn build(self) -> Result<FrameRouteService<State, E>, Error> {
        let api_key = ApiVersionsRequest::KEY;
        let mut supported = self.routes.keys().copied().collect::<Vec<_>>();
        supported.push(api_key);

        self.build_with_api_versions_service(ApiVersionsService {
            supported,
            error: PhantomData,
        })
    }

    /// Build the route table with an explicitly supplied API versions service.
    ///
    /// Unlike [`Self::build`], the response produced by `service` is independent
    /// of the other registered routes. This permits a broker to keep a route
    /// callable without advertising it to clients.
    pub fn build_with_api_versions_service<S>(
        self,
        service: S,
    ) -> Result<FrameRouteService<State, E>, Error>
    where
        S: Service<State, Frame, Response = Frame, Error = E> + Send + Sync + 'static,
    {
        self.with_route(ApiVersionsRequest::KEY, service.boxed())
            .map(|builder| FrameRouteService {
                routes: Arc::new(builder.routes),
            })
    }
}

#[cfg(test)]
mod tests {
    use rama::{Context, Layer as _, Service as _};
    use tansu_sans_io::{
        ApiKey as _, ApiVersionsRequest, Body, ErrorCode, Frame, Header, MetadataRequest,
        MetadataResponse,
    };

    use super::{ApiVersionsService, FrameRouteService};
    use crate::{Error, RequestLayer, ResponseService};

    fn api_versions_request() -> Frame {
        Frame {
            size: 0,
            header: Header::Request {
                api_key: ApiVersionsRequest::KEY,
                api_version: 4,
                correlation_id: 23,
                client_id: Some("test".into()),
            },
            body: Body::ApiVersionsRequest(
                ApiVersionsRequest::default()
                    .client_software_name(Some("test".into()))
                    .client_software_version(Some("1".into())),
            ),
        }
    }

    #[tokio::test]
    async fn default_build_matches_equivalent_explicit_service() -> Result<(), Error> {
        let default = FrameRouteService::<(), Error>::builder().build()?;
        let explicit = FrameRouteService::<(), Error>::builder().build_with_api_versions_service(
            ApiVersionsService {
                supported: vec![ApiVersionsRequest::KEY],
                error: std::marker::PhantomData,
            },
        )?;

        let request = api_versions_request();
        let default_response = default.serve(Context::default(), request.clone()).await?;
        let explicit_response = explicit.serve(Context::default(), request).await?;

        let default_bytes = Frame::response(
            default_response.header,
            default_response.body,
            ApiVersionsRequest::KEY,
            4,
        )?;
        let explicit_bytes = Frame::response(
            explicit_response.header,
            explicit_response.body,
            ApiVersionsRequest::KEY,
            4,
        )?;

        assert_eq!(default_bytes, explicit_bytes);
        Ok(())
    }

    #[tokio::test]
    async fn explicit_api_versions_can_hide_a_callable_route() -> Result<(), Error> {
        let metadata =
            RequestLayer::<MetadataRequest>::new().into_layer(ResponseService::new(|_, _| {
                Ok::<_, Error>(
                    MetadataResponse::default()
                        .brokers(Some([].into()))
                        .topics(Some([].into()))
                        .cluster_id(Some("denial-route".into()))
                        .controller_id(Some(111))
                        .throttle_time_ms(Some(0))
                        .cluster_authorized_operations(Some(-1)),
                )
            }));

        let route = FrameRouteService::<(), Error>::builder()
            .with_service(metadata)?
            .build_with_api_versions_service(ApiVersionsService {
                supported: vec![ApiVersionsRequest::KEY],
                error: std::marker::PhantomData,
            })?;

        let versions = route
            .serve(Context::default(), api_versions_request())
            .await?
            .body;
        let versions = tansu_sans_io::ApiVersionsResponse::try_from(versions)?;
        assert_eq!(ErrorCode::None, ErrorCode::try_from(versions.error_code)?);
        assert_eq!(
            vec![ApiVersionsRequest::KEY],
            versions
                .api_keys
                .unwrap_or_default()
                .into_iter()
                .map(|version| version.api_key)
                .collect::<Vec<_>>(),
        );

        let metadata_response = route
            .serve(
                Context::default(),
                Frame {
                    size: 0,
                    header: Header::Request {
                        api_key: MetadataRequest::KEY,
                        api_version: 12,
                        correlation_id: 29,
                        client_id: Some("test".into()),
                    },
                    body: Body::MetadataRequest(MetadataRequest::default()),
                },
            )
            .await?;
        assert_eq!(
            Some("denial-route".into()),
            MetadataResponse::try_from(metadata_response.body)?.cluster_id,
        );

        Ok(())
    }

    #[test]
    fn explicit_api_versions_preserves_duplicate_route_error() -> Result<(), Error> {
        let builder = FrameRouteService::<(), Error>::builder().with_route(
            ApiVersionsRequest::KEY,
            ApiVersionsService {
                supported: vec![ApiVersionsRequest::KEY],
                error: std::marker::PhantomData,
            }
            .boxed(),
        )?;

        assert!(matches!(
            builder.build_with_api_versions_service(ApiVersionsService {
                supported: vec![ApiVersionsRequest::KEY],
                error: std::marker::PhantomData,
            }),
            Err(Error::DuplicateRoute(key)) if key == ApiVersionsRequest::KEY
        ));

        Ok(())
    }

    #[test]
    fn cloned_router_shares_the_immutable_route_table() -> Result<(), Error> {
        let route = FrameRouteService::<(), Error>::builder().build()?;
        let cloned = route.clone();

        assert!(std::sync::Arc::ptr_eq(&route.routes, &cloned.routes));
        Ok(())
    }
}
