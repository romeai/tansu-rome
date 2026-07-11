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

use std::sync::Arc;

use rama::Layer;
use rsasl::config::SASLConfig;
use tansu_service::{
    AdmittedRouteBuilder, BytesFrameLayer, BytesFrameService, FrameRouteBuilder, FrameRouteService,
    TcpBytesLayer, TcpBytesService, TcpContext, TcpContextLayer, TcpContextService,
};
use tansu_storage::Storage;
use tracing::debug;

use crate::{DEFAULT_MAXIMUM_FRAME_SIZE, Error, Result, coordinator::group::Coordinator};

pub mod auth;
pub mod coordinator;
pub mod storage;

type TcpRouteFrame =
    TcpContextService<TcpBytesService<BytesFrameService<FrameRouteService<(), Error>>, ()>>;

/// Build the immutable Kafka API route table shared by all connections.
pub fn routes<C, S>(coordinator: C, storage: S) -> Result<FrameRouteService<(), Error>, Error>
where
    S: Storage + Clone,
    C: Coordinator,
{
    route_builder(coordinator, storage).and_then(|builder| builder.build().map_err(Into::into))
}

/// Compose Tansu's complete standard storage, coordinator, and auth surface.
///
/// Keeping the unbuilt form lets an embedding select admitted representations
/// without reproducing the broker's API list.
pub fn route_builder<C, S>(
    coordinator: C,
    storage: S,
) -> Result<FrameRouteBuilder<(), Error>, Error>
where
    S: Storage + Clone,
    C: Coordinator,
{
    storage::services(FrameRouteService::<(), Error>::builder(), storage)
        .inspect(|builder| debug!(?builder))
        .and_then(|builder| {
            coordinator::services(builder, coordinator).inspect(|builder| debug!(?builder))
        })
        .and_then(auth::services)
}

/// Compose the standard surface for admission before owned request decoding.
pub fn admitted_route_builder<C, S, L>(
    coordinator: C,
    storage: S,
    decode_limits: tansu_sans_io::DecodeLimits,
) -> Result<AdmittedRouteBuilder<(), Error, L>, Error>
where
    S: Storage + Clone,
    C: Coordinator,
    L: Send + 'static,
{
    route_builder(coordinator, storage)?
        .into_admitted_with_limits(decode_limits)
        .map_err(Into::into)
}

/// Add connection-local protocol state and TCP framing to a shared route table.
pub fn connection_service(
    cluster_id: &str,
    route: FrameRouteService<(), Error>,
    sasl_config: Option<Arc<SASLConfig>>,
    maximum_frame_size: usize,
) -> TcpRouteFrame {
    (
        TcpContextLayer::new(
            TcpContext::default()
                .cluster_id(Some(cluster_id.into()))
                .maximum_frame_size(Some(maximum_frame_size)),
        ),
        TcpBytesLayer::default(),
        BytesFrameLayer::default().with_sasl_config(sasl_config),
    )
        .into_layer(route)
}

/// Build a route table and a single connection service.
///
/// The broker uses [`routes`] and [`connection_service`] separately so route
/// construction occurs once rather than once per accepted socket.
pub fn services<C, S>(
    cluster_id: &str,
    coordinator: C,
    storage: S,
    sasl_config: Option<Arc<SASLConfig>>,
) -> Result<TcpRouteFrame, Error>
where
    S: Storage + Clone,
    C: Coordinator,
{
    services_with_maximum_frame_size(
        cluster_id,
        coordinator,
        storage,
        sasl_config,
        DEFAULT_MAXIMUM_FRAME_SIZE,
    )
}

/// Construct broker services with a maximum Kafka request body size.
///
/// `maximum_frame_size` excludes the four-byte Kafka frame prefix.
pub fn services_with_maximum_frame_size<C, S>(
    cluster_id: &str,
    coordinator: C,
    storage: S,
    sasl_config: Option<Arc<SASLConfig>>,
    maximum_frame_size: usize,
) -> Result<TcpRouteFrame, Error>
where
    S: Storage + Clone,
    C: Coordinator,
{
    routes(coordinator, storage)
        .map(|route| connection_service(cluster_id, route, sasl_config, maximum_frame_size))
}
