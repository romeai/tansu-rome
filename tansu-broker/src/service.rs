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

use std::{mem::size_of, sync::Arc};

use rama::{Layer, layer::limit::policy::UnlimitedPolicy};
use rsasl::config::SASLConfig;
use tansu_auth::SaslLimits;
use tansu_sans_io::DecodeLimits;
use tansu_service::{
    AdmittedConnectionRouteService, AdmittedRouteBuilder, AdmittedRouteService,
    AdmittedTcpBytesService, FrameRouteBuilder, FrameRouteService, RouteSession, TcpBytesLayer,
    TcpContext, TcpContextLayer, TcpContextService,
};
use tansu_storage::Storage;
use tracing::debug;

use crate::{DEFAULT_MAXIMUM_FRAME_SIZE, Error, Result, coordinator::group::Coordinator};

pub mod auth;
pub mod coordinator;
pub mod storage;

type TcpRouteFrame = TcpContextService<
    AdmittedTcpBytesService<AdmittedConnectionRouteService<(), Error, ()>, (), UnlimitedPolicy>,
>;

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
    decode_limits: DecodeLimits,
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

/// Build the immutable admitted route table used by the broker runtime.
pub(crate) fn admitted_routes<C, S>(
    coordinator: C,
    storage: S,
    decode_limits: DecodeLimits,
) -> Result<AdmittedRouteService<(), Error, ()>, Error>
where
    S: Storage + Clone,
    C: Coordinator,
{
    admitted_route_builder(coordinator, storage, decode_limits).map(AdmittedRouteBuilder::build)
}

/// Derive the owned decoder's compatibility bounds from the transport body ceiling.
pub(crate) fn compatibility_decode_limits(
    maximum_frame_size: usize,
) -> Result<DecodeLimits, Error> {
    let max_frame_bytes = maximum_frame_size
        .checked_add(size_of::<i32>())
        .ok_or_else(|| {
            Error::Custom("maximum Kafka frame size does not fit this address space".into())
        })?;
    let defaults = DecodeLimits::default();
    // Compact arrays can encode one element per body byte. The decoder may
    // retain both mezzanine and public values plus one pointer-sized sequence
    // charge, so the compatibility policy covers that wire-reachable shape.
    let max_sequence_elements = maximum_frame_size.max(1);
    let max_total_allocation_bytes = maximum_frame_size
        .checked_mul(2 + size_of::<usize>())
        .ok_or_else(|| {
            Error::Custom("Kafka decode allocation compatibility bound overflowed".into())
        })?;
    let max_total_work_units = max_frame_bytes
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(max_sequence_elements))
        .ok_or_else(|| Error::Custom("Kafka decode work compatibility bound overflowed".into()))?;

    Ok(DecodeLimits {
        max_frame_bytes,
        max_string_bytes: maximum_frame_size,
        max_bytes: maximum_frame_size,
        max_sequence_elements,
        max_nesting_depth: defaults.max_nesting_depth,
        max_total_allocation_bytes,
        max_total_work_units,
    })
}

/// Add connection-local protocol state and TCP framing to a shared route table.
pub fn connection_service(
    cluster_id: &str,
    routes: AdmittedRouteService<(), Error, ()>,
    sasl_config: Option<Arc<SASLConfig>>,
    maximum_frame_size: usize,
) -> TcpRouteFrame {
    // Authentication identity and opaque-v0 framing are mutable socket state.
    // The same fresh session is shared by transport classification and route
    // authorization, while the immutable route registry remains process-wide.
    let session = sasl_config.map_or_else(RouteSession::anonymous, |config| {
        RouteSession::sasl(config, SaslLimits::default())
    });
    let route = routes.for_connection(session.clone());
    (
        TcpContextLayer::new(
            TcpContext::default()
                .cluster_id(Some(cluster_id.into()))
                .maximum_frame_size(Some(maximum_frame_size)),
        ),
        TcpBytesLayer::default()
            .with_request_policy(UnlimitedPolicy::new())
            .with_route_session(session),
    )
        .into_layer(route)
}

/// Build one admitted route table and a single connection service.
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
    compatibility_decode_limits(maximum_frame_size)
        .and_then(|limits| admitted_routes(coordinator, storage, limits))
        .map(|routes| connection_service(cluster_id, routes, sasl_config, maximum_frame_size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatibility_decode_bounds_follow_the_transport_body_ceiling() {
        let body = DEFAULT_MAXIMUM_FRAME_SIZE;
        let limits = compatibility_decode_limits(body).unwrap();

        assert_eq!(body + size_of::<i32>(), limits.max_frame_bytes);
        assert_eq!(body, limits.max_string_bytes);
        assert_eq!(body, limits.max_bytes);
        assert_eq!(body, limits.max_sequence_elements);
        assert_eq!(
            body * (2 + size_of::<usize>()),
            limits.max_total_allocation_bytes
        );
        assert_eq!(
            2 * (body + size_of::<i32>()) + body,
            limits.max_total_work_units
        );
    }

    #[test]
    fn compatibility_decode_bounds_reject_address_space_overflow() {
        assert!(compatibility_decode_limits(usize::MAX).is_err());
    }
}
