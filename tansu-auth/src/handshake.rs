// Copyright ⓒ 2024-2026 Peter Morgan <peter.james.morgan@gmail.com>
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

use crate::{Authentication, Error, SaslSession, Stage, is_verified_mechanism};
use rama::{Context, Service};
use rsasl::prelude::Mechname;
use tansu_sans_io::{ApiKey, ErrorCode, SaslHandshakeRequest, SaslHandshakeResponse};
use tracing::{debug, instrument};

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SaslHandshakeService;

impl ApiKey for SaslHandshakeService {
    const KEY: i16 = SaslHandshakeRequest::KEY;
}

impl<S> Service<S, SaslHandshakeRequest> for SaslHandshakeService
where
    S: Send + Sync + 'static,
{
    type Response = SaslHandshakeResponse;
    type Error = Error;

    #[instrument(skip(self, ctx), ret)]
    async fn serve(
        &self,
        ctx: Context<S>,
        req: SaslHandshakeRequest,
    ) -> Result<Self::Response, Self::Error> {
        if let Some(authentication) = ctx.get::<Authentication>().cloned() {
            authentication
                .stage
                .lock()
                .map_err(Into::into)
                .map(|mut guard| {
                    // Re-authentication (KIP-368): a Java kafka-clients
                    // connection periodically issues another SaslHandshake
                    // on the same TCP socket. The previous handshake left
                    // the Stage in `Session`/`Finished`, so a stale
                    // `take()` would fall into the else branch and reject
                    // a perfectly valid mechanism with
                    // `UnsupportedSaslMechanism`. Always start with a
                    // fresh `SASLServer` built from the stored config.
                    if guard
                        .as_ref()
                        .is_none_or(|guard| !matches!(guard, Stage::Server(_)))
                    {
                        debug!(?guard);
                        _ = guard.replace(authentication.fresh_server());
                    }

                    let Some(Stage::Server(server)) = guard.take() else {
                        return unsupported_sasl_mechanism(Vec::new());
                    };
                    let mechanisms = server
                        .get_available()
                        .into_iter()
                        .filter(|mechanism| is_verified_mechanism(mechanism.mechanism.as_str()))
                        .map(|mechanism| mechanism.mechanism.to_string())
                        .collect::<Vec<_>>();
                    debug!(?mechanisms);

                    if !mechanisms.contains(&req.mechanism) {
                        _ = guard.replace(Stage::Server(server));
                        return unsupported_sasl_mechanism(mechanisms);
                    }

                    let Ok(mechanism) = Mechname::parse(req.mechanism.as_bytes()) else {
                        _ = guard.replace(Stage::Server(server));
                        return unsupported_sasl_mechanism(mechanisms);
                    };

                    match server
                        .start_suggested(mechanism)
                        .inspect_err(|err| debug!(?err, ?mechanism))
                    {
                        Ok(session) => {
                            let selected_mechanism = session.get_mechname().to_string();
                            _ = guard.replace(Stage::Session(SaslSession::new(session)));

                            SaslHandshakeResponse::default()
                                .error_code(ErrorCode::None.into())
                                .mechanisms(Some(vec![selected_mechanism]))
                        }
                        Err(_) => {
                            _ = guard.replace(authentication.fresh_server());
                            unsupported_sasl_mechanism(mechanisms)
                        }
                    }
                })
        } else {
            Ok(unsupported_sasl_mechanism(Vec::new()))
        }
    }
}

fn unsupported_sasl_mechanism(mechanisms: Vec<String>) -> SaslHandshakeResponse {
    SaslHandshakeResponse::default()
        .error_code(ErrorCode::UnsupportedSaslMechanism.into())
        .mechanisms(Some(mechanisms))
}
