// Copyright ⓒ 2024-2026 Peter Morgan <peter.james.morgan@gmail.com>
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

use crate::{Error, Justification, check_identity, configuration_with_callback};
use rsasl::{
    callback::{Context, Request, SessionCallback, SessionData},
    config::SASLConfig,
    mechanisms::scram::properties::ScramStoredPassword,
    prelude::SessionError,
    property::AuthId,
    validate::{Validate, ValidationError},
};
use std::{fmt, str::FromStr, sync::Arc};
use tansu_sans_io::ScramMechanism;
use tansu_storage::Storage;
use tracing::{debug, instrument};

/// Bridges Tansu's storage credential records to rsasl's callback contract.
#[derive(Clone)]
pub struct Callback<S> {
    storage: S,
}

impl<S> Callback<S>
where
    S: Storage,
{
    pub fn new(storage: S) -> Self {
        Self { storage }
    }
}

impl<S> fmt::Debug for Callback<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct(stringify!(Callback)).finish_non_exhaustive()
    }
}

impl<S> SessionCallback for Callback<S>
where
    S: Storage,
{
    #[instrument(skip_all)]
    fn callback(
        &self,
        session_data: &SessionData,
        context: &Context<'_>,
        request: &mut Request<'_>,
    ) -> Result<(), SessionError> {
        debug!(mechanism = %session_data.mechanism().mechanism);

        if session_data.mechanism().mechanism.starts_with("SCRAM-") {
            let mechanism = ScramMechanism::from_str(session_data.mechanism().mechanism)
                .map_err(|error| SessionError::Boxed(Box::new(error)))?;

            let auth_id = context
                .get_ref::<AuthId>()
                .ok_or(SessionError::ValidationError(
                    ValidationError::MissingRequiredProperty,
                ))?;

            debug!(?auth_id, ?mechanism);

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;

            if let Ok(Some(credential)) = rt
                .block_on(
                    async move { self.storage.user_scram_credential(auth_id, mechanism).await },
                )
                .inspect_err(|err| debug!(auth_id, ?mechanism, ?err))
            {
                _ = request
                    .satisfy::<ScramStoredPassword<'_>>(&ScramStoredPassword::new(
                        credential.iterations as u32,
                        &credential.salt[..],
                        &credential.stored_key[..],
                        &credential.server_key[..],
                    ))
                    .inspect_err(|err| debug!(auth_id, ?mechanism, ?err))?;
            }
        }

        Ok(())
    }

    #[instrument(skip_all)]
    fn validate(
        &self,
        session_data: &SessionData,
        context: &Context<'_>,
        validate: &mut Validate<'_>,
    ) -> Result<(), ValidationError> {
        debug!(mechanism = %session_data.mechanism().mechanism);

        _ = validate.with::<Justification, _>(|| {
            check_identity(session_data, context).map_err(|e| ValidationError::Boxed(Box::new(e)))
        })?;

        Ok(())
    }
}

/// Builds the broker's storage-backed SCRAM configuration.
pub fn configuration<S>(storage: S) -> Result<Arc<SASLConfig>, Error>
where
    S: Storage,
{
    configuration_with_callback(Callback::new(storage))
}
