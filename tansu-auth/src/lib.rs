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

use rsasl::{
    callback::SessionCallback,
    config::SASLConfig,
    mechanisms::scram::{SCRAM_SHA256, SCRAM_SHA512},
    prelude::{Mechanism, Registry, SASLError, SASLServer, Session, SessionError, Validation},
};
#[cfg(any(feature = "storage", test))]
use rsasl::{
    callback::{Context, SessionData},
    property::{AuthId, AuthzId},
};
use std::{
    fmt::{self, Debug, Formatter},
    sync::{Arc, Mutex, PoisonError},
};
use tansu_sans_io::ScramMechanism;
use thiserror::Error;
use tokio::task::JoinError;
#[cfg(any(feature = "storage", test))]
use tracing::{debug, instrument};

mod authenticate;
mod handshake;
#[cfg(feature = "storage")]
mod storage;

pub use authenticate::SaslAuthenticateService;
pub use handshake::SaslHandshakeService;
#[cfg(feature = "storage")]
pub use storage::{Callback, configuration};

/// SASL mechanisms whose credentials Tansu verifies before granting an identity.
static VERIFIED_MECHANISMS: &[Mechanism] = &[SCRAM_SHA512, SCRAM_SHA256];

/// The verified rsasl registry for callers that intentionally offer only SCRAM-SHA-256.
static SCRAM_SHA256_MECHANISM: &[Mechanism] = &[SCRAM_SHA256];

/// The verified rsasl registry for callers that intentionally offer only SCRAM-SHA-512.
static SCRAM_SHA512_MECHANISM: &[Mechanism] = &[SCRAM_SHA512];

/// Kafka's default maximum server-side SASL token size is 512 KiB.
const DEFAULT_MAXIMUM_SASL_TOKEN_SIZE: usize = 512 * 1024;

/// Four maximum-sized tokens allow a complete SCRAM exchange while bounding cumulative work.
const DEFAULT_MAXIMUM_SASL_TRANSCRIPT_SIZE: usize = 4 * DEFAULT_MAXIMUM_SASL_TOKEN_SIZE;

fn is_verified_mechanism(mechanism: &str) -> bool {
    VERIFIED_MECHANISMS
        .iter()
        .any(|verified| verified.mechanism.as_str() == mechanism)
}

#[derive(Clone, Debug, Error)]
pub enum Error {
    Join(Arc<JoinError>),
    Poison,
    SansIo(#[from] tansu_sans_io::Error),
    Sasl(Arc<SASLError>),
    SaslSession(Arc<SessionError>),
}

/// Invalid bounds for a SASL exchange.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SaslLimitsError {
    #[error("maximum SASL token size must be greater than zero")]
    ZeroTokenSize,
    #[error("maximum SASL transcript size must be greater than zero")]
    ZeroTranscriptSize,
}

/// Per-connection bounds applied to caller-supplied SASL configurations.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SaslLimits {
    maximum_token_size: usize,
    maximum_transcript_size: usize,
}

impl SaslLimits {
    pub fn new(
        maximum_token_size: usize,
        maximum_transcript_size: usize,
    ) -> Result<Self, SaslLimitsError> {
        if maximum_token_size == 0 {
            return Err(SaslLimitsError::ZeroTokenSize);
        }

        if maximum_transcript_size == 0 {
            return Err(SaslLimitsError::ZeroTranscriptSize);
        }

        Ok(Self {
            maximum_token_size,
            maximum_transcript_size,
        })
    }

    pub fn maximum_token_size(self) -> usize {
        self.maximum_token_size
    }

    pub fn maximum_transcript_size(self) -> usize {
        self.maximum_transcript_size
    }
}

impl Default for SaslLimits {
    fn default() -> Self {
        Self {
            maximum_token_size: DEFAULT_MAXIMUM_SASL_TOKEN_SIZE,
            maximum_transcript_size: DEFAULT_MAXIMUM_SASL_TRANSCRIPT_SIZE,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<JoinError> for Error {
    fn from(value: JoinError) -> Self {
        Self::Join(Arc::new(value))
    }
}

impl<T> From<PoisonError<T>> for Error {
    fn from(_value: PoisonError<T>) -> Self {
        Self::Poison
    }
}

impl From<SASLError> for Error {
    fn from(value: SASLError) -> Self {
        Self::Sasl(Arc::new(value))
    }
}

impl From<SessionError> for Error {
    fn from(value: SessionError) -> Self {
        Self::SaslSession(Arc::new(value))
    }
}

#[derive(Clone)]
pub struct Authentication {
    config: Arc<SASLConfig>,
    limits: SaslLimits,
    stage: Arc<Mutex<Option<Stage>>>,
}

pub enum Stage {
    Server(SASLServer<Justification>),
    Session(SaslSession),
    Finished(Result<Success, AuthError>),
}

pub struct SaslSession {
    session: Session<Justification>,
    transcript_size: usize,
}

impl SaslSession {
    fn new(session: Session<Justification>) -> Self {
        Self {
            session,
            transcript_size: 0,
        }
    }
}

impl Debug for SaslSession {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct(stringify!(SaslSession))
            .field("transcript_size", &self.transcript_size)
            .finish_non_exhaustive()
    }
}

impl Debug for Stage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct(stringify!(Stage)).finish()
    }
}

impl Authentication {
    pub fn server(config: Arc<SASLConfig>) -> Self {
        Self::server_with_limits(config, SaslLimits::default())
    }

    pub fn server_with_limits(config: Arc<SASLConfig>, limits: SaslLimits) -> Self {
        let server = SASLServer::<Justification>::new(config.clone());
        Self {
            config,
            limits,
            stage: Arc::new(Mutex::new(Some(Stage::Server(server)))),
        }
    }

    pub fn is_authenticated(&self) -> bool {
        self.stage
            .lock()
            .map(|guard| matches!(guard.as_ref(), Some(Stage::Finished(Ok(_)))))
            .ok()
            .unwrap_or_default()
    }

    /// Build a fresh `Stage::Server` from the stored config. Used by
    /// the SASL handshake handler to support re-authentication
    /// (KIP-368): a client periodically issues a new SaslHandshake on
    /// an existing connection, and the broker must be willing to
    /// initiate a new SASL exchange even though the previous one
    /// already succeeded.
    pub fn fresh_server(&self) -> Stage {
        Stage::Server(SASLServer::<Justification>::new(self.config.clone()))
    }
}

impl Debug for Authentication {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct(stringify!(Authentication)).finish()
    }
}

#[derive(Debug, Error)]
pub enum AuthError {
    Bad,
    Io(tansu_sans_io::Error),
    MissingValidation,
    MissingProperty { mechanism: String, property: String },
    NoSuchUser,
    TokenTooLarge { length: usize, maximum: usize },
    TranscriptTooLarge { length: usize, maximum: usize },
    UnknownMechanism(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Success {
    auth_id: String,
}

impl Success {
    /// Records the authenticated identity returned by a caller-supplied rsasl callback.
    pub fn new(auth_id: impl Into<String>) -> Self {
        Self {
            auth_id: auth_id.into(),
        }
    }

    /// Returns the identity authenticated by the SASL exchange.
    pub fn auth_id(&self) -> &str {
        &self.auth_id
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Justification;

impl Validation for Justification {
    type Value = Result<Success, AuthError>;
}

/// Builds a SCRAM-only SASL configuration from a caller-supplied rsasl callback.
///
/// The callback supplies credentials and records a [`Success`] verdict. Protocol
/// handling remains in this crate, while callers can source credentials without
/// depending on Tansu's storage crate.
pub fn configuration_with_callback<C>(callback: C) -> Result<Arc<SASLConfig>, Error>
where
    C: SessionCallback + 'static,
{
    SASLConfig::builder()
        .with_registry(Registry::with_mechanisms(VERIFIED_MECHANISMS))
        .with_callback(callback)
        .map_err(Into::into)
}

/// Builds a SASL configuration offering exactly one verified SCRAM mechanism.
pub fn configuration_with_callback_for<C>(
    callback: C,
    mechanism: ScramMechanism,
) -> Result<Arc<SASLConfig>, Error>
where
    C: SessionCallback + 'static,
{
    let mechanisms = match mechanism {
        ScramMechanism::Scram256 => SCRAM_SHA256_MECHANISM,
        ScramMechanism::Scram512 => SCRAM_SHA512_MECHANISM,
    };

    SASLConfig::builder()
        .with_registry(Registry::with_mechanisms(mechanisms))
        .with_callback(callback)
        .map_err(Into::into)
}

#[cfg(any(feature = "storage", test))]
#[instrument(skip_all)]
fn check_identity(
    session_data: &SessionData,
    context: &Context<'_>,
) -> Result<Result<Success, AuthError>, Error> {
    debug!(mechanism = %session_data.mechanism().mechanism);

    if is_verified_mechanism(session_data.mechanism().mechanism.as_str()) {
        Ok(context
            .get_ref::<AuthId>()
            .inspect(|auth_id| debug!(mechanism = %session_data.mechanism().mechanism, auth_id))
            .ok_or(AuthError::MissingProperty {
                mechanism: session_data.mechanism().mechanism.to_string(),
                property: "AuthId".into(),
            })
            .and_then(|auth_id| {
                context
                    .get_ref::<AuthzId>()
                    .inspect(|authz_id| {
                        debug!(mechanism = %session_data.mechanism().mechanism, authz_id)
                    })
                    .map_or(
                        Ok(Success {
                            auth_id: auth_id.to_string(),
                        }),
                        |authz_id| {
                            if authz_id == auth_id {
                                Ok(Success {
                                    auth_id: auth_id.to_string(),
                                })
                            } else {
                                Err(AuthError::Bad)
                            }
                        },
                    )
            }))
    } else {
        Ok(Err(AuthError::UnknownMechanism(
            session_data.mechanism().mechanism.to_string(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use rama::{Context as RamaContext, Service as _};
    use rsasl::{
        callback::{Request, SessionCallback},
        mechanisms::plain::PLAIN,
        mechanisms::scram::properties::ScramStoredPassword,
        prelude::{Mechanism, Mechname, Registry, SASLClient, State},
        property::AuthId,
        validate::{Validate, ValidationError},
    };
    use std::io::Cursor;
    use tansu_sans_io::{ErrorCode, SaslAuthenticateRequest, SaslHandshakeRequest, ScramMechanism};

    /// Test registry simulating a downstream feature-unified PLAIN configuration.
    static PLAIN_MECHANISMS: &[Mechanism] = &[PLAIN];

    #[derive(Clone, Copy, Debug)]
    struct PlainCallback;

    impl SessionCallback for PlainCallback {
        fn validate(
            &self,
            session_data: &SessionData,
            context: &Context<'_>,
            validate: &mut Validate<'_>,
        ) -> Result<(), ValidationError> {
            _ = validate.with::<Justification, _>(|| {
                check_identity(session_data, context)
                    .map_err(|error| ValidationError::Boxed(Box::new(error)))
            })?;

            Ok(())
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct StaticScramCallback;

    impl SessionCallback for StaticScramCallback {
        fn callback(
            &self,
            _session_data: &SessionData,
            context: &Context<'_>,
            request: &mut Request<'_>,
        ) -> Result<(), SessionError> {
            /// Salt for the test-only `alice` / `secret` SCRAM-SHA-256 credential.
            const SALT: &[u8] = b"k52tay1vvtia5e6lc37gn3f3h";
            /// Stored key for the test-only `alice` / `secret` SCRAM-SHA-256 credential.
            const STORED_KEY: &[u8] = &[
                150, 254, 7, 121, 81, 205, 192, 207, 60, 206, 251, 24, 31, 131, 31, 15, 96, 75, 20,
                228, 251, 132, 22, 235, 160, 72, 200, 130, 127, 49, 29, 150,
            ];
            /// Server key for the test-only `alice` / `secret` SCRAM-SHA-256 credential.
            const SERVER_KEY: &[u8] = &[
                186, 175, 253, 227, 176, 106, 88, 53, 186, 173, 104, 88, 94, 40, 115, 166, 44, 183,
                199, 177, 137, 41, 225, 132, 56, 32, 70, 255, 223, 209, 22, 146,
            ];
            /// PBKDF2 iteration count used to generate the test-only SCRAM credential.
            const ITERATIONS: u32 = 8192;

            if context.get_ref::<AuthId>() == Some("alice") {
                _ = request.satisfy::<ScramStoredPassword<'_>>(&ScramStoredPassword::new(
                    ITERATIONS, SALT, STORED_KEY, SERVER_KEY,
                ))?;
            }

            Ok(())
        }

        fn validate(
            &self,
            _session_data: &SessionData,
            context: &Context<'_>,
            validate: &mut Validate<'_>,
        ) -> Result<(), ValidationError> {
            _ = validate.with::<Justification, _>(|| {
                Ok(context
                    .get_ref::<AuthId>()
                    .filter(|auth_id| *auth_id == "alice")
                    .map(Success::new)
                    .ok_or(AuthError::NoSuchUser))
            })?;

            Ok(())
        }
    }

    fn is_send<T: Send>() {}
    fn is_sync<T: Sync>() {}

    #[test]
    fn authentication() {
        is_send::<Authentication>();
        is_sync::<Authentication>();
    }

    #[test]
    fn sasl_limits_reject_zero_bounds() {
        assert_eq!(Err(SaslLimitsError::ZeroTokenSize), SaslLimits::new(0, 1),);
        assert_eq!(
            Err(SaslLimitsError::ZeroTranscriptSize),
            SaslLimits::new(1, 0),
        );
    }

    #[tokio::test]
    async fn caller_supplied_scram_configuration_authenticates_without_storage() {
        let config = configuration_with_callback_for(StaticScramCallback, ScramMechanism::Scram256)
            .expect("static SCRAM configuration");
        let authentication = Authentication::server(config);
        let mut context = RamaContext::default();
        assert!(context.insert(authentication.clone()).is_none());

        let handshake = SaslHandshakeService
            .serve(
                context.clone(),
                SaslHandshakeRequest::default().mechanism("SCRAM-SHA-256".into()),
            )
            .await
            .expect("SASL handshake response");
        assert_eq!(Some(vec!["SCRAM-SHA-256".into()]), handshake.mechanisms);

        let client = SASLClient::new(
            SASLConfig::with_credentials(None, "alice".into(), "secret".into())
                .expect("client credentials"),
        );
        let offered = [Mechname::parse(b"SCRAM-SHA-256").expect("static SCRAM mechanism name")];
        let mut session = client
            .start_suggested(&offered)
            .expect("SCRAM client session");
        let mut input = None;

        loop {
            let mut output = Cursor::new(Vec::new());
            let state = session
                .step(input.as_deref(), &mut output)
                .expect("SCRAM client step");
            match state {
                State::Running => {
                    let response = SaslAuthenticateService::default()
                        .serve(
                            context.clone(),
                            SaslAuthenticateRequest::default()
                                .auth_bytes(Bytes::from(output.into_inner())),
                        )
                        .await
                        .expect("SASL authenticate response");
                    assert_eq!(
                        ErrorCode::None,
                        ErrorCode::try_from(response.error_code).expect("known Kafka error code"),
                    );
                    input = Some(response.auth_bytes);
                }
                State::Finished(_) => break,
            }
        }

        assert!(authentication.is_authenticated());
    }

    #[tokio::test]
    async fn plain_capable_config_cannot_authenticate() {
        let config = SASLConfig::builder()
            .with_registry(Registry::with_mechanisms(PLAIN_MECHANISMS))
            .with_callback(PlainCallback)
            .expect("PLAIN-capable test config");
        let authentication = Authentication::server(config);

        {
            let mut guard = authentication.stage.lock().expect("authentication stage");
            let Some(Stage::Server(server)) = guard.take() else {
                panic!("authentication must start with a SASL server")
            };
            let session = server
                .start_suggested(PLAIN.mechanism)
                .expect("test config explicitly enables PLAIN");
            _ = guard.replace(Stage::Session(SaslSession::new(session)));
        }

        let mut context = RamaContext::default();
        assert!(context.insert(authentication.clone()).is_none());
        let response = SaslAuthenticateService::default()
            .serve(
                context,
                SaslAuthenticateRequest::default()
                    .auth_bytes(Bytes::from_static(b"\0alice\0anything")),
            )
            .await
            .expect("SASL authenticate response");

        assert_eq!(
            ErrorCode::SaslAuthenticationFailed,
            ErrorCode::try_from(response.error_code).expect("known Kafka error code"),
        );
        assert!(!authentication.is_authenticated());
        assert!(matches!(
            authentication
                .stage
                .lock()
                .expect("authentication stage")
                .as_ref(),
            Some(Stage::Finished(Err(AuthError::UnknownMechanism(mechanism))))
                if mechanism == "PLAIN"
        ));
    }

    #[tokio::test]
    async fn oversized_sasl_token_is_rejected_before_session_processing() {
        let config = SASLConfig::builder()
            .with_registry(Registry::with_mechanisms(PLAIN_MECHANISMS))
            .with_callback(PlainCallback)
            .expect("PLAIN-capable test config");
        let authentication = Authentication::server_with_limits(
            config,
            SaslLimits::new(4, 16).expect("valid bounds"),
        );

        {
            let mut guard = authentication.stage.lock().expect("authentication stage");
            let Some(Stage::Server(server)) = guard.take() else {
                panic!("authentication must start with a SASL server")
            };
            let session = server
                .start_suggested(PLAIN.mechanism)
                .expect("test config explicitly enables PLAIN");
            _ = guard.replace(Stage::Session(SaslSession::new(session)));
        }

        let mut context = RamaContext::default();
        assert!(context.insert(authentication.clone()).is_none());
        let response = SaslAuthenticateService::default()
            .serve(
                context,
                SaslAuthenticateRequest::default().auth_bytes(Bytes::from_static(b"12345")),
            )
            .await
            .expect("SASL authenticate response");

        assert_eq!(
            ErrorCode::SaslAuthenticationFailed,
            ErrorCode::try_from(response.error_code).expect("known Kafka error code"),
        );
        assert!(matches!(
            authentication
                .stage
                .lock()
                .expect("authentication stage")
                .as_ref(),
            Some(Stage::Finished(Err(AuthError::TokenTooLarge {
                length: 5,
                maximum: 4,
            })))
        ));
    }

    #[tokio::test]
    async fn oversized_sasl_transcript_is_rejected_before_session_processing() {
        let config = SASLConfig::builder()
            .with_registry(Registry::with_mechanisms(PLAIN_MECHANISMS))
            .with_callback(PlainCallback)
            .expect("PLAIN-capable test config");
        let authentication = Authentication::server_with_limits(
            config,
            SaslLimits::new(8, 4).expect("valid bounds"),
        );

        {
            let mut guard = authentication.stage.lock().expect("authentication stage");
            let Some(Stage::Server(server)) = guard.take() else {
                panic!("authentication must start with a SASL server")
            };
            let session = server
                .start_suggested(PLAIN.mechanism)
                .expect("test config explicitly enables PLAIN");
            _ = guard.replace(Stage::Session(SaslSession::new(session)));
        }

        let mut context = RamaContext::default();
        assert!(context.insert(authentication.clone()).is_none());
        let response = SaslAuthenticateService::default()
            .serve(
                context,
                SaslAuthenticateRequest::default().auth_bytes(Bytes::from_static(b"12345")),
            )
            .await
            .expect("SASL authenticate response");

        assert_eq!(
            ErrorCode::SaslAuthenticationFailed,
            ErrorCode::try_from(response.error_code).expect("known Kafka error code"),
        );
        assert!(matches!(
            authentication
                .stage
                .lock()
                .expect("authentication stage")
                .as_ref(),
            Some(Stage::Finished(Err(AuthError::TranscriptTooLarge {
                length: 5,
                maximum: 4,
            })))
        ));
    }
}
