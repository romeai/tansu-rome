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

use std::io::{self, Write};

use crate::{AuthError, Authentication, Error, SaslLimits, Stage};
use bytes::Bytes;
use rama::{Context, Service};
use rsasl::prelude::State;
use tansu_sans_io::{ApiKey, ErrorCode, SaslAuthenticateRequest, SaslAuthenticateResponse};
use tokio::task;
use tracing::debug;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LimitExceeded {
    Token { length: usize, maximum: usize },
    Transcript { length: usize, maximum: usize },
}

impl From<LimitExceeded> for AuthError {
    fn from(value: LimitExceeded) -> Self {
        match value {
            LimitExceeded::Token { length, maximum } => Self::TokenTooLarge { length, maximum },
            LimitExceeded::Transcript { length, maximum } => {
                Self::TranscriptTooLarge { length, maximum }
            }
        }
    }
}

struct BoundedTokenWriter {
    bytes: Vec<u8>,
    limits: SaslLimits,
    transcript_before_output: usize,
    exceeded: Option<LimitExceeded>,
}

impl BoundedTokenWriter {
    fn new(limits: SaslLimits, transcript_before_output: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limits,
            transcript_before_output,
            exceeded: None,
        }
    }

    fn into_parts(self) -> (Vec<u8>, Option<LimitExceeded>) {
        (self.bytes, self.exceeded)
    }
}

impl Write for BoundedTokenWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let token_length = self.bytes.len().saturating_add(buf.len());
        let transcript_length = self.transcript_before_output.saturating_add(token_length);

        let exceeded = if token_length > self.limits.maximum_token_size() {
            Some(LimitExceeded::Token {
                length: token_length,
                maximum: self.limits.maximum_token_size(),
            })
        } else if transcript_length > self.limits.maximum_transcript_size() {
            Some(LimitExceeded::Transcript {
                length: transcript_length,
                maximum: self.limits.maximum_transcript_size(),
            })
        } else {
            None
        };

        if let Some(exceeded) = exceeded {
            self.exceeded = Some(exceeded);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SASL exchange exceeded its configured bound",
            ));
        }

        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn authentication_failed() -> SaslAuthenticateResponse {
    SaslAuthenticateResponse::default()
        .error_code(ErrorCode::SaslAuthenticationFailed.into())
        .error_message(Some(ErrorCode::SaslAuthenticationFailed.to_string()))
        .auth_bytes(Bytes::from_static(b""))
        .session_lifetime_ms(Some(0))
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SaslAuthenticateService {
    session_lifetime_ms: Option<i64>,
}

impl Default for SaslAuthenticateService {
    fn default() -> Self {
        Self {
            session_lifetime_ms: Some(60_000),
        }
    }
}

impl SaslAuthenticateService {
    pub fn session_lifetime_ms(self, session_lifetime_ms: Option<i64>) -> Self {
        Self {
            session_lifetime_ms,
        }
    }
}

impl ApiKey for SaslAuthenticateService {
    const KEY: i16 = SaslAuthenticateRequest::KEY;
}

impl<S> Service<S, SaslAuthenticateRequest> for SaslAuthenticateService
where
    S: Send + Sync + 'static,
{
    type Response = SaslAuthenticateResponse;
    type Error = Error;

    async fn serve(
        &self,
        ctx: Context<S>,
        req: SaslAuthenticateRequest,
    ) -> Result<Self::Response, Self::Error> {
        if let Some(authentication) = ctx.get::<Authentication>().cloned() {
            let session_lifetime_ms = self.session_lifetime_ms;

            task::spawn_blocking(move || {
                authentication
                    .stage
                    .lock()
                    .map_err(Into::into)
                    .map(|mut guard| {
                        if let Some(Stage::Session(session)) = guard.as_mut() {
                            let input_length = req.auth_bytes.len();
                            let input_exceeded =
                                if input_length > authentication.limits.maximum_token_size() {
                                    Some(LimitExceeded::Token {
                                        length: input_length,
                                        maximum: authentication.limits.maximum_token_size(),
                                    })
                                } else {
                                    let transcript_length =
                                        session.transcript_size.saturating_add(input_length);

                                    (transcript_length
                                        > authentication.limits.maximum_transcript_size())
                                    .then_some(LimitExceeded::Transcript {
                                        length: transcript_length,
                                        maximum: authentication.limits.maximum_transcript_size(),
                                    })
                                };

                            if let Some(exceeded) = input_exceeded {
                                _ = guard.replace(Stage::Finished(Err(exceeded.into())));
                                return authentication_failed();
                            }

                            let transcript_before_output = session.transcript_size + input_length;
                            let mut outcome = BoundedTokenWriter::new(
                                authentication.limits,
                                transcript_before_output,
                            );

                            let state = session
                                .session
                                .step(Some(&req.auth_bytes), &mut outcome)
                                .inspect(|state| debug!(?state))
                                .inspect_err(|err| debug!(?err));
                            let (auth_bytes, output_exceeded) = outcome.into_parts();

                            let Ok(state) = state else {
                                if let Some(exceeded) = output_exceeded {
                                    _ = guard.replace(Stage::Finished(Err(exceeded.into())));
                                } else {
                                    _ = guard.take();
                                }

                                return authentication_failed();
                            };

                            session.transcript_size = transcript_before_output + auth_bytes.len();
                            let auth_bytes = Bytes::from(auth_bytes);

                            if let State::Finished(_) = state {
                                let verdict = session
                                    .session
                                    .validation()
                                    .unwrap_or(Err(AuthError::MissingValidation));
                                let authenticated = verdict.is_ok();

                                debug!(?verdict, authenticated);
                                _ = guard.replace(Stage::Finished(verdict));

                                if !authenticated {
                                    return SaslAuthenticateResponse::default()
                                        .error_code(ErrorCode::SaslAuthenticationFailed.into())
                                        .error_message(Some(
                                            ErrorCode::SaslAuthenticationFailed.to_string(),
                                        ))
                                        .auth_bytes(auth_bytes)
                                        .session_lifetime_ms(Some(0));
                                }
                            }

                            SaslAuthenticateResponse::default()
                                .error_code(ErrorCode::None.into())
                                .error_message(Some("NONE".into()))
                                .auth_bytes(auth_bytes)
                                .session_lifetime_ms(session_lifetime_ms)
                        } else {
                            _ = guard.take();

                            SaslAuthenticateResponse::default()
                                .error_code(ErrorCode::IllegalSaslState.into())
                                .error_message(Some(ErrorCode::IllegalSaslState.to_string()))
                                .auth_bytes(Bytes::from_static(b""))
                                .session_lifetime_ms(Some(0))
                        }
                    })
            })
            .await?
        } else {
            Ok(SaslAuthenticateResponse::default()
                .error_code(ErrorCode::IllegalSaslState.into())
                .error_message(Some(ErrorCode::IllegalSaslState.to_string()))
                .auth_bytes(Bytes::from_static(b""))
                .session_lifetime_ms(Some(0)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_output_token_is_rejected_before_vector_growth() {
        let limits = SaslLimits::new(4, 16).expect("valid bounds");
        let mut writer = BoundedTokenWriter::new(limits, 0);

        assert!(writer.write_all(b"12345").is_err());
        let (bytes, exceeded) = writer.into_parts();
        assert!(bytes.is_empty());
        assert_eq!(
            Some(LimitExceeded::Token {
                length: 5,
                maximum: 4,
            }),
            exceeded,
        );
    }

    #[test]
    fn oversized_output_transcript_is_rejected_before_vector_growth() {
        let limits = SaslLimits::new(8, 4).expect("valid bounds");
        let mut writer = BoundedTokenWriter::new(limits, 3);

        assert!(writer.write_all(b"12").is_err());
        let (bytes, exceeded) = writer.into_parts();
        assert!(bytes.is_empty());
        assert_eq!(
            Some(LimitExceeded::Transcript {
                length: 5,
                maximum: 4,
            }),
            exceeded,
        );
    }
}
