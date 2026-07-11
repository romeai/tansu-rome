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

use bytes::Bytes;
use tansu_sans_io::{
    ApiKey as _, DecodeLimit, DecodeLimits, Error, Frame, Header, MetadataRequest,
    SaslAuthenticateRequest, SaslHandshakeRequest, metadata_request::MetadataRequestTopic,
};

fn header(api_key: i16, api_version: i16) -> Header {
    Header::Request {
        api_key,
        api_version,
        correlation_id: 42,
        client_id: None,
    }
}

fn sasl_handshake() -> tansu_sans_io::Result<Bytes> {
    Frame::request(
        header(SaslHandshakeRequest::KEY, 0),
        SaslHandshakeRequest::default()
            .mechanism("PLAIN".into())
            .into(),
    )
}

fn sasl_authenticate() -> tansu_sans_io::Result<Bytes> {
    Frame::request(
        header(SaslAuthenticateRequest::KEY, 0),
        SaslAuthenticateRequest::default()
            .auth_bytes(Bytes::from_static(b"proof"))
            .into(),
    )
}

fn metadata(api_version: i16) -> tansu_sans_io::Result<Bytes> {
    Frame::request(
        header(MetadataRequest::KEY, api_version),
        MetadataRequest::default()
            .topics(Some(
                [MetadataRequestTopic::default()
                    .topic_id((api_version >= 10).then_some([0; 16]))
                    .name(Some("orders".into()))]
                .into(),
            ))
            .allow_auto_topic_creation((api_version >= 4).then_some(false))
            .include_cluster_authorized_operations((8..=10).contains(&api_version).then_some(false))
            .include_topic_authorized_operations((api_version >= 8).then_some(false))
            .into(),
    )
}

fn assert_limit(error: Error, expected: DecodeLimit) {
    assert!(
        matches!(error, Error::DecodeLimitExceeded { kind, .. } if kind == expected),
        "unexpected error: {error:?}"
    );
}

#[test]
fn explicit_limits_preserve_non_flexible_and_flexible_semantics() -> tansu_sans_io::Result<()> {
    for (name, encoded) in [
        ("metadata v0", metadata(0)?),
        ("metadata v12", metadata(12)?),
        ("SASL handshake v0", sasl_handshake()?),
    ] {
        let expected = Frame::request_from_bytes(&encoded[..])
            .unwrap_or_else(|error| panic!("failed to decode {name}: {error:?}"));
        assert_eq!(
            expected,
            Frame::request_from_bytes_with_limits(&encoded[..], DecodeLimits::default())
                .unwrap_or_else(|error| panic!("failed to decode bounded {name}: {error:?}"))
        );
    }
    Ok(())
}

#[test]
fn complete_input_is_bounded_before_decoding() -> tansu_sans_io::Result<()> {
    let encoded = sasl_handshake()?;
    let limits = DecodeLimits {
        max_frame_bytes: encoded.len() - 1,
        ..DecodeLimits::default()
    };

    assert_limit(
        Frame::request_from_bytes_with_limits(&encoded[..], limits).unwrap_err(),
        DecodeLimit::FrameBytes,
    );
    assert!(
        Frame::request_from_bytes_with_limits(
            &encoded[..],
            DecodeLimits {
                max_frame_bytes: encoded.len(),
                ..DecodeLimits::default()
            }
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn string_length_is_bounded_before_payload_allocation() -> tansu_sans_io::Result<()> {
    let encoded = sasl_handshake()?;
    let mut forged = encoded.to_vec();
    forged[14..16].copy_from_slice(&i16::MAX.to_be_bytes());

    assert_limit(
        Frame::request_from_bytes_with_limits(
            &forged[..],
            DecodeLimits {
                max_string_bytes: 16,
                ..DecodeLimits::default()
            },
        )
        .unwrap_err(),
        DecodeLimit::StringBytes,
    );
    assert!(
        Frame::request_from_bytes_with_limits(
            &encoded[..],
            DecodeLimits {
                max_string_bytes: "PLAIN".len(),
                ..DecodeLimits::default()
            }
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn bytes_length_is_bounded_before_payload_allocation() -> tansu_sans_io::Result<()> {
    let encoded = sasl_authenticate()?;
    let mut forged = encoded.to_vec();
    forged[14..18].copy_from_slice(&i32::MAX.to_be_bytes());

    assert_limit(
        Frame::request_from_bytes_with_limits(
            &forged[..],
            DecodeLimits {
                max_bytes: 16,
                ..DecodeLimits::default()
            },
        )
        .unwrap_err(),
        DecodeLimit::Bytes,
    );
    assert!(
        Frame::request_from_bytes_with_limits(
            &encoded[..],
            DecodeLimits {
                max_bytes: b"proof".len(),
                ..DecodeLimits::default()
            }
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn array_count_is_bounded_before_traversal() -> tansu_sans_io::Result<()> {
    let encoded = metadata(0)?;
    let mut forged = encoded.to_vec();
    forged[14..18].copy_from_slice(&i32::MAX.to_be_bytes());

    assert_limit(
        Frame::request_from_bytes_with_limits(
            &forged[..],
            DecodeLimits {
                max_sequence_elements: 16,
                ..DecodeLimits::default()
            },
        )
        .unwrap_err(),
        DecodeLimit::SequenceElements,
    );
    assert!(
        Frame::request_from_bytes_with_limits(
            &encoded[..],
            DecodeLimits {
                max_sequence_elements: 1,
                ..DecodeLimits::default()
            }
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn flexible_lengths_obey_the_same_limits() -> tansu_sans_io::Result<()> {
    let metadata = metadata(12)?;
    assert_limit(
        Frame::request_from_bytes_with_limits(
            &metadata[..],
            DecodeLimits {
                max_sequence_elements: 0,
                ..DecodeLimits::default()
            },
        )
        .unwrap_err(),
        DecodeLimit::SequenceElements,
    );
    assert_limit(
        Frame::request_from_bytes_with_limits(
            &metadata[..],
            DecodeLimits {
                max_string_bytes: 5,
                ..DecodeLimits::default()
            },
        )
        .unwrap_err(),
        DecodeLimit::StringBytes,
    );

    let authenticate = Frame::request(
        header(SaslAuthenticateRequest::KEY, 2),
        SaslAuthenticateRequest::default()
            .auth_bytes(Bytes::from_static(b"proof"))
            .into(),
    )?;
    assert_limit(
        Frame::request_from_bytes_with_limits(
            &authenticate[..],
            DecodeLimits {
                max_bytes: 4,
                ..DecodeLimits::default()
            },
        )
        .unwrap_err(),
        DecodeLimit::Bytes,
    );
    Ok(())
}

#[test]
fn generated_nesting_and_work_are_bounded() -> tansu_sans_io::Result<()> {
    let encoded = metadata(12)?;
    assert_limit(
        Frame::request_from_bytes_with_limits(
            &encoded[..],
            DecodeLimits {
                max_nesting_depth: 1,
                ..DecodeLimits::default()
            },
        )
        .unwrap_err(),
        DecodeLimit::NestingDepth,
    );
    assert_limit(
        Frame::request_from_bytes_with_limits(
            &encoded[..],
            DecodeLimits {
                max_work_units: 0,
                ..DecodeLimits::default()
            },
        )
        .unwrap_err(),
        DecodeLimit::WorkUnits,
    );
    Ok(())
}

#[test]
fn limits_must_allow_the_frame_prefix() {
    assert!(matches!(
        DecodeLimits {
            max_frame_bytes: 3,
            ..DecodeLimits::default()
        }
        .validate(),
        Err(Error::InvalidDecodeLimits(_))
    ));
}
