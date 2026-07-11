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
fn complete_frame_length_must_match_prefix() -> tansu_sans_io::Result<()> {
    let encoded = sasl_handshake()?;
    let mut forged = encoded.to_vec();
    forged[..4].copy_from_slice(&i32::try_from(encoded.len())?.to_be_bytes());

    assert!(matches!(
        Frame::request_from_bytes_with_limits(&forged[..], DecodeLimits::default()),
        Err(Error::FrameSizeMismatch { .. })
    ));
    Ok(())
}

#[test]
fn complete_frame_is_checked_before_decoding() -> tansu_sans_io::Result<()> {
    let encoded = sasl_handshake()?;
    let limits = DecodeLimits {
        max_frame_bytes: encoded.len() - 1,
        ..DecodeLimits::default()
    };

    assert_limit(
        Frame::request_from_bytes_with_limits(&encoded[..], limits).unwrap_err(),
        DecodeLimit::FrameBytes,
    );
    Ok(())
}

#[test]
fn forged_string_length_is_rejected_before_reading_payload() -> tansu_sans_io::Result<()> {
    let encoded = sasl_handshake()?;
    let mut forged = encoded.to_vec();
    forged[14..16].copy_from_slice(&i16::MAX.to_be_bytes());
    let limits = DecodeLimits {
        max_string_bytes: 16,
        ..DecodeLimits::default()
    };

    assert_limit(
        Frame::request_from_bytes_with_limits(&forged[..], limits).unwrap_err(),
        DecodeLimit::StringBytes,
    );
    Ok(())
}

#[test]
fn forged_bytes_length_is_rejected_before_allocation() -> tansu_sans_io::Result<()> {
    let encoded = Frame::request(
        header(SaslAuthenticateRequest::KEY, 0),
        SaslAuthenticateRequest::default()
            .auth_bytes(Bytes::from_static(b"proof"))
            .into(),
    )?;
    let mut forged = encoded.to_vec();
    forged[14..18].copy_from_slice(&i32::MAX.to_be_bytes());
    let limits = DecodeLimits {
        max_bytes: 16,
        ..DecodeLimits::default()
    };

    assert_limit(
        Frame::request_from_bytes_with_limits(&forged[..], limits).unwrap_err(),
        DecodeLimit::Bytes,
    );
    Ok(())
}

#[test]
fn forged_array_count_is_rejected_before_traversal() -> tansu_sans_io::Result<()> {
    let encoded = metadata(0)?;
    let mut forged = encoded.to_vec();
    forged[14..18].copy_from_slice(&i32::MAX.to_be_bytes());
    let limits = DecodeLimits {
        max_sequence_elements: 16,
        ..DecodeLimits::default()
    };

    assert_limit(
        Frame::request_from_bytes_with_limits(&forged[..], limits).unwrap_err(),
        DecodeLimit::SequenceElements,
    );
    Ok(())
}

#[test]
fn flexible_lengths_obey_the_same_string_bytes_and_array_limits() -> tansu_sans_io::Result<()> {
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
fn nesting_depth_is_bounded() -> tansu_sans_io::Result<()> {
    let encoded = metadata(12)?;
    let limits = DecodeLimits {
        max_nesting_depth: 1,
        ..DecodeLimits::default()
    };

    assert_limit(
        Frame::request_from_bytes_with_limits(&encoded[..], limits).unwrap_err(),
        DecodeLimit::NestingDepth,
    );
    Ok(())
}

#[test]
fn aggregate_allocation_is_checked_before_allocating_value() -> tansu_sans_io::Result<()> {
    let encoded = sasl_handshake()?;
    let limits = DecodeLimits {
        max_total_allocation_bytes: 4,
        ..DecodeLimits::default()
    };

    assert_limit(
        Frame::request_from_bytes_with_limits(&encoded[..], limits).unwrap_err(),
        DecodeLimit::TotalAllocationBytes,
    );
    Ok(())
}

#[test]
fn aggregate_work_includes_input_and_structural_visits() -> tansu_sans_io::Result<()> {
    let encoded = sasl_handshake()?;
    let limits = DecodeLimits {
        max_total_work_units: encoded.len(),
        ..DecodeLimits::default()
    };

    assert_limit(
        Frame::request_from_bytes_with_limits(&encoded[..], limits).unwrap_err(),
        DecodeLimit::TotalWorkUnits,
    );
    Ok(())
}
