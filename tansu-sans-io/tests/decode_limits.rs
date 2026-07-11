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
    ApiKey as _, DecodeLimit, DecodeLimits, Error, Frame, Header, MetadataRequest, ProduceRequest,
    SaslAuthenticateRequest, SaslHandshakeRequest,
    metadata_request::MetadataRequestTopic,
    produce_request::{PartitionProduceData, TopicProduceData},
    record::{Record, deflated, inflated},
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

fn produce_with_one_batch(base_offset: i64) -> tansu_sans_io::Result<Bytes> {
    let batch = inflated::Batch::builder()
        .base_offset(base_offset)
        .record(Record::builder().value(Some(Bytes::from_static(b"value"))))
        .producer_id(-1)
        .producer_epoch(-1)
        .build()?;
    let records: deflated::Frame = inflated::Frame {
        batches: [batch].into(),
    }
    .try_into()?;

    Frame::request(
        header(ProduceRequest::KEY, 9),
        ProduceRequest::default()
            .transactional_id(None)
            .acks(1)
            .timeout_ms(1_000)
            .topic_data(Some(
                [TopicProduceData::default()
                    .name("orders".into())
                    .partition_data(Some(
                        [PartitionProduceData::default()
                            .index(0)
                            .records(Some(records))]
                        .into(),
                    ))]
                .into(),
            ))
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

#[test]
fn frame_prefix_must_match_the_complete_input() -> tansu_sans_io::Result<()> {
    let encoded = sasl_handshake()?;

    let mut declares_too_many = encoded.to_vec();
    declares_too_many[..4].copy_from_slice(&i32::try_from(encoded.len())?.to_be_bytes());
    assert!(matches!(
        Frame::request_from_bytes(&declares_too_many[..]),
        Err(Error::FrameSizeMismatch { .. })
    ));

    let mut declares_too_few = encoded.to_vec();
    let declared = i32::from_be_bytes(declares_too_few[..4].try_into()?);
    declares_too_few[..4].copy_from_slice(&(declared - 1).to_be_bytes());
    assert!(matches!(
        Frame::request_from_bytes(&declares_too_few[..]),
        Err(Error::FrameSizeMismatch { .. })
    ));

    let mut negative = encoded.to_vec();
    negative[..4].copy_from_slice(&(-1_i32).to_be_bytes());
    assert!(matches!(
        Frame::request_from_bytes(&negative[..]),
        Err(Error::InvalidFrameSize(-1))
    ));
    Ok(())
}

#[test]
fn one_frame_must_consume_the_declared_input() -> tansu_sans_io::Result<()> {
    let encoded = sasl_handshake()?;

    let mut concatenated = encoded.to_vec();
    concatenated.extend_from_slice(&encoded);
    assert!(matches!(
        Frame::request_from_bytes(&concatenated[..]),
        Err(Error::FrameSizeMismatch { .. })
    ));

    let mut trailing = encoded.to_vec();
    trailing.extend_from_slice(&[0xAA, 0xBB]);
    let payload_bytes = trailing.len() - size_of::<i32>();
    trailing[..4].copy_from_slice(&i32::try_from(payload_bytes)?.to_be_bytes());
    assert!(matches!(
        Frame::request_from_bytes(&trailing[..]),
        Err(Error::TrailingFrameBytes(2))
    ));
    Ok(())
}

#[test]
fn zero_compact_bytes_length_is_an_error_not_a_panic() -> tansu_sans_io::Result<()> {
    let encoded = Frame::request(
        header(SaslAuthenticateRequest::KEY, 2),
        SaslAuthenticateRequest::default()
            .auth_bytes(Bytes::from_static(b"proof"))
            .into(),
    )?;
    let mut forged = encoded.to_vec();
    let proof = forged
        .windows(b"proof".len())
        .position(|window| window == b"proof")
        .expect("encoded request contains its authentication bytes");
    forged[proof - 1] = 0;

    assert!(Frame::request_from_bytes(&forged[..]).is_err());
    Ok(())
}

#[test]
fn peer_batch_length_is_validated_before_batch_allocation() -> tansu_sans_io::Result<()> {
    /// Distinctive record-batch offset used to locate the batch prefix in the encoded fixture.
    const BASE_OFFSET: i64 = 0x0102_0304_0506_0708;

    let encoded = produce_with_one_batch(BASE_OFFSET)?;
    let batch = encoded
        .windows(size_of::<i64>())
        .position(|window| window == BASE_OFFSET.to_be_bytes())
        .expect("encoded request contains the record batch base offset");
    let batch_length = batch + size_of::<i64>();

    for invalid_length in [-1_i32, i32::MAX] {
        let mut forged = encoded.to_vec();
        forged[batch_length..batch_length + size_of::<i32>()]
            .copy_from_slice(&invalid_length.to_be_bytes());
        assert!(
            Frame::request_from_bytes(&forged[..]).is_err(),
            "batch length {invalid_length} must be rejected"
        );
    }
    Ok(())
}
