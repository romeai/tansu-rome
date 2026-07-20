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

//! Decode of client-shaped request frames that this crate's own encoder never
//! emits.
//!
//! Every frame here is assembled byte by byte as a librdkafka 2.x client puts
//! it on the wire, rather than round-tripped through [`Frame::request`]. A
//! round-trip only proves the encoder and decoder agree with each other.

use bytes::Bytes;
use tansu_sans_io::{ApiKey as _, Body, DecodeLimits, Error, Frame, MetadataRequest};

fn append_unsigned_varint(encoded: &mut Vec<u8>, mut value: u32) {
    while value >= 0x80 {
        encoded.push(u8::try_from(value & 0x7f).unwrap() | 0x80);
        value >>= 7;
    }
    encoded.push(u8::try_from(value).unwrap());
}

fn length_prefixed(payload: Vec<u8>) -> Bytes {
    let mut frame = Vec::with_capacity(payload.len() + size_of::<i32>());
    frame.extend_from_slice(&i32::try_from(payload.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(&payload);
    frame.into()
}

/// Request header v2: api key, api version, correlation id, nullable legacy
/// client id, then the header tag buffer.
fn request_header_v2(
    api_key: i16,
    api_version: i16,
    correlation_id: i32,
    client_id: &str,
) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&api_key.to_be_bytes());
    encoded.extend_from_slice(&api_version.to_be_bytes());
    encoded.extend_from_slice(&correlation_id.to_be_bytes());
    encoded.extend_from_slice(&i16::try_from(client_id.len()).unwrap().to_be_bytes());
    encoded.extend_from_slice(client_id.as_bytes());
    encoded.push(0);
    encoded
}

/// The exact bytes librdkafka 2.13 sends for `kcat -L`, captured off the wire.
///
/// The topics array is null (all topics). librdkafka reserved four bytes for
/// the compact array count, wrote the single-byte null varint into the front of
/// that slot and never erased the remainder, so `allow_auto_topic_creation`,
/// `include_topic_authorized_operations` and the body tag buffer are preceded
/// by three bytes of padding.
const KCAT_METADATA_ALL_TOPICS: &[u8] = &[
    0x00, 0x00, 0x00, 0x19, // frame length: 25
    0x00, 0x03, // api key: Metadata
    0x00, 0x0c, // api version: 12
    0x00, 0x00, 0x00, 0x03, // correlation id
    0x00, 0x07, b'r', b'd', b'k', b'a', b'f', b'k', b'a', // client id
    0x00, // header tag buffer
    0x00, // topics: compact array null
    0x00, 0x00, 0x00, // librdkafka's unerased arraycnt padding
    0x01, // allow_auto_topic_creation, as librdkafka meant it: true
    0x00, // include_topic_authorized_operations, as librdkafka meant it: false
    0x00, // body tag buffer, as librdkafka meant it
];

fn decode(encoded: &[u8]) -> Result<Frame, Error> {
    Frame::request_from_bytes_with_limits(encoded, DecodeLimits::default())
}

fn metadata_request(frame: Frame) -> MetadataRequest {
    let Body::MetadataRequest(request) = frame.body else {
        panic!("expected a metadata request");
    };
    request
}

/// The frame decodes, and it decodes to exactly what Apache Kafka decodes it
/// to -- which is not what librdkafka meant.
///
/// Kafka's `RequestContext.parseRequest` calls
/// `AbstractRequest.parseRequest(apiKey, apiVersion, new ByteBufferAccessor(buffer))`
/// and returns; there is no `buffer.remaining()` check. So it reads the null
/// topics array, then takes the FIRST padding byte as
/// `allow_auto_topic_creation` (`false`, where the client wrote `true` three
/// bytes later), the second as `include_topic_authorized_operations`, the third
/// as an empty body tag buffer, and silently ignores the client's real trailing
/// `01 00 00`.
///
/// Being bug-compatible is the whole point: recovering the intended `true`
/// would mean guessing which zero bytes are padding, which is a guess about one
/// client's encoder rather than a protocol rule.
#[test]
fn librdkafka_metadata_for_all_topics_decodes_as_apache_kafka_decodes_it() {
    let request =
        metadata_request(decode(KCAT_METADATA_ALL_TOPICS).expect("kcat -L must reach the broker"));

    assert_eq!(None, request.topics);
    assert_eq!(Some(false), request.allow_auto_topic_creation);
    assert_eq!(Some(false), request.include_topic_authorized_operations);
}

/// Trailing bytes are ignored however many there are and whatever they hold:
/// the relaxation is a property of the request path, not a repair of one shape.
#[test]
fn further_trailing_bytes_are_ignored_too() {
    let mut forged = KCAT_METADATA_ALL_TOPICS.to_vec();
    forged[3] += 2;
    forged.extend_from_slice(&[0x07, 0x07]);

    let request = metadata_request(decode(&forged).expect("must decode"));

    assert_eq!(None, request.topics);
}

/// The length prefix still owns the frame. Bytes appended without extending it
/// are a framing disagreement and stay fatal.
#[test]
fn bytes_outside_the_declared_frame_are_still_rejected() {
    let mut forged = KCAT_METADATA_ALL_TOPICS.to_vec();
    forged.extend_from_slice(&[0x07, 0x07]);

    assert!(
        matches!(decode(&forged), Err(Error::FrameSizeMismatch { .. })),
        "unexpected: {:?}",
        decode(&forged)
    );
}

/// Zero bytes that really are fields must not be swallowed: here they are the
/// `allow_auto_topic_creation` / `include_topic_authorized_operations` / tag
/// buffer of an all-topics request from a client that finalized its count.
#[test]
fn a_body_that_already_decodes_exactly_is_left_alone() {
    let mut payload = request_header_v2(MetadataRequest::KEY, 12, 2, "rdkafka");
    payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    let request = metadata_request(decode(&length_prefixed(payload)).expect("must decode"));

    assert_eq!(None, request.topics);
    assert_eq!(Some(false), request.allow_auto_topic_creation);
}

/// A non-null topics array occupies the reserved slot, so librdkafka erases the
/// slack: this frame is exact, and its fields must decode as written.
#[test]
fn a_named_topic_carries_no_padding() {
    let mut payload = request_header_v2(MetadataRequest::KEY, 12, 3, "rdkafka");
    append_unsigned_varint(&mut payload, 2); // compact array: one topic
    payload.extend_from_slice(&[0; 16]); // topic id
    append_unsigned_varint(&mut payload, 7); // compact string: "orders"
    payload.extend_from_slice(b"orders");
    payload.push(0); // topic tag buffer
    payload.extend_from_slice(&[0x01, 0x00, 0x00]);

    let request = metadata_request(decode(&length_prefixed(payload)).expect("must decode"));

    assert_eq!(1, request.topics.as_ref().unwrap().len());
    assert_eq!(Some(true), request.allow_auto_topic_creation);
}

/// librdkafka's own connection-setup probe asks for no topics at all. It goes
/// through the finalizing path, so it is already exact.
#[test]
fn the_brokers_only_probe_is_unpadded() {
    let mut payload = request_header_v2(MetadataRequest::KEY, 12, 2, "rdkafka");
    payload.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

    let request = metadata_request(decode(&length_prefixed(payload)).expect("must decode"));

    assert_eq!(Some(0), request.topics.map(|topics| topics.len()));
    assert_eq!(Some(false), request.allow_auto_topic_creation);
}
