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

//! One bounded, version-aware writer for owned and borrowed Produce responses.

use bytes::{BufMut as _, Bytes, BytesMut};

use crate::{Error, ProduceResponse, Result, produce_response};

/// Oldest Produce response version advertised by the Kafka descriptor.
pub const PRODUCE_RESPONSE_MIN_VERSION: i16 = 0;

/// Newest Produce response version advertised by the Kafka descriptor.
pub const PRODUCE_RESPONSE_MAX_VERSION: i16 = 11;

/// First Produce response version using Kafka flexible encoding.
pub const PRODUCE_RESPONSE_FLEXIBLE_START: i16 = 9;

/// Current-leader values carried by the version-10 partition tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProduceCurrentLeader {
    pub leader_id: i32,
    pub leader_epoch: i32,
}

/// Replayable semantic view of one Produce response.
///
/// Every iterator method must return a fresh traversal. The encoder calls the
/// same view once to determine exact wire size and once to write that many
/// bytes, without constructing an owned topic/partition response graph.
pub trait ProduceResponseView {
    type Topic<'a>: ProduceTopicResponseView
    where
        Self: 'a;
    type Topics<'a>: ExactSizeIterator<Item = Self::Topic<'a>>
    where
        Self: 'a;
    type NodeEndpoint<'a>: ProduceNodeEndpointView
    where
        Self: 'a;
    type NodeEndpoints<'a>: ExactSizeIterator<Item = Self::NodeEndpoint<'a>>
    where
        Self: 'a;

    fn topics(&self) -> Self::Topics<'_>;
    fn throttle_time_ms(&self) -> i32;
    fn node_endpoints(&self) -> Option<Self::NodeEndpoints<'_>>;
}

/// Replayable semantic view of one topic in a Produce response.
pub trait ProduceTopicResponseView {
    type Partition<'a>: ProducePartitionResponseView
    where
        Self: 'a;
    type Partitions<'a>: ExactSizeIterator<Item = Self::Partition<'a>>
    where
        Self: 'a;

    fn name(&self) -> &str;
    fn partitions(&self) -> Self::Partitions<'_>;
}

/// Replayable semantic view of one partition in a Produce response.
pub trait ProducePartitionResponseView {
    type RecordError<'a>: ProduceRecordErrorView
    where
        Self: 'a;
    type RecordErrors<'a>: ExactSizeIterator<Item = Self::RecordError<'a>>
    where
        Self: 'a;

    fn index(&self) -> i32;
    fn error_code(&self) -> i16;
    fn base_offset(&self) -> i64;
    fn log_append_time_ms(&self) -> i64;
    fn log_start_offset(&self) -> i64;
    fn record_errors(&self) -> Self::RecordErrors<'_>;
    fn error_message(&self) -> Option<&str>;
    fn current_leader(&self) -> Option<ProduceCurrentLeader>;
}

/// Semantic view of one record-level Produce error.
pub trait ProduceRecordErrorView {
    fn batch_index(&self) -> i32;
    fn message(&self) -> Option<&str>;
}

/// Semantic view of one version-10 Produce node endpoint.
pub trait ProduceNodeEndpointView {
    fn node_id(&self) -> i32;
    fn host(&self) -> &str;
    fn port(&self) -> i32;
    fn rack(&self) -> Option<&str>;
}

impl ProduceResponseView for ProduceResponse {
    type Topic<'a> = &'a produce_response::TopicProduceResponse;
    type Topics<'a> = std::slice::Iter<'a, produce_response::TopicProduceResponse>;
    type NodeEndpoint<'a> = &'a produce_response::NodeEndpoint;
    type NodeEndpoints<'a> = std::slice::Iter<'a, produce_response::NodeEndpoint>;

    fn topics(&self) -> Self::Topics<'_> {
        self.responses.as_deref().unwrap_or(&[]).iter()
    }

    fn throttle_time_ms(&self) -> i32 {
        self.throttle_time_ms.unwrap_or_default()
    }

    fn node_endpoints(&self) -> Option<Self::NodeEndpoints<'_>> {
        self.node_endpoints.as_deref().map(<[_]>::iter)
    }
}

impl ProduceTopicResponseView for &produce_response::TopicProduceResponse {
    type Partition<'a>
        = &'a produce_response::PartitionProduceResponse
    where
        Self: 'a;
    type Partitions<'a>
        = std::slice::Iter<'a, produce_response::PartitionProduceResponse>
    where
        Self: 'a;

    fn name(&self) -> &str {
        &self.name
    }

    fn partitions(&self) -> Self::Partitions<'_> {
        self.partition_responses.as_deref().unwrap_or(&[]).iter()
    }
}

impl ProducePartitionResponseView for &produce_response::PartitionProduceResponse {
    type RecordError<'a>
        = &'a produce_response::BatchIndexAndErrorMessage
    where
        Self: 'a;
    type RecordErrors<'a>
        = std::slice::Iter<'a, produce_response::BatchIndexAndErrorMessage>
    where
        Self: 'a;

    fn index(&self) -> i32 {
        self.index
    }
    fn error_code(&self) -> i16 {
        self.error_code
    }
    fn base_offset(&self) -> i64 {
        self.base_offset
    }
    fn log_append_time_ms(&self) -> i64 {
        self.log_append_time_ms.unwrap_or(-1)
    }
    fn log_start_offset(&self) -> i64 {
        self.log_start_offset.unwrap_or(-1)
    }
    fn record_errors(&self) -> Self::RecordErrors<'_> {
        self.record_errors.as_deref().unwrap_or(&[]).iter()
    }
    fn error_message(&self) -> Option<&str> {
        self.error_message.as_deref()
    }
    fn current_leader(&self) -> Option<ProduceCurrentLeader> {
        self.current_leader
            .as_ref()
            .map(|leader| ProduceCurrentLeader {
                leader_id: leader.leader_id,
                leader_epoch: leader.leader_epoch,
            })
    }
}

impl ProduceRecordErrorView for &produce_response::BatchIndexAndErrorMessage {
    fn batch_index(&self) -> i32 {
        self.batch_index
    }
    fn message(&self) -> Option<&str> {
        self.batch_index_error_message.as_deref()
    }
}

impl ProduceNodeEndpointView for &produce_response::NodeEndpoint {
    fn node_id(&self) -> i32 {
        self.node_id
    }
    fn host(&self) -> &str {
        &self.host
    }
    fn port(&self) -> i32 {
        self.port
    }
    fn rack(&self) -> Option<&str> {
        self.rack.as_deref()
    }
}

trait Sink {
    fn put(&mut self, bytes: &[u8]) -> Result<()>;
    fn len(&self) -> usize;
}

#[derive(Default)]
struct Count(usize);

impl Sink for Count {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        self.0 = self.0.checked_add(bytes.len()).ok_or(Error::Overflow)?;
        Ok(())
    }
    fn len(&self) -> usize {
        self.0
    }
}

struct BoundedBuffer {
    bytes: BytesMut,
    expected: usize,
}

impl Sink for BoundedBuffer {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        let actual = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(Error::Overflow)?;
        if actual > self.expected {
            return Err(Error::ProduceResponseViewChanged {
                expected: self.expected,
                actual,
            });
        }
        self.bytes.put_slice(bytes);
        Ok(())
    }
    fn len(&self) -> usize {
        self.bytes.len()
    }
}

fn i16(sink: &mut dyn Sink, value: i16) -> Result<()> {
    sink.put(&value.to_be_bytes())
}
fn i32(sink: &mut dyn Sink, value: i32) -> Result<()> {
    sink.put(&value.to_be_bytes())
}
fn i64(sink: &mut dyn Sink, value: i64) -> Result<()> {
    sink.put(&value.to_be_bytes())
}

fn unsigned_varint(sink: &mut dyn Sink, mut value: u32) -> Result<()> {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        sink.put(&[byte])?;
        if value == 0 {
            return Ok(());
        }
    }
}

fn sequence(sink: &mut dyn Sink, count: usize, flexible: bool) -> Result<()> {
    if flexible {
        unsigned_varint(
            sink,
            u32::try_from(count.checked_add(1).ok_or(Error::Overflow)?)?,
        )
    } else {
        i32(sink, i32::try_from(count)?)
    }
}

fn string(sink: &mut dyn Sink, value: &str, flexible: bool) -> Result<()> {
    if flexible {
        unsigned_varint(
            sink,
            u32::try_from(value.len().checked_add(1).ok_or(Error::Overflow)?)?,
        )?;
    } else {
        i16(sink, i16::try_from(value.len())?)?;
    }
    sink.put(value.as_bytes())
}

fn nullable_string(sink: &mut dyn Sink, value: Option<&str>, flexible: bool) -> Result<()> {
    match value {
        Some(value) => string(sink, value, flexible),
        None if flexible => unsigned_varint(sink, 0),
        None => i16(sink, -1),
    }
}

fn empty_tags(sink: &mut dyn Sink) -> Result<()> {
    unsigned_varint(sink, 0)
}

fn tag(sink: &mut dyn Sink, id: u32, payload: &dyn Fn(&mut dyn Sink) -> Result<()>) -> Result<()> {
    let mut count = Count::default();
    payload(&mut count)?;
    unsigned_varint(sink, id)?;
    unsigned_varint(sink, u32::try_from(count.len())?)?;
    payload(sink)
}

fn write<V: ProduceResponseView>(
    response: &V,
    api_version: i16,
    correlation_id: i32,
    sink: &mut dyn Sink,
) -> Result<()> {
    let flexible = api_version >= PRODUCE_RESPONSE_FLEXIBLE_START;
    i32(sink, 0)?;
    i32(sink, correlation_id)?;
    if flexible {
        empty_tags(sink)?;
    }

    let topics = response.topics();
    sequence(sink, topics.len(), flexible)?;
    for topic in topics {
        string(sink, topic.name(), flexible)?;
        let partitions = topic.partitions();
        sequence(sink, partitions.len(), flexible)?;
        for partition in partitions {
            i32(sink, partition.index())?;
            i16(sink, partition.error_code())?;
            i64(sink, partition.base_offset())?;
            if api_version >= 2 {
                i64(sink, partition.log_append_time_ms())?;
            }
            if api_version >= 5 {
                i64(sink, partition.log_start_offset())?;
            }
            if api_version >= 8 {
                let record_errors = partition.record_errors();
                sequence(sink, record_errors.len(), flexible)?;
                for record_error in record_errors {
                    i32(sink, record_error.batch_index())?;
                    nullable_string(sink, record_error.message(), flexible)?;
                    if flexible {
                        empty_tags(sink)?;
                    }
                }
                nullable_string(sink, partition.error_message(), flexible)?;
            }
            if flexible {
                let leader = (api_version >= 10)
                    .then(|| partition.current_leader())
                    .flatten();
                unsigned_varint(sink, u32::from(leader.is_some()))?;
                if let Some(leader) = leader {
                    tag(sink, 0, &|sink| {
                        i32(sink, leader.leader_id)?;
                        i32(sink, leader.leader_epoch)?;
                        empty_tags(sink)
                    })?;
                }
            }
        }
        if flexible {
            empty_tags(sink)?;
        }
    }
    if api_version >= 1 {
        i32(sink, response.throttle_time_ms())?;
    }
    if flexible {
        let endpoints = (api_version >= 10)
            .then(|| response.node_endpoints())
            .flatten();
        unsigned_varint(sink, u32::from(endpoints.is_some()))?;
        if endpoints.is_some() {
            tag(sink, 0, &|sink| {
                let endpoints = response.node_endpoints().expect("checked above");
                sequence(sink, endpoints.len(), true)?;
                for endpoint in endpoints {
                    i32(sink, endpoint.node_id())?;
                    string(sink, endpoint.host(), true)?;
                    i32(sink, endpoint.port())?;
                    nullable_string(sink, endpoint.rack(), true)?;
                    empty_tags(sink)?;
                }
                Ok(())
            })?;
        }
    }
    Ok(())
}

/// Encode a semantic Produce response using a route-admitted request identity.
///
/// Protocol services should expose this only through an admitted reply, so an
/// application cannot choose `api_version` or `correlation_id` independently
/// of the request which owns the response.
#[doc(hidden)]
pub fn encode<V: ProduceResponseView>(
    response: &V,
    api_version: i16,
    correlation_id: i32,
    maximum_frame_bytes: usize,
) -> Result<Bytes> {
    if !(PRODUCE_RESPONSE_MIN_VERSION..=PRODUCE_RESPONSE_MAX_VERSION).contains(&api_version) {
        return Err(Error::UnsupportedProduceResponseVersion {
            version: api_version,
            minimum: PRODUCE_RESPONSE_MIN_VERSION,
            maximum: PRODUCE_RESPONSE_MAX_VERSION,
        });
    }
    let mut count = Count::default();
    write(response, api_version, correlation_id, &mut count)?;
    if count.len() > maximum_frame_bytes {
        return Err(Error::ProduceResponseSizeLimitExceeded {
            limit: maximum_frame_bytes,
            actual: count.len(),
        });
    }
    let payload = count
        .len()
        .checked_sub(size_of::<i32>())
        .ok_or(Error::Overflow)?;
    let payload = i32::try_from(payload)?;
    let mut encoded = BoundedBuffer {
        bytes: BytesMut::with_capacity(count.len()),
        expected: count.len(),
    };
    write(response, api_version, correlation_id, &mut encoded)?;
    if encoded.len() != encoded.expected {
        return Err(Error::ProduceResponseViewChanged {
            expected: encoded.expected,
            actual: encoded.len(),
        });
    }
    encoded.bytes[..size_of::<i32>()].copy_from_slice(&payload.to_be_bytes());
    Ok(encoded.bytes.freeze())
}
