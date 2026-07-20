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

use bytes::{Bytes, BytesMut};
use tansu_sans_io::{
    ApiKey as _, BorrowedProduceRequest, DecodeLimit, DecodeLimits, Error, Frame, Header,
    ProduceRequest,
    produce_request::{PartitionProduceData, TopicProduceData},
    record::{Record, deflated, inflated},
};

fn record_batch() -> tansu_sans_io::Result<deflated::Batch> {
    inflated::Batch {
        base_offset: 0,
        partition_leader_epoch: -1,
        magic: 2,
        attributes: 0,
        last_offset_delta: 0,
        base_timestamp: 1_726_000_000_000,
        max_timestamp: 1_726_000_000_000,
        producer_id: -1,
        producer_epoch: -1,
        base_sequence: -1,
        records: [Record::builder()
            .value(Some(Bytes::from_static(b"frame-backed-value")))
            .build()?]
        .into(),
        ..Default::default()
    }
    .try_into()
}

fn encoded_request(
    version: i16,
    topics: impl IntoIterator<Item = TopicProduceData>,
) -> tansu_sans_io::Result<Bytes> {
    Frame::request(
        Header::Request {
            api_key: ProduceRequest::KEY,
            api_version: version,
            correlation_id: 42,
            client_id: Some("borrowed-record-request".into()),
        },
        ProduceRequest::default()
            .transactional_id((version >= 3).then(|| "transaction-7".into()))
            .acks(-1)
            .timeout_ms(1_500)
            .topic_data(Some(topics.into_iter().collect()))
            .into(),
    )
}

fn topic(
    name: &str,
    partitions: impl IntoIterator<Item = PartitionProduceData>,
) -> TopicProduceData {
    TopicProduceData::default()
        .name(name.into())
        .partition_data(Some(partitions.into_iter().collect()))
}

#[test]
fn generated_view_tracks_all_produce_versions_and_flexible_cutover() -> tansu_sans_io::Result<()> {
    for version in 0..=11 {
        let encoded = encoded_request(
            version,
            [topic(
                "events",
                [PartitionProduceData::default()
                    .index(3)
                    .records(Some(deflated::Frame { batches: vec![] }))],
            )],
        )?;
        let request = BorrowedProduceRequest::from_bytes(encoded)?;

        assert_eq!(version, request.api_version());
        assert_eq!(42, request.correlation_id());
        assert_eq!(Some("borrowed-record-request"), request.client_id()?);
        assert_eq!(
            (version >= 3).then_some("transaction-7"),
            request.transactional_id()?
        );
        assert_eq!(-1, request.acks());
        assert_eq!(1_500, request.timeout_ms());

        let mut work = request.work_budget()?;
        let topic = request.topic_data().next(&mut work).expect("one topic")?;
        assert_eq!("events", topic.name()?);
        let partition = topic
            .partition_data()
            .next(&mut work)
            .expect("one partition")?;
        assert_eq!(3, partition.index());
        assert_eq!(Some(&[][..]), partition.records_bytes());
    }
    Ok(())
}

#[test]
fn nullable_records_preserve_null_and_empty_in_legacy_and_compact_encodings()
-> tansu_sans_io::Result<()> {
    for version in [8, 9] {
        let encoded = encoded_request(
            version,
            [topic(
                "events",
                [
                    PartitionProduceData::default().index(0).records(None),
                    PartitionProduceData::default()
                        .index(1)
                        .records(Some(deflated::Frame { batches: vec![] })),
                ],
            )],
        )?;
        let request = BorrowedProduceRequest::from_bytes(encoded.clone())?;
        let mut work = request.work_budget()?;
        let topic = request.topic_data().next(&mut work).expect("one topic")?;
        let first = topic
            .partition_data()
            .next(&mut work)
            .expect("one partition")?;
        let records = first
            .records_bytes()
            .expect("owned encoder represents None as empty");
        let records_start = records.as_ptr() as usize - encoded.as_ptr() as usize;

        let mut nullable = BytesMut::from(&encoded[..]);
        if version < 9 {
            nullable[records_start - size_of::<i32>()..records_start]
                .copy_from_slice(&(-1i32).to_be_bytes());
        } else {
            nullable[records_start - size_of::<u8>()] = 0;
        }
        let request = BorrowedProduceRequest::from_bytes(nullable.freeze())?;
        let mut work = request.work_budget()?;
        let topic = request.topic_data().next(&mut work).expect("one topic")?;
        let mut partitions = topic.partition_data();
        assert!(
            partitions
                .next(&mut work)
                .expect("null records")?
                .records_bytes()
                .is_none()
        );
        assert_eq!(
            Some(&[][..]),
            partitions
                .next(&mut work)
                .expect("empty records")?
                .records_bytes()
        );
    }
    Ok(())
}

#[test]
fn descendant_strings_and_records_share_the_retained_frame() -> tansu_sans_io::Result<()> {
    let encoded = encoded_request(
        9,
        [topic(
            "events",
            [PartitionProduceData::default()
                .index(0)
                .records(Some(deflated::Frame {
                    batches: vec![record_batch()?],
                }))],
        )],
    )?;
    let request = BorrowedProduceRequest::from_bytes(encoded.clone())?;
    let mut work = request.work_budget()?;
    let start = request.frame().as_ptr() as usize;
    let end = start + request.frame().len();
    let topic = request.topic_data().next(&mut work).expect("one topic")?;
    let name = topic.name()?;
    let partition = topic
        .partition_data()
        .next(&mut work)
        .expect("one partition")?;
    let records = partition.records_bytes().expect("records");

    assert!((start..end).contains(&(name.as_ptr() as usize)));
    assert!((start..end).contains(&(records.as_ptr() as usize)));
    assert_eq!(&encoded[..], &request.frame()[..]);
    Ok(())
}

#[test]
fn record_payload_is_opaque_to_request_validation() -> tansu_sans_io::Result<()> {
    let encoded = encoded_request(
        9,
        [topic(
            "events",
            [PartitionProduceData::default()
                .index(0)
                .records(Some(deflated::Frame {
                    batches: vec![record_batch()?],
                }))],
        )],
    )?;
    let request = BorrowedProduceRequest::from_bytes(encoded.clone())?;
    let mut work = request.work_budget()?;
    let topic = request.topic_data().next(&mut work).expect("topic")?;
    let partition = topic.partition_data().next(&mut work).expect("partition")?;
    let records = partition.records_bytes().expect("records");
    let last = records.as_ptr() as usize - encoded.as_ptr() as usize + records.len() - 1;

    let mut corrupt = BytesMut::from(&encoded[..]);
    corrupt[last] ^= 1;
    let request = BorrowedProduceRequest::from_bytes(corrupt.freeze())?;
    let mut work = request.work_budget()?;
    let topic = request.topic_data().next(&mut work).expect("topic")?;
    assert!(
        topic
            .partition_data()
            .next(&mut work)
            .expect("partition")?
            .records_bytes()
            .is_some()
    );
    Ok(())
}

#[test]
fn truncated_or_over_long_inputs_are_rejected() -> tansu_sans_io::Result<()> {
    let encoded = encoded_request(
        8,
        [topic(
            "events",
            [PartitionProduceData::default().index(0).records(None)],
        )],
    )?;
    for length in 0..encoded.len() {
        assert!(BorrowedProduceRequest::from_bytes(encoded.slice(..length)).is_err());
    }

    let mut trailing = BytesMut::from(&encoded[..]);
    trailing.extend_from_slice(&[0]);
    assert!(matches!(
        BorrowedProduceRequest::from_bytes(trailing.freeze()),
        Err(Error::FrameSizeMismatch { .. })
    ));
    Ok(())
}

/// The borrowed request views relax exactly as the owned decoder does: bytes
/// inside the declared frame that the schema's fields do not describe are
/// accepted, matching Apache Kafka's `RequestContext.parseRequest`, which never
/// checks `buffer.remaining()`. Produce rather than Metadata, so this is a
/// property of the request path and not of one client's Metadata shape.
#[test]
fn trailing_bytes_inside_the_declared_frame_are_accepted() -> tansu_sans_io::Result<()> {
    let encoded = encoded_request(
        8,
        [topic(
            "events",
            [PartitionProduceData::default().index(0).records(None)],
        )],
    )?;

    let mut padded = BytesMut::from(&encoded[..]);
    padded.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
    let payload_bytes = i32::try_from(padded.len() - size_of::<i32>())?;
    padded[..size_of::<i32>()].copy_from_slice(&payload_bytes.to_be_bytes());

    let view = BorrowedProduceRequest::from_bytes(padded.freeze())?;
    assert_eq!(8, view.api_version());
    assert_eq!(42, view.correlation_id());
    Ok(())
}

#[test]
fn high_cardinality_views_retain_constant_sized_state() -> tansu_sans_io::Result<()> {
    const PARTITIONS: usize = 4_096;
    let encoded = encoded_request(
        8,
        [topic(
            "events",
            (0..PARTITIONS).map(|index| {
                PartitionProduceData::default()
                    .index(i32::try_from(index).expect("test index"))
                    .records(None)
            }),
        )],
    )?;
    let request = BorrowedProduceRequest::from_bytes_with_limits(
        encoded,
        DecodeLimits {
            max_sequence_elements: PARTITIONS,
            max_total_work_units: 100_000,
            ..DecodeLimits::default()
        },
    )?;
    let mut work = request.work_budget()?;
    let topic = request.topic_data().next(&mut work).expect("topic")?;
    let mut partitions = topic.partition_data();
    let mut count = 0;
    while let Some(partition) = partitions.next(&mut work) {
        let _ = partition?;
        count += 1;
    }
    assert_eq!(PARTITIONS, count);
    assert!(size_of_val(&request) < 256);
    Ok(())
}

#[test]
fn structural_limits_apply_before_lending_descendants() -> tansu_sans_io::Result<()> {
    let encoded = encoded_request(
        8,
        [topic(
            "events",
            [PartitionProduceData::default().index(0).records(None)],
        )],
    )?;
    let error = BorrowedProduceRequest::from_bytes_with_limits(
        encoded,
        DecodeLimits {
            max_nesting_depth: 4,
            ..DecodeLimits::default()
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        Error::DecodeLimitExceeded {
            kind: DecodeLimit::NestingDepth,
            limit: 4,
            actual: 5,
        }
    ));
    Ok(())
}

#[test]
fn repeated_traversal_debits_one_caller_owned_work_budget() -> tansu_sans_io::Result<()> {
    let encoded = encoded_request(
        9,
        [
            topic(
                "events-0",
                [PartitionProduceData::default().index(0).records(None)],
            ),
            topic(
                "events-1",
                [PartitionProduceData::default().index(1).records(None)],
            ),
        ],
    )?;
    let measured = BorrowedProduceRequest::from_bytes(encoded.clone())?;
    let mut measured_work = measured.work_budget()?;
    let structural = measured_work.attempted();
    let topic = measured
        .topic_data()
        .next(&mut measured_work)
        .expect("topic")?;
    let _partition = topic
        .partition_data()
        .next(&mut measured_work)
        .expect("partition")?;
    let one_traversal = measured_work.attempted() - structural;
    assert!(one_traversal > 0);

    let request = BorrowedProduceRequest::from_bytes_with_limits(
        encoded,
        DecodeLimits {
            max_total_work_units: structural + one_traversal,
            ..DecodeLimits::default()
        },
    )?;
    let mut work = request.work_budget()?;
    let topic = request.topic_data().next(&mut work).expect("topic")?;
    let _partition = topic.partition_data().next(&mut work).expect("partition")?;
    let mut replay = request.topic_data();
    let error = replay.next(&mut work).expect("replayed topic").unwrap_err();
    assert!(matches!(
        error,
        Error::DecodeLimitExceeded {
            kind: DecodeLimit::TotalWorkUnits,
            ..
        }
    ));
    let attempted = work.attempted();
    let remaining = replay.len();
    let error = replay
        .next(&mut work)
        .expect("exhausted replay budget remains an error")
        .unwrap_err();
    assert!(matches!(
        error,
        Error::DecodeLimitExceeded {
            kind: DecodeLimit::TotalWorkUnits,
            ..
        }
    ));
    assert_eq!(attempted, work.attempted());
    assert_eq!(remaining, replay.len());
    Ok(())
}
