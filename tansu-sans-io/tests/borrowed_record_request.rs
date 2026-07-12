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

        let topic = request.topic_data().next().expect("one topic")?;
        assert_eq!("events", topic.name()?);
        let partition = topic.partition_data().next().expect("one partition")?;
        assert_eq!(3, partition.index());
        assert!(
            partition
                .records()?
                .expect("encoded empty record set")
                .as_bytes()
                .is_empty()
        );
    }
    Ok(())
}

#[test]
fn nullable_records_preserve_null_and_empty_in_both_encodings() -> tansu_sans_io::Result<()> {
    for version in [8, 9] {
        let encoded_empty = encoded_request(
            version,
            [topic(
                "events",
                [
                    PartitionProduceData::default().index(0).records(None),
                    PartitionProduceData::default()
                        .index(1)
                        .records(Some(deflated::Frame { batches: vec![] })),
                    PartitionProduceData::default()
                        .index(2)
                        .records(Some(deflated::Frame {
                            batches: vec![record_batch()?],
                        })),
                ],
            )],
        )?;
        let empty_view = BorrowedProduceRequest::from_bytes(encoded_empty.clone())?;
        let empty_topic = empty_view.topic_data().next().expect("one topic")?;
        let empty_partition = empty_topic
            .partition_data()
            .next()
            .expect("first partition")?;
        let empty_records = empty_partition
            .records()?
            .expect("the owned encoder represents None as empty");
        let records_start =
            empty_records.as_bytes().as_ptr() as usize - encoded_empty.as_ptr() as usize;
        let mut encoded = BytesMut::from(&encoded_empty[..]);
        if version < 9 {
            encoded[records_start - size_of::<i32>()..records_start]
                .copy_from_slice(&(-1i32).to_be_bytes());
        } else {
            encoded[records_start - size_of::<u8>()] = 0;
        }
        let encoded = encoded.freeze();
        let request = BorrowedProduceRequest::from_bytes(encoded)?;
        let topic = request.topic_data().next().expect("one topic")?;
        let mut partitions = topic.partition_data();

        let null = partitions.next().expect("null records")?;
        assert!(null.records()?.is_none());

        let empty = partitions.next().expect("empty records")?;
        let empty = empty.records()?.expect("Some(empty)");
        assert!(empty.as_bytes().is_empty());
        assert_eq!(0, empty.batch_count());

        let populated = partitions.next().expect("populated records")?;
        let populated = populated.records()?.expect("one batch");
        assert_eq!(1, populated.batch_count());
    }
    Ok(())
}

#[test]
fn descendant_strings_records_and_batches_share_the_root_frame() -> tansu_sans_io::Result<()> {
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
    let start = request.frame().as_ptr() as usize;
    let end = start + request.frame().len();
    let topic = request.topic_data().next().expect("one topic")?;
    let name = topic.name()?;
    let partition = topic.partition_data().next().expect("one partition")?;
    let records = partition.records()?.expect("records");
    let batch = records.batches().next().expect("batch");

    assert!((start..end).contains(&(name.as_ptr() as usize)));
    assert!((start..end).contains(&(records.as_bytes().as_ptr() as usize)));
    assert!((start..end).contains(&(batch.as_bytes().as_ptr() as usize)));
    assert!((start..end).contains(&(batch.record_data().as_ptr() as usize)));
    assert_eq!(&encoded[..], &request.frame()[..]);
    Ok(())
}

#[test]
fn exact_frame_consumption_rejects_truncation_and_trailing_bytes() -> tansu_sans_io::Result<()> {
    let encoded = encoded_request(
        8,
        [topic(
            "events",
            [PartitionProduceData::default().index(0).records(None)],
        )],
    )?;

    for length in 0..encoded.len() {
        assert!(
            BorrowedProduceRequest::from_bytes(encoded.slice(..length)).is_err(),
            "truncation at {length} bytes unexpectedly decoded"
        );
    }

    let mut unchanged_prefix = BytesMut::from(&encoded[..]);
    unchanged_prefix.extend_from_slice(&[0]);
    assert!(matches!(
        BorrowedProduceRequest::from_bytes(unchanged_prefix.freeze()),
        Err(Error::FrameSizeMismatch { .. })
    ));

    let mut declared_trailing = BytesMut::from(&encoded[..]);
    declared_trailing.extend_from_slice(&[0]);
    let payload_bytes = i32::try_from(declared_trailing.len() - size_of::<i32>())?;
    declared_trailing[..size_of::<i32>()].copy_from_slice(&payload_bytes.to_be_bytes());
    assert!(matches!(
        BorrowedProduceRequest::from_bytes(declared_trailing.freeze()),
        Err(Error::TrailingFrameBytes(1))
    ));
    Ok(())
}

#[test]
fn peer_counts_and_request_wide_batch_work_are_bounded() -> tansu_sans_io::Result<()> {
    let two_batches = record_batch()?;
    let encoded = encoded_request(
        8,
        [topic(
            "events",
            [
                PartitionProduceData::default()
                    .index(0)
                    .records(Some(deflated::Frame {
                        batches: vec![two_batches.clone()],
                    })),
                PartitionProduceData::default()
                    .index(1)
                    .records(Some(deflated::Frame {
                        batches: vec![two_batches],
                    })),
            ],
        )],
    )?;

    // The structural scan consumes 23 units; the second request-wide batch validation is unit 24.
    let limits = DecodeLimits {
        max_work_units: 23,
        ..DecodeLimits::default()
    };
    assert!(matches!(
        BorrowedProduceRequest::from_bytes_with_limits(encoded, limits),
        Err(Error::DecodeLimitExceeded {
            kind: DecodeLimit::WorkUnits,
            limit: 23,
            actual: 24,
        })
    ));

    let encoded = encoded_request(
        8,
        [
            topic(
                "a",
                [PartitionProduceData::default().index(0).records(None)],
            ),
            topic(
                "b",
                [PartitionProduceData::default().index(0).records(None)],
            ),
        ],
    )?;
    let limits = DecodeLimits {
        max_sequence_elements: 1,
        ..DecodeLimits::default()
    };
    assert!(matches!(
        BorrowedProduceRequest::from_bytes_with_limits(encoded, limits),
        Err(Error::DecodeLimitExceeded {
            kind: DecodeLimit::SequenceElements,
            limit: 1,
            actual: 2,
        })
    ));

    let encoded = encoded_request(
        8,
        [topic(
            "events",
            [PartitionProduceData::default().index(0).records(None)],
        )],
    )?;
    let limits = DecodeLimits {
        max_nesting_depth: 4,
        ..DecodeLimits::default()
    };
    assert!(matches!(
        BorrowedProduceRequest::from_bytes_with_limits(encoded.clone(), limits),
        Err(Error::DecodeLimitExceeded {
            kind: DecodeLimit::NestingDepth,
            limit: 4,
            actual: 5,
        })
    ));
    let limits = DecodeLimits {
        max_nesting_depth: 5,
        ..DecodeLimits::default()
    };
    let _ = BorrowedProduceRequest::from_bytes_with_limits(encoded, limits)?;
    Ok(())
}

#[test]
fn corrupt_record_batch_is_rejected_during_initial_request_validation() -> tansu_sans_io::Result<()>
{
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
    let topic = request.topic_data().next().expect("topic")?;
    let partition = topic.partition_data().next().expect("partition")?;
    let records = partition.records()?.expect("records");
    let batch = records.batches().next().expect("batch");
    let batch_offset = batch.as_bytes().as_ptr() as usize - encoded.as_ptr() as usize;
    let last_batch_byte = batch_offset + batch.as_bytes().len() - 1;

    let mut corrupt = BytesMut::from(&encoded[..]);
    corrupt[last_batch_byte] ^= 1;
    let error = BorrowedProduceRequest::from_bytes(corrupt.freeze()).expect_err("CRC mismatch");
    assert!(error.to_string().contains("CRC mismatch"));
    Ok(())
}
