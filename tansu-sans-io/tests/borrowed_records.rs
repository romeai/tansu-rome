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

use std::io::Cursor;

use bytes::{BufMut as _, Bytes, BytesMut};
use tansu_sans_io::{
    BatchAttribute, Compression, Encode as _,
    record::{
        Header, Record, borrowed::RecordDecodeError, borrowed::RecordDecodeLimit,
        borrowed::RecordDecodeLimits, borrowed::RecordSet, borrowed::ValueRecords, deflated,
        inflated,
    },
};

fn source_records() -> tansu_sans_io::Result<Vec<Record>> {
    let mut first = Record::builder()
        .attributes(7)
        .timestamp_delta(-3)
        .offset_delta(4)
        .key(Some(Bytes::new()))
        .value(Some(Bytes::from_static(b"frame-backed-value")))
        .build()?;
    set_headers(
        &mut first,
        vec![
            Header {
                key: Some(Bytes::from_static(b"format")),
                value: None,
            },
            Header {
                key: Some(Bytes::new()),
                value: Some(Bytes::new()),
            },
        ],
    )?;

    Ok(vec![
        first,
        Record::builder()
            .offset_delta(5)
            .key(None)
            .value(Some(Bytes::new()))
            .build()?,
    ])
}

#[test]
fn failed_borrowed_decode_exposes_exact_immutable_progress()
-> Result<(), Box<dyn std::error::Error>> {
    let record = Record::builder()
        .value(Some(Bytes::from_static(b"too-large")))
        .build()?;
    let encoded = Bytes::from(batch_from_records(Compression::None, vec![record])?);
    let set = RecordSet::from_bytes(&encoded)?;
    let batch = set.batches().next().expect("batch");
    let limits = RecordDecodeLimits {
        max_value_bytes: 4,
        ..RecordDecodeLimits::default()
    };
    let mut records = batch.records_with_limits(limits)?;

    assert!(matches!(
        records.next_record(),
        Err(RecordDecodeError::LimitExceeded {
            kind: RecordDecodeLimit::ValueBytes,
            limit: 4,
            actual: 9,
        })
    ));
    assert_eq!(batch.record_data().len(), records.progress().decoded_bytes);
    assert_eq!(1, records.progress().records_begun);
    assert_eq!(0, records.progress().records_emitted);
    assert_eq!(0, records.progress().headers_declared);
    let progress = records.progress();
    assert_eq!(progress, records.progress());
    assert_eq!(
        records.next_record().expect_err("sticky first error"),
        RecordDecodeError::LimitExceeded {
            kind: RecordDecodeLimit::ValueBytes,
            limit: 4,
            actual: 9,
        }
    );
    assert_eq!(progress, records.progress());
    Ok(())
}

fn set_headers(record: &mut Record, headers: Vec<Header>) -> tansu_sans_io::Result<()> {
    record.headers = headers;
    record.length = 0;
    record.length = i32::try_from(record.encode()?.len() - size_of::<u8>())?;
    Ok(())
}

fn batch_from_records(
    compression: Compression,
    records: Vec<Record>,
) -> tansu_sans_io::Result<deflated::Batch> {
    inflated::Batch {
        base_offset: 0,
        partition_leader_epoch: -1,
        magic: 2,
        attributes: BatchAttribute::default().compression(compression).into(),
        last_offset_delta: i32::try_from(records.len())? - 1,
        base_timestamp: 1_726_000_000_000,
        max_timestamp: 1_726_000_000_001,
        producer_id: -1,
        producer_epoch: -1,
        base_sequence: -1,
        records,
        ..Default::default()
    }
    .try_into()
}

fn replace_record_data(
    batch: &mut deflated::Batch,
    record_count: i32,
    record_data: Bytes,
) -> tansu_sans_io::Result<()> {
    let fixed_body_bytes = usize::try_from(batch.batch_length)?
        .checked_sub(batch.record_data.len())
        .expect("a deflated test batch has its fixed header");
    batch.batch_length = i32::try_from(fixed_body_bytes + record_data.len())?;
    batch.record_count = u32::try_from(record_count)?;
    batch.record_data = record_data;

    let mut crc_data = BytesMut::new();
    crc_data.put_i16(batch.attributes);
    crc_data.put_i32(batch.last_offset_delta);
    crc_data.put_i64(batch.base_timestamp);
    crc_data.put_i64(batch.max_timestamp);
    crc_data.put_i64(batch.producer_id);
    crc_data.put_i16(batch.producer_epoch);
    crc_data.put_i32(batch.base_sequence);
    crc_data.put_i32(record_count);
    crc_data.extend_from_slice(&batch.record_data);
    let mut digest = crc_fast::Digest::new(crc_fast::CrcAlgorithm::Crc32Iscsi);
    digest.update(&crc_data);
    batch.crc = digest.finalize() as u32;
    Ok(())
}

fn encoded_batch_with_data(record_count: i32, record_data: Bytes) -> tansu_sans_io::Result<Bytes> {
    let mut batch = batch_from_records(Compression::None, vec![])?;
    replace_record_data(&mut batch, record_count, record_data)?;
    Ok(batch.into())
}

fn parity_limits(record_data_bytes: usize) -> RecordDecodeLimits {
    RecordDecodeLimits {
        max_record_bytes: record_data_bytes,
        max_decoded_bytes: record_data_bytes,
        max_records: 4,
        max_key_bytes: record_data_bytes,
        max_value_bytes: record_data_bytes,
        max_header_key_bytes: record_data_bytes,
        max_header_value_bytes: record_data_bytes,
        max_headers: 4,
        max_work_units: 1_000,
    }
}

fn assert_adapter_error_parity(
    record_data: Bytes,
    record_count: i32,
    limits: RecordDecodeLimits,
    expected: RecordDecodeError,
) -> Result<(), Box<dyn std::error::Error>> {
    let encoded = encoded_batch_with_data(record_count, record_data.clone())?;
    let set = RecordSet::from_bytes(&encoded)?;
    let batch = set.batches().next().expect("batch");
    let mut borrowed = batch.records_with_limits(limits)?;
    assert_eq!(
        expected,
        borrowed.next_record().expect_err("borrowed adapter error")
    );

    let mut scratch = vec![0u8; limits.max_value_bytes];
    let mut transfer = [0u8; 32];
    let mut streaming = ValueRecords::new(
        Cursor::new(record_data),
        &mut scratch,
        &mut transfer,
        record_count,
        limits,
    )?;
    assert_eq!(
        expected,
        streaming.next_value().expect_err("streaming adapter error")
    );
    Ok(())
}

#[test]
fn borrowed_and_streaming_adapters_share_exact_grammar_errors()
-> Result<(), Box<dyn std::error::Error>> {
    let zero_body = Bytes::from_static(b"\x00");
    assert_adapter_error_parity(
        zero_body.clone(),
        1,
        parity_limits(zero_body.len()),
        RecordDecodeError::Truncated("record attributes"),
    )?;

    let oversized_key = Bytes::from_static(b"\x08\x00\x00\x00\x14");
    let mut oversized_key_limits = parity_limits(oversized_key.len());
    oversized_key_limits.max_key_bytes = 10;
    assert_adapter_error_parity(
        oversized_key.clone(),
        1,
        oversized_key_limits,
        RecordDecodeError::Truncated("key"),
    )?;

    let record = Record::builder()
        .value(Some(Bytes::from_static(b"too-large")))
        .build()?;
    let record_data = (&[record][..]).encode()?;
    let mut value_limits = parity_limits(record_data.len());
    value_limits.max_value_bytes = 4;
    assert_adapter_error_parity(
        record_data.clone(),
        1,
        value_limits,
        RecordDecodeError::LimitExceeded {
            kind: RecordDecodeLimit::ValueBytes,
            limit: 4,
            actual: 9,
        },
    )?;

    let declared_body = record_data.len() - 1;
    let mut record_limits = parity_limits(record_data.len());
    record_limits.max_record_bytes = declared_body - 1;
    assert_adapter_error_parity(
        record_data,
        1,
        record_limits,
        RecordDecodeError::LimitExceeded {
            kind: RecordDecodeLimit::RecordBytes,
            limit: declared_body - 1,
            actual: declared_body,
        },
    )?;
    Ok(())
}

#[test]
fn borrowed_and_streaming_adapters_charge_empty_fields_consistently()
-> Result<(), Box<dyn std::error::Error>> {
    let mut record = Record::builder()
        .key(Some(Bytes::new()))
        .value(Some(Bytes::new()))
        .build()?;
    set_headers(
        &mut record,
        vec![Header {
            key: Some(Bytes::new()),
            value: Some(Bytes::new()),
        }],
    )?;
    let record_data = (&[record][..]).encode()?;
    let limits = parity_limits(record_data.len());
    let encoded = encoded_batch_with_data(1, record_data.clone())?;
    let set = RecordSet::from_bytes(&encoded)?;
    let batch = set.batches().next().expect("batch");
    let mut borrowed = batch.records_with_limits(limits)?;
    let _ = borrowed.next_record()?.expect("borrowed record");
    assert!(borrowed.next_record()?.is_none());
    let borrowed_progress = borrowed.finish()?;

    let mut scratch = vec![0u8; limits.max_value_bytes];
    let mut transfer = [0u8; 3];
    let mut streaming = ValueRecords::new(
        Cursor::new(record_data),
        &mut scratch,
        &mut transfer,
        1,
        limits,
    )?;
    let _ = streaming.next_value()?.expect("streamed value");
    assert!(streaming.next_value()?.is_none());
    let (_, streaming_progress) = streaming.finish()?;

    assert_eq!(borrowed_progress, streaming_progress);
    Ok(())
}

#[test]
fn lends_scalars_null_empty_values_headers_and_frame_storage()
-> Result<(), Box<dyn std::error::Error>> {
    let records = source_records()?;
    let encoded = Bytes::from(batch_from_records(Compression::None, records)?);
    let set = RecordSet::from_bytes(&encoded)?;
    let batch = set.batches().next().expect("batch");
    let frame_start = encoded.as_ptr() as usize;
    let frame_end = frame_start + encoded.len();
    let mut stream = batch.records()?;

    {
        let first = stream.next_record()?.expect("first record");
        assert_eq!(7, first.attributes());
        assert_eq!(-3, first.timestamp_delta());
        assert_eq!(4, first.offset_delta());
        assert_eq!(Some(&b""[..]), first.key());
        assert_eq!(Some(&b"frame-backed-value"[..]), first.value());
        assert!((frame_start..frame_end).contains(&(first.as_bytes().as_ptr() as usize)));
        assert!(
            (frame_start..frame_end).contains(&(first.value().expect("value").as_ptr() as usize))
        );

        let mut headers = first.headers();
        let first_header = headers.next().expect("first header")?;
        assert_eq!(&b"format"[..], first_header.key());
        assert_eq!(None, first_header.value());
        let second_header = headers.next().expect("second header")?;
        assert_eq!(&b""[..], second_header.key());
        assert_eq!(Some(&b""[..]), second_header.value());
        assert!(headers.next().is_none());
    }

    {
        let second = stream.next_record()?.expect("second record");
        assert_eq!(None, second.key());
        assert_eq!(Some(&b""[..]), second.value());
        assert_eq!(5, second.offset_delta());
        assert_eq!(0, second.headers().len());
    }

    assert!(stream.next_record()?.is_none());
    assert_eq!(2, stream.emitted_count());
    let _ = stream.finish()?;
    Ok(())
}

#[test]
fn null_and_empty_record_values_are_distinct() -> Result<(), Box<dyn std::error::Error>> {
    let records = vec![
        Record::builder().value(None).build()?,
        Record::builder().value(Some(Bytes::new())).build()?,
    ];
    let encoded = Bytes::from(batch_from_records(Compression::None, records)?);
    let set = RecordSet::from_bytes(&encoded)?;
    let batch = set.batches().next().expect("batch");
    let mut stream = batch.records()?;
    {
        let null = stream.next_record()?.expect("null value record");
        assert_eq!(None, null.value());
    }
    {
        let empty = stream.next_record()?.expect("empty value record");
        assert_eq!(Some(&b""[..]), empty.value());
    }
    assert!(stream.next_record()?.is_none());
    let _ = stream.finish()?;
    Ok(())
}

#[test]
fn finish_and_full_exhaustion_detect_count_and_trailing_mismatches()
-> Result<(), Box<dyn std::error::Error>> {
    let records = source_records()?;
    let record_data = records.as_slice().encode()?;

    let encoded = encoded_batch_with_data(2, record_data.clone())?;
    let set = RecordSet::from_bytes(&encoded)?;
    let batch = set.batches().next().expect("batch");
    let mut early = batch.records()?;
    let _ = early.next_record()?.expect("first");
    let failure = early.finish().expect_err("early finish");
    assert!(matches!(
        failure.error(),
        RecordDecodeError::RecordCountMismatch {
            declared: 2,
            actual: 1,
        }
    ));
    assert_eq!(1, failure.progress().records_emitted);

    let encoded = encoded_batch_with_data(1, record_data.clone())?;
    let set = RecordSet::from_bytes(&encoded)?;
    let batch = set.batches().next().expect("batch");
    let mut trailing = batch.records()?;
    let _ = trailing.next_record()?.expect("declared record");
    assert!(matches!(
        trailing.next_record(),
        Err(RecordDecodeError::TrailingBytes(actual)) if actual > 0
    ));

    let encoded = encoded_batch_with_data(3, record_data)?;
    let set = RecordSet::from_bytes(&encoded)?;
    let batch = set.batches().next().expect("batch");
    let mut missing = batch.records()?;
    let _ = missing.next_record()?.expect("first");
    let _ = missing.next_record()?.expect("second");
    assert!(matches!(
        missing.next_record(),
        Err(RecordDecodeError::RecordCountMismatch {
            declared: 3,
            actual: 2,
        })
    ));
    Ok(())
}

#[test]
fn malformed_negative_overflow_and_truncated_varints_are_typed()
-> Result<(), Box<dyn std::error::Error>> {
    for (data, expected) in [
        (
            Bytes::from_static(b"\x01"),
            "invalid negative record length -1",
        ),
        (Bytes::from_static(b"\x80"), "truncated record length"),
        (
            Bytes::from_static(b"\x80\x80\x80\x80\x10"),
            "invalid record length varint",
        ),
        (Bytes::from_static(b"\x14\x00"), "truncated record body"),
    ] {
        let encoded = encoded_batch_with_data(1, data)?;
        let set = RecordSet::from_bytes(&encoded)?;
        let batch = set.batches().next().expect("batch");
        let mut stream = batch.records()?;
        let error = stream.next_record().expect_err("malformed record");
        assert_eq!(expected, error.to_string());
    }
    Ok(())
}

#[test]
fn malformed_varlong_negative_headers_and_record_trailing_data_fail()
-> Result<(), Box<dyn std::error::Error>> {
    let mut bad_varlong_body = BytesMut::new();
    bad_varlong_body.put_u8(0);
    bad_varlong_body.extend_from_slice(&[0x80; 9]);
    bad_varlong_body.put_u8(0x02);
    let mut bad_varlong = BytesMut::new();
    bad_varlong.put_u8(u8::try_from(bad_varlong_body.len() * 2)?);
    bad_varlong.extend_from_slice(&bad_varlong_body);
    let encoded = encoded_batch_with_data(1, bad_varlong.freeze())?;
    let set = RecordSet::from_bytes(&encoded)?;
    let batch = set.batches().next().expect("batch");
    assert!(matches!(
        batch.records()?.next_record(),
        Err(RecordDecodeError::InvalidVarint {
            field: "timestamp delta"
        })
    ));

    let encoded = encoded_batch_with_data(1, Bytes::from_static(b"\x0c\x00\x00\x00\x01\x01\x01"))?;
    let set = RecordSet::from_bytes(&encoded)?;
    let batch = set.batches().next().expect("batch");
    assert!(matches!(
        batch.records()?.next_record(),
        Err(RecordDecodeError::NegativeLength {
            field: "header count",
            actual: -1,
        })
    ));

    let encoded = encoded_batch_with_data(
        1,
        Bytes::from_static(b"\x10\x00\x00\x00\x01\x01\x02\x01\x01"),
    )?;
    let set = RecordSet::from_bytes(&encoded)?;
    let batch = set.batches().next().expect("batch");
    assert!(matches!(
        batch.records()?.next_record(),
        Err(RecordDecodeError::NegativeLength {
            field: "header key",
            actual: -1,
        })
    ));

    let mut valid = BytesMut::from(&(&source_records()?[..1]).encode()?[..]);
    valid[0] = valid[0].checked_add(2).expect("small record length");
    let mut with_trailing_body = BytesMut::from(&valid[..]);
    with_trailing_body.put_u8(0);
    let encoded = encoded_batch_with_data(1, with_trailing_body.freeze())?;
    let set = RecordSet::from_bytes(&encoded)?;
    let batch = set.batches().next().expect("batch");
    assert!(matches!(
        batch.records()?.next_record(),
        Err(RecordDecodeError::RecordLengthMismatch { .. })
    ));
    Ok(())
}

#[test]
fn cumulative_record_decoded_header_and_work_limits_are_enforced()
-> Result<(), Box<dyn std::error::Error>> {
    let records = source_records()?;
    let encoded = Bytes::from(batch_from_records(Compression::None, records)?);
    let set = RecordSet::from_bytes(&encoded)?;
    let batch = set.batches().next().expect("batch");

    let invalid = RecordDecodeLimits {
        max_record_bytes: 2,
        max_decoded_bytes: 1,
        ..RecordDecodeLimits::default()
    };
    assert!(matches!(
        batch.records_with_limits(invalid),
        Err(RecordDecodeError::InvalidLimits(
            "max_record_bytes must not exceed max_decoded_bytes"
        ))
    ));

    for (limits, expected) in [
        (
            RecordDecodeLimits {
                max_decoded_bytes: batch.record_data().len() - 1,
                max_record_bytes: batch.record_data().len() - 1,
                ..RecordDecodeLimits::default()
            },
            RecordDecodeLimit::DecodedBytes,
        ),
        (
            RecordDecodeLimits {
                max_records: 1,
                ..RecordDecodeLimits::default()
            },
            RecordDecodeLimit::Records,
        ),
    ] {
        assert!(matches!(
            batch.records_with_limits(limits),
            Err(RecordDecodeError::LimitExceeded { kind, .. }) if kind == expected
        ));
    }

    let limits = RecordDecodeLimits {
        max_headers: 1,
        ..RecordDecodeLimits::default()
    };
    assert!(matches!(
        batch.records_with_limits(limits)?.next_record(),
        Err(RecordDecodeError::LimitExceeded {
            kind: RecordDecodeLimit::Headers,
            limit: 1,
            actual: 2,
        })
    ));

    let limits = RecordDecodeLimits {
        max_record_bytes: 1,
        ..RecordDecodeLimits::default()
    };
    assert!(matches!(
        batch.records_with_limits(limits)?.next_record(),
        Err(RecordDecodeError::LimitExceeded {
            kind: RecordDecodeLimit::RecordBytes,
            ..
        })
    ));

    let limits = RecordDecodeLimits {
        max_work_units: 1,
        ..RecordDecodeLimits::default()
    };
    assert!(matches!(
        batch.records_with_limits(limits)?.next_record(),
        Err(RecordDecodeError::LimitExceeded {
            kind: RecordDecodeLimit::WorkUnits,
            ..
        })
    ));
    Ok(())
}

#[test]
fn key_value_and_header_field_limits_are_independent() -> Result<(), Box<dyn std::error::Error>> {
    let records = source_records()?;
    let encoded = Bytes::from(batch_from_records(Compression::None, records)?);
    let set = RecordSet::from_bytes(&encoded)?;
    let batch = set.batches().next().expect("batch");

    for (limits, expected) in [
        (
            RecordDecodeLimits {
                max_key_bytes: 0,
                ..RecordDecodeLimits::default()
            },
            None,
        ),
        (
            RecordDecodeLimits {
                max_value_bytes: 8,
                ..RecordDecodeLimits::default()
            },
            Some(RecordDecodeLimit::ValueBytes),
        ),
        (
            RecordDecodeLimits {
                max_header_key_bytes: 3,
                ..RecordDecodeLimits::default()
            },
            Some(RecordDecodeLimit::HeaderKeyBytes),
        ),
    ] {
        let mut stream = batch.records_with_limits(limits)?;
        let result = stream.next_record();
        if let Some(expected) = expected {
            assert!(matches!(
                result,
                Err(RecordDecodeError::LimitExceeded { kind, .. }) if kind == expected
            ));
        } else {
            assert!(result.is_ok(), "an empty key fits a zero-byte key limit");
        }
    }

    let mut record = source_records()?.remove(0);
    record.headers[0].value = Some(Bytes::from_static(b"header-value"));
    let headers = std::mem::take(&mut record.headers);
    set_headers(&mut record, headers)?;
    let encoded = Bytes::from(batch_from_records(Compression::None, vec![record])?);
    let set = RecordSet::from_bytes(&encoded)?;
    let batch = set.batches().next().expect("batch");
    let limits = RecordDecodeLimits {
        max_header_value_bytes: 4,
        ..RecordDecodeLimits::default()
    };
    assert!(matches!(
        batch.records_with_limits(limits)?.next_record(),
        Err(RecordDecodeError::LimitExceeded {
            kind: RecordDecodeLimit::HeaderValueBytes,
            ..
        })
    ));

    let record = Record::builder()
        .key(Some(Bytes::from_static(b"nonempty-key")))
        .value(None)
        .build()?;
    let encoded = Bytes::from(batch_from_records(Compression::None, vec![record])?);
    let set = RecordSet::from_bytes(&encoded)?;
    let batch = set.batches().next().expect("batch");
    let limits = RecordDecodeLimits {
        max_key_bytes: 0,
        ..RecordDecodeLimits::default()
    };
    assert!(matches!(
        batch.records_with_limits(limits)?.next_record(),
        Err(RecordDecodeError::LimitExceeded {
            kind: RecordDecodeLimit::KeyBytes,
            ..
        })
    ));
    Ok(())
}

#[test]
fn header_limit_is_cumulative_across_records() -> Result<(), Box<dyn std::error::Error>> {
    let mut records = vec![
        Record::builder().offset_delta(0).build()?,
        Record::builder().offset_delta(1).build()?,
    ];
    for record in &mut records {
        set_headers(
            record,
            vec![Header {
                key: Some(Bytes::new()),
                value: None,
            }],
        )?;
    }
    let encoded = Bytes::from(batch_from_records(Compression::None, records)?);
    let set = RecordSet::from_bytes(&encoded)?;
    let batch = set.batches().next().expect("batch");
    let limits = RecordDecodeLimits {
        max_headers: 1,
        ..RecordDecodeLimits::default()
    };
    let mut stream = batch.records_with_limits(limits)?;
    {
        let first = stream.next_record()?.expect("first record");
        assert_eq!(1, first.headers().len());
    }
    assert!(matches!(
        stream.next_record(),
        Err(RecordDecodeError::LimitExceeded {
            kind: RecordDecodeLimit::Headers,
            limit: 1,
            actual: 2,
        })
    ));
    Ok(())
}

#[test]
fn compressed_batches_are_explicitly_unsupported_in_c1() -> Result<(), Box<dyn std::error::Error>> {
    let encoded = Bytes::from(batch_from_records(Compression::Gzip, source_records()?)?);
    let set = RecordSet::from_bytes(&encoded)?;
    let batch = set.batches().next().expect("batch");
    assert!(matches!(
        batch.records(),
        Err(RecordDecodeError::UnsupportedCompression(_))
    ));
    Ok(())
}
