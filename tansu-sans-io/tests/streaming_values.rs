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

use std::{
    cell::{Cell, RefCell},
    io::{self, Cursor, Read},
    rc::Rc,
};

use bytes::{Bytes, BytesMut};
use tansu_sans_io::{
    Encode as _,
    record::{
        Header, Record,
        borrowed::{
            RecordDecodeError, RecordDecodeLimit, RecordDecodeLimits, RecordDecodeProgress,
            ValueRecords, ValueRef,
        },
    },
};

fn limits(stream_bytes: usize, max_value_bytes: usize) -> RecordDecodeLimits {
    RecordDecodeLimits {
        max_record_bytes: stream_bytes,
        max_decoded_bytes: stream_bytes,
        max_records: 32,
        max_key_bytes: stream_bytes,
        max_value_bytes,
        max_header_key_bytes: stream_bytes,
        max_header_value_bytes: stream_bytes,
        max_headers: 32,
        max_work_units: 10_000,
    }
}

fn set_headers(record: &mut Record, headers: Vec<Header>) -> tansu_sans_io::Result<()> {
    record.headers = headers;
    record.length = 0;
    record.length = i32::try_from(record.encode()?.len() - size_of::<u8>())?;
    Ok(())
}

#[derive(Debug)]
struct ShortReader<R> {
    inner: R,
    max_read: usize,
}

impl<R> Read for ShortReader<R>
where
    R: Read,
{
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let allowed = output.len().min(self.max_read);
        self.inner.read(&mut output[..allowed])
    }
}

#[derive(Debug)]
struct ErrorReader<R> {
    inner: R,
    bytes_before_error: usize,
}

impl<R> Read for ErrorReader<R>
where
    R: Read,
{
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.bytes_before_error == 0 {
            return Err(io::Error::new(io::ErrorKind::ConnectionReset, "injected"));
        }
        let allowed = output.len().min(self.bytes_before_error);
        let read = self.inner.read(&mut output[..allowed])?;
        self.bytes_before_error -= read;
        Ok(read)
    }
}

#[derive(Debug)]
struct BudgetRecordingReader<R> {
    inner: R,
    decoded_limit: usize,
    returned: usize,
    largest_requested: Rc<Cell<usize>>,
    largest_excess: Rc<Cell<usize>>,
}

impl<R> Read for BudgetRecordingReader<R>
where
    R: Read,
{
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.largest_requested
            .set(self.largest_requested.get().max(output.len()));
        let permitted = self
            .decoded_limit
            .saturating_sub(self.returned)
            .saturating_add(1)
            .max(1);
        self.largest_excess.set(
            self.largest_excess
                .get()
                .max(output.len().saturating_sub(permitted)),
        );
        let read = self.inner.read(output)?;
        self.returned += read;
        Ok(read)
    }
}

#[derive(Debug)]
struct InterruptedOnce<R> {
    inner: R,
    interrupted: bool,
}

#[derive(Debug)]
struct PointerRecordingReader<R> {
    inner: R,
    bulk_output_addresses: Rc<RefCell<Vec<usize>>>,
}

impl<R> Read for PointerRecordingReader<R>
where
    R: Read,
{
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.len() > 1 {
            self.bulk_output_addresses
                .borrow_mut()
                .push(output.as_ptr() as usize);
        }
        self.inner.read(output)
    }
}

impl<R> Read for InterruptedOnce<R>
where
    R: Read,
{
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        self.inner.read(output)
    }
}

#[test]
fn lends_null_empty_and_present_values_while_streaming_other_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let mut present = Record::builder()
        .key(Some(Bytes::from_static(b"ignored-key")))
        .value(Some(Bytes::from_static(b"selected")))
        .build()?;
    set_headers(
        &mut present,
        vec![Header {
            key: Some(Bytes::from_static(b"ignored-header")),
            value: Some(Bytes::from_static(b"ignored-value")),
        }],
    )?;
    let records = vec![
        Record::builder().value(None).build()?,
        Record::builder().value(Some(Bytes::new())).build()?,
        present,
    ];
    let encoded = records.as_slice().encode()?;
    let mut scratch = [0u8; 16];
    let mut transfer = [0u8; 32];
    let scratch_start = scratch.as_ptr() as usize;
    let scratch_end = scratch_start + scratch.len();
    let mut values = ValueRecords::new(
        Cursor::new(encoded.clone()),
        &mut scratch,
        &mut transfer,
        3,
        limits(encoded.len(), 16),
    )?;

    assert_eq!(Some(ValueRef::Null), values.next_value()?);
    assert_eq!(Some(ValueRef::Bytes(&b""[..])), values.next_value()?);
    {
        let value = values.next_value()?.expect("present value");
        assert_eq!(Some(&b"selected"[..]), value.as_option());
        let pointer = value.as_option().expect("bytes").as_ptr() as usize;
        assert!((scratch_start..scratch_end).contains(&pointer));
    }
    assert_eq!(None, values.next_value()?);
    assert_eq!(
        RecordDecodeProgress {
            decoded_bytes: encoded.len(),
            records_begun: 3,
            records_emitted: 3,
            headers_declared: 1,
            work_units: values.progress().work_units,
        },
        values.progress()
    );
    let _ = values.finish()?;
    Ok(())
}

#[test]
fn arbitrary_short_reads_do_not_change_the_wire_grammar() -> Result<(), Box<dyn std::error::Error>>
{
    let record = Record::builder()
        .key(Some(Bytes::from(vec![7; 20_000])))
        .value(Some(Bytes::from_static(b"kept")))
        .build()?;
    let encoded = (&[record][..]).encode()?;
    let reader = ShortReader {
        inner: Cursor::new(encoded.clone()),
        max_read: 3,
    };
    let mut scratch = [0u8; 4];
    let mut transfer = [0u8; 32];
    let mut values = ValueRecords::new(
        reader,
        &mut scratch,
        &mut transfer,
        1,
        limits(encoded.len(), 4),
    )?;
    assert_eq!(Some(ValueRef::Bytes(&b"kept"[..])), values.next_value()?);
    assert_eq!(None, values.next_value()?);
    let _ = values.finish()?;
    Ok(())
}

#[test]
fn caller_transfer_scratch_is_reused_across_fields_records_and_eof()
-> Result<(), Box<dyn std::error::Error>> {
    let mut records = vec![
        Record::builder()
            .key(Some(Bytes::from(vec![1; 20])))
            .value(None)
            .build()?,
        Record::builder()
            .key(Some(Bytes::from(vec![2; 20])))
            .value(None)
            .build()?,
    ];
    for record in &mut records {
        set_headers(
            record,
            vec![Header {
                key: Some(Bytes::from(vec![3; 10])),
                value: Some(Bytes::from(vec![4; 12])),
            }],
        )?;
    }
    let encoded = records.as_slice().encode()?;
    let addresses = Rc::new(RefCell::new(Vec::new()));
    let reader = PointerRecordingReader {
        inner: Cursor::new(encoded.clone()),
        bulk_output_addresses: Rc::clone(&addresses),
    };
    let mut scratch = [];
    let mut transfer = [0u8; 7];
    let transfer_address = transfer.as_ptr() as usize;
    let mut values = ValueRecords::new(
        reader,
        &mut scratch,
        &mut transfer,
        2,
        limits(encoded.len(), 0),
    )?;
    assert_eq!(Some(ValueRef::Null), values.next_value()?);
    assert_eq!(Some(ValueRef::Null), values.next_value()?);
    assert_eq!(None, values.next_value()?);
    let _ = values.finish()?;

    let addresses = addresses.borrow();
    assert!(
        addresses.len() > 6,
        "multiple transfer chunks were observed"
    );
    assert!(
        addresses.iter().all(|address| *address == transfer_address),
        "every bulk skip and EOF read reused the caller's one transfer buffer"
    );
    Ok(())
}

#[test]
fn interrupted_reads_are_retried_without_losing_progress() -> Result<(), Box<dyn std::error::Error>>
{
    let record = Record::builder()
        .value(Some(Bytes::from_static(b"after-interrupt")))
        .build()?;
    let encoded = (&[record][..]).encode()?;
    let reader = InterruptedOnce {
        inner: Cursor::new(encoded.clone()),
        interrupted: false,
    };
    let mut scratch = [0u8; 16];
    let mut transfer = [0u8; 32];
    let mut values = ValueRecords::new(
        reader,
        &mut scratch,
        &mut transfer,
        1,
        limits(encoded.len(), 16),
    )?;
    assert_eq!(
        Some(ValueRef::Bytes(&b"after-interrupt"[..])),
        values.next_value()?
    );
    assert_eq!(None, values.next_value()?);
    assert_eq!(encoded.len(), values.progress().decoded_bytes);
    assert!(values.progress().work_units > 0);
    Ok(())
}

#[test]
fn zero_count_and_invalid_declared_counts_are_exact() -> Result<(), Box<dyn std::error::Error>> {
    let mut scratch = [];
    let mut transfer = [0u8; 32];
    let mut empty = ValueRecords::new(
        Cursor::new(Bytes::new()),
        &mut scratch,
        &mut transfer,
        0,
        limits(0, 0),
    )?;
    assert_eq!(None, empty.next_value()?);
    let (_, progress) = empty.finish()?;
    assert_eq!(
        RecordDecodeProgress {
            work_units: 1,
            ..RecordDecodeProgress::default()
        },
        progress
    );

    let mut scratch = [];
    let mut transfer = [0u8; 32];
    let mut trailing = ValueRecords::new(
        Cursor::new(Bytes::from_static(b"x")),
        &mut scratch,
        &mut transfer,
        0,
        limits(1, 0),
    )?;
    assert_eq!(
        RecordDecodeError::TrailingBytes(1),
        trailing.next_value().expect_err("zero-count trailing byte")
    );
    assert_eq!(1, trailing.progress().decoded_bytes);

    let mut scratch = [];
    let mut transfer = [0u8; 32];
    assert!(matches!(
        ValueRecords::new(
            Cursor::new(Bytes::new()),
            &mut scratch,
            &mut transfer,
            -1,
            limits(0, 0),
        ),
        Err(RecordDecodeError::NegativeLength {
            field: "record count",
            actual: -1,
        })
    ));

    let mut scratch = [];
    let mut transfer = [0u8; 32];
    let mut count_limits = limits(0, 0);
    count_limits.max_records = 1;
    assert!(matches!(
        ValueRecords::new(
            Cursor::new(Bytes::new()),
            &mut scratch,
            &mut transfer,
            2,
            count_limits,
        ),
        Err(RecordDecodeError::LimitExceeded {
            kind: RecordDecodeLimit::Records,
            limit: 1,
            actual: 2,
        })
    ));
    Ok(())
}

#[test]
fn reader_errors_are_typed_sticky_and_preserve_exact_progress()
-> Result<(), Box<dyn std::error::Error>> {
    let record = Record::builder()
        .value(Some(Bytes::from_static(b"reader-failure")))
        .build()?;
    let encoded = (&[record][..]).encode()?;
    let reader = ErrorReader {
        inner: Cursor::new(encoded.clone()),
        bytes_before_error: 6,
    };
    let mut scratch = [0u8; 32];
    let mut transfer = [0u8; 32];
    let mut values = ValueRecords::new(
        reader,
        &mut scratch,
        &mut transfer,
        1,
        limits(encoded.len(), 32),
    )?;
    let expected = RecordDecodeError::ReaderIo {
        field: "value",
        kind: io::ErrorKind::ConnectionReset,
    };
    assert_eq!(
        expected,
        values.next_value().expect_err("injected reader error")
    );
    assert_eq!(
        RecordDecodeProgress {
            decoded_bytes: 6,
            records_begun: 1,
            records_emitted: 0,
            headers_declared: 0,
            work_units: 8,
        },
        values.progress()
    );
    assert_eq!(
        expected,
        values.next_value().expect_err("sticky first error")
    );
    assert_eq!(6, values.progress().decoded_bytes);
    Ok(())
}

#[test]
fn scratch_and_field_bombs_fail_at_the_configured_boundaries()
-> Result<(), Box<dyn std::error::Error>> {
    let record = Record::builder()
        .key(Some(Bytes::from_static(b"key")))
        .value(Some(Bytes::from_static(b"12345678")))
        .build()?;
    let encoded = (&[record][..]).encode()?;
    let exact_limits = limits(encoded.len(), 8);
    let mut too_small = [0u8; 7];
    let mut transfer = [0u8; 32];
    assert!(matches!(
        ValueRecords::new(
            Cursor::new(encoded.clone()),
            &mut too_small,
            &mut transfer,
            1,
            exact_limits
        ),
        Err(RecordDecodeError::ScratchTooSmall {
            required: 8,
            actual: 7,
        })
    ));

    let mut exact = [0u8; 8];
    let mut empty_transfer = [];
    assert!(matches!(
        ValueRecords::new(
            Cursor::new(encoded.clone()),
            &mut exact,
            &mut empty_transfer,
            1,
            exact_limits,
        ),
        Err(RecordDecodeError::TransferScratchEmpty)
    ));

    let mut exact = [0u8; 8];
    let mut transfer = [0u8; 32];
    let mut values = ValueRecords::new(
        Cursor::new(encoded.clone()),
        &mut exact,
        &mut transfer,
        1,
        exact_limits,
    )?;
    assert_eq!(
        Some(ValueRef::Bytes(&b"12345678"[..])),
        values.next_value()?
    );
    assert_eq!(None, values.next_value()?);

    let mut limited = [0u8; 7];
    let mut transfer = [0u8; 32];
    let mut values = ValueRecords::new(
        Cursor::new(encoded.clone()),
        &mut limited,
        &mut transfer,
        1,
        limits(encoded.len(), 7),
    )?;
    assert!(matches!(
        values.next_value(),
        Err(RecordDecodeError::LimitExceeded {
            kind: RecordDecodeLimit::ValueBytes,
            limit: 7,
            actual: 8,
        })
    ));
    assert_eq!(1, values.progress().records_begun);
    assert_eq!(0, values.progress().records_emitted);

    let mut decoded_limited = limits(encoded.len(), 8);
    decoded_limited.max_decoded_bytes -= 1;
    decoded_limited.max_record_bytes = decoded_limited.max_decoded_bytes;
    let mut scratch = [0u8; 8];
    let mut transfer = [0u8; 32];
    let mut values = ValueRecords::new(
        Cursor::new(encoded),
        &mut scratch,
        &mut transfer,
        1,
        decoded_limited,
    )?;
    assert!(matches!(
        values.next_value(),
        Err(RecordDecodeError::LimitExceeded {
            kind: RecordDecodeLimit::DecodedBytes,
            ..
        })
    ));
    Ok(())
}

#[test]
fn cumulative_header_and_work_budgets_include_the_failing_attempt()
-> Result<(), Box<dyn std::error::Error>> {
    let mut record = Record::builder().value(None).build()?;
    set_headers(
        &mut record,
        vec![
            Header {
                key: Some(Bytes::from_static(b"first")),
                value: Some(Bytes::from_static(b"value")),
            },
            Header {
                key: Some(Bytes::from_static(b"second")),
                value: None,
            },
        ],
    )?;
    let encoded = (&[record][..]).encode()?;

    let mut header_limits = limits(encoded.len(), 0);
    header_limits.max_headers = 1;
    let mut scratch = [];
    let mut transfer = [0u8; 32];
    let mut values = ValueRecords::new(
        Cursor::new(encoded.clone()),
        &mut scratch,
        &mut transfer,
        1,
        header_limits,
    )?;
    assert_eq!(
        RecordDecodeError::LimitExceeded {
            kind: RecordDecodeLimit::Headers,
            limit: 1,
            actual: 2,
        },
        values.next_value().expect_err("header bomb")
    );
    assert_eq!(2, values.progress().headers_declared);
    assert_eq!(1, values.progress().records_begun);
    assert_eq!(0, values.progress().records_emitted);

    for (field_limits, expected) in [
        (
            RecordDecodeLimits {
                max_header_key_bytes: 4,
                ..limits(encoded.len(), 0)
            },
            RecordDecodeError::LimitExceeded {
                kind: RecordDecodeLimit::HeaderKeyBytes,
                limit: 4,
                actual: 5,
            },
        ),
        (
            RecordDecodeLimits {
                max_header_value_bytes: 4,
                ..limits(encoded.len(), 0)
            },
            RecordDecodeError::LimitExceeded {
                kind: RecordDecodeLimit::HeaderValueBytes,
                limit: 4,
                actual: 5,
            },
        ),
    ] {
        let mut scratch = [];
        let mut transfer = [0u8; 32];
        let mut values = ValueRecords::new(
            Cursor::new(encoded.clone()),
            &mut scratch,
            &mut transfer,
            1,
            field_limits,
        )?;
        assert_eq!(expected, values.next_value().expect_err("header field cap"));
        assert_eq!(2, values.progress().headers_declared);
        assert_eq!(1, values.progress().records_begun);
        assert_eq!(0, values.progress().records_emitted);
    }

    let mut work_limits = limits(encoded.len(), 0);
    work_limits.max_work_units = 1;
    let mut scratch = [];
    let mut transfer = [0u8; 32];
    let mut values = ValueRecords::new(
        Cursor::new(encoded),
        &mut scratch,
        &mut transfer,
        1,
        work_limits,
    )?;
    assert_eq!(
        RecordDecodeError::LimitExceeded {
            kind: RecordDecodeLimit::WorkUnits,
            limit: 1,
            actual: 2,
        },
        values.next_value().expect_err("work bomb")
    );
    assert_eq!(1, values.progress().decoded_bytes);
    assert_eq!(1, values.progress().records_begun);
    assert_eq!(2, values.progress().work_units);
    Ok(())
}

#[test]
fn eof_probe_reader_errors_propagate_from_next_and_finish() -> Result<(), Box<dyn std::error::Error>>
{
    let record = Record::builder().value(None).build()?;
    let encoded = (&[record][..]).encode()?;
    let expected = RecordDecodeError::ReaderIo {
        field: "trailing record data",
        kind: io::ErrorKind::ConnectionReset,
    };

    let mut scratch = [];
    let mut transfer = [0u8; 32];
    let reader = ErrorReader {
        inner: Cursor::new(encoded.clone()),
        bytes_before_error: encoded.len(),
    };
    let mut next = ValueRecords::new(
        reader,
        &mut scratch,
        &mut transfer,
        1,
        limits(encoded.len(), 0),
    )?;
    assert_eq!(Some(ValueRef::Null), next.next_value()?);
    assert_eq!(expected, next.next_value().expect_err("next EOF probe"));
    assert_eq!(encoded.len(), next.progress().decoded_bytes);
    assert_eq!(1, next.progress().records_emitted);

    let mut scratch = [];
    let mut transfer = [0u8; 32];
    let reader = ErrorReader {
        inner: Cursor::new(encoded.clone()),
        bytes_before_error: encoded.len(),
    };
    let mut finish = ValueRecords::new(
        reader,
        &mut scratch,
        &mut transfer,
        1,
        limits(encoded.len(), 0),
    )?;
    assert_eq!(Some(ValueRef::Null), finish.next_value()?);
    let failure = finish.finish().expect_err("finish EOF probe");
    assert_eq!(&expected, failure.error());
    assert_eq!(encoded.len(), failure.progress().decoded_bytes);
    assert_eq!(1, failure.progress().records_emitted);
    Ok(())
}

#[test]
fn underlying_reads_cannot_overshoot_the_decoded_budget_by_more_than_one_byte()
-> Result<(), Box<dyn std::error::Error>> {
    let records = vec![
        Record::builder()
            .value(Some(Bytes::from(vec![1; 40])))
            .build()?,
        Record::builder()
            .value(Some(Bytes::from(vec![2; 80])))
            .build()?,
    ];
    let encoded = records.as_slice().encode()?;
    let decoded_limit = 90;
    let largest_requested = Rc::new(Cell::new(0));
    let largest_excess = Rc::new(Cell::new(0));
    let reader = BudgetRecordingReader {
        inner: Cursor::new(encoded),
        decoded_limit,
        returned: 0,
        largest_requested: Rc::clone(&largest_requested),
        largest_excess: Rc::clone(&largest_excess),
    };
    let mut decode_limits = limits(decoded_limit, 80);
    decode_limits.max_record_bytes = decoded_limit;
    let mut scratch = [0u8; 80];
    let mut transfer = [0u8; 32];
    let mut values = ValueRecords::new(reader, &mut scratch, &mut transfer, 2, decode_limits)?;
    assert!(matches!(values.next_value()?, Some(ValueRef::Bytes(_))));
    assert!(matches!(
        values.next_value(),
        Err(RecordDecodeError::LimitExceeded {
            kind: RecordDecodeLimit::DecodedBytes,
            limit: 90,
            actual: 91,
        })
    ));
    assert_eq!(91, values.progress().decoded_bytes);
    assert!(
        largest_requested.get() > 1,
        "the body path performed a bulk read"
    );
    assert_eq!(0, largest_excess.get());

    let decoded_limit = 4;
    let largest_requested = Rc::new(Cell::new(0));
    let largest_excess = Rc::new(Cell::new(0));
    let reader = BudgetRecordingReader {
        inner: Cursor::new(vec![0u8; 64]),
        decoded_limit,
        returned: 0,
        largest_requested: Rc::clone(&largest_requested),
        largest_excess: Rc::clone(&largest_excess),
    };
    let mut decode_limits = limits(decoded_limit, 0);
    decode_limits.max_record_bytes = decoded_limit;
    let mut scratch = [];
    let mut transfer = [0u8; 32];
    let mut values = ValueRecords::new(reader, &mut scratch, &mut transfer, 0, decode_limits)?;
    assert!(matches!(
        values.next_value(),
        Err(RecordDecodeError::LimitExceeded {
            kind: RecordDecodeLimit::DecodedBytes,
            limit: 4,
            actual: 5,
        })
    ));
    assert_eq!(5, largest_requested.get());
    assert_eq!(0, largest_excess.get());
    Ok(())
}

#[test]
fn required_header_keys_reject_kafkas_null_sentinel() -> Result<(), Box<dyn std::error::Error>> {
    let encoded = Bytes::from_static(b"\x0e\x00\x00\x00\x01\x01\x02\x01");
    let mut scratch = [];
    let mut transfer = [0u8; 32];
    let mut values = ValueRecords::new(
        Cursor::new(encoded.clone()),
        &mut scratch,
        &mut transfer,
        1,
        limits(encoded.len(), 0),
    )?;
    assert_eq!(
        RecordDecodeError::NegativeLength {
            field: "header key",
            actual: -1,
        },
        values.next_value().expect_err("null required header key")
    );
    assert_eq!(1, values.progress().headers_declared);
    Ok(())
}

#[test]
fn malformed_lengths_counts_bodies_and_trailing_bytes_fail_loudly()
-> Result<(), Box<dyn std::error::Error>> {
    for (encoded, expected) in [
        (
            Bytes::from_static(b"\x01"),
            RecordDecodeError::NegativeLength {
                field: "record length",
                actual: -1,
            },
        ),
        (
            Bytes::from_static(b"\x80"),
            RecordDecodeError::Truncated("record length"),
        ),
        (
            Bytes::from_static(b"\x80\x80\x80\x80\x10"),
            RecordDecodeError::InvalidVarint {
                field: "record length",
            },
        ),
    ] {
        let mut scratch = [0u8; 1];
        let mut transfer = [0u8; 32];
        let mut values = ValueRecords::new(
            Cursor::new(encoded.clone()),
            &mut scratch,
            &mut transfer,
            1,
            limits(encoded.len(), 1),
        )?;
        assert_eq!(expected, values.next_value().expect_err("malformed length"));
    }

    let record = Record::builder().value(None).build()?;
    let encoded = (&[record][..]).encode()?;
    let mut extended = BytesMut::from(&encoded[..]);
    extended[0] = extended[0].checked_add(2).expect("small record length");
    extended.extend_from_slice(&[0]);
    let mut scratch = [];
    let mut transfer = [0u8; 32];
    let mut values = ValueRecords::new(
        Cursor::new(extended.clone()),
        &mut scratch,
        &mut transfer,
        1,
        limits(extended.len(), 0),
    )?;
    assert!(matches!(
        values.next_value(),
        Err(RecordDecodeError::RecordLengthMismatch { .. })
    ));

    let mut scratch = [];
    let mut transfer = [0u8; 32];
    let mut missing = ValueRecords::new(
        Cursor::new(encoded.clone()),
        &mut scratch,
        &mut transfer,
        2,
        limits(encoded.len(), 0),
    )?;
    assert_eq!(Some(ValueRef::Null), missing.next_value()?);
    assert_eq!(
        RecordDecodeError::RecordCountMismatch {
            declared: 2,
            actual: 1,
        },
        missing.next_value().expect_err("missing record")
    );

    let mut two = BytesMut::from(&encoded[..]);
    two.extend_from_slice(&encoded);
    let mut scratch = [];
    let mut transfer = [0u8; 32];
    let mut trailing = ValueRecords::new(
        Cursor::new(two.clone()),
        &mut scratch,
        &mut transfer,
        1,
        limits(two.len(), 0),
    )?;
    assert_eq!(Some(ValueRef::Null), trailing.next_value()?);
    assert_eq!(
        RecordDecodeError::TrailingBytes(encoded.len()),
        trailing.next_value().expect_err("trailing record")
    );
    assert_eq!(two.len(), trailing.progress().decoded_bytes);
    Ok(())
}

#[test]
fn finish_is_mandatory_for_early_termination() -> Result<(), Box<dyn std::error::Error>> {
    let records = vec![
        Record::builder().value(None).build()?,
        Record::builder().value(None).build()?,
    ];
    let encoded = records.as_slice().encode()?;
    let mut scratch = [];
    let mut transfer = [0u8; 32];
    let mut values = ValueRecords::new(
        Cursor::new(encoded.clone()),
        &mut scratch,
        &mut transfer,
        2,
        limits(encoded.len(), 0),
    )?;
    assert_eq!(Some(ValueRef::Null), values.next_value()?);
    let failure = values.finish().expect_err("early finish");
    assert!(matches!(
        failure.error(),
        RecordDecodeError::RecordCountMismatch {
            declared: 2,
            actual: 1,
        }
    ));
    assert_eq!(1, failure.progress().records_emitted);
    Ok(())
}
