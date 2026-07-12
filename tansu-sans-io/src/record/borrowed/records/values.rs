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

//! Streaming value projection from an already decompressed record stream.

use std::io::{self, Read};

use super::{
    RecordBodyCursor, RecordDecodeBudget, RecordDecodeError, RecordDecodeFailure,
    RecordDecodeLimit, RecordDecodeLimits, RecordDecodeProgress, check_limit, decode_varint_i32,
    decode_varint_i64, parse_record_fields,
};

/// One selected record value borrowed from caller-owned fixed scratch.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ValueRef<'scratch> {
    /// Kafka's signed negative-one value-length sentinel.
    Null,
    /// A present value; an empty slice remains distinct from [`Self::Null`].
    Bytes(&'scratch [u8]),
}

impl<'scratch> ValueRef<'scratch> {
    /// Convert to the protocol's nullable byte-slice shape.
    pub fn as_option(self) -> Option<&'scratch [u8]> {
        match self {
            Self::Null => None,
            Self::Bytes(bytes) => Some(bytes),
        }
    }
}

/// Lending value projection over a generic already-decompressed record-stream reader.
///
/// Only the selected value is copied, into the fixed scratch supplied by the caller. Keys and
/// headers are validated and skipped through separate nonempty transfer scratch supplied by the
/// caller and reused across every field, record, and EOF drain. Keeping both buffers caller-owned
/// makes the complete fixed memory cost explicit to an embedder and avoids placing a hidden buffer
/// in an async future. Transfer scratch size controls read-call amortization, not field limits.
/// `next_value` lends value scratch, so the reader cannot advance while a selected value is live.
///
/// Call [`Self::finish`] when intentionally stopping early. Normal full traversal performs the
/// same declared-count and exact-EOF invariant before returning `None`.
///
/// ```compile_fail
/// use std::io::Cursor;
/// use tansu_sans_io::record::borrowed::{RecordDecodeLimits, ValueRecords};
///
/// fn cannot_advance_while_value_is_live(bytes: Vec<u8>, scratch: &mut [u8]) {
///     let mut transfer = [0u8; 8 * 1024];
///     let mut values = ValueRecords::new(
///         Cursor::new(bytes),
///         scratch,
///         &mut transfer,
///         1,
///         RecordDecodeLimits::default(),
///     ).unwrap();
///     let first = values.next_value().unwrap().unwrap();
///     let _second = values.next_value();
///     println!("{first:?}");
/// }
/// ```
#[must_use = "value streams must be exhausted or passed to ValueRecords::finish"]
#[derive(Debug)]
pub struct ValueRecords<'value, 'transfer, R> {
    reader: R,
    scratch: &'value mut [u8],
    declared: i32,
    emitted: usize,
    budget: RecordDecodeBudget,
    /// Caller-owned transfer storage reused for all skipped fields and terminal EOF validation.
    transfer: &'transfer mut [u8],
    terminal: bool,
    failure: Option<RecordDecodeError>,
}

impl<'value, 'transfer, R> ValueRecords<'value, 'transfer, R>
where
    R: Read,
{
    /// Construct a streaming projection from an already-decompressed record stream.
    ///
    /// `scratch` must hold the configured maximum selected value. `transfer` must be nonempty and
    /// is reused for every discarded key/header and the final EOF probe; its size changes only I/O
    /// call amortization, so embedders can account and tune the complete fixed memory footprint.
    pub fn new(
        reader: R,
        scratch: &'value mut [u8],
        transfer: &'transfer mut [u8],
        declared_count: i32,
        limits: RecordDecodeLimits,
    ) -> Result<Self, RecordDecodeError> {
        limits.validate()?;
        let declared =
            usize::try_from(declared_count).map_err(|_| RecordDecodeError::NegativeLength {
                field: "record count",
                actual: declared_count,
            })?;
        check_limit(RecordDecodeLimit::Records, limits.max_records, declared)?;
        if scratch.len() < limits.max_value_bytes {
            return Err(RecordDecodeError::ScratchTooSmall {
                required: limits.max_value_bytes,
                actual: scratch.len(),
            });
        }
        if transfer.is_empty() {
            return Err(RecordDecodeError::TransferScratchEmpty);
        }

        Ok(Self {
            reader,
            scratch,
            declared: declared_count,
            emitted: 0,
            budget: RecordDecodeBudget::new(limits),
            transfer,
            terminal: false,
            failure: None,
        })
    }

    /// Decode the next record while retaining only its nullable value in caller scratch.
    pub fn next_value(&mut self) -> Result<Option<ValueRef<'_>>, RecordDecodeError> {
        if let Some(error) = self.failure.as_ref() {
            return Err(error.clone());
        }
        if self.terminal {
            return Ok(None);
        }

        let declared =
            usize::try_from(self.declared).map_err(|_| RecordDecodeError::NegativeLength {
                field: "record count",
                actual: self.declared,
            })?;
        if self.emitted == declared {
            return self.exhausted().map(|()| None);
        }

        let length = match self.next_record_length() {
            Ok(Some(length)) => length,
            Ok(None) => {
                let error = RecordDecodeError::RecordCountMismatch {
                    declared: self.declared,
                    actual: self.emitted,
                };
                self.failure = Some(error.clone());
                return Err(error);
            }
            Err(error) => {
                self.failure = Some(error.clone());
                return Err(error);
            }
        };
        if let Err(error) = check_limit(
            RecordDecodeLimit::RecordBytes,
            self.budget.limits().max_record_bytes,
            length,
        ) {
            self.failure = Some(error.clone());
            return Err(error);
        }
        if let Err(error) = self.budget.begin_record() {
            self.failure = Some(error.clone());
            return Err(error);
        }

        let value_length = {
            let mut body = StreamingBody::new(
                &mut self.reader,
                &mut self.budget,
                self.scratch,
                self.transfer,
                length,
            );
            match parse_record_fields(&mut body) {
                Ok(parsed) => parsed.value,
                Err(error) => {
                    self.failure = Some(error.clone());
                    return Err(error);
                }
            }
        };
        self.emitted += 1;

        Ok(Some(match value_length {
            None => ValueRef::Null,
            Some(length) => ValueRef::Bytes(&self.scratch[..length]),
        }))
    }

    /// Prove declared-count equality and exact EOF, then recover the reader and final progress.
    ///
    /// Failure always carries final resource evidence, including a failed EOF probe, so consuming
    /// terminal validation cannot reset an embedder's request-wide accounting.
    pub fn finish(mut self) -> Result<(R, RecordDecodeProgress), RecordDecodeFailure> {
        let result = (|| {
            if let Some(error) = self.failure.take() {
                return Err(error);
            }
            let declared =
                usize::try_from(self.declared).map_err(|_| RecordDecodeError::NegativeLength {
                    field: "record count",
                    actual: self.declared,
                })?;
            if self.emitted != declared {
                return Err(RecordDecodeError::RecordCountMismatch {
                    declared: self.declared,
                    actual: self.emitted,
                });
            }
            self.exhausted()
        })();
        let progress = self.progress();
        match result {
            Ok(()) => Ok((self.reader, progress)),
            Err(error) => Err(RecordDecodeFailure::new(error, progress)),
        }
    }

    /// Signed record count supplied alongside the decompressed stream.
    pub fn declared_count(&self) -> i32 {
        self.declared
    }

    /// Values successfully emitted so far.
    pub fn emitted_count(&self) -> usize {
        self.emitted
    }

    /// Snapshot attempted resource use, including counters charged by the first failed operation.
    pub fn progress(&self) -> RecordDecodeProgress {
        self.budget.progress(self.emitted)
    }

    fn next_record_length(&mut self) -> Result<Option<usize>, RecordDecodeError> {
        let Some(first) = self.read_optional_byte("record length")? else {
            return Ok(None);
        };
        let mut first = Some(first);
        let length = decode_varint_i32("record length", || {
            first
                .take()
                .map_or_else(|| self.read_required_byte("record length"), Ok)
        })?;
        usize::try_from(length)
            .map(Some)
            .map_err(|_| RecordDecodeError::NegativeLength {
                field: "record length",
                actual: length,
            })
    }

    fn read_optional_byte(&mut self, field: &'static str) -> Result<Option<u8>, RecordDecodeError> {
        let mut byte = [0u8; 1];
        loop {
            self.budget.charge_work(1)?;
            match self.reader.read(&mut byte) {
                Ok(0) => return Ok(None),
                Ok(1) => {
                    self.budget.charge_decoded(1)?;
                    return Ok(Some(byte[0]));
                }
                Ok(_) => unreachable!("one-byte read cannot return more than one byte"),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(reader_error(error, field)),
            }
        }
    }

    fn read_required_byte(&mut self, field: &'static str) -> Result<u8, RecordDecodeError> {
        self.read_optional_byte(field)?
            .ok_or(RecordDecodeError::Truncated(field))
    }

    fn exhausted(&mut self) -> Result<(), RecordDecodeError> {
        if self.terminal {
            return Ok(());
        }
        let trailing = match drain_to_end(&mut self.reader, &mut self.budget, self.transfer) {
            Ok(trailing) => trailing,
            Err(error) => {
                self.failure = Some(error.clone());
                return Err(error);
            }
        };
        if trailing > 0 {
            let error = RecordDecodeError::TrailingBytes(trailing);
            self.failure = Some(error.clone());
            return Err(error);
        }
        self.terminal = true;
        Ok(())
    }
}

struct StreamingBody<'reader, R> {
    reader: &'reader mut R,
    budget: &'reader mut RecordDecodeBudget,
    scratch: &'reader mut [u8],
    transfer: &'reader mut [u8],
    declared: usize,
    remaining: usize,
}

impl<'reader, R> StreamingBody<'reader, R>
where
    R: Read,
{
    fn new(
        reader: &'reader mut R,
        budget: &'reader mut RecordDecodeBudget,
        scratch: &'reader mut [u8],
        transfer: &'reader mut [u8],
        declared: usize,
    ) -> Self {
        Self {
            reader,
            budget,
            scratch,
            transfer,
            declared,
            remaining: declared,
        }
    }

    fn nullable_length(
        &mut self,
        field: &'static str,
        kind: RecordDecodeLimit,
        limit: usize,
    ) -> Result<Option<usize>, RecordDecodeError> {
        let length = decode_varint_i32(field, || self.read_required_byte(field))?;
        if length == -1 {
            return Ok(None);
        }
        let length = usize::try_from(length).map_err(|_| RecordDecodeError::NegativeLength {
            field,
            actual: length,
        })?;
        check_limit(kind, limit, length)?;
        Ok(Some(length))
    }

    fn required_length(
        &mut self,
        field: &'static str,
        kind: RecordDecodeLimit,
        limit: usize,
    ) -> Result<usize, RecordDecodeError> {
        let length = decode_varint_i32(field, || self.read_required_byte(field))?;
        let length = usize::try_from(length).map_err(|_| RecordDecodeError::NegativeLength {
            field,
            actual: length,
        })?;
        check_limit(kind, limit, length)?;
        Ok(length)
    }

    fn read_required_byte(&mut self, field: &'static str) -> Result<u8, RecordDecodeError> {
        let mut byte = [0u8; 1];
        self.read_exact(&mut byte, field)?;
        Ok(byte[0])
    }

    fn read_value(&mut self, length: usize) -> Result<(), RecordDecodeError> {
        read_exact_from(
            self.reader,
            self.budget,
            &mut self.remaining,
            &mut self.scratch[..length],
            "value",
        )
    }

    fn read_exact(
        &mut self,
        output: &mut [u8],
        field: &'static str,
    ) -> Result<(), RecordDecodeError> {
        read_exact_from(self.reader, self.budget, &mut self.remaining, output, field)
    }

    fn skip(&mut self, mut length: usize, field: &'static str) -> Result<(), RecordDecodeError> {
        if length > self.remaining {
            return Err(RecordDecodeError::Truncated(field));
        }
        if length == 0 {
            return read_exact_from(
                self.reader,
                self.budget,
                &mut self.remaining,
                &mut [],
                field,
            );
        }
        while length > 0 {
            let read = length.min(self.transfer.len());
            read_exact_from(
                self.reader,
                self.budget,
                &mut self.remaining,
                &mut self.transfer[..read],
                field,
            )?;
            length -= read;
        }
        Ok(())
    }
}

impl<R> RecordBodyCursor for StreamingBody<'_, R>
where
    R: Read,
{
    type Bytes = usize;

    fn limits(&self) -> RecordDecodeLimits {
        self.budget.limits()
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, RecordDecodeError> {
        self.read_required_byte(field)
    }

    fn varint_i32(&mut self, field: &'static str) -> Result<i32, RecordDecodeError> {
        decode_varint_i32(field, || self.read_required_byte(field))
    }

    fn varint_i64(&mut self, field: &'static str) -> Result<i64, RecordDecodeError> {
        decode_varint_i64(field, || self.read_required_byte(field))
    }

    fn nullable_bytes(
        &mut self,
        field: &'static str,
        kind: RecordDecodeLimit,
        limit: usize,
    ) -> Result<Option<Self::Bytes>, RecordDecodeError> {
        let Some(length) = self.nullable_length(field, kind, limit)? else {
            return Ok(None);
        };
        if kind == RecordDecodeLimit::ValueBytes {
            self.read_value(length)?;
        } else {
            self.skip(length, field)?;
        }
        Ok(Some(length))
    }

    fn required_bytes(
        &mut self,
        field: &'static str,
        kind: RecordDecodeLimit,
        limit: usize,
    ) -> Result<Self::Bytes, RecordDecodeError> {
        let length = self.required_length(field, kind, limit)?;
        self.skip(length, field)?;
        Ok(length)
    }

    fn add_headers(&mut self, headers: usize) -> Result<(), RecordDecodeError> {
        self.budget.add_headers(headers)
    }

    fn position(&self) -> usize {
        self.declared - self.remaining
    }

    fn finish_body(&self) -> Result<(), RecordDecodeError> {
        if self.remaining != 0 {
            return Err(RecordDecodeError::RecordLengthMismatch {
                declared: self.declared,
                actual: self.declared - self.remaining,
            });
        }
        Ok(())
    }
}

fn read_exact_from(
    reader: &mut impl Read,
    budget: &mut RecordDecodeBudget,
    remaining: &mut usize,
    output: &mut [u8],
    field: &'static str,
) -> Result<(), RecordDecodeError> {
    if output.len() > *remaining {
        return Err(RecordDecodeError::Truncated(field));
    }
    if output.is_empty() {
        return budget.charge_work(1);
    }
    let mut written = 0usize;
    while written < output.len() {
        budget.charge_work(1)?;
        let read_capacity = budget
            .remaining_decoded()
            .saturating_add(1)
            .max(1)
            .min(output.len() - written);
        match reader.read(&mut output[written..written + read_capacity]) {
            Ok(0) => return Err(RecordDecodeError::Truncated(field)),
            Ok(read) => {
                budget.charge_decoded(read)?;
                *remaining -= read;
                written += read;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(reader_error(error, field)),
        }
    }
    Ok(())
}

fn drain_to_end(
    reader: &mut impl Read,
    budget: &mut RecordDecodeBudget,
    transfer: &mut [u8],
) -> Result<usize, RecordDecodeError> {
    let mut total = 0usize;
    loop {
        budget.charge_work(1)?;
        let read_capacity = budget
            .remaining_decoded()
            .saturating_add(1)
            .max(1)
            .min(transfer.len());
        match reader.read(&mut transfer[..read_capacity]) {
            Ok(0) => return Ok(total),
            Ok(read) => {
                budget.charge_decoded(read)?;
                total = total
                    .checked_add(read)
                    .ok_or(RecordDecodeError::CounterOverflow {
                        resource: "trailing bytes",
                    })?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(reader_error(error, "trailing record data")),
        }
    }
}

fn reader_error(error: io::Error, field: &'static str) -> RecordDecodeError {
    RecordDecodeError::ReaderIo {
        field,
        kind: error.kind(),
    }
}
