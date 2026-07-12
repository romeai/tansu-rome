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

//! Lending, allocation-free decoding of uncompressed magic-v2 records.
//!
//! One semantic parser owns Kafka's record-field grammar behind a private primitive cursor seam.
//! The uncompressed adapter supplies frame-backed ranges, while the streaming adapter visits
//! decompressed fields incrementally. Both therefore share field order, nullability, limits,
//! headers, and exact-body validation without requiring whole-record scratch merely to retain one
//! selected value.

use std::{fmt, ops::Range};

use crate::Compression;

use super::Batch;

mod values;

pub use values::{ValueRecords, ValueRef};

/// Maximum bytes in Kafka's zigzag-encoded signed INT32 representation.
const MAX_VARINT_BYTES: usize = 5;
/// Maximum payload in the fifth INT32 varint byte before bits would exceed 32 bits.
const LAST_VARINT_PAYLOAD: u8 = 0x0f;
/// Maximum bytes in Kafka's zigzag-encoded signed INT64 representation.
const MAX_VARLONG_BYTES: usize = 10;
/// Maximum payload in the tenth INT64 varint byte before bits would exceed 64 bits.
const LAST_VARLONG_PAYLOAD: u8 = 0x01;

/// The bounded resource exhausted while decoding a magic-v2 record stream.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RecordDecodeLimit {
    /// Bytes declared by one record body.
    RecordBytes,
    /// All decoded stream bytes, including record-length varints and bodies.
    DecodedBytes,
    /// Records observed in one batch.
    Records,
    /// Bytes in one record key.
    KeyBytes,
    /// Bytes in one record value.
    ValueBytes,
    /// Bytes in one record-header key.
    HeaderKeyBytes,
    /// Bytes in one record-header value.
    HeaderValueBytes,
    /// Headers observed across every record in one batch.
    Headers,
    /// Primitive parse and traversal operations across one batch.
    WorkUnits,
}

impl fmt::Display for RecordDecodeLimit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RecordBytes => "record bytes",
            Self::DecodedBytes => "decoded bytes",
            Self::Records => "records",
            Self::KeyBytes => "key bytes",
            Self::ValueBytes => "value bytes",
            Self::HeaderKeyBytes => "header key bytes",
            Self::HeaderValueBytes => "header value bytes",
            Self::Headers => "headers",
            Self::WorkUnits => "work units",
        })
    }
}

/// Resource limits shared by uncompressed and streaming-decompression record adapters.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecordDecodeLimits {
    /// Maximum bytes declared by one record body.
    pub max_record_bytes: usize,
    /// Maximum decoded stream bytes, including every length varint and record body.
    pub max_decoded_bytes: usize,
    /// Maximum records declared and observed in one batch.
    pub max_records: usize,
    /// Maximum bytes in one optional record key.
    pub max_key_bytes: usize,
    /// Maximum bytes in one optional record value.
    pub max_value_bytes: usize,
    /// Maximum bytes in one required record-header key.
    pub max_header_key_bytes: usize,
    /// Maximum bytes in one optional record-header value.
    pub max_header_value_bytes: usize,
    /// Maximum headers observed cumulatively across the batch.
    pub max_headers: usize,
    /// Maximum primitive parse and traversal operations across the batch.
    pub max_work_units: usize,
}

/// Immutable resource evidence from one record-decoder attempt.
///
/// A caller can snapshot this value after a failed `next_record` or `next_value` call and charge
/// the observed work to a request-wide budget before dropping the failed decoder. Counters are
/// monotonic, count attempted work even when the operation that charged it fails, and never grant
/// access to mutate or reset the decoder's internal budget.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecordDecodeProgress {
    /// Bytes actually consumed from the record stream, including length prefixes, bodies, and
    /// trailing bytes inspected while proving exact exhaustion.
    pub decoded_bytes: usize,
    /// Records whose semantic body decode began after a valid nonnegative, bounded record length.
    /// A record remains begun when a later field, limit, or reader operation rejects its body.
    pub records_begun: usize,
    /// Records whose complete body passed validation and whose view or value was returned.
    pub records_emitted: usize,
    /// Headers declared by successfully decoded header-count fields, including headers whose later
    /// key or value validation fails.
    pub headers_declared: usize,
    /// Primitive parse, traversal, and reader operations attempted, including the operation that
    /// first exceeds the configured work limit.
    pub work_units: usize,
}

/// Terminal decode failure paired with the monotonic resource evidence observed before failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{error}")]
pub struct RecordDecodeFailure {
    #[source]
    error: RecordDecodeError,
    progress: RecordDecodeProgress,
}

impl RecordDecodeFailure {
    fn new(error: RecordDecodeError, progress: RecordDecodeProgress) -> Self {
        Self { error, progress }
    }

    /// Typed protocol, limit, or reader failure discovered by terminal validation.
    pub fn error(&self) -> &RecordDecodeError {
        &self.error
    }

    /// Final immutable resource evidence, including the operation that caused failure.
    pub fn progress(&self) -> RecordDecodeProgress {
        self.progress
    }

    /// Consume the failure into independently owned error and progress values.
    pub fn into_parts(self) -> (RecordDecodeError, RecordDecodeProgress) {
        (self.error, self.progress)
    }
}

impl RecordDecodeLimits {
    /// Validate relationships required for a single monotonic resource budget.
    pub fn validate(&self) -> Result<(), RecordDecodeError> {
        if self.max_record_bytes > self.max_decoded_bytes {
            return Err(RecordDecodeError::InvalidLimits(
                "max_record_bytes must not exceed max_decoded_bytes",
            ));
        }
        Ok(())
    }
}

impl Default for RecordDecodeLimits {
    fn default() -> Self {
        /// Kafka's default maximum request size provides a compatibility-preserving stream bound.
        const DEFAULT_MAX_DECODED_BYTES: usize = 100 * 1024 * 1024;
        /// A single record may occupy the full bounded decoded stream.
        const DEFAULT_MAX_RECORD_BYTES: usize = DEFAULT_MAX_DECODED_BYTES;
        /// One million records matches the generated request decoder's conservative sequence cap.
        const DEFAULT_MAX_RECORDS: usize = 1_000_000;
        /// Keys may use the complete record body by default; callers can impose a tighter policy.
        const DEFAULT_MAX_KEY_BYTES: usize = DEFAULT_MAX_RECORD_BYTES;
        /// Values preserve Kafka's request-sized default; embedders can impose a tighter policy.
        const DEFAULT_MAX_VALUE_BYTES: usize = DEFAULT_MAX_RECORD_BYTES;
        /// Header keys preserve wire compatibility while the decoded-stream bound remains finite.
        const DEFAULT_MAX_HEADER_KEY_BYTES: usize = DEFAULT_MAX_RECORD_BYTES;
        /// Header values preserve wire compatibility while the decoded-stream bound remains finite.
        const DEFAULT_MAX_HEADER_VALUE_BYTES: usize = DEFAULT_MAX_RECORD_BYTES;
        /// One million cumulative headers bounds peer-controlled replay work across the batch.
        const DEFAULT_MAX_HEADERS: usize = 1_000_000;
        /// Forty-eight units cover worst-width record varints and fixed fields; sixteen cover both
        /// worst-width header lengths plus range and cumulative-header accounting.
        const DEFAULT_MAX_WORK_UNITS: usize = DEFAULT_MAX_RECORDS * 48 + DEFAULT_MAX_HEADERS * 16;

        Self {
            max_record_bytes: DEFAULT_MAX_RECORD_BYTES,
            max_decoded_bytes: DEFAULT_MAX_DECODED_BYTES,
            max_records: DEFAULT_MAX_RECORDS,
            max_key_bytes: DEFAULT_MAX_KEY_BYTES,
            max_value_bytes: DEFAULT_MAX_VALUE_BYTES,
            max_header_key_bytes: DEFAULT_MAX_HEADER_KEY_BYTES,
            max_header_value_bytes: DEFAULT_MAX_HEADER_VALUE_BYTES,
            max_headers: DEFAULT_MAX_HEADERS,
            max_work_units: DEFAULT_MAX_WORK_UNITS,
        }
    }
}

/// Typed failures from bounded record-stream decoding.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RecordDecodeError {
    /// Caller-supplied limits cannot form a coherent resource policy.
    #[error("invalid record decode limits: {0}")]
    InvalidLimits(&'static str),
    /// A compressed batch reached the deliberately uncompressed-only C1 adapter.
    #[error("record compression is unsupported by the uncompressed decoder: attributes {0}")]
    UnsupportedCompression(i16),
    /// A peer-controlled resource exceeded its configured bound.
    #[error("record decode {kind} exceeds limit {limit} (actual {actual})")]
    LimitExceeded {
        kind: RecordDecodeLimit,
        limit: usize,
        actual: usize,
    },
    /// A cumulative counter could not represent another observed unit.
    #[error("record decode {resource} counter overflow")]
    CounterOverflow { resource: &'static str },
    /// Caller-owned fixed scratch cannot retain the configured maximum selected value.
    #[error("value scratch has {actual} bytes but record limits require {required}")]
    ScratchTooSmall { required: usize, actual: usize },
    /// Caller-owned transfer scratch must make forward progress while skipping fields or probing
    /// EOF; requiring one byte avoids hidden allocation and a zero-capacity read loop.
    #[error("record transfer scratch must not be empty")]
    TransferScratchEmpty,
    /// The caller-supplied decompressed reader failed.
    #[error("record reader failed while decoding {field} with {kind:?}")]
    ReaderIo {
        /// Record field or exhaustion check whose read failed.
        field: &'static str,
        /// Stable standard-library classification of the underlying reader failure.
        kind: std::io::ErrorKind,
    },
    /// The stream ended or the caller finished before the signed declared count was observed.
    #[error("record count mismatch: batch declared {declared}, decoded {actual}")]
    RecordCountMismatch { declared: i32, actual: usize },
    /// Bytes remained after the declared number of records had been decoded.
    #[error("{0} trailing bytes remain after the declared record count")]
    TrailingBytes(usize),
    /// A length-delimited or fixed-width record field ended early.
    #[error("truncated {0}")]
    Truncated(&'static str),
    /// A varint continued beyond its signed field's wire width.
    #[error("invalid {field} varint")]
    InvalidVarint { field: &'static str },
    /// A length or count was negative where only the null sentinel may be negative.
    #[error("invalid negative {field} {actual}")]
    NegativeLength { field: &'static str, actual: i32 },
    /// Parsed fields did not consume exactly the peer-declared record body.
    #[error("record declared {declared} body bytes but parser consumed {actual}")]
    RecordLengthMismatch { declared: usize, actual: usize },
}

#[derive(Debug)]
pub(crate) struct RecordDecodeBudget {
    limits: RecordDecodeLimits,
    decoded_bytes: usize,
    records: usize,
    headers: usize,
    work_units: usize,
}

impl RecordDecodeBudget {
    pub(crate) fn new(limits: RecordDecodeLimits) -> Self {
        Self {
            limits,
            decoded_bytes: 0,
            records: 0,
            headers: 0,
            work_units: 0,
        }
    }

    /// Limits owned by this monotonic budget, shared unchanged with codec adapters.
    pub(crate) fn limits(&self) -> RecordDecodeLimits {
        self.limits
    }

    /// Bytes still allowed before a one-byte read is needed to distinguish exact EOF from an
    /// over-limit stream.
    pub(crate) fn remaining_decoded(&self) -> usize {
        self.limits
            .max_decoded_bytes
            .saturating_sub(self.decoded_bytes)
    }

    /// Snapshot monotonic internal counters without lending or resetting the unique budget.
    pub(crate) fn progress(&self, records_emitted: usize) -> RecordDecodeProgress {
        RecordDecodeProgress {
            decoded_bytes: self.decoded_bytes,
            records_begun: self.records,
            records_emitted,
            headers_declared: self.headers,
            work_units: self.work_units,
        }
    }

    pub(crate) fn charge_decoded(&mut self, bytes: usize) -> Result<(), RecordDecodeError> {
        self.decoded_bytes =
            self.decoded_bytes
                .checked_add(bytes)
                .ok_or(RecordDecodeError::CounterOverflow {
                    resource: "decoded bytes",
                })?;
        check_limit(
            RecordDecodeLimit::DecodedBytes,
            self.limits.max_decoded_bytes,
            self.decoded_bytes,
        )
    }

    fn begin_record(&mut self) -> Result<(), RecordDecodeError> {
        self.records = self
            .records
            .checked_add(1)
            .ok_or(RecordDecodeError::CounterOverflow {
                resource: "records",
            })?;
        check_limit(
            RecordDecodeLimit::Records,
            self.limits.max_records,
            self.records,
        )?;
        self.charge_work(1)
    }

    fn add_headers(&mut self, headers: usize) -> Result<(), RecordDecodeError> {
        self.headers =
            self.headers
                .checked_add(headers)
                .ok_or(RecordDecodeError::CounterOverflow {
                    resource: "headers",
                })?;
        check_limit(
            RecordDecodeLimit::Headers,
            self.limits.max_headers,
            self.headers,
        )?;
        self.charge_work(headers)
    }

    fn charge_work(&mut self, units: usize) -> Result<(), RecordDecodeError> {
        self.work_units =
            self.work_units
                .checked_add(units)
                .ok_or(RecordDecodeError::CounterOverflow {
                    resource: "work units",
                })?;
        check_limit(
            RecordDecodeLimit::WorkUnits,
            self.limits.max_work_units,
            self.work_units,
        )
    }
}

/// Lending record stream over immutable uncompressed magic-v2 bytes.
///
/// `next_record` ties each returned view to the mutable stream borrow, preventing advancement while
/// a record is live. Call [`Self::finish`] after intentionally stopping early; normal full traversal
/// performs the same count and trailing-byte invariant before returning `None`.
///
/// ```compile_fail
/// use tansu_sans_io::record::borrowed::Records;
///
/// fn cannot_advance_while_record_is_live(records: &mut Records<'_>) {
///     let first = records.next_record().unwrap().unwrap();
///     let _second = records.next_record();
///     println!("{:?}", first.value());
/// }
/// ```
#[must_use = "record streams must be exhausted or passed to Records::finish"]
#[derive(Debug)]
pub struct Records<'source> {
    source: &'source [u8],
    position: usize,
    declared: i32,
    emitted: usize,
    budget: RecordDecodeBudget,
    terminal: bool,
    failure: Option<RecordDecodeError>,
}

impl<'source> Records<'source> {
    /// Decode and eagerly validate the next complete record and all of its headers.
    pub fn next_record(&mut self) -> Result<Option<RecordRef<'_>>, RecordDecodeError> {
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
        if self.position == self.source.len() {
            let error = RecordDecodeError::RecordCountMismatch {
                declared: self.declared,
                actual: self.emitted,
            };
            self.failure = Some(error.clone());
            return Err(error);
        }

        let boundary = self.next_boundary();
        let body = match boundary {
            Ok(body) => body,
            Err(error) => {
                self.failure = Some(error.clone());
                return Err(error);
            }
        };
        let parsed = match parse_record_body(&self.source[body.clone()], &mut self.budget) {
            Ok(parsed) => parsed,
            Err(error) => {
                self.failure = Some(error.clone());
                return Err(error);
            }
        };

        self.emitted += 1;
        Ok(Some(RecordRef::from_parsed(&self.source[body], parsed)))
    }

    /// Consume the stream and prove exact declared-count and byte exhaustion.
    ///
    /// Success returns final resource evidence. Failure carries the same evidence alongside the
    /// typed error, so terminal validation cannot discard request-wide accounting.
    pub fn finish(mut self) -> Result<RecordDecodeProgress, RecordDecodeFailure> {
        let result = (|| {
            if let Some(error) = self.failure.take() {
                return Err(error);
            }
            self.charge_remaining()?;
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
            let remaining = self.source.len() - self.position;
            if remaining > 0 {
                return Err(RecordDecodeError::TrailingBytes(remaining));
            }
            Ok(())
        })();
        let progress = self.progress();
        result
            .map(|()| progress)
            .map_err(|error| RecordDecodeFailure::new(error, progress))
    }

    /// Signed count declared by the magic-v2 batch.
    pub fn declared_count(&self) -> i32 {
        self.declared
    }

    /// Records successfully emitted so far.
    pub fn emitted_count(&self) -> usize {
        self.emitted
    }

    /// Snapshot attempted resource use, including counters charged by the first failed operation.
    pub fn progress(&self) -> RecordDecodeProgress {
        self.budget.progress(self.emitted)
    }

    fn next_boundary(&mut self) -> Result<Range<usize>, RecordDecodeError> {
        let (body, position) = {
            let mut cursor = RecordCursor::stream(
                self.source,
                self.position,
                self.source.len(),
                &mut self.budget,
            );
            let length = cursor.varint_i32("record length")?;
            let length =
                usize::try_from(length).map_err(|_| RecordDecodeError::NegativeLength {
                    field: "record length",
                    actual: length,
                })?;
            check_limit(
                RecordDecodeLimit::RecordBytes,
                cursor.budget.limits.max_record_bytes,
                length,
            )?;
            let body = cursor.take(length, "record body")?;
            (body, cursor.position)
        };
        self.position = position;
        Ok(body)
    }

    fn exhausted(&mut self) -> Result<(), RecordDecodeError> {
        if self.terminal {
            return Ok(());
        }
        let remaining = self.source.len() - self.position;
        if remaining > 0 {
            if let Err(error) = self.budget.charge_decoded(remaining) {
                self.failure = Some(error.clone());
                return Err(error);
            }
            self.position = self.source.len();
            let error = RecordDecodeError::TrailingBytes(remaining);
            self.failure = Some(error.clone());
            return Err(error);
        }
        self.terminal = true;
        Ok(())
    }

    fn charge_remaining(&mut self) -> Result<(), RecordDecodeError> {
        let remaining = self.source.len() - self.position;
        if remaining > 0 {
            self.budget.charge_decoded(remaining)?;
        }
        Ok(())
    }
}

/// One lending record whose fields borrow immutable decoded record-body bytes.
#[derive(Clone, Debug)]
pub struct RecordRef<'source> {
    source: &'source [u8],
    parsed: ParsedRecord,
}

impl<'source> RecordRef<'source> {
    pub(crate) fn from_parsed(source: &'source [u8], parsed: ParsedRecord) -> Self {
        Self { source, parsed }
    }

    /// Exact record body, excluding its leading length varint.
    pub fn as_bytes(&self) -> &'source [u8] {
        self.source
    }

    /// Record attributes byte.
    pub fn attributes(&self) -> u8 {
        self.parsed.attributes
    }

    /// Timestamp delta from the batch base timestamp.
    pub fn timestamp_delta(&self) -> i64 {
        self.parsed.timestamp_delta
    }

    /// Offset delta from the batch base offset.
    pub fn offset_delta(&self) -> i32 {
        self.parsed.offset_delta
    }

    /// Optional key; `Some(&[])` remains distinct from `None`.
    pub fn key(&self) -> Option<&'source [u8]> {
        self.parsed
            .key
            .as_ref()
            .map(|range| &self.source[range.clone()])
    }

    /// Optional value; `Some(&[])` remains distinct from `None`.
    pub fn value(&self) -> Option<&'source [u8]> {
        self.parsed
            .value
            .as_ref()
            .map(|range| &self.source[range.clone()])
    }

    /// Replay eagerly validated headers with O(1) iterator state.
    pub fn headers(&self) -> Headers<'source> {
        Headers {
            cursor: ReplayCursor::bounded(
                self.source,
                self.parsed.headers.start,
                self.parsed.headers.end,
            ),
            remaining: self.parsed.header_count,
        }
    }
}

/// Defensive O(1)-state replay iterator over eagerly validated record headers.
#[derive(Clone, Debug)]
pub struct Headers<'source> {
    cursor: ReplayCursor<'source>,
    remaining: usize,
}

impl<'source> Iterator for Headers<'source> {
    type Item = Result<HeaderRef<'source>, RecordDecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        Some((|| {
            let key = self.cursor.required_bytes("header key")?;
            let value = self.cursor.nullable_bytes("header value")?;
            Ok(HeaderRef {
                source: self.cursor.source,
                key,
                value,
            })
        })())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for Headers<'_> {}

/// One record header borrowing its required key and optional value from a validated record body.
#[derive(Clone, Debug)]
pub struct HeaderRef<'source> {
    source: &'source [u8],
    key: Range<usize>,
    value: Option<Range<usize>>,
}

impl<'source> HeaderRef<'source> {
    /// Required header key; an empty key remains a valid empty slice.
    pub fn key(&self) -> &'source [u8] {
        &self.source[self.key.clone()]
    }

    /// Optional header value; null and empty remain distinct.
    pub fn value(&self) -> Option<&'source [u8]> {
        self.value.as_ref().map(|range| &self.source[range.clone()])
    }
}

impl<'batch> Batch<'batch> {
    /// Create a lending decoder for an uncompressed batch with default limits.
    pub fn records(&self) -> Result<Records<'_>, RecordDecodeError> {
        self.records_with_limits(RecordDecodeLimits::default())
    }

    /// Create a lending decoder for an uncompressed batch with explicit limits.
    pub fn records_with_limits(
        &self,
        limits: RecordDecodeLimits,
    ) -> Result<Records<'_>, RecordDecodeError> {
        limits.validate()?;
        if !matches!(
            Compression::try_from(self.attributes()),
            Ok(Compression::None)
        ) {
            return Err(RecordDecodeError::UnsupportedCompression(self.attributes()));
        }
        let declared = self.record_count();
        let declared_usize =
            usize::try_from(declared).map_err(|_| RecordDecodeError::NegativeLength {
                field: "record count",
                actual: declared,
            })?;
        check_limit(
            RecordDecodeLimit::Records,
            limits.max_records,
            declared_usize,
        )?;
        check_limit(
            RecordDecodeLimit::DecodedBytes,
            limits.max_decoded_bytes,
            self.record_data().len(),
        )?;

        Ok(Records {
            source: self.record_data(),
            position: 0,
            declared,
            emitted: 0,
            budget: RecordDecodeBudget::new(limits),
            terminal: false,
            failure: None,
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ParsedRecord<Bytes = Range<usize>> {
    attributes: u8,
    timestamp_delta: i64,
    offset_delta: i32,
    key: Option<Bytes>,
    value: Option<Bytes>,
    headers: Range<usize>,
    header_count: usize,
}

/// Adapter seam beneath the one canonical Kafka record-field grammar.
///
/// Implementations decide whether fields borrow frame ranges or are streamed and discarded, but
/// cannot change field order, nullability, limit categories, header semantics, or exact-body
/// exhaustion.
trait RecordBodyCursor {
    type Bytes;

    fn limits(&self) -> RecordDecodeLimits;
    fn u8(&mut self, field: &'static str) -> Result<u8, RecordDecodeError>;
    fn varint_i32(&mut self, field: &'static str) -> Result<i32, RecordDecodeError>;
    fn varint_i64(&mut self, field: &'static str) -> Result<i64, RecordDecodeError>;
    fn nullable_bytes(
        &mut self,
        field: &'static str,
        kind: RecordDecodeLimit,
        limit: usize,
    ) -> Result<Option<Self::Bytes>, RecordDecodeError>;
    fn required_bytes(
        &mut self,
        field: &'static str,
        kind: RecordDecodeLimit,
        limit: usize,
    ) -> Result<Self::Bytes, RecordDecodeError>;
    fn add_headers(&mut self, headers: usize) -> Result<(), RecordDecodeError>;
    fn position(&self) -> usize;
    fn finish_body(&self) -> Result<(), RecordDecodeError>;
}

fn parse_record_fields<Cursor>(
    cursor: &mut Cursor,
) -> Result<ParsedRecord<Cursor::Bytes>, RecordDecodeError>
where
    Cursor: RecordBodyCursor,
{
    let limits = cursor.limits();
    let attributes = cursor.u8("record attributes")?;
    let timestamp_delta = cursor.varint_i64("timestamp delta")?;
    let offset_delta = cursor.varint_i32("offset delta")?;
    let key = cursor.nullable_bytes("key", RecordDecodeLimit::KeyBytes, limits.max_key_bytes)?;
    let value = cursor.nullable_bytes(
        "value",
        RecordDecodeLimit::ValueBytes,
        limits.max_value_bytes,
    )?;
    let header_count = cursor.varint_i32("header count")?;
    let header_count =
        usize::try_from(header_count).map_err(|_| RecordDecodeError::NegativeLength {
            field: "header count",
            actual: header_count,
        })?;
    cursor.add_headers(header_count)?;
    let headers_start = cursor.position();
    for _ in 0..header_count {
        let _ = cursor.required_bytes(
            "header key",
            RecordDecodeLimit::HeaderKeyBytes,
            limits.max_header_key_bytes,
        )?;
        let _ = cursor.nullable_bytes(
            "header value",
            RecordDecodeLimit::HeaderValueBytes,
            limits.max_header_value_bytes,
        )?;
    }
    cursor.finish_body()?;

    Ok(ParsedRecord {
        attributes,
        timestamp_delta,
        offset_delta,
        key,
        value,
        headers: headers_start..cursor.position(),
        header_count,
    })
}

pub(crate) fn parse_record_body(
    body: &[u8],
    budget: &mut RecordDecodeBudget,
) -> Result<ParsedRecord, RecordDecodeError> {
    check_limit(
        RecordDecodeLimit::RecordBytes,
        budget.limits().max_record_bytes,
        body.len(),
    )?;
    budget.begin_record()?;
    let mut cursor = RecordCursor::semantic(body, budget);
    parse_record_fields(&mut cursor)
}

#[derive(Debug)]
struct RecordCursor<'source, 'budget> {
    source: &'source [u8],
    position: usize,
    end: usize,
    budget: &'budget mut RecordDecodeBudget,
    charge_decoded: bool,
}

impl<'source, 'budget> RecordCursor<'source, 'budget> {
    fn stream(
        source: &'source [u8],
        position: usize,
        end: usize,
        budget: &'budget mut RecordDecodeBudget,
    ) -> Self {
        Self {
            source,
            position,
            end,
            budget,
            charge_decoded: true,
        }
    }

    fn semantic(source: &'source [u8], budget: &'budget mut RecordDecodeBudget) -> Self {
        Self {
            source,
            position: 0,
            end: source.len(),
            budget,
            charge_decoded: false,
        }
    }

    fn take(
        &mut self,
        length: usize,
        field: &'static str,
    ) -> Result<Range<usize>, RecordDecodeError> {
        self.budget.charge_work(1)?;
        let end = self
            .position
            .checked_add(length)
            .ok_or(RecordDecodeError::Truncated(field))?;
        if end > self.end {
            if self.charge_decoded {
                let available = self.end - self.position;
                self.budget.charge_decoded(available)?;
                self.position = self.end;
            }
            return Err(RecordDecodeError::Truncated(field));
        }
        if self.charge_decoded {
            self.budget.charge_decoded(length)?;
        }
        let range = self.position..end;
        self.position = end;
        Ok(range)
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, RecordDecodeError> {
        let range = self.take(1, field)?;
        Ok(self.source[range.start])
    }

    fn varint_i32(&mut self, field: &'static str) -> Result<i32, RecordDecodeError> {
        decode_varint_i32(field, || self.u8(field))
    }

    fn varint_i64(&mut self, field: &'static str) -> Result<i64, RecordDecodeError> {
        decode_varint_i64(field, || self.u8(field))
    }

    fn nullable_bytes(
        &mut self,
        field: &'static str,
        kind: RecordDecodeLimit,
        limit: usize,
    ) -> Result<Option<Range<usize>>, RecordDecodeError> {
        let length = self.varint_i32(field)?;
        if length == -1 {
            return Ok(None);
        }
        let length = usize::try_from(length).map_err(|_| RecordDecodeError::NegativeLength {
            field,
            actual: length,
        })?;
        check_limit(kind, limit, length)?;
        self.take(length, field).map(Some)
    }

    fn required_bytes(
        &mut self,
        field: &'static str,
        kind: RecordDecodeLimit,
        limit: usize,
    ) -> Result<Range<usize>, RecordDecodeError> {
        let length = self.varint_i32(field)?;
        let length = usize::try_from(length).map_err(|_| RecordDecodeError::NegativeLength {
            field,
            actual: length,
        })?;
        check_limit(kind, limit, length)?;
        self.take(length, field)
    }
}

impl RecordBodyCursor for RecordCursor<'_, '_> {
    type Bytes = Range<usize>;

    fn limits(&self) -> RecordDecodeLimits {
        self.budget.limits()
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, RecordDecodeError> {
        RecordCursor::u8(self, field)
    }

    fn varint_i32(&mut self, field: &'static str) -> Result<i32, RecordDecodeError> {
        RecordCursor::varint_i32(self, field)
    }

    fn varint_i64(&mut self, field: &'static str) -> Result<i64, RecordDecodeError> {
        RecordCursor::varint_i64(self, field)
    }

    fn nullable_bytes(
        &mut self,
        field: &'static str,
        kind: RecordDecodeLimit,
        limit: usize,
    ) -> Result<Option<Self::Bytes>, RecordDecodeError> {
        RecordCursor::nullable_bytes(self, field, kind, limit)
    }

    fn required_bytes(
        &mut self,
        field: &'static str,
        kind: RecordDecodeLimit,
        limit: usize,
    ) -> Result<Self::Bytes, RecordDecodeError> {
        RecordCursor::required_bytes(self, field, kind, limit)
    }

    fn add_headers(&mut self, headers: usize) -> Result<(), RecordDecodeError> {
        self.budget.add_headers(headers)
    }

    fn position(&self) -> usize {
        self.position
    }

    fn finish_body(&self) -> Result<(), RecordDecodeError> {
        if self.position != self.end {
            return Err(RecordDecodeError::RecordLengthMismatch {
                declared: self.end,
                actual: self.position,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct ReplayCursor<'source> {
    source: &'source [u8],
    position: usize,
    end: usize,
}

impl<'source> ReplayCursor<'source> {
    fn bounded(source: &'source [u8], position: usize, end: usize) -> Self {
        Self {
            source,
            position,
            end,
        }
    }

    fn nullable_bytes(
        &mut self,
        field: &'static str,
    ) -> Result<Option<Range<usize>>, RecordDecodeError> {
        let length = self.varint_i32(field)?;
        if length == -1 {
            return Ok(None);
        }
        let length = usize::try_from(length).map_err(|_| RecordDecodeError::NegativeLength {
            field,
            actual: length,
        })?;
        self.take(length, field).map(Some)
    }

    fn required_bytes(&mut self, field: &'static str) -> Result<Range<usize>, RecordDecodeError> {
        let length = self.varint_i32(field)?;
        let length = usize::try_from(length).map_err(|_| RecordDecodeError::NegativeLength {
            field,
            actual: length,
        })?;
        self.take(length, field)
    }

    fn varint_i32(&mut self, field: &'static str) -> Result<i32, RecordDecodeError> {
        decode_varint_i32(field, || {
            let byte = *self
                .source
                .get(self.position)
                .filter(|_| self.position < self.end)
                .ok_or(RecordDecodeError::Truncated(field))?;
            self.position += 1;
            Ok(byte)
        })
    }

    fn take(
        &mut self,
        length: usize,
        field: &'static str,
    ) -> Result<Range<usize>, RecordDecodeError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(RecordDecodeError::Truncated(field))?;
        if end > self.end {
            return Err(RecordDecodeError::Truncated(field));
        }
        let range = self.position..end;
        self.position = end;
        Ok(range)
    }
}

pub(crate) fn decode_varint_i32(
    field: &'static str,
    mut next_byte: impl FnMut() -> Result<u8, RecordDecodeError>,
) -> Result<i32, RecordDecodeError> {
    let mut value = 0u32;
    for index in 0..MAX_VARINT_BYTES {
        let byte = next_byte()?;
        let shift = index * 7;
        if index + 1 == MAX_VARINT_BYTES && byte > LAST_VARINT_PAYLOAD {
            return Err(RecordDecodeError::InvalidVarint { field });
        }
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(((value >> 1) as i32) ^ -((value & 1) as i32));
        }
    }
    Err(RecordDecodeError::InvalidVarint { field })
}

pub(crate) fn decode_varint_i64(
    field: &'static str,
    mut next_byte: impl FnMut() -> Result<u8, RecordDecodeError>,
) -> Result<i64, RecordDecodeError> {
    let mut value = 0u64;
    for index in 0..MAX_VARLONG_BYTES {
        let byte = next_byte()?;
        let shift = index * 7;
        if index + 1 == MAX_VARLONG_BYTES && byte > LAST_VARLONG_PAYLOAD {
            return Err(RecordDecodeError::InvalidVarint { field });
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(((value >> 1) as i64) ^ -((value & 1) as i64));
        }
    }
    Err(RecordDecodeError::InvalidVarint { field })
}

fn check_limit(
    kind: RecordDecodeLimit,
    limit: usize,
    actual: usize,
) -> Result<(), RecordDecodeError> {
    if actual > limit {
        Err(RecordDecodeError::LimitExceeded {
            kind,
            limit,
            actual,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailing_decoded_limit_failure_is_sticky_and_preserves_progress() {
        let limits = RecordDecodeLimits {
            max_record_bytes: 0,
            max_decoded_bytes: 0,
            max_records: 0,
            max_key_bytes: 0,
            max_value_bytes: 0,
            max_header_key_bytes: 0,
            max_header_value_bytes: 0,
            max_headers: 0,
            max_work_units: 1,
        };
        let mut records = Records {
            source: &[0],
            position: 0,
            declared: 0,
            emitted: 0,
            budget: RecordDecodeBudget::new(limits),
            terminal: false,
            failure: None,
        };
        let expected = RecordDecodeError::LimitExceeded {
            kind: RecordDecodeLimit::DecodedBytes,
            limit: 0,
            actual: 1,
        };

        assert_eq!(expected, records.next_record().expect_err("decoded limit"));
        assert_eq!(1, records.progress().decoded_bytes);
        assert_eq!(expected, records.next_record().expect_err("sticky failure"));
        assert_eq!(1, records.progress().decoded_bytes);
    }
}
