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

//! Allocation-free, borrowed views of Kafka magic-v2 record batches.
//!
//! [`RecordSet`] validates the complete byte slice before exposing it. Validation walks every
//! batch boundary and verifies every CRC exactly once while retaining no collection whose capacity
//! comes from the peer. A later [`Batches`] traversal only walks the already validated boundaries;
//! it does not repeat CRC work or create a second resource budget.
//!
//! Only Kafka record batch magic 2 is accepted. Earlier message-set encodings use a different wire
//! structure and must be decoded by a format-specific implementation.

use std::ops::Range;

use crate::{DecodeLimit, DecodeLimits, Error, Result, borrowed::DecodeBudget};

pub(crate) mod records;

pub use records::{
    HeaderRef, Headers, RecordDecodeError, RecordDecodeLimit, RecordDecodeLimits, RecordRef,
    Records,
};

/// Offset of `base_offset`, the first field in Kafka's magic-v2 record batch layout.
const BASE_OFFSET_OFFSET: usize = 0;
/// Width of `base_offset`, which Kafka encodes as a signed 64-bit integer.
const BASE_OFFSET_BYTES: usize = size_of::<i64>();
/// Offset of `batch_length`, immediately after the fixed-width `base_offset`.
const BATCH_LENGTH_OFFSET: usize = BASE_OFFSET_OFFSET + BASE_OFFSET_BYTES;
/// Width of `batch_length`, which Kafka encodes as a signed 32-bit integer.
const BATCH_LENGTH_BYTES: usize = size_of::<i32>();
/// Offset of `partition_leader_epoch`, the first byte counted by `batch_length`.
const PARTITION_LEADER_EPOCH_OFFSET: usize = BATCH_LENGTH_OFFSET + BATCH_LENGTH_BYTES;
/// Width of `partition_leader_epoch`, which Kafka encodes as a signed 32-bit integer.
const PARTITION_LEADER_EPOCH_BYTES: usize = size_of::<i32>();
/// Offset of the record-batch magic byte, immediately after `partition_leader_epoch`.
const MAGIC_OFFSET: usize = PARTITION_LEADER_EPOCH_OFFSET + PARTITION_LEADER_EPOCH_BYTES;
/// Width of the signed record-batch magic field.
const MAGIC_BYTES: usize = size_of::<i8>();
/// The record-batch magic supported by this borrowed representation.
const MAGIC_V2: i8 = 2;
/// Offset of the declared CRC-32C, immediately after the magic byte.
const CRC_OFFSET: usize = MAGIC_OFFSET + MAGIC_BYTES;
/// Width of Kafka's unsigned CRC-32C field.
const CRC_BYTES: usize = size_of::<u32>();
/// Offset of record-batch attributes and the first CRC-covered byte.
const ATTRIBUTES_OFFSET: usize = CRC_OFFSET + CRC_BYTES;
/// Width of record-batch attributes, which Kafka encodes as a signed 16-bit bit field.
const ATTRIBUTES_BYTES: usize = size_of::<i16>();
/// Offset of `last_offset_delta`, immediately after attributes.
const LAST_OFFSET_DELTA_OFFSET: usize = ATTRIBUTES_OFFSET + ATTRIBUTES_BYTES;
/// Width of `last_offset_delta`, which Kafka encodes as a signed 32-bit integer.
const LAST_OFFSET_DELTA_BYTES: usize = size_of::<i32>();
/// Offset of `base_timestamp`, immediately after `last_offset_delta`.
const BASE_TIMESTAMP_OFFSET: usize = LAST_OFFSET_DELTA_OFFSET + LAST_OFFSET_DELTA_BYTES;
/// Width of Kafka's signed 64-bit timestamp fields.
const TIMESTAMP_BYTES: usize = size_of::<i64>();
/// Offset of `max_timestamp`, immediately after `base_timestamp`.
const MAX_TIMESTAMP_OFFSET: usize = BASE_TIMESTAMP_OFFSET + TIMESTAMP_BYTES;
/// Offset of `producer_id`, immediately after `max_timestamp`.
const PRODUCER_ID_OFFSET: usize = MAX_TIMESTAMP_OFFSET + TIMESTAMP_BYTES;
/// Width of `producer_id`, which Kafka encodes as a signed 64-bit integer.
const PRODUCER_ID_BYTES: usize = size_of::<i64>();
/// Offset of `producer_epoch`, immediately after `producer_id`.
const PRODUCER_EPOCH_OFFSET: usize = PRODUCER_ID_OFFSET + PRODUCER_ID_BYTES;
/// Width of `producer_epoch`, which Kafka encodes as a signed 16-bit integer.
const PRODUCER_EPOCH_BYTES: usize = size_of::<i16>();
/// Offset of `base_sequence`, immediately after `producer_epoch`.
const BASE_SEQUENCE_OFFSET: usize = PRODUCER_EPOCH_OFFSET + PRODUCER_EPOCH_BYTES;
/// Width of `base_sequence`, which Kafka encodes as a signed 32-bit integer.
const BASE_SEQUENCE_BYTES: usize = size_of::<i32>();
/// Offset of the peer-declared record count, immediately after `base_sequence`.
const RECORD_COUNT_OFFSET: usize = BASE_SEQUENCE_OFFSET + BASE_SEQUENCE_BYTES;
/// Width of the signed INT32 record count in a magic-v2 batch.
const RECORD_COUNT_BYTES: usize = size_of::<i32>();
/// Offset of encoded record data, immediately after the fixed record count.
const RECORD_DATA_OFFSET: usize = RECORD_COUNT_OFFSET + RECORD_COUNT_BYTES;
/// Bytes preceding the body whose size is declared by `batch_length`.
const BATCH_PREFIX_BYTES: usize = PARTITION_LEADER_EPOCH_OFFSET;
/// Bytes in the fixed magic-v2 body, derived from the protocol field layout above.
const FIXED_BATCH_BODY_BYTES: usize = RECORD_DATA_OFFSET - BATCH_PREFIX_BYTES;
/// Bytes in the smallest complete magic-v2 batch, which has empty record data.
const MIN_BATCH_BYTES: usize = RECORD_DATA_OFFSET;
/// Offset of the first CRC-covered byte; Kafka excludes the prefix, magic, and CRC itself.
const CRC_DATA_OFFSET: usize = ATTRIBUTES_OFFSET;

/// A completely validated, magic-v2 Kafka record set borrowing its wire bytes.
///
/// Construction is the only validation boundary. It scans all batch lengths, magic bytes, and
/// CRCs under one cumulative limit budget. The representation is constant-sized regardless of the
/// number of batches or the peer-declared number of records.
#[derive(Clone, Copy, Debug)]
pub struct RecordSet<'a> {
    bytes: &'a [u8],
    validation: Validation,
}

/// Proof retained from the single complete validation pass.
///
/// Keeping only aggregate metadata makes the proof independent of peer-controlled cardinality.
#[derive(Clone, Copy, Debug)]
struct Validation {
    batch_count: usize,
}

impl<'a> RecordSet<'a> {
    /// Validate a record set using [`DecodeLimits::default`].
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        Self::from_bytes_with_limits(bytes, DecodeLimits::default())
    }

    /// Validate a record set with explicit resource limits.
    ///
    /// [`DecodeLimits::max_bytes`] bounds the record-set bytes, while
    /// [`DecodeLimits::max_sequence_elements`] bounds both the number of batches and each
    /// peer-declared record count. [`DecodeLimits::max_work_units`] charges only batches actually
    /// inspected because this layer does not visit individual records; a later record decoder must
    /// charge the records it really traverses. Declared counts are validated but never used to
    /// allocate or traverse. CRC work is linear in `bytes.len()` and is therefore already bounded
    /// by `max_bytes`.
    pub fn from_bytes_with_limits(bytes: &'a [u8], limits: DecodeLimits) -> Result<Self> {
        limits.validate()?;
        let mut budget = DecodeBudget::new(limits);
        let batch_count = validate_with_budget(bytes, &mut budget)?;
        Ok(Self {
            bytes,
            validation: Validation { batch_count },
        })
    }

    /// The exact validated record-set bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Number of batches found by the validation pass.
    ///
    /// This count is derived from validated byte boundaries, not a peer-declared cardinality.
    pub fn batch_count(&self) -> usize {
        self.validation.batch_count
    }

    /// Traverse the already validated batches without recomputing CRCs.
    pub fn batches(&self) -> Batches<'a> {
        Batches {
            bytes: self.bytes,
            offset: 0,
            remaining: self.validation.batch_count,
        }
    }
}

pub(crate) fn validate_with_budget(bytes: &[u8], budget: &mut DecodeBudget) -> Result<usize> {
    let limits = budget.limits();
    check_limit(DecodeLimit::Bytes, limits.max_bytes, bytes.len())?;

    let mut offset = 0usize;
    let mut local_batch_count = 0usize;
    while offset < bytes.len() {
        let batch = validate_batch(bytes, offset, limits)?;
        budget.charge_batch()?;
        local_batch_count = local_batch_count.checked_add(1).ok_or(Error::Overflow)?;
        offset = batch.end;
    }

    debug_assert_eq!(offset, bytes.len());
    Ok(local_batch_count)
}

/// Allocation-free iterator over the batches in a validated [`RecordSet`].
///
/// Iteration is infallible because [`RecordSet`] construction established every boundary. It reads
/// each batch length again only to advance through the borrowed slice; magic and CRC validation are
/// deliberately not repeated.
#[derive(Clone, Debug)]
pub struct Batches<'a> {
    bytes: &'a [u8],
    offset: usize,
    remaining: usize,
}

impl<'a> Iterator for Batches<'a> {
    type Item = Batch<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        // `RecordSet` validated this field and the resulting boundary. Re-reading the four bytes
        // keeps the view O(1) instead of retaining a peer-cardinality-sized range table.
        let batch_length = read_i32(self.bytes, self.offset + BATCH_LENGTH_OFFSET)
            .expect("validated record batch length must remain readable");
        let batch_length = usize::try_from(batch_length)
            .expect("validated record batch length must remain non-negative");
        let end = self
            .offset
            .checked_add(BATCH_PREFIX_BYTES)
            .and_then(|prefix_end| prefix_end.checked_add(batch_length))
            .expect("validated record batch boundary must remain representable");
        let range = self.offset..end;

        self.offset = end;
        self.remaining -= 1;
        Some(Batch {
            record_set: self.bytes,
            range,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for Batches<'_> {}

/// A validated magic-v2 batch borrowing its exact wire range from a [`RecordSet`].
#[derive(Clone, Debug)]
pub struct Batch<'a> {
    record_set: &'a [u8],
    range: Range<usize>,
}

impl<'a> Batch<'a> {
    /// Complete batch bytes, beginning with `base_offset` and `batch_length`.
    pub fn as_bytes(&self) -> &'a [u8] {
        &self.record_set[self.range.clone()]
    }

    /// Batch range relative to [`RecordSet::as_bytes`].
    pub fn range(&self) -> Range<usize> {
        self.range.clone()
    }

    /// Encoded record data, compressed according to [`Self::attributes`].
    pub fn record_data(&self) -> &'a [u8] {
        &self.as_bytes()[RECORD_DATA_OFFSET..]
    }

    /// Record-data range relative to [`RecordSet::as_bytes`].
    pub fn record_data_range(&self) -> Range<usize> {
        (self.range.start + RECORD_DATA_OFFSET)..self.range.end
    }

    /// Base offset encoded in the batch.
    pub fn base_offset(&self) -> i64 {
        validated_i64(self.as_bytes(), BASE_OFFSET_OFFSET)
    }

    /// Declared bytes after the `batch_length` field.
    pub fn batch_length(&self) -> i32 {
        validated_i32(self.as_bytes(), BATCH_LENGTH_OFFSET)
    }

    /// Partition leader epoch encoded in the batch.
    pub fn partition_leader_epoch(&self) -> i32 {
        validated_i32(self.as_bytes(), PARTITION_LEADER_EPOCH_OFFSET)
    }

    /// Record batch magic. This representation only constructs batches with magic 2.
    pub fn magic(&self) -> i8 {
        self.as_bytes()[MAGIC_OFFSET] as i8
    }

    /// Declared CRC-32C, verified when the containing [`RecordSet`] was constructed.
    pub fn crc(&self) -> u32 {
        validated_u32(self.as_bytes(), CRC_OFFSET)
    }

    /// Record batch attributes, including the compression codec bits.
    pub fn attributes(&self) -> i16 {
        validated_i16(self.as_bytes(), ATTRIBUTES_OFFSET)
    }

    /// Last record offset relative to [`Self::base_offset`].
    pub fn last_offset_delta(&self) -> i32 {
        validated_i32(self.as_bytes(), LAST_OFFSET_DELTA_OFFSET)
    }

    /// Base timestamp for record timestamp deltas.
    pub fn base_timestamp(&self) -> i64 {
        validated_i64(self.as_bytes(), BASE_TIMESTAMP_OFFSET)
    }

    /// Maximum timestamp declared by the batch.
    pub fn max_timestamp(&self) -> i64 {
        validated_i64(self.as_bytes(), MAX_TIMESTAMP_OFFSET)
    }

    /// Idempotent producer id, or negative one for a non-idempotent batch.
    pub fn producer_id(&self) -> i64 {
        validated_i64(self.as_bytes(), PRODUCER_ID_OFFSET)
    }

    /// Idempotent producer epoch, or negative one for a non-idempotent batch.
    pub fn producer_epoch(&self) -> i16 {
        validated_i16(self.as_bytes(), PRODUCER_EPOCH_OFFSET)
    }

    /// Idempotent base sequence, or negative one for a non-idempotent batch.
    pub fn base_sequence(&self) -> i32 {
        validated_i32(self.as_bytes(), BASE_SEQUENCE_OFFSET)
    }

    /// Peer-declared record count.
    ///
    /// The value is exposed as protocol metadata but is never used to reserve memory or control
    /// batch traversal.
    pub fn record_count(&self) -> i32 {
        validated_i32(self.as_bytes(), RECORD_COUNT_OFFSET)
    }
}

fn validate_batch(bytes: &[u8], start: usize, limits: DecodeLimits) -> Result<Range<usize>> {
    let available = bytes.len().saturating_sub(start);
    if available < BATCH_PREFIX_BYTES {
        return Err(Error::Message(format!(
            "record set has {available} trailing bytes, fewer than the {BATCH_PREFIX_BYTES}-byte batch prefix"
        )));
    }

    let batch_length = read_i32(bytes, start + BATCH_LENGTH_OFFSET)?;
    let batch_length = usize::try_from(batch_length)
        .map_err(|_| Error::Message(format!("negative record batch length {batch_length}")))?;
    if batch_length < FIXED_BATCH_BODY_BYTES {
        return Err(Error::Message(format!(
            "record batch length {batch_length} is smaller than the {FIXED_BATCH_BODY_BYTES}-byte magic-v2 header"
        )));
    }

    let end = start
        .checked_add(BATCH_PREFIX_BYTES)
        .and_then(|prefix_end| prefix_end.checked_add(batch_length))
        .ok_or(Error::Overflow)?;
    if end > bytes.len() {
        return Err(Error::Message(format!(
            "record batch declares {} bytes but only {available} remain",
            BATCH_PREFIX_BYTES + batch_length
        )));
    }

    let batch = &bytes[start..end];
    debug_assert!(batch.len() >= MIN_BATCH_BYTES);
    let magic = read_i8(batch, MAGIC_OFFSET)?;
    if magic != MAGIC_V2 {
        return Err(Error::Message(format!(
            "unsupported record batch magic {magic}; borrowed batches require magic {MAGIC_V2}"
        )));
    }

    let declared_record_count = read_i32(batch, RECORD_COUNT_OFFSET)?;
    let record_count = usize::try_from(declared_record_count).map_err(|_| {
        Error::Message(format!(
            "negative record count {declared_record_count} in magic-v2 batch"
        ))
    })?;
    check_limit(
        DecodeLimit::SequenceElements,
        limits.max_sequence_elements,
        record_count,
    )?;

    let declared_crc = read_u32(batch, CRC_OFFSET)?;
    let computed_crc = crc32c(&batch[CRC_DATA_OFFSET..]);
    if declared_crc != computed_crc {
        return Err(Error::Message(format!(
            "record batch CRC mismatch: declared {declared_crc:#010x}, computed {computed_crc:#010x}"
        )));
    }

    Ok(start..end)
}

fn check_limit(kind: DecodeLimit, limit: usize, actual: usize) -> Result<()> {
    if actual > limit {
        Err(Error::DecodeLimitExceeded {
            kind,
            limit,
            actual,
        })
    } else {
        Ok(())
    }
}

fn crc32c(bytes: &[u8]) -> u32 {
    let mut digest = crc_fast::Digest::new(crc_fast::CrcAlgorithm::Crc32Iscsi);
    digest.update(bytes);
    digest.finalize() as u32
}

fn read_i8(bytes: &[u8], offset: usize) -> Result<i8> {
    bytes
        .get(offset)
        .copied()
        .map(|value| value as i8)
        .ok_or(Error::Overflow)
}

fn read_i16(bytes: &[u8], offset: usize) -> Result<i16> {
    Ok(i16::from_be_bytes(read_array(bytes, offset)?))
}

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32> {
    Ok(i32::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(read_array(bytes, offset)?))
}

fn read_i64(bytes: &[u8], offset: usize) -> Result<i64> {
    Ok(i64::from_be_bytes(read_array(bytes, offset)?))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    let end = offset.checked_add(N).ok_or(Error::Overflow)?;
    Ok(bytes.get(offset..end).ok_or(Error::Overflow)?.try_into()?)
}

fn validated_i16(bytes: &[u8], offset: usize) -> i16 {
    read_i16(bytes, offset).expect("validated record batch field must remain readable")
}

fn validated_i32(bytes: &[u8], offset: usize) -> i32 {
    read_i32(bytes, offset).expect("validated record batch field must remain readable")
}

fn validated_u32(bytes: &[u8], offset: usize) -> u32 {
    read_u32(bytes, offset).expect("validated record batch field must remain readable")
}

fn validated_i64(bytes: &[u8], offset: usize) -> i64 {
    read_i64(bytes, offset).expect("validated record batch field must remain readable")
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use bytes::{BufMut as _, BytesMut};

    use super::*;

    /// Distinct nonzero base offset proving the accessor does not return a default.
    const TEST_BASE_OFFSET: i64 = 23;
    /// Distinct leader epoch proving the adjacent magic byte does not shift the view.
    const TEST_PARTITION_LEADER_EPOCH: i32 = 7;
    /// Compression-bit-bearing attributes proving the CRC-covered header offset.
    const TEST_ATTRIBUTES: i16 = 3;
    /// Distinct offset delta proving the four-byte field following attributes.
    const TEST_LAST_OFFSET_DELTA: i32 = 11;
    /// Millisecond-scale base timestamp proving signed 64-bit field decoding.
    const TEST_BASE_TIMESTAMP: i64 = 1_726_000_000_000;
    /// Timestamp distinct from the base so the two adjacent fields cannot be confused.
    const TEST_MAX_TIMESTAMP: i64 = 1_726_000_000_123;
    /// Non-default producer id proving the first idempotent-producer field offset.
    const TEST_PRODUCER_ID: i64 = 99;
    /// Non-default producer epoch proving its signed 16-bit field width.
    const TEST_PRODUCER_EPOCH: i16 = 4;
    /// Non-default base sequence proving the field before record count.
    const TEST_BASE_SEQUENCE: i32 = 31;

    fn batch(record_count: i32, record_data: &[u8]) -> Vec<u8> {
        let batch_length = FIXED_BATCH_BODY_BYTES + record_data.len();
        let mut encoded = BytesMut::with_capacity(BATCH_PREFIX_BYTES + batch_length);
        encoded.put_i64(TEST_BASE_OFFSET);
        encoded.put_i32(i32::try_from(batch_length).expect("small test batch"));
        encoded.put_i32(TEST_PARTITION_LEADER_EPOCH);
        encoded.put_i8(MAGIC_V2);
        encoded.put_u32(0);
        encoded.put_i16(TEST_ATTRIBUTES);
        encoded.put_i32(TEST_LAST_OFFSET_DELTA);
        encoded.put_i64(TEST_BASE_TIMESTAMP);
        encoded.put_i64(TEST_MAX_TIMESTAMP);
        encoded.put_i64(TEST_PRODUCER_ID);
        encoded.put_i16(TEST_PRODUCER_EPOCH);
        encoded.put_i32(TEST_BASE_SEQUENCE);
        encoded.put_i32(record_count);
        encoded.extend_from_slice(record_data);

        assert_eq!(BATCH_PREFIX_BYTES + batch_length, encoded.len());
        let computed = crc32c(&encoded[CRC_DATA_OFFSET..]);
        encoded[CRC_OFFSET..CRC_OFFSET + CRC_BYTES].copy_from_slice(&computed.to_be_bytes());
        encoded.to_vec()
    }

    fn joined(batches: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
        batches.into_iter().flatten().collect()
    }

    #[test]
    fn empty_record_set_and_exact_minimum_batch_are_valid() -> Result<()> {
        let empty = RecordSet::from_bytes(&[])?;
        assert_eq!(0, empty.batch_count());
        assert_eq!(0, empty.batches().len());

        let encoded = batch(0, &[]);
        assert_eq!(MIN_BATCH_BYTES, encoded.len());
        let records = RecordSet::from_bytes(&encoded)?;
        let one = records.batches().next().expect("one batch");
        assert_eq!(FIXED_BATCH_BODY_BYTES as i32, one.batch_length());
        assert!(one.record_data().is_empty());
        assert_eq!(0, one.record_count());
        assert_eq!(0..MIN_BATCH_BYTES, one.range());
        Ok(())
    }

    #[test]
    fn borrowed_views_preserve_metadata_and_share_input_storage() -> Result<()> {
        let encoded = batch(2, b"encoded-record-data");
        let start = encoded.as_ptr() as usize;
        let end = start + encoded.len();
        let records = RecordSet::from_bytes(&encoded)?;
        let view = records.batches().next().expect("one batch");

        assert_eq!(TEST_BASE_OFFSET, view.base_offset());
        assert_eq!(TEST_PARTITION_LEADER_EPOCH, view.partition_leader_epoch());
        assert_eq!(MAGIC_V2, view.magic());
        assert_eq!(TEST_ATTRIBUTES, view.attributes());
        assert_eq!(TEST_LAST_OFFSET_DELTA, view.last_offset_delta());
        assert_eq!(TEST_BASE_TIMESTAMP, view.base_timestamp());
        assert_eq!(TEST_MAX_TIMESTAMP, view.max_timestamp());
        assert_eq!(TEST_PRODUCER_ID, view.producer_id());
        assert_eq!(TEST_PRODUCER_EPOCH, view.producer_epoch());
        assert_eq!(TEST_BASE_SEQUENCE, view.base_sequence());
        assert_eq!(2, view.record_count());
        assert_eq!(crc32c(&encoded[CRC_DATA_OFFSET..]), view.crc());
        assert_eq!(&encoded[..], view.as_bytes());
        assert_eq!(b"encoded-record-data", view.record_data());
        assert!((start..end).contains(&(records.as_bytes().as_ptr() as usize)));
        assert!((start..end).contains(&(view.as_bytes().as_ptr() as usize)));
        assert!((start..end).contains(&(view.record_data().as_ptr() as usize)));
        Ok(())
    }

    #[test]
    fn multiple_batches_have_exact_ranges_and_size_hints() -> Result<()> {
        let first = batch(0, &[]);
        let second = batch(1, b"record");
        let first_len = first.len();
        let encoded = joined([first, second]);
        let records = RecordSet::from_bytes(&encoded)?;
        let mut batches = records.batches();

        assert_eq!(2, records.batch_count());
        assert_eq!((2, Some(2)), batches.size_hint());
        assert_eq!(0..first_len, batches.next().expect("first").range());
        assert_eq!((1, Some(1)), batches.size_hint());
        assert_eq!(
            first_len..encoded.len(),
            batches.next().expect("second").range()
        );
        assert!(batches.next().is_none());
        Ok(())
    }

    #[test]
    fn negative_short_huge_and_truncated_lengths_are_rejected() {
        let valid = batch(0, &[]);

        let mut negative = valid.clone();
        negative[BATCH_LENGTH_OFFSET..BATCH_LENGTH_OFFSET + BATCH_LENGTH_BYTES]
            .copy_from_slice(&(-1i32).to_be_bytes());
        assert!(RecordSet::from_bytes(&negative).is_err());

        let mut short = valid.clone();
        short[BATCH_LENGTH_OFFSET..BATCH_LENGTH_OFFSET + BATCH_LENGTH_BYTES]
            .copy_from_slice(&(FIXED_BATCH_BODY_BYTES as i32 - 1).to_be_bytes());
        assert!(RecordSet::from_bytes(&short).is_err());

        let mut huge = valid.clone();
        huge[BATCH_LENGTH_OFFSET..BATCH_LENGTH_OFFSET + BATCH_LENGTH_BYTES]
            .copy_from_slice(&i32::MAX.to_be_bytes());
        assert!(RecordSet::from_bytes(&huge).is_err());

        for length in 1..valid.len() {
            assert!(
                RecordSet::from_bytes(&valid[..length]).is_err(),
                "truncation at {length} bytes unexpectedly validated"
            );
        }
    }

    #[test]
    fn corrupt_magic_and_crc_are_rejected() {
        let valid = batch(0, &[]);

        let mut bad_magic = valid.clone();
        bad_magic[MAGIC_OFFSET] = 1;
        let error = RecordSet::from_bytes(&bad_magic).expect_err("magic 1");
        assert!(error.to_string().contains("magic 1"));

        let mut bad_declared_crc = valid.clone();
        bad_declared_crc[CRC_OFFSET] ^= 1;
        let error = RecordSet::from_bytes(&bad_declared_crc).expect_err("declared CRC");
        assert!(error.to_string().contains("CRC mismatch"));

        let mut bad_crc_data = valid;
        bad_crc_data[ATTRIBUTES_OFFSET] ^= 1;
        let error = RecordSet::from_bytes(&bad_crc_data).expect_err("CRC-covered data");
        assert!(error.to_string().contains("CRC mismatch"));
    }

    #[test]
    fn trailing_bytes_are_not_silently_ignored() {
        let mut encoded = batch(0, &[]);
        encoded.push(0);
        let error = RecordSet::from_bytes(&encoded).expect_err("trailing byte");
        assert!(error.to_string().contains("trailing bytes"));
    }

    #[test]
    fn record_counts_are_signed_validated_metadata_never_capacities() -> Result<()> {
        let negative = batch(-1, &[]);
        let error = RecordSet::from_bytes(&negative).expect_err("negative count");
        assert!(error.to_string().contains("negative record count -1"));

        let huge = batch(i32::MAX, &[]);
        assert!(matches!(
            RecordSet::from_bytes(&huge),
            Err(Error::DecodeLimitExceeded {
                kind: DecodeLimit::SequenceElements,
                actual,
                ..
            }) if actual == i32::MAX as usize
        ));

        let declared = 17;
        let encoded = batch(declared, &[]);
        let limits = DecodeLimits {
            max_sequence_elements: declared as usize,
            ..DecodeLimits::default()
        };
        let records = RecordSet::from_bytes_with_limits(&encoded, limits)?;
        assert_eq!(
            declared,
            records.batches().next().expect("batch").record_count()
        );
        Ok(())
    }

    #[test]
    fn byte_batch_and_cumulative_work_limits_are_independent() {
        let first = batch(0, &[]);
        let encoded = joined([first.clone(), first]);

        let byte_limit = DecodeLimits {
            max_bytes: encoded.len() - 1,
            ..DecodeLimits::default()
        };
        assert!(matches!(
            RecordSet::from_bytes_with_limits(&encoded, byte_limit),
            Err(Error::DecodeLimitExceeded {
                kind: DecodeLimit::Bytes,
                ..
            })
        ));

        let batch_limit = DecodeLimits {
            max_sequence_elements: 1,
            ..DecodeLimits::default()
        };
        assert!(matches!(
            RecordSet::from_bytes_with_limits(&encoded, batch_limit),
            Err(Error::DecodeLimitExceeded {
                kind: DecodeLimit::SequenceElements,
                actual: 2,
                ..
            })
        ));

        let work_limit = DecodeLimits {
            max_work_units: 1,
            ..DecodeLimits::default()
        };
        assert!(matches!(
            RecordSet::from_bytes_with_limits(&encoded, work_limit),
            Err(Error::DecodeLimitExceeded {
                kind: DecodeLimit::WorkUnits,
                actual: 2,
                ..
            })
        ));
    }

    #[test]
    fn view_storage_is_cardinality_independent() -> Result<()> {
        /// Enough batches to expose any representation that retained one range per batch.
        const MANY_BATCHES: usize = 4_096;
        let one = batch(0, &[]);
        let encoded = one.repeat(MANY_BATCHES);
        let records = RecordSet::from_bytes(&encoded)?;

        assert_eq!(MANY_BATCHES, records.batch_count());
        assert_eq!(MANY_BATCHES, records.batches().count());
        assert_eq!(3 * size_of::<usize>(), size_of::<RecordSet<'static>>());
        assert_eq!(4 * size_of::<usize>(), size_of::<Batches<'static>>());
        Ok(())
    }
}
