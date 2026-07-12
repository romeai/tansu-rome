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

//! Shared bounded cursor for generated borrowed request views.
//!
//! The Kafka JSON descriptors decide which fields generated views read and in which order. This
//! module owns only primitive wire operations, checked ranges, and one cumulative structural-work
//! budget, keeping resource policy independent from any particular request schema.

use std::{ops::Range, str};

use bytes::Bytes;

use crate::{DecodeLimit, DecodeLimits, Error, Result};

/// Width of Kafka's signed frame-length prefix.
const FRAME_LENGTH_BYTES: usize = size_of::<i32>();

#[derive(Clone, Debug)]
pub(crate) struct RequestHead {
    pub(crate) api_version: i16,
    pub(crate) correlation_id: i32,
    pub(crate) client_id: Option<Range<usize>>,
    pub(crate) flexible: bool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Sequence {
    pub(crate) count: usize,
    pub(crate) elements_start: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct Cursor<'a> {
    bytes: &'a [u8],
    budget: DecodeBudget,
    position: usize,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DecodeBudget {
    limits: DecodeLimits,
    work_units: usize,
}

impl DecodeBudget {
    pub(crate) fn new(limits: DecodeLimits) -> Self {
        Self {
            limits,
            work_units: 0,
        }
    }

    pub(crate) fn limits(&self) -> DecodeLimits {
        self.limits
    }

    pub(crate) fn charge(&mut self, units: usize) -> Result<()> {
        self.work_units = self.work_units.checked_add(units).ok_or(Error::Overflow)?;
        check_limit(
            DecodeLimit::TotalWorkUnits,
            self.limits.max_total_work_units,
            self.work_units,
        )
    }
}

// The generator emits calls only for primitive kinds present in today's record-bearing request
// schemas. Keeping the complete primitive cursor here lets a descriptor add another primitive
// without requiring a handwritten protocol path or silently falling back to owned decoding.
#[allow(dead_code)]
impl<'a> Cursor<'a> {
    pub(crate) fn request(
        frame: &'a Bytes,
        limits: DecodeLimits,
        expected_api_key: i16,
        min_version: i16,
        max_version: i16,
        flexible_start: i16,
        flexible_end: i16,
    ) -> Result<(RequestHead, Self)> {
        limits.validate()?;
        check_limit(DecodeLimit::FrameBytes, limits.max_frame_bytes, frame.len())?;
        if frame.len() < FRAME_LENGTH_BYTES {
            return Err(Error::FrameSizeMismatch {
                declared: 0,
                actual: frame.len().saturating_sub(FRAME_LENGTH_BYTES),
            });
        }

        let declared_payload_bytes = i32::from_be_bytes(frame[..FRAME_LENGTH_BYTES].try_into()?);
        let declared_payload_bytes = usize::try_from(declared_payload_bytes)
            .map_err(|_| Error::InvalidFrameSize(declared_payload_bytes))?;
        let expected_frame_bytes = declared_payload_bytes
            .checked_add(FRAME_LENGTH_BYTES)
            .ok_or(Error::Overflow)?;
        if expected_frame_bytes != frame.len() {
            return Err(Error::FrameSizeMismatch {
                declared: declared_payload_bytes,
                actual: frame.len().saturating_sub(FRAME_LENGTH_BYTES),
            });
        }

        let mut cursor = Self::validating(frame, limits, FRAME_LENGTH_BYTES);
        let api_key = cursor.i16()?;
        if api_key != expected_api_key {
            return Err(Error::NoSuchRequest(api_key));
        }
        let api_version = cursor.i16()?;
        if !(min_version..=max_version).contains(&api_version) {
            return Err(Error::Message(format!(
                "unsupported request version {api_version}; expected {min_version}..={max_version}"
            )));
        }
        let flexible = (flexible_start..=flexible_end).contains(&api_version);
        let correlation_id = cursor.i32()?;
        let client_id = cursor.nullable_legacy_string()?;
        if flexible {
            cursor.tagged_fields()?;
        }

        Ok((
            RequestHead {
                api_version,
                correlation_id,
                client_id,
                flexible,
            },
            cursor,
        ))
    }

    pub(crate) fn at(bytes: &'a [u8], limits: DecodeLimits, position: usize) -> Self {
        Self {
            bytes,
            budget: DecodeBudget::new(limits),
            position,
        }
    }

    fn validating(bytes: &'a [u8], limits: DecodeLimits, position: usize) -> Self {
        Self {
            bytes,
            budget: DecodeBudget::new(limits),
            position,
        }
    }

    pub(crate) fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub(crate) fn limits(&self) -> DecodeLimits {
        self.budget.limits()
    }

    pub(crate) fn finish(&self) -> Result<()> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::TrailingFrameBytes(self.bytes.len() - self.position))
        }
    }

    pub(crate) fn i8(&mut self) -> Result<i8> {
        Ok(self.take(size_of::<i8>())?[0] as i8)
    }

    pub(crate) fn i16(&mut self) -> Result<i16> {
        Ok(i16::from_be_bytes(self.take(size_of::<i16>())?.try_into()?))
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(size_of::<u16>())?.try_into()?))
    }

    pub(crate) fn i32(&mut self) -> Result<i32> {
        Ok(i32::from_be_bytes(self.take(size_of::<i32>())?.try_into()?))
    }

    pub(crate) fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_be_bytes(self.take(size_of::<i64>())?.try_into()?))
    }

    pub(crate) fn f64(&mut self) -> Result<f64> {
        Ok(f64::from_bits(u64::from_be_bytes(
            self.take(size_of::<f64>())?.try_into()?,
        )))
    }

    pub(crate) fn boolean(&mut self) -> Result<bool> {
        match self.take(size_of::<u8>())?[0] {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(Error::Message(format!(
                "invalid Kafka boolean value {value}; expected 0 or 1"
            ))),
        }
    }

    pub(crate) fn uuid(&mut self) -> Result<[u8; 16]> {
        Ok(self.take(size_of::<[u8; 16]>())?.try_into()?)
    }

    pub(crate) fn string(
        &mut self,
        flexible: bool,
        nullable: bool,
    ) -> Result<Option<Range<usize>>> {
        let length = if flexible {
            self.compact_length(nullable, "string")?
        } else {
            self.legacy_i16_length(nullable, "string")?
        };
        length.map(|length| self.string_bytes(length)).transpose()
    }

    pub(crate) fn nullable_legacy_string(&mut self) -> Result<Option<Range<usize>>> {
        let length = self.legacy_i16_length(true, "string")?;
        length.map(|length| self.string_bytes(length)).transpose()
    }

    pub(crate) fn bytes_field(
        &mut self,
        flexible: bool,
        nullable: bool,
    ) -> Result<Option<Range<usize>>> {
        let length = if flexible {
            self.compact_length(nullable, "bytes")?
        } else {
            self.legacy_i32_length(nullable, "bytes")?
        };
        length.map(|length| self.byte_range(length)).transpose()
    }

    pub(crate) fn sequence(&mut self, flexible: bool, nullable: bool) -> Result<Option<Sequence>> {
        let count = if flexible {
            self.compact_length(nullable, "array")?
        } else {
            self.legacy_i32_length(nullable, "array")?
        };
        count
            .map(|count| {
                check_limit(
                    DecodeLimit::SequenceElements,
                    self.budget.limits().max_sequence_elements,
                    count,
                )?;
                self.charge(count)?;
                Ok(Sequence {
                    count,
                    elements_start: self.position,
                })
            })
            .transpose()
    }

    pub(crate) fn tagged_fields(&mut self) -> Result<()> {
        let count = self.unsigned_varint()? as usize;
        check_limit(
            DecodeLimit::SequenceElements,
            self.budget.limits().max_sequence_elements,
            count,
        )?;
        self.charge(count)?;

        let mut previous = None;
        for _ in 0..count {
            let tag = self.unsigned_varint()?;
            if previous.is_some_and(|previous| tag <= previous) {
                return Err(Error::Message(
                    "Kafka tag ids must be strictly increasing".into(),
                ));
            }
            previous = Some(tag);
            let length = self.unsigned_varint()? as usize;
            check_limit(DecodeLimit::Bytes, self.budget.limits().max_bytes, length)?;
            let _ = self.take(length)?;
        }
        Ok(())
    }

    fn legacy_i16_length(&mut self, nullable: bool, kind: &str) -> Result<Option<usize>> {
        let encoded = self.i16()?;
        if encoded == -1 && nullable {
            return Ok(None);
        }
        usize::try_from(encoded).map(Some).map_err(|_| {
            Error::Message(format!("invalid negative non-null {kind} length {encoded}"))
        })
    }

    fn legacy_i32_length(&mut self, nullable: bool, kind: &str) -> Result<Option<usize>> {
        let encoded = self.i32()?;
        if encoded == -1 && nullable {
            return Ok(None);
        }
        usize::try_from(encoded).map(Some).map_err(|_| {
            Error::Message(format!("invalid negative non-null {kind} length {encoded}"))
        })
    }

    fn compact_length(&mut self, nullable: bool, kind: &str) -> Result<Option<usize>> {
        let encoded = self.unsigned_varint()?;
        if encoded == 0 && nullable {
            return Ok(None);
        }
        encoded
            .checked_sub(1)
            .map(|length| Some(length as usize))
            .ok_or_else(|| Error::Message(format!("null non-nullable compact {kind}")))
    }

    fn string_bytes(&mut self, length: usize) -> Result<Range<usize>> {
        check_limit(
            DecodeLimit::StringBytes,
            self.budget.limits().max_string_bytes,
            length,
        )?;
        let range = self.range(length)?;
        let _ = str::from_utf8(&self.bytes[range.clone()])?;
        Ok(range)
    }

    fn byte_range(&mut self, length: usize) -> Result<Range<usize>> {
        check_limit(DecodeLimit::Bytes, self.budget.limits().max_bytes, length)?;
        self.range(length)
    }

    fn range(&mut self, length: usize) -> Result<Range<usize>> {
        let start = self.position;
        let _ = self.take(length)?;
        Ok(start..self.position)
    }

    fn unsigned_varint(&mut self) -> Result<u32> {
        let mut value = 0u32;
        for shift in (0..=28).step_by(7) {
            let byte = self.take(size_of::<u8>())?[0];
            if shift == 28 && byte > 0x0f {
                return Err(Error::Overflow);
            }
            value |= u32::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(Error::Overflow)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        self.charge(1)?;
        let end = self.position.checked_add(length).ok_or(Error::Overflow)?;
        let value = self.bytes.get(self.position..end).ok_or(Error::Overflow)?;
        self.position = end;
        Ok(value)
    }

    fn charge(&mut self, units: usize) -> Result<()> {
        self.budget.charge(units)
    }
}

pub(crate) fn borrow_string<'a>(bytes: &'a [u8], range: &Range<usize>) -> Result<&'a str> {
    str::from_utf8(&bytes[range.clone()]).map_err(Error::from)
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
