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

use std::io::{self, Read};

use flate2::{Crc, Decompress, FlushDecompress, Status};

use crate::Compression;

use super::CompressionDecodeError;

/// Bytes in gzip's fixed header through the operating-system field (RFC 1952 section 2.3.1).
const FIXED_HEADER_BYTES: usize = 10;
/// Bytes in gzip's CRC32 and ISIZE trailer (RFC 1952 section 2.3.1).
const TRAILER_BYTES: usize = 8;
/// Gzip identification byte one from RFC 1952.
const ID1: u8 = 0x1f;
/// Gzip identification byte two from RFC 1952.
const ID2: u8 = 0x8b;
/// Gzip's DEFLATE compression-method identifier from RFC 1952.
const DEFLATE_METHOD: u8 = 8;
/// Flag selecting a two-byte header CRC after all optional header fields.
const FLAG_HEADER_CRC: u8 = 0x02;
/// Flag selecting a length-prefixed optional extra field.
const FLAG_EXTRA: u8 = 0x04;
/// Flag selecting a NUL-terminated original filename.
const FLAG_NAME: u8 = 0x08;
/// Flag selecting a NUL-terminated comment.
const FLAG_COMMENT: u8 = 0x10;
/// RFC 1952 reserves the three high flag bits and requires them to be zero.
const RESERVED_FLAGS: u8 = 0xe0;

/// Streaming decoder for an exact RFC 1952 gzip stream borrowing immutable encoded record data.
///
/// Each member envelope is parsed without retaining optional fields. Raw DEFLATE output is
/// produced directly into the caller's `Read` buffer, while each CRC32 and ISIZE is verified before
/// advancing to the next concatenated member or exposing exact overall EOF. The inflater and CRC
/// state are reset in place between members, so peer-selected member count does not accumulate
/// codec state. Bytes that do not begin a valid subsequent member are rejected as trailing data.
///
/// With Tansu's default `flate2` rust backend, the only heap state is miniz's fixed inflate state:
/// a format-mandated 32-KiB history plus fixed tables. No peer-selected header or decoded batch is
/// allocated. A different `flate2` backend may change that fixed component, so embedders should
/// reserve a backend-version-pinned fixed margin rather than treating this as an allocator-byte
/// promise.
#[derive(Debug)]
pub struct GzipDecoder<'data> {
    encoded: &'data [u8],
    cursor: usize,
    inflater: Decompress,
    crc: Crc,
    state: ReadState,
}

impl<'data> GzipDecoder<'data> {
    /// Validate the first allocation-free gzip header before constructing fixed backend state.
    ///
    /// Later member headers are validated when the preceding member establishes their exact
    /// boundary; discovering a malformed later member produces a sticky read failure.
    pub fn new(encoded: &'data [u8]) -> Result<Self, CompressionDecodeError> {
        let cursor = header_end(encoded, 0)?;
        Ok(Self {
            encoded,
            cursor,
            inflater: Decompress::new(false),
            crc: Crc::new(),
            state: ReadState::Active,
        })
    }

    fn failure(&mut self, kind: io::ErrorKind, produced: usize) -> io::Result<usize> {
        self.state = ReadState::Failed(kind);
        if produced > 0 {
            Ok(produced)
        } else {
            Err(io::Error::from(kind))
        }
    }

    fn finish_member(&mut self, produced: usize) -> io::Result<Option<usize>> {
        let Some(trailer_end) = self.cursor.checked_add(TRAILER_BYTES) else {
            return self.failure(io::ErrorKind::InvalidData, produced).map(Some);
        };
        let Some(trailer) = self.encoded.get(self.cursor..trailer_end) else {
            return self.failure(io::ErrorKind::InvalidData, produced).map(Some);
        };
        let expected_crc = u32::from_le_bytes(trailer[..4].try_into().expect("four bytes"));
        let expected_size = u32::from_le_bytes(trailer[4..].try_into().expect("four bytes"));
        if expected_crc != self.crc.sum() || expected_size != self.crc.amount() {
            return self.failure(io::ErrorKind::InvalidData, produced).map(Some);
        }
        self.cursor = trailer_end;
        if trailer_end == self.encoded.len() {
            self.state = ReadState::Finished;
            return Ok(Some(produced));
        }

        let next_body = match header_end(self.encoded, trailer_end) {
            Ok(next_body) => next_body,
            Err(_) => {
                return self.failure(io::ErrorKind::InvalidData, produced).map(Some);
            }
        };
        self.cursor = next_body;
        self.inflater.reset(false);
        self.crc.reset();
        if produced == 0 {
            Ok(None)
        } else {
            Ok(Some(produced))
        }
    }
}

impl Read for GzipDecoder<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        match self.state {
            ReadState::Finished => return Ok(0),
            ReadState::Failed(kind) => return Err(io::Error::from(kind)),
            ReadState::Active => {}
        }

        loop {
            let before_in = self.inflater.total_in();
            let before_out = self.inflater.total_out();
            let input = &self.encoded[self.cursor..];
            let flush = if input.is_empty() {
                FlushDecompress::Finish
            } else {
                FlushDecompress::None
            };
            let result = self.inflater.decompress(input, output, flush);
            let consumed = usize::try_from(self.inflater.total_in() - before_in)
                .expect("one read cannot consume more than addressable input");
            let produced = usize::try_from(self.inflater.total_out() - before_out)
                .expect("one read cannot produce more than the caller buffer");
            self.cursor += consumed;
            self.crc.update(&output[..produced]);
            let status = match result {
                Ok(status) => status,
                Err(_) => return self.failure(io::ErrorKind::InvalidData, produced),
            };

            if status == Status::StreamEnd {
                if let Some(produced) = self.finish_member(produced)? {
                    return Ok(produced);
                }
                continue;
            }
            if produced > 0 {
                return Ok(produced);
            }
            if consumed == 0 {
                return self.failure(io::ErrorKind::InvalidData, 0);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadState {
    Active,
    Finished,
    Failed(io::ErrorKind),
}

fn header_end(encoded: &[u8], start: usize) -> Result<usize, CompressionDecodeError> {
    let invalid = |reason| CompressionDecodeError::InvalidData {
        codec: Compression::Gzip,
        reason,
    };
    let Some(fixed_end) = start.checked_add(FIXED_HEADER_BYTES) else {
        return Err(invalid("fixed header overflows the input"));
    };
    let Some(header) = encoded.get(start..fixed_end) else {
        return Err(invalid("fixed header is truncated"));
    };
    if header[0] != ID1 || header[1] != ID2 {
        return Err(invalid("identification bytes do not match gzip"));
    }
    if header[2] != DEFLATE_METHOD {
        return Err(invalid("compression method is not DEFLATE"));
    }
    let flags = header[3];
    if flags & RESERVED_FLAGS != 0 {
        return Err(invalid("reserved header flags are set"));
    }

    let mut cursor = fixed_end;
    if flags & FLAG_EXTRA != 0 {
        let Some(length_end) = cursor.checked_add(2) else {
            return Err(invalid("extra-field length overflows the input"));
        };
        let Some(length) = encoded.get(cursor..length_end) else {
            return Err(invalid("extra-field length is truncated"));
        };
        cursor = length_end;
        let length = usize::from(u16::from_le_bytes(length.try_into().expect("two bytes")));
        cursor = cursor
            .checked_add(length)
            .filter(|end| *end <= encoded.len())
            .ok_or_else(|| invalid("extra field is truncated"))?;
    }
    if flags & FLAG_NAME != 0 {
        cursor = nul_terminated_end(encoded, cursor)
            .ok_or_else(|| invalid("original filename is not NUL-terminated"))?;
    }
    if flags & FLAG_COMMENT != 0 {
        cursor = nul_terminated_end(encoded, cursor)
            .ok_or_else(|| invalid("comment is not NUL-terminated"))?;
    }
    if flags & FLAG_HEADER_CRC != 0 {
        let Some(crc_end) = cursor.checked_add(2) else {
            return Err(invalid("header CRC overflows the input"));
        };
        let Some(expected) = encoded.get(cursor..crc_end) else {
            return Err(invalid("header CRC is truncated"));
        };
        let expected = u16::from_le_bytes(expected.try_into().expect("two bytes"));
        let mut crc = Crc::new();
        crc.update(&encoded[start..cursor]);
        if expected != crc.sum() as u16 {
            return Err(invalid("header CRC16 is invalid"));
        }
        cursor = crc_end;
    }
    if encoded.len().saturating_sub(cursor) < TRAILER_BYTES {
        return Err(invalid("DEFLATE body or trailer is truncated"));
    }
    Ok(cursor)
}

fn nul_terminated_end(encoded: &[u8], start: usize) -> Option<usize> {
    encoded
        .get(start..)?
        .iter()
        .position(|byte| *byte == 0)
        .and_then(|offset| start.checked_add(offset + 1))
}
