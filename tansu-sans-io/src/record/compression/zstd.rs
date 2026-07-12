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

use std::io::{self, Cursor, Read};

use crate::Compression;

use super::{CompressionDecodeError, CompressionDecodeLimit, ZstdWindowLimit};

/// Standard Zstandard frame magic in its wire byte order.
const FRAME_MAGIC: &[u8; 4] = b"\x28\xb5\x2f\xfd";
/// First magic value in Zstandard's sixteen-value skippable-frame range.
const SKIPPABLE_MAGIC_START: u32 = 0x184d_2a50;
/// Mask that normalizes every Zstandard skippable magic to [`SKIPPABLE_MAGIC_START`].
const SKIPPABLE_MAGIC_MASK: u32 = 0xffff_fff0;
/// Bytes preceding the optional Zstandard frame-header fields.
const FRAME_PREFIX_BYTES: usize = 5;
/// Absolute minimum window exponent encoded by a Zstandard window descriptor.
const WINDOW_LOG_ABSOLUTE_MIN: u32 = 10;

/// Streaming decoder for one exact Zstandard frame with an admitted history window.
///
/// The exact byte window—including a descriptor mantissa or a single-segment content size—is
/// checked before native decoder construction. `window_log_max` repeats the bound in the backend,
/// rounded up only because its API is logarithmic. `Cursor` supplies `BufRead` directly and avoids
/// the extra Rust input buffer used by `Decoder::new`.
///
/// The native decoder still owns fixed context, an input block, and an output ring whose size is
/// driven by the admitted window plus block/alignment overhead. [`ZstdWindowLimit`] constrains the
/// peer-selected history component; it is not a promise of exact total allocator usage.
pub struct ZstdDecoder<'data> {
    decoder: zstd::stream::read::Decoder<'static, Cursor<&'data [u8]>>,
    window_bytes: u64,
    state: ReadState,
}

impl<'data> ZstdDecoder<'data> {
    /// Validate exactly one non-dictionary frame and its exact window before backend construction.
    pub fn new(
        encoded: &'data [u8],
        limit: ZstdWindowLimit,
    ) -> Result<Self, CompressionDecodeError> {
        let header = parse_header(encoded)?;
        if header.window_bytes > limit.bytes() {
            return Err(CompressionDecodeError::LimitExceeded {
                kind: CompressionDecodeLimit::ZstdWindowBytes,
                limit: limit.bytes(),
                actual: header.window_bytes,
            });
        }
        let frame_size = zstd::zstd_safe::find_frame_compressed_size(encoded)
            .map_err(|_| invalid("frame body is truncated or structurally invalid"))?;
        if frame_size != encoded.len() {
            return Err(invalid("bytes follow the complete Zstandard frame"));
        }

        let mut decoder = zstd::stream::read::Decoder::with_buffer(Cursor::new(encoded))
            .map_err(initialization)?
            .single_frame();
        decoder
            .window_log_max(limit.backend_window_log())
            .map_err(initialization)?;
        Ok(Self {
            decoder,
            window_bytes: header.window_bytes,
            state: ReadState::Active,
        })
    }

    /// Exact peer-selected history-window bytes parsed from the frame header.
    pub fn window_bytes(&self) -> u64 {
        self.window_bytes
    }
}

impl Read for ZstdDecoder<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        match self.state {
            ReadState::Finished => return Ok(0),
            ReadState::Failed => return Err(io::Error::from(io::ErrorKind::InvalidData)),
            ReadState::Active => {}
        }
        match self.decoder.read(output) {
            Ok(0) => {
                self.state = ReadState::Finished;
                Ok(0)
            }
            Ok(read) => Ok(read),
            Err(_) => {
                self.state = ReadState::Failed;
                Err(io::Error::from(io::ErrorKind::InvalidData))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadState {
    Active,
    Finished,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FrameHeader {
    window_bytes: u64,
}

fn parse_header(encoded: &[u8]) -> Result<FrameHeader, CompressionDecodeError> {
    let Some(prefix) = encoded.get(..FRAME_PREFIX_BYTES) else {
        return Err(invalid("frame header is truncated"));
    };
    if &prefix[..FRAME_MAGIC.len()] != FRAME_MAGIC {
        let magic = u32::from_le_bytes(
            prefix[..FRAME_MAGIC.len()]
                .try_into()
                .expect("four-byte magic"),
        );
        return Err(if magic & SKIPPABLE_MAGIC_MASK == SKIPPABLE_MAGIC_START {
            invalid("skippable frames are not Kafka record-data frames")
        } else {
            invalid("frame magic is unsupported")
        });
    }

    let descriptor = prefix[4];
    if descriptor & 0b0001_0000 != 0 {
        return Err(invalid("unused frame-header bit is set"));
    }
    if descriptor & 0b0000_1000 != 0 {
        return Err(invalid("reserved frame-header bit is set"));
    }
    let single_segment = descriptor & 0b0010_0000 != 0;
    let dictionary_size = match descriptor & 0b0000_0011 {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        _ => unreachable!("two-bit dictionary-size field"),
    };
    let content_size_bytes = match descriptor >> 6 {
        0 if single_segment => 1,
        0 => 0,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!("two-bit content-size field"),
    };

    let mut cursor = FRAME_PREFIX_BYTES;
    let window_bytes = if single_segment {
        0
    } else {
        let window_descriptor = *encoded
            .get(cursor)
            .ok_or_else(|| invalid("window descriptor is truncated"))?;
        cursor += 1;
        let exponent = u32::from(window_descriptor >> 3) + WINDOW_LOG_ABSOLUTE_MIN;
        let base = 1u64 << exponent;
        base + (base >> 3) * u64::from(window_descriptor & 0b111)
    };

    let dictionary_end = cursor
        .checked_add(dictionary_size)
        .filter(|end| *end <= encoded.len())
        .ok_or_else(|| invalid("dictionary identifier is truncated"))?;
    let dictionary_id = read_little_endian(&encoded[cursor..dictionary_end]);
    if dictionary_id != 0 {
        return Err(invalid("dictionary-compressed frames are unsupported"));
    }
    cursor = dictionary_end;

    let content_size_end = cursor
        .checked_add(content_size_bytes)
        .filter(|end| *end <= encoded.len())
        .ok_or_else(|| invalid("frame content size is truncated"))?;
    let mut content_size = read_little_endian(&encoded[cursor..content_size_end]);
    if descriptor >> 6 == 1 {
        content_size += 256;
    }
    if single_segment {
        Ok(FrameHeader {
            window_bytes: content_size,
        })
    } else {
        Ok(FrameHeader { window_bytes })
    }
}

fn read_little_endian(bytes: &[u8]) -> u64 {
    bytes.iter().enumerate().fold(0, |value, (shift, byte)| {
        value | (u64::from(*byte) << (shift * u8::BITS as usize))
    })
}

fn invalid(reason: &'static str) -> CompressionDecodeError {
    CompressionDecodeError::InvalidData {
        codec: Compression::Zstd,
        reason,
    }
}

fn initialization(error: io::Error) -> CompressionDecodeError {
    CompressionDecodeError::Initialization {
        codec: Compression::Zstd,
        kind: error.kind(),
    }
}
