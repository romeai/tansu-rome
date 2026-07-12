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

use super::{CompressionDecodeError, CompressionDecodeLimit, Lz4BlockLimit};

/// Standard LZ4 frame magic in its wire byte order.
const FRAME_MAGIC: &[u8; 4] = b"\x04\x22\x4d\x18";
/// Fixed magic, FLG, and BD bytes before optional LZ4 frame-header fields.
const FIXED_HEADER_BYTES: usize = 6;
/// One-byte checksum terminating an LZ4 frame header.
const HEADER_CHECKSUM_BYTES: usize = 1;
/// Optional little-endian content-size field selected by FLG bit 3.
const CONTENT_SIZE_BYTES: usize = 8;
/// Optional little-endian dictionary identifier selected by FLG bit 0.
const DICTIONARY_ID_BYTES: usize = 4;
/// Little-endian size prefix before every LZ4 data block.
const BLOCK_SIZE_BYTES: usize = 4;
/// Optional checksum after each LZ4 block when FLG bit 4 is set.
const BLOCK_CHECKSUM_BYTES: usize = 4;
/// Optional content checksum after the zero block marker when FLG bit 2 is set.
const CONTENT_CHECKSUM_BYTES: usize = 4;
/// High bit distinguishing an uncompressed LZ4 frame block from a compressed block.
const UNCOMPRESSED_BLOCK_FLAG: u32 = 1 << 31;
/// Mask selecting the encoded payload length from an LZ4 block-size word.
const BLOCK_LENGTH_MASK: u32 = !UNCOMPRESSED_BLOCK_FLAG;

/// Streaming decoder for one structurally exact, block-bounded LZ4 frame.
///
/// The `lz4` crate buffers compressed input internally, so inspecting its returned reader cannot
/// distinguish one frame from a valid frame followed by trailing bytes. Construction therefore
/// scans the complete frame through its zero block marker and optional checksums before allocating
/// the native decoder. This also admits the peer-selected BD block size before liblz4 allocates
/// block-dependent state.
#[derive(Debug)]
pub struct Lz4Decoder<'data> {
    decoder: lz4::Decoder<Cursor<&'data [u8]>>,
    selected_block_limit: Lz4BlockLimit,
    linked_blocks: bool,
    state: ReadState,
}

impl<'data> Lz4Decoder<'data> {
    /// Validate exactly one complete frame and its block-state ceiling before backend construction.
    pub fn new(encoded: &'data [u8], limit: Lz4BlockLimit) -> Result<Self, CompressionDecodeError> {
        let frame = scan_frame(encoded, limit)?;
        let decoder = lz4::Decoder::new(Cursor::new(encoded)).map_err(|error| {
            CompressionDecodeError::Initialization {
                codec: Compression::Lz4,
                kind: error.kind(),
            }
        })?;
        Ok(Self {
            decoder,
            selected_block_limit: frame.selected_block_limit,
            linked_blocks: frame.linked_blocks,
            state: ReadState::Active,
        })
    }

    /// Exact standard block ceiling selected by the frame BD byte.
    pub fn selected_block_limit(&self) -> Lz4BlockLimit {
        self.selected_block_limit
    }

    /// Whether the frame retains the preceding decoded block as a compression dictionary.
    pub fn has_linked_blocks(&self) -> bool {
        self.linked_blocks
    }
}

impl Read for Lz4Decoder<'_> {
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
struct FrameInfo {
    selected_block_limit: Lz4BlockLimit,
    linked_blocks: bool,
}

fn scan_frame(encoded: &[u8], limit: Lz4BlockLimit) -> Result<FrameInfo, CompressionDecodeError> {
    let invalid = |reason| CompressionDecodeError::InvalidData {
        codec: Compression::Lz4,
        reason,
    };
    let Some(fixed) = encoded.get(..FIXED_HEADER_BYTES) else {
        return Err(invalid("frame header is truncated"));
    };
    if &fixed[..FRAME_MAGIC.len()] != FRAME_MAGIC {
        return Err(invalid("frame magic is unsupported"));
    }

    let flags = fixed[4];
    if flags >> 6 != 1 {
        return Err(invalid("frame descriptor version is unsupported"));
    }
    if flags & 0b0000_0010 != 0 {
        return Err(invalid("reserved frame-descriptor bit is set"));
    }

    let block_descriptor = fixed[5];
    if block_descriptor & 0b1000_1111 != 0 {
        return Err(invalid("reserved block-descriptor bits are set"));
    }
    let selected_block_limit = match (block_descriptor >> 4) & 0b111 {
        4 => Lz4BlockLimit::KiB64,
        5 => Lz4BlockLimit::KiB256,
        6 => Lz4BlockLimit::MiB1,
        7 => Lz4BlockLimit::MiB4,
        _ => return Err(invalid("block-size identifier is unsupported")),
    };
    if selected_block_limit.bytes() > limit.bytes() {
        return Err(CompressionDecodeError::LimitExceeded {
            kind: CompressionDecodeLimit::Lz4BlockBytes,
            limit: limit.bytes() as u64,
            actual: selected_block_limit.bytes() as u64,
        });
    }

    let content_size = flags & 0b0000_1000 != 0;
    let block_checksum = flags & 0b0001_0000 != 0;
    let content_checksum = flags & 0b0000_0100 != 0;
    let dictionary_id = flags & 0b0000_0001 != 0;
    let linked_blocks = flags & 0b0010_0000 == 0;

    let optional_header_bytes = usize::from(content_size) * CONTENT_SIZE_BYTES
        + usize::from(dictionary_id) * DICTIONARY_ID_BYTES;
    let mut cursor = FIXED_HEADER_BYTES
        .checked_add(optional_header_bytes)
        .and_then(|cursor| cursor.checked_add(HEADER_CHECKSUM_BYTES))
        .filter(|cursor| *cursor <= encoded.len())
        .ok_or_else(|| invalid("optional frame header is truncated"))?;

    loop {
        let size_end = cursor
            .checked_add(BLOCK_SIZE_BYTES)
            .filter(|end| *end <= encoded.len())
            .ok_or_else(|| invalid("block-size word is truncated"))?;
        let size_word = u32::from_le_bytes(
            encoded[cursor..size_end]
                .try_into()
                .expect("four-byte block size"),
        );
        cursor = size_end;
        if size_word == 0 {
            break;
        }
        let block_length = usize::try_from(size_word & BLOCK_LENGTH_MASK)
            .map_err(|_| invalid("block payload length does not fit this address space"))?;
        if block_length == 0 {
            return Err(invalid("data block has an empty payload"));
        }
        if block_length > selected_block_limit.bytes() {
            return Err(invalid(
                "encoded block exceeds the frame block-size identifier",
            ));
        }
        cursor = cursor
            .checked_add(block_length)
            .and_then(|cursor| {
                cursor.checked_add(usize::from(block_checksum) * BLOCK_CHECKSUM_BYTES)
            })
            .filter(|cursor| *cursor <= encoded.len())
            .ok_or_else(|| invalid("block payload or checksum is truncated"))?;
    }

    cursor = cursor
        .checked_add(usize::from(content_checksum) * CONTENT_CHECKSUM_BYTES)
        .filter(|cursor| *cursor <= encoded.len())
        .ok_or_else(|| invalid("content checksum is truncated"))?;
    if cursor != encoded.len() {
        return Err(invalid("bytes follow the complete LZ4 frame"));
    }

    Ok(FrameInfo {
        selected_block_limit,
        linked_blocks,
    })
}
