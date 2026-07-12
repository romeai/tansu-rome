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

use crate::Compression;

use super::{CompressionDecodeError, CompressionDecodeLimit, SnappyBlockLimit};

/// Xerial Snappy stream identifier used by Kafka's Snappy record-data encoding.
const XERIAL_MAGIC: &[u8; 8] = b"\x82SNAPPY\0";
/// Bytes in Xerial's magic, version, and compatible-version prefix.
const XERIAL_HEADER_BYTES: usize = 16;
/// Xerial framing version implemented by this reader and written in canonical streams.
const XERIAL_HEADER_VERSION: i32 = 1;
/// Oldest Xerial writer version whose framing this reader understands.
const XERIAL_MINIMUM_COMPATIBLE_VERSION: i32 = 1;
/// Bytes in each big-endian Xerial compressed-block length.
const BLOCK_LENGTH_BYTES: usize = 4;

/// Streaming Kafka Xerial Snappy decoder using caller-owned block scratch.
///
/// Construction scans every compressed block and asks Snappy for its decoded length before any
/// decompression. Consequently a later oversized block cannot publish earlier records and cannot
/// select an allocation. The raw Snappy decoder itself owns no heap state; peak codec memory is
/// exactly the caller scratch required by [`SnappyBlockLimit`].
#[derive(Debug)]
pub struct XerialSnappyDecoder<'data, 'scratch> {
    encoded: &'data [u8],
    scratch: &'scratch mut [u8],
    encoded_cursor: usize,
    block_cursor: usize,
    block_length: usize,
    decoder: snap::raw::Decoder,
    state: ReadState,
}

impl<'data, 'scratch> XerialSnappyDecoder<'data, 'scratch> {
    /// Validate the complete Xerial envelope and all block sizes before retaining caller scratch.
    pub fn new(
        encoded: &'data [u8],
        scratch: &'scratch mut [u8],
        limit: SnappyBlockLimit,
    ) -> Result<Self, CompressionDecodeError> {
        Self::preflight(encoded, limit)?.decoder(scratch)
    }

    /// Validate every Xerial block and determine the scratch required by this stream.
    pub fn preflight(
        encoded: &'data [u8],
        limit: SnappyBlockLimit,
    ) -> Result<XerialSnappyPreflight<'data>, CompressionDecodeError> {
        validate_header(encoded)?;
        scan_blocks(encoded, limit).map(|required_scratch_bytes| XerialSnappyPreflight {
            encoded,
            required_scratch_bytes,
        })
    }

    fn from_preflight(
        preflight: XerialSnappyPreflight<'data>,
        scratch: &'scratch mut [u8],
    ) -> Result<Self, CompressionDecodeError> {
        if scratch.len() < preflight.required_scratch_bytes {
            return Err(CompressionDecodeError::ScratchTooSmall {
                kind: CompressionDecodeLimit::SnappyBlockBytes,
                required: preflight.required_scratch_bytes,
                actual: scratch.len(),
            });
        }
        Ok(Self {
            encoded: preflight.encoded,
            scratch,
            encoded_cursor: XERIAL_HEADER_BYTES,
            block_cursor: 0,
            block_length: 0,
            decoder: snap::raw::Decoder::new(),
            state: ReadState::Active,
        })
    }

    fn fail(&mut self) -> io::Error {
        self.state = ReadState::Failed;
        io::Error::from(io::ErrorKind::InvalidData)
    }

    fn load_block(&mut self) -> io::Result<bool> {
        if self.encoded_cursor == self.encoded.len() {
            self.state = ReadState::Finished;
            return Ok(false);
        }
        let length_end = self.encoded_cursor + BLOCK_LENGTH_BYTES;
        let compressed_length = usize::try_from(u32::from_be_bytes(
            self.encoded[self.encoded_cursor..length_end]
                .try_into()
                .expect("prevalidated block length"),
        ))
        .expect("u32 block length fits supported address spaces");
        let compressed_start = length_end;
        let compressed_end = compressed_start + compressed_length;
        let compressed = &self.encoded[compressed_start..compressed_end];
        let decoded_length = snap::raw::decompress_len(compressed)
            .expect("constructor prevalidated every Snappy block header");
        match self
            .decoder
            .decompress(compressed, &mut self.scratch[..decoded_length])
        {
            Ok(actual) if actual == decoded_length => {
                self.encoded_cursor = compressed_end;
                self.block_cursor = 0;
                self.block_length = decoded_length;
                Ok(true)
            }
            Ok(_) | Err(_) => Err(self.fail()),
        }
    }
}

/// Allocation-free proof that every Xerial block fits an explicit decoded-block ceiling.
///
/// The proof borrows the exact encoded stream it describes, preventing construction with bytes
/// that were not scanned. This split lets owned consumers allocate only the largest block present,
/// while admission-aware consumers can lend scratch reserved for their configured ceiling.
#[derive(Debug)]
pub struct XerialSnappyPreflight<'data> {
    encoded: &'data [u8],
    required_scratch_bytes: usize,
}

impl<'data> XerialSnappyPreflight<'data> {
    /// Largest decoded block in the validated stream.
    pub fn required_scratch_bytes(&self) -> usize {
        self.required_scratch_bytes
    }

    /// Construct a decoder by lending scratch for the largest validated block.
    pub fn decoder<'scratch>(
        self,
        scratch: &'scratch mut [u8],
    ) -> Result<XerialSnappyDecoder<'data, 'scratch>, CompressionDecodeError> {
        XerialSnappyDecoder::from_preflight(self, scratch)
    }
}

impl Read for XerialSnappyDecoder<'_, '_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        match self.state {
            ReadState::Finished => return Ok(0),
            ReadState::Failed => return Err(io::Error::from(io::ErrorKind::InvalidData)),
            ReadState::Active => {}
        }
        while self.block_cursor == self.block_length {
            if !self.load_block()? {
                return Ok(0);
            }
        }
        let available = &self.scratch[self.block_cursor..self.block_length];
        let copied = available.len().min(output.len());
        output[..copied].copy_from_slice(&available[..copied]);
        self.block_cursor += copied;
        Ok(copied)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadState {
    Active,
    Finished,
    Failed,
}

fn validate_header(encoded: &[u8]) -> Result<(), CompressionDecodeError> {
    let invalid = |reason| CompressionDecodeError::InvalidData {
        codec: Compression::Snappy,
        reason,
    };
    let Some(header) = encoded.get(..XERIAL_HEADER_BYTES) else {
        return Err(invalid("Xerial header is truncated"));
    };
    if &header[..XERIAL_MAGIC.len()] != XERIAL_MAGIC {
        return Err(invalid("magic bytes do not match Xerial Snappy"));
    }
    let version = i32::from_be_bytes(header[8..12].try_into().expect("four bytes"));
    let compatible = i32::from_be_bytes(header[12..16].try_into().expect("four bytes"));
    if version < XERIAL_MINIMUM_COMPATIBLE_VERSION {
        return Err(invalid("writer version predates this Xerial reader"));
    }
    if !(0..=XERIAL_HEADER_VERSION).contains(&compatible) {
        return Err(invalid(
            "minimum reader version is unsupported by this Xerial reader",
        ));
    }
    Ok(())
}

fn scan_blocks(encoded: &[u8], limit: SnappyBlockLimit) -> Result<usize, CompressionDecodeError> {
    let invalid = |reason| CompressionDecodeError::InvalidData {
        codec: Compression::Snappy,
        reason,
    };
    let mut cursor = XERIAL_HEADER_BYTES;
    let mut required_scratch_bytes = 0;
    while cursor < encoded.len() {
        let length_end = cursor
            .checked_add(BLOCK_LENGTH_BYTES)
            .filter(|end| *end <= encoded.len())
            .ok_or_else(|| invalid("block length is truncated"))?;
        let compressed_length = usize::try_from(u32::from_be_bytes(
            encoded[cursor..length_end].try_into().expect("four bytes"),
        ))
        .map_err(|_| invalid("compressed block length does not fit this address space"))?;
        if compressed_length == 0 {
            return Err(invalid("compressed block is empty"));
        }
        let block_end = length_end
            .checked_add(compressed_length)
            .filter(|end| *end <= encoded.len())
            .ok_or_else(|| invalid("compressed block is truncated"))?;
        let decoded = snap::raw::decompress_len(&encoded[length_end..block_end])
            .map_err(|_| invalid("Snappy block header is invalid"))?;
        if decoded > limit.bytes() {
            return Err(CompressionDecodeError::LimitExceeded {
                kind: CompressionDecodeLimit::SnappyBlockBytes,
                limit: limit.bytes() as u64,
                actual: decoded as u64,
            });
        }
        required_scratch_bytes = required_scratch_bytes.max(decoded);
        cursor = block_end;
    }
    Ok(required_scratch_bytes)
}
