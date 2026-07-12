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

//! Explicit resource vocabulary for bounded Kafka record-data decompression.
//!
//! Each codec accepts only its own limit type. There is deliberately no aggregate policy or
//! `Default`: an embedder must choose memory ceilings that match its admission reservation and
//! compatibility requirements. Existing owned record inflation remains unchanged.

use std::{
    fmt, io,
    num::{NonZeroU64, NonZeroUsize},
};

use crate::Compression;

mod gzip;
mod snappy;

pub use gzip::GzipDecoder;
pub use snappy::XerialSnappyDecoder;

/// Zstandard's backend minimum window-log parameter; exact preflight may enforce a smaller
/// single-segment byte ceiling, but the native decoder still retains at least this state class.
pub const ZSTD_BACKEND_MIN_WINDOW_LOG: u32 = 10;
/// Minimum backend window state derived from [`ZSTD_BACKEND_MIN_WINDOW_LOG`].
pub const ZSTD_BACKEND_MIN_WINDOW_BYTES: u64 = 1 << ZSTD_BACKEND_MIN_WINDOW_LOG;
/// Zstandard's 32-bit backend maximum window-log parameter from `ZSTD_WINDOWLOG_MAX_32`.
#[cfg(target_pointer_width = "32")]
pub const ZSTD_BACKEND_MAX_WINDOW_LOG: u32 = 30;
/// Zstandard's 64-bit backend maximum window-log parameter from `ZSTD_WINDOWLOG_MAX_64`.
#[cfg(target_pointer_width = "64")]
pub const ZSTD_BACKEND_MAX_WINDOW_LOG: u32 = 31;
/// Maximum exact window ceiling representable by this platform's Zstandard backend parameter.
pub const ZSTD_BACKEND_MAX_WINDOW_BYTES: u64 = 1 << ZSTD_BACKEND_MAX_WINDOW_LOG;

/// Peer-selected codec state constrained before or during record-data decompression.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CompressionDecodeLimit {
    /// Decoded bytes in one Kafka Xerial Snappy block.
    SnappyBlockBytes,
    /// Maximum decoded block size selected by an LZ4 frame descriptor.
    Lz4BlockBytes,
    /// Exact history-window bytes selected by a Zstandard frame header.
    ZstdWindowBytes,
}

impl fmt::Display for CompressionDecodeLimit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SnappyBlockBytes => "Snappy block bytes",
            Self::Lz4BlockBytes => "LZ4 block bytes",
            Self::ZstdWindowBytes => "Zstd window bytes",
        })
    }
}

/// Allocation-free construction failure for a bounded compression adapter.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CompressionDecodeError {
    /// A codec-specific limit cannot express a useful bounded decoder policy.
    #[error("invalid {kind} limit {actual}: {reason}")]
    InvalidLimit {
        kind: CompressionDecodeLimit,
        actual: u64,
        reason: &'static str,
    },
    /// Peer-selected state exceeds the explicit codec limit.
    #[error("{kind} exceed limit {limit} (actual {actual})")]
    LimitExceeded {
        kind: CompressionDecodeLimit,
        limit: u64,
        actual: u64,
    },
    /// Caller scratch cannot hold the configured maximum codec block.
    #[error("{kind} scratch has {actual} bytes but configured limit requires {required}")]
    ScratchTooSmall {
        kind: CompressionDecodeLimit,
        required: usize,
        actual: usize,
    },
    /// The encoded envelope is structurally invalid before backend construction.
    #[error("invalid {codec:?} record-data envelope: {reason}")]
    InvalidData {
        codec: Compression,
        reason: &'static str,
    },
    /// A bounded backend could not initialize after the envelope passed preflight.
    #[error("{codec:?} record-data decoder initialization failed with {kind:?}")]
    Initialization {
        codec: Compression,
        kind: io::ErrorKind,
    },
}

/// Nonzero decoded-byte ceiling for one Xerial Snappy block.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SnappyBlockLimit(NonZeroUsize);

impl SnappyBlockLimit {
    /// Construct an explicit block ceiling; zero cannot decode even a one-byte block.
    pub fn new(bytes: usize) -> Result<Self, CompressionDecodeError> {
        NonZeroUsize::new(bytes)
            .map(Self)
            .ok_or(CompressionDecodeError::InvalidLimit {
                kind: CompressionDecodeLimit::SnappyBlockBytes,
                actual: 0,
                reason: "the block ceiling must be nonzero",
            })
    }

    /// Configured maximum decoded bytes in one Xerial block.
    pub fn bytes(self) -> usize {
        self.0.get()
    }
}

/// Standard LZ4 frame block ceilings, encoded by the frame BD byte.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Lz4BlockLimit {
    /// Accept only the 64-KiB standard LZ4 block-size identifier.
    KiB64,
    /// Accept standard LZ4 block-size identifiers through 256 KiB.
    KiB256,
    /// Accept standard LZ4 block-size identifiers through one MiB.
    MiB1,
    /// Accept all standard LZ4 block-size identifiers through four MiB.
    MiB4,
}

impl Lz4BlockLimit {
    /// Exact maximum decoded block bytes admitted by this discrete ceiling.
    pub fn bytes(self) -> usize {
        match self {
            Self::KiB64 => 64 * 1024,
            Self::KiB256 => 256 * 1024,
            Self::MiB1 => 1024 * 1024,
            Self::MiB4 => 4 * 1024 * 1024,
        }
    }
}

/// Nonzero exact-byte ceiling for a Zstandard frame history window.
///
/// Zstandard's window descriptor includes a mantissa, so valid windows are not restricted to
/// powers of two. Adapters compare the parsed byte count exactly and use a rounded-up window-log
/// backend setting only as defense in depth.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ZstdWindowLimit(NonZeroU64);

impl ZstdWindowLimit {
    /// Construct an explicit exact window ceiling; zero cannot admit a Zstd frame and ceilings
    /// above the platform backend maximum cannot be enforced by `window_log_max`.
    pub fn new(bytes: u64) -> Result<Self, CompressionDecodeError> {
        let bytes = NonZeroU64::new(bytes).ok_or(CompressionDecodeError::InvalidLimit {
            kind: CompressionDecodeLimit::ZstdWindowBytes,
            actual: 0,
            reason: "the window ceiling must be nonzero",
        })?;
        if bytes.get() > ZSTD_BACKEND_MAX_WINDOW_BYTES {
            return Err(CompressionDecodeError::InvalidLimit {
                kind: CompressionDecodeLimit::ZstdWindowBytes,
                actual: bytes.get(),
                reason: "the exact ceiling exceeds this platform's Zstd backend maximum",
            });
        }
        Ok(Self(bytes))
    }

    /// Exact maximum history-window bytes admitted from a frame header.
    pub fn bytes(self) -> u64 {
        self.0.get()
    }

    /// Backend log parameter that safely covers the exact byte ceiling.
    ///
    /// Small single-segment frames remain governed by [`Self::bytes`], while the native decoder
    /// receives its minimum supported log. Embedders must therefore reserve at least
    /// [`ZSTD_BACKEND_MIN_WINDOW_BYTES`] of backend window state even for a tighter exact ceiling.
    pub fn backend_window_log(self) -> u32 {
        let ceiling_log = u64::BITS - self.bytes().saturating_sub(1).leading_zeros();
        ceiling_log.max(ZSTD_BACKEND_MIN_WINDOW_LOG)
    }
}
