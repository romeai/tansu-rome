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

use tansu_sans_io::record::compression::{
    CompressionDecodeError, CompressionDecodeLimit, Lz4BlockLimit, SnappyBlockLimit,
    ZSTD_BACKEND_MAX_WINDOW_BYTES, ZSTD_BACKEND_MAX_WINDOW_LOG, ZSTD_BACKEND_MIN_WINDOW_BYTES,
    ZSTD_BACKEND_MIN_WINDOW_LOG, ZstdWindowLimit,
};

#[test]
fn codec_limits_are_explicit_nonzero_values() {
    assert_eq!(1, SnappyBlockLimit::new(1).expect("limit").bytes());
    assert!(matches!(
        SnappyBlockLimit::new(0),
        Err(CompressionDecodeError::InvalidLimit {
            kind: CompressionDecodeLimit::SnappyBlockBytes,
            actual: 0,
            ..
        })
    ));

    let one = ZstdWindowLimit::new(1).expect("limit");
    assert_eq!(1, one.bytes());
    assert_eq!(ZSTD_BACKEND_MIN_WINDOW_LOG, one.backend_window_log());
    assert_eq!(1024, ZSTD_BACKEND_MIN_WINDOW_BYTES);
    assert!(matches!(
        ZstdWindowLimit::new(0),
        Err(CompressionDecodeError::InvalidLimit {
            kind: CompressionDecodeLimit::ZstdWindowBytes,
            actual: 0,
            ..
        })
    ));

    let above_min = ZstdWindowLimit::new(ZSTD_BACKEND_MIN_WINDOW_BYTES + 1).expect("limit");
    assert_eq!(
        ZSTD_BACKEND_MIN_WINDOW_LOG + 1,
        above_min.backend_window_log()
    );

    let maximum = ZstdWindowLimit::new(ZSTD_BACKEND_MAX_WINDOW_BYTES).expect("maximum");
    assert_eq!(ZSTD_BACKEND_MAX_WINDOW_LOG, maximum.backend_window_log());
    assert!(matches!(
        ZstdWindowLimit::new(ZSTD_BACKEND_MAX_WINDOW_BYTES + 1),
        Err(CompressionDecodeError::InvalidLimit {
            kind: CompressionDecodeLimit::ZstdWindowBytes,
            actual,
            ..
        }) if actual == ZSTD_BACKEND_MAX_WINDOW_BYTES + 1
    ));
}

#[test]
fn lz4_limits_are_exact_standard_frame_sizes() {
    assert_eq!(64 * 1024, Lz4BlockLimit::KiB64.bytes());
    assert_eq!(256 * 1024, Lz4BlockLimit::KiB256.bytes());
    assert_eq!(1024 * 1024, Lz4BlockLimit::MiB1.bytes());
    assert_eq!(4 * 1024 * 1024, Lz4BlockLimit::MiB4.bytes());
}
