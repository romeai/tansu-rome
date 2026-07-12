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

use std::io::{self, Read, Write as _};

use flate2::{Compression as Level, Crc, write::GzEncoder};
use tansu_sans_io::record::compression::{CompressionDecodeError, GzipDecoder};

fn gzip(input: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Level::default());
    encoder.write_all(input).expect("encode");
    encoder.finish().expect("finish")
}

fn with_all_optional_fields(ordinary: &[u8]) -> Vec<u8> {
    let mut header = vec![0x1f, 0x8b, 8, 0x1e, 0, 0, 0, 0, 0, 255];
    header.extend_from_slice(&3u16.to_le_bytes());
    header.extend_from_slice(b"ext");
    header.extend_from_slice(b"records\0");
    header.extend_from_slice(b"bounded\0");
    let mut crc = Crc::new();
    crc.update(&header);
    header.extend_from_slice(&(crc.sum() as u16).to_le_bytes());
    header.extend_from_slice(&ordinary[10..]);
    header
}

fn read_all(decoder: &mut GzipDecoder<'_>) -> io::Result<Vec<u8>> {
    let mut decoded = Vec::new();
    let mut chunk = [0u8; 3];
    loop {
        let read = decoder.read(&mut chunk)?;
        if read == 0 {
            return Ok(decoded);
        }
        decoded.extend_from_slice(&chunk[..read]);
    }
}

#[test]
fn streams_exact_concatenated_members_and_all_optional_header_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let input = b"bounded gzip record data";
    let mut concatenated = gzip(b"bounded ");
    concatenated.extend_from_slice(&with_all_optional_fields(&gzip(b"gzip ")));
    concatenated.extend_from_slice(&gzip(b""));
    concatenated.extend_from_slice(&gzip(b"record data"));
    for encoded in [
        gzip(input),
        with_all_optional_fields(&gzip(input)),
        concatenated,
    ] {
        let mut decoder = GzipDecoder::new(&encoded)?;
        assert_eq!(0, decoder.read(&mut [])?);
        assert_eq!(input, read_all(&mut decoder)?.as_slice());
        assert_eq!(0, decoder.read(&mut [0; 1])?);
        assert_eq!(0, decoder.read(&mut [0; 1])?);
    }
    Ok(())
}

#[test]
fn malformed_fixed_and_optional_headers_fail_before_backend_construction() {
    for (encoded, reason) in [
        (vec![], "fixed header is truncated"),
        (vec![0; 18], "identification bytes do not match gzip"),
        (
            vec![0x1f, 0x8b, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            "compression method is not DEFLATE",
        ),
        (
            vec![
                0x1f, 0x8b, 8, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            "reserved header flags are set",
        ),
        (
            vec![
                0x1f, 0x8b, 8, 0x08, 0, 0, 0, 0, 0, 0, b'x', 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff,
            ],
            "original filename is not NUL-terminated",
        ),
    ] {
        assert!(matches!(
            GzipDecoder::new(&encoded),
            Err(CompressionDecodeError::InvalidData { reason: actual, .. }) if actual == reason
        ));
    }

    let ordinary = gzip(b"value");
    let mut bad_crc = with_all_optional_fields(&ordinary);
    let header_crc = bad_crc.len() - (ordinary.len() - 10) - 2;
    bad_crc[header_crc] ^= 1;
    assert!(matches!(
        GzipDecoder::new(&bad_crc),
        Err(CompressionDecodeError::InvalidData {
            reason: "header CRC16 is invalid",
            ..
        })
    ));
}

#[test]
fn footer_truncation_crc_size_and_trailing_data_are_sticky() {
    let valid = gzip(b"value");
    let mut cases = Vec::new();

    let mut truncated = valid.clone();
    let _ = truncated.pop();
    cases.push(truncated);

    let mut bad_crc = valid.clone();
    let crc = bad_crc.len() - 8;
    bad_crc[crc] ^= 1;
    cases.push(bad_crc);

    let mut bad_size = valid.clone();
    let size = bad_size.len() - 4;
    bad_size[size] ^= 1;
    cases.push(bad_size);

    let mut trailing = valid.clone();
    trailing.push(0);
    cases.push(trailing);

    for encoded in cases {
        let mut decoder = GzipDecoder::new(&encoded).expect("header");
        let error = read_all(&mut decoder).expect_err("invalid exact stream");
        assert_eq!(io::ErrorKind::InvalidData, error.kind());
        assert_eq!(0, decoder.read(&mut []).expect("zero read"));
        assert_eq!(
            io::ErrorKind::InvalidData,
            decoder.read(&mut [0; 1]).expect_err("sticky").kind()
        );
    }
}

#[test]
fn malformed_later_members_fail_after_prior_output_and_remain_sticky() {
    let first = gzip(b"first member");
    let mut bad_header = first.clone();
    bad_header.push(0);

    let mut bad_trailer_member = gzip(b"second member");
    let crc = bad_trailer_member.len() - 8;
    bad_trailer_member[crc] ^= 1;
    let mut bad_trailer = first;
    bad_trailer.extend_from_slice(&bad_trailer_member);

    for encoded in [bad_header, bad_trailer] {
        let mut decoder = GzipDecoder::new(&encoded).expect("first header");
        let error = read_all(&mut decoder).expect_err("invalid later member");
        assert_eq!(io::ErrorKind::InvalidData, error.kind());
        assert_eq!(0, decoder.read(&mut []).expect("zero read"));
        assert_eq!(
            io::ErrorKind::InvalidData,
            decoder.read(&mut [0; 1]).expect_err("sticky").kind()
        );
    }
}

#[test]
fn truncated_deflate_body_never_becomes_clean_eof() {
    let valid = gzip(&vec![7u8; 32 * 1024]);
    let mut truncated = valid[..valid.len() - 9].to_vec();
    truncated.extend_from_slice(&valid[valid.len() - 8..]);
    let mut decoder = GzipDecoder::new(&truncated).expect("header");
    assert_eq!(
        io::ErrorKind::InvalidData,
        read_all(&mut decoder).expect_err("truncated body").kind()
    );
}
