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

use std::io::{self, Read, Write};

use tansu_sans_io::record::compression::{
    CompressionDecodeError, CompressionDecodeLimit, ZstdDecoder, ZstdWindowLimit,
};

const ZSTD_MAGIC: &[u8; 4] = b"\x28\xb5\x2f\xfd";

fn raw_single_segment(value: &[u8], content_size_flag: u8) -> Vec<u8> {
    let mut encoded = ZSTD_MAGIC.to_vec();
    encoded.push(0b0010_0000 | (content_size_flag << 6));
    match content_size_flag {
        0 => encoded.push(u8::try_from(value.len()).expect("one-byte content size")),
        1 => encoded.extend_from_slice(
            &u16::try_from(value.len() - 256)
                .expect("biased two-byte content size")
                .to_le_bytes(),
        ),
        2 => encoded.extend_from_slice(
            &u32::try_from(value.len())
                .expect("four-byte content size")
                .to_le_bytes(),
        ),
        3 => encoded.extend_from_slice(&(value.len() as u64).to_le_bytes()),
        _ => panic!("two-bit content-size flag"),
    }
    let block_header = (u32::try_from(value.len()).expect("test block size") << 3) | 1;
    encoded.extend_from_slice(&block_header.to_le_bytes()[..3]);
    encoded.extend_from_slice(value);
    encoded
}

fn ordinary_window(value: &[u8], window_descriptor: u8) -> Vec<u8> {
    let mut encoded = ZSTD_MAGIC.to_vec();
    encoded.push(0);
    encoded.push(window_descriptor);
    let block_header = (u32::try_from(value.len()).expect("test block size") << 3) | 1;
    encoded.extend_from_slice(&block_header.to_le_bytes()[..3]);
    encoded.extend_from_slice(value);
    encoded
}

fn decode_all(decoder: &mut ZstdDecoder<'_>) -> io::Result<Vec<u8>> {
    let mut decoded = Vec::new();
    let mut chunk = [0u8; 257];
    loop {
        let read = decoder.read(&mut chunk)?;
        if read == 0 {
            return Ok(decoded);
        }
        decoded.extend_from_slice(&chunk[..read]);
    }
}

#[test]
fn parses_all_single_segment_content_size_widths_exactly() -> Result<(), Box<dyn std::error::Error>>
{
    for (flag, size) in [(0, 2), (1, 256), (2, 65_536), (3, 65_537)] {
        let value = vec![b'x'; size];
        let encoded = raw_single_segment(&value, flag);
        let mut decoder = ZstdDecoder::new(&encoded, ZstdWindowLimit::new(size as u64)?)?;
        assert_eq!(size as u64, decoder.window_bytes());
        assert_eq!(0, decoder.read(&mut [])?);
        assert_eq!(value, decode_all(&mut decoder)?);
        assert_eq!(0, decoder.read(&mut [0; 1])?);
        assert_eq!(0, decoder.read(&mut [0; 1])?);

        assert!(matches!(
            ZstdDecoder::new(&encoded, ZstdWindowLimit::new(size as u64 - 1)?),
            Err(CompressionDecodeError::LimitExceeded {
                kind: CompressionDecodeLimit::ZstdWindowBytes,
                limit,
                actual,
            }) if limit == size as u64 - 1 && actual == size as u64
        ));
    }

    let empty = raw_single_segment(b"", 0);
    let mut decoder = ZstdDecoder::new(&empty, ZstdWindowLimit::new(1)?)?;
    assert_eq!(0, decoder.window_bytes());
    assert_eq!(0, decoder.read(&mut [0; 1])?);
    assert_eq!(0, decoder.read(&mut [0; 1])?);
    Ok(())
}

#[test]
fn parses_window_descriptor_mantissa_without_power_of_two_rounding()
-> Result<(), Box<dyn std::error::Error>> {
    let encoded = ordinary_window(b"mantissa", 0b0000_0111);
    let mut decoder = ZstdDecoder::new(&encoded, ZstdWindowLimit::new(1_920)?)?;
    assert_eq!(1_920, decoder.window_bytes());
    assert_eq!(b"mantissa", decode_all(&mut decoder)?.as_slice());
    assert!(matches!(
        ZstdDecoder::new(&encoded, ZstdWindowLimit::new(1_919)?),
        Err(CompressionDecodeError::LimitExceeded {
            kind: CompressionDecodeLimit::ZstdWindowBytes,
            limit: 1_919,
            actual: 1_920,
        })
    ));

    let eight_mib = 8 * 1024 * 1024;
    let exact = ordinary_window(b"exact", 13 << 3);
    let mut decoder = ZstdDecoder::new(&exact, ZstdWindowLimit::new(eight_mib)?)?;
    assert_eq!(eight_mib, decoder.window_bytes());
    assert_eq!(b"exact", decode_all(&mut decoder)?.as_slice());

    let nine_mib = ordinary_window(b"over", (13 << 3) | 1);
    assert!(matches!(
        ZstdDecoder::new(&nine_mib, ZstdWindowLimit::new(eight_mib)?),
        Err(CompressionDecodeError::LimitExceeded {
            kind: CompressionDecodeLimit::ZstdWindowBytes,
            limit: 8_388_608,
            actual: 9_437_184,
        })
    ));
    Ok(())
}

#[test]
fn rejects_dictionary_skippable_truncated_and_non_exact_frames()
-> Result<(), Box<dyn std::error::Error>> {
    let valid = raw_single_segment(b"value", 0);
    let mut dictionary = ZSTD_MAGIC.to_vec();
    dictionary.push(0b0010_0001);
    dictionary.push(1);
    dictionary.push(1);
    dictionary.extend_from_slice(&9u32.to_le_bytes()[..3]);
    dictionary.push(b'x');
    let mut skippable = b"\x50\x2a\x4d\x18".to_vec();
    skippable.extend_from_slice(&0u32.to_le_bytes());
    let mut reserved = valid.clone();
    reserved[4] |= 0b0000_1000;
    let mut unused = valid.clone();
    unused[4] |= 0b0001_0000;
    let mut trailing = valid.clone();
    trailing.push(0);
    let mut concatenated = valid.clone();
    concatenated.extend_from_slice(&valid);
    let mut truncated = valid.clone();
    let _ = truncated.pop();

    for encoded in [
        vec![],
        vec![0; 5],
        dictionary,
        skippable,
        reserved,
        unused,
        trailing,
        concatenated,
        truncated,
    ] {
        assert!(matches!(
            ZstdDecoder::new(&encoded, ZstdWindowLimit::new(128 * 1024)?),
            Err(CompressionDecodeError::InvalidData { .. })
        ));
    }
    Ok(())
}

#[test]
fn backend_corruption_is_invalid_data_and_sticky() -> Result<(), Box<dyn std::error::Error>> {
    let value = b"checksum protected Zstandard frame";
    let mut encoder = zstd::stream::Encoder::new(Vec::new(), 1)?;
    encoder.include_checksum(true)?;
    encoder.write_all(value)?;
    let mut encoded = encoder.finish()?;
    let checksum = encoded.last_mut().expect("content checksum");
    *checksum ^= 1;

    let mut decoder = ZstdDecoder::new(&encoded, ZstdWindowLimit::new(512 * 1024)?)?;
    assert_eq!(0, decoder.read(&mut [])?);
    loop {
        match decoder.read(&mut [0; 8]) {
            Ok(read) if read > 0 => {}
            Err(error) => {
                assert_eq!(io::ErrorKind::InvalidData, error.kind());
                break;
            }
            result => panic!("corrupt frame unexpectedly terminated: {result:?}"),
        }
    }
    assert_eq!(0, decoder.read(&mut [])?);
    assert_eq!(
        io::ErrorKind::InvalidData,
        decoder.read(&mut [0; 1]).expect_err("sticky").kind()
    );
    Ok(())
}
