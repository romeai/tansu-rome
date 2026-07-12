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

use tansu_sans_io::record::compression::{
    CompressionDecodeError, CompressionDecodeLimit, SnappyBlockLimit, XerialSnappyDecoder,
};

fn xerial(blocks: &[&[u8]]) -> Vec<u8> {
    let mut encoded = b"\x82SNAPPY\0".to_vec();
    encoded.extend_from_slice(&1u32.to_be_bytes());
    encoded.extend_from_slice(&1u32.to_be_bytes());
    for block in blocks {
        let compressed = snap::raw::Encoder::new()
            .compress_vec(block)
            .expect("compress");
        encoded.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&compressed);
    }
    encoded
}

fn read_all(decoder: &mut XerialSnappyDecoder<'_, '_>) -> io::Result<Vec<u8>> {
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
fn streams_multiple_blocks_through_one_caller_scratch() -> Result<(), Box<dyn std::error::Error>> {
    let encoded = xerial(&[b"first", b"second block", b"third"]);
    let mut scratch = [0u8; 16];
    let scratch_address = scratch.as_ptr();
    {
        let mut decoder =
            XerialSnappyDecoder::new(&encoded, &mut scratch, SnappyBlockLimit::new(16)?)?;
        assert_eq!(0, decoder.read(&mut [])?);
        assert_eq!(
            b"firstsecond blockthird",
            read_all(&mut decoder)?.as_slice()
        );
        assert_eq!(0, decoder.read(&mut [0; 1])?);
        assert_eq!(0, decoder.read(&mut [0; 1])?);
    }
    assert_eq!(scratch_address, scratch.as_ptr());
    assert_eq!(&scratch[..5], b"third");

    let mut future_writer = xerial(&[b"future writer"]);
    future_writer[8..12].copy_from_slice(&2i32.to_be_bytes());
    let mut decoder =
        XerialSnappyDecoder::new(&future_writer, &mut scratch, SnappyBlockLimit::new(16)?)?;
    assert_eq!(b"future writer", read_all(&mut decoder)?.as_slice());
    Ok(())
}

#[test]
fn scans_later_blocks_and_scratch_before_decompression() -> Result<(), Box<dyn std::error::Error>> {
    let encoded = xerial(&[b"ok", b"later block is too large"]);
    let mut scratch = [0u8; 8];
    assert!(matches!(
        XerialSnappyDecoder::new(&encoded, &mut scratch, SnappyBlockLimit::new(8)?),
        Err(CompressionDecodeError::LimitExceeded {
            kind: CompressionDecodeLimit::SnappyBlockBytes,
            limit: 8,
            actual: 24,
        })
    ));

    let encoded = xerial(&[b"12345678"]);
    let mut scratch = [0u8; 7];
    assert!(matches!(
        XerialSnappyDecoder::new(&encoded, &mut scratch, SnappyBlockLimit::new(8)?),
        Err(CompressionDecodeError::ScratchTooSmall {
            kind: CompressionDecodeLimit::SnappyBlockBytes,
            required: 8,
            actual: 7,
        })
    ));
    Ok(())
}

#[test]
fn malformed_xerial_envelopes_fail_deterministically() -> Result<(), Box<dyn std::error::Error>> {
    let mut zero_version = xerial(&[b"value"]);
    zero_version[8..12].copy_from_slice(&0i32.to_be_bytes());
    let mut negative_version = xerial(&[b"value"]);
    negative_version[8..12].copy_from_slice(&(-1i32).to_be_bytes());
    let mut future_compatible = xerial(&[b"value"]);
    future_compatible[12..16].copy_from_slice(&2i32.to_be_bytes());
    let mut negative_compatible = xerial(&[b"value"]);
    negative_compatible[12..16].copy_from_slice(&(-1i32).to_be_bytes());
    let mut truncated_length = xerial(&[]);
    truncated_length.push(0);
    let mut truncated_block = xerial(&[]);
    truncated_block.extend_from_slice(&4u32.to_be_bytes());
    truncated_block.push(0);
    let mut empty_block = xerial(&[]);
    empty_block.extend_from_slice(&0u32.to_be_bytes());

    for encoded in [
        vec![],
        vec![0; 16],
        zero_version,
        negative_version,
        future_compatible,
        negative_compatible,
        truncated_length,
        truncated_block,
        empty_block,
    ] {
        let mut scratch = [0u8; 32];
        assert!(matches!(
            XerialSnappyDecoder::new(&encoded, &mut scratch, SnappyBlockLimit::new(32)?),
            Err(CompressionDecodeError::InvalidData { .. })
        ));
    }
    Ok(())
}

#[test]
fn corrupt_block_failure_is_sticky_and_zero_reads_are_side_effect_free()
-> Result<(), Box<dyn std::error::Error>> {
    let mut encoded = xerial(&[b"a sufficiently long value to corrupt"]);
    let compressed_length = u32::from_be_bytes(encoded[16..20].try_into().expect("length"));
    encoded[16..20].copy_from_slice(&(compressed_length - 1).to_be_bytes());
    let _ = encoded.pop();
    let mut scratch = [0u8; 64];
    let mut decoder = XerialSnappyDecoder::new(&encoded, &mut scratch, SnappyBlockLimit::new(64)?)?;
    assert_eq!(0, decoder.read(&mut [])?);
    assert_eq!(
        io::ErrorKind::InvalidData,
        decoder.read(&mut [0; 64]).expect_err("corrupt").kind()
    );
    assert_eq!(0, decoder.read(&mut [])?);
    assert_eq!(
        io::ErrorKind::InvalidData,
        decoder.read(&mut [0; 1]).expect_err("sticky").kind()
    );
    Ok(())
}
