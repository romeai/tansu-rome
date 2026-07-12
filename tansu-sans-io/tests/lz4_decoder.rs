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

use lz4::{BlockMode, BlockSize, ContentChecksum, EncoderBuilder, liblz4::BlockChecksum};
use tansu_sans_io::record::compression::{
    CompressionDecodeError, CompressionDecodeLimit, Lz4BlockLimit, Lz4Decoder,
};

fn frame(
    value: &[u8],
    block_size: BlockSize,
    block_mode: BlockMode,
    checksums: bool,
    content_size: bool,
) -> io::Result<Vec<u8>> {
    let mut builder = EncoderBuilder::new();
    let _ = builder
        .block_size(block_size)
        .block_mode(block_mode)
        .block_checksum(if checksums {
            BlockChecksum::BlockChecksumEnabled
        } else {
            BlockChecksum::NoBlockChecksum
        })
        .checksum(if checksums {
            ContentChecksum::ChecksumEnabled
        } else {
            ContentChecksum::NoChecksum
        })
        .content_size(if content_size { value.len() as u64 } else { 0 });
    let mut encoder = builder.build(Vec::new())?;
    encoder.write_all(value)?;
    let (encoded, result) = encoder.finish();
    result?;
    Ok(encoded)
}

fn decode_all(decoder: &mut Lz4Decoder<'_>) -> io::Result<Vec<u8>> {
    let mut decoded = Vec::new();
    let mut chunk = [0u8; 5];
    loop {
        let read = decoder.read(&mut chunk)?;
        if read == 0 {
            return Ok(decoded);
        }
        decoded.extend_from_slice(&chunk[..read]);
    }
}

#[test]
fn streams_all_standard_block_sizes_and_both_block_modes() -> Result<(), Box<dyn std::error::Error>>
{
    for (size, limit) in [
        (BlockSize::Max64KB, Lz4BlockLimit::KiB64),
        (BlockSize::Max256KB, Lz4BlockLimit::KiB256),
        (BlockSize::Max1MB, Lz4BlockLimit::MiB1),
        (BlockSize::Max4MB, Lz4BlockLimit::MiB4),
    ] {
        for (mode, linked) in [(BlockMode::Linked, true), (BlockMode::Independent, false)] {
            let encoded = frame(b"bounded lz4", size.clone(), mode, true, true)?;
            let mut decoder = Lz4Decoder::new(&encoded, limit)?;
            assert_eq!(limit, decoder.selected_block_limit());
            assert_eq!(linked, decoder.has_linked_blocks());
            assert_eq!(0, decoder.read(&mut [])?);
            assert_eq!(b"bounded lz4", decode_all(&mut decoder)?.as_slice());
            assert_eq!(0, decoder.read(&mut [0; 1])?);
            assert_eq!(0, decoder.read(&mut [0; 1])?);
        }
    }
    Ok(())
}

#[test]
fn rejects_selected_and_encoded_blocks_above_admitted_size()
-> Result<(), Box<dyn std::error::Error>> {
    let encoded = frame(
        b"value",
        BlockSize::Max4MB,
        BlockMode::Independent,
        false,
        false,
    )?;
    assert!(matches!(
        Lz4Decoder::new(&encoded, Lz4BlockLimit::KiB64),
        Err(CompressionDecodeError::LimitExceeded {
            kind: CompressionDecodeLimit::Lz4BlockBytes,
            limit: 65_536,
            actual: 4_194_304,
        })
    ));

    let mut impossible_block = b"\x04\x22\x4d\x18\x60\x40\0".to_vec();
    impossible_block.extend_from_slice(&65_537u32.to_le_bytes());
    assert!(matches!(
        Lz4Decoder::new(&impossible_block, Lz4BlockLimit::KiB64),
        Err(CompressionDecodeError::InvalidData { .. })
    ));
    Ok(())
}

#[test]
fn preflight_requires_one_exact_structural_frame() -> Result<(), Box<dyn std::error::Error>> {
    let valid = frame(
        b"value",
        BlockSize::Max64KB,
        BlockMode::Independent,
        true,
        true,
    )?;
    let mut concatenated = valid.clone();
    concatenated.extend_from_slice(&valid);
    let mut trailing = valid.clone();
    trailing.push(0);
    let mut bad_version = valid.clone();
    bad_version[4] = (bad_version[4] & 0b0011_1111) | 0b1000_0000;
    let mut reserved_flag = valid.clone();
    reserved_flag[4] |= 0b0000_0010;
    let mut reserved_descriptor = valid.clone();
    reserved_descriptor[5] |= 1;
    let mut bad_block_identifier = valid.clone();
    bad_block_identifier[5] = (bad_block_identifier[5] & 0b1000_1111) | 0b0011_0000;
    let mut truncated_payload = frame(
        b"payload",
        BlockSize::Max64KB,
        BlockMode::Independent,
        false,
        false,
    )?;
    truncated_payload.truncate(truncated_payload.len() - 5);
    let mut truncated_checksum = valid.clone();
    let _ = truncated_checksum.pop();

    for encoded in [
        vec![],
        vec![0; 6],
        concatenated,
        trailing,
        bad_version,
        reserved_flag,
        reserved_descriptor,
        bad_block_identifier,
        truncated_payload,
        truncated_checksum,
    ] {
        assert!(matches!(
            Lz4Decoder::new(&encoded, Lz4BlockLimit::MiB4),
            Err(CompressionDecodeError::InvalidData { .. })
        ));
    }
    Ok(())
}

#[test]
fn checksum_corruption_and_empty_frames_have_sticky_terminal_states()
-> Result<(), Box<dyn std::error::Error>> {
    let mut corrupt = frame(
        b"checksum protected",
        BlockSize::Max64KB,
        BlockMode::Linked,
        true,
        false,
    )?;
    let last = corrupt.last_mut().expect("content checksum");
    *last ^= 1;
    let mut decoder = Lz4Decoder::new(&corrupt, Lz4BlockLimit::KiB64)?;
    assert_eq!(0, decoder.read(&mut [])?);
    loop {
        match decoder.read(&mut [0; 4]) {
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

    let empty = frame(
        b"",
        BlockSize::Max64KB,
        BlockMode::Independent,
        false,
        false,
    )?;
    let mut decoder = Lz4Decoder::new(&empty, Lz4BlockLimit::KiB64)?;
    assert_eq!(0, decoder.read(&mut [0; 1])?);
    assert_eq!(0, decoder.read(&mut [0; 1])?);
    Ok(())
}
