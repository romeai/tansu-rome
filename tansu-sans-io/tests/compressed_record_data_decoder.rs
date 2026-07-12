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

use std::io::{self, Write};

use bytes::Bytes;
use tansu_sans_io::{
    Encode as _,
    record::{
        Record,
        borrowed::{RecordDecodeError, RecordDecodeLimits, ValueRecords, ValueRef},
        compression::{
            CompressedRecordDataDecoder, Lz4BlockLimit, SnappyBlockLimit, ZstdWindowLimit,
        },
    },
};

fn record_data() -> tansu_sans_io::Result<Bytes> {
    let records = [
        Record::builder()
            .value(Some(Bytes::from_static(b"selected value")))
            .build()?,
        Record::builder().value(None).build()?,
    ];
    records.as_slice().encode()
}

fn limits(stream_bytes: usize) -> RecordDecodeLimits {
    RecordDecodeLimits {
        max_record_bytes: stream_bytes,
        max_decoded_bytes: stream_bytes,
        max_records: 2,
        max_key_bytes: stream_bytes,
        max_value_bytes: 32,
        max_header_key_bytes: stream_bytes,
        max_header_value_bytes: stream_bytes,
        max_headers: 0,
        max_work_units: 1_000,
    }
}

fn assert_values(
    decoder: CompressedRecordDataDecoder<'_, '_>,
    stream_bytes: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut value_scratch = [0u8; 32];
    let mut transfer_scratch = [0u8; 16];
    let mut values = ValueRecords::new(
        decoder,
        &mut value_scratch,
        &mut transfer_scratch,
        2,
        limits(stream_bytes),
    )?;
    assert_eq!(
        Some(ValueRef::Bytes(b"selected value")),
        values.next_value()?
    );
    assert_eq!(Some(ValueRef::Null), values.next_value()?);
    assert_eq!(None, values.next_value()?);
    assert_eq!(None, values.next_value()?);
    Ok(())
}

fn xerial_snappy(value: &[u8]) -> Result<Vec<u8>, snap::Error> {
    let mut encoded = b"\x82SNAPPY\0".to_vec();
    encoded.extend_from_slice(&1u32.to_be_bytes());
    encoded.extend_from_slice(&1u32.to_be_bytes());
    append_xerial_block(&mut encoded, value)?;
    Ok(encoded)
}

fn append_xerial_block(encoded: &mut Vec<u8>, value: &[u8]) -> Result<(), snap::Error> {
    let compressed = snap::raw::Encoder::new().compress_vec(value)?;
    encoded.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&compressed);
    Ok(())
}

fn assert_terminal_corruption(
    decoder: CompressedRecordDataDecoder<'_, '_>,
    stream_bytes: usize,
    finish: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut value_scratch = [0u8; 32];
    let mut transfer_scratch = [0u8; 16];
    let mut values = ValueRecords::new(
        decoder,
        &mut value_scratch,
        &mut transfer_scratch,
        2,
        limits(stream_bytes),
    )?;
    assert_eq!(
        Some(ValueRef::Bytes(b"selected value")),
        values.next_value()?
    );
    assert_eq!(Some(ValueRef::Null), values.next_value()?);
    let expected = RecordDecodeError::ReaderIo {
        field: "trailing record data",
        kind: io::ErrorKind::InvalidData,
    };
    if finish {
        let failure = match values.finish() {
            Ok(_) => panic!("terminal codec corruption became successful EOF"),
            Err(failure) => failure,
        };
        assert_eq!(&expected, failure.error());
    } else {
        assert_eq!(
            expected,
            values.next_value().expect_err("terminal codec corruption")
        );
    }
    Ok(())
}

#[test]
fn every_compressed_variant_feeds_the_bounded_value_stream()
-> Result<(), Box<dyn std::error::Error>> {
    let record_data = record_data()?;

    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gzip.write_all(&record_data)?;
    let gzip = gzip.finish()?;
    assert_values(CompressedRecordDataDecoder::gzip(&gzip)?, record_data.len())?;

    let snappy = xerial_snappy(&record_data)?;
    let mut snappy_scratch = [0u8; 256];
    assert_values(
        CompressedRecordDataDecoder::xerial_snappy(
            &snappy,
            &mut snappy_scratch,
            SnappyBlockLimit::new(256)?,
        )?,
        record_data.len(),
    )?;

    let mut lz4 = lz4::EncoderBuilder::new().build(Vec::new())?;
    lz4.write_all(&record_data)?;
    let (lz4, result) = lz4.finish();
    result?;
    assert_values(
        CompressedRecordDataDecoder::lz4(&lz4, Lz4BlockLimit::KiB64)?,
        record_data.len(),
    )?;

    let zstd = zstd::stream::encode_all(record_data.as_ref(), 1)?;
    assert_values(
        CompressedRecordDataDecoder::zstd(&zstd, ZstdWindowLimit::new(1024 * 1024)?)?,
        record_data.len(),
    )?;
    Ok(())
}

#[test]
fn terminal_corruption_in_every_codec_rejects_next_and_finish_at_exact_eof()
-> Result<(), Box<dyn std::error::Error>> {
    let record_data = record_data()?;

    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gzip.write_all(&record_data)?;
    let mut gzip = gzip.finish()?;
    gzip.push(0);
    for finish in [false, true] {
        assert_terminal_corruption(
            CompressedRecordDataDecoder::gzip(&gzip)?,
            record_data.len(),
            finish,
        )?;
    }

    let mut snappy = xerial_snappy(&record_data)?;
    let mut corrupt_block = snap::raw::Encoder::new()
        .compress_vec(b"later corrupt block with a valid decoded length")?;
    let _ = corrupt_block.pop();
    snappy.extend_from_slice(&(corrupt_block.len() as u32).to_be_bytes());
    snappy.extend_from_slice(&corrupt_block);
    for finish in [false, true] {
        let mut block_scratch = [0u8; 256];
        assert_terminal_corruption(
            CompressedRecordDataDecoder::xerial_snappy(
                &snappy,
                &mut block_scratch,
                SnappyBlockLimit::new(256)?,
            )?,
            record_data.len(),
            finish,
        )?;
    }

    let mut lz4 = lz4::EncoderBuilder::new().build(Vec::new())?;
    lz4.write_all(&record_data)?;
    let (mut lz4, result) = lz4.finish();
    result?;
    *lz4.last_mut().expect("content checksum") ^= 1;
    for finish in [false, true] {
        assert_terminal_corruption(
            CompressedRecordDataDecoder::lz4(&lz4, Lz4BlockLimit::KiB64)?,
            record_data.len(),
            finish,
        )?;
    }

    let mut zstd = zstd::stream::Encoder::new(Vec::new(), 1)?;
    zstd.include_checksum(true)?;
    zstd.write_all(&record_data)?;
    let mut zstd = zstd.finish()?;
    *zstd.last_mut().expect("content checksum") ^= 1;
    for finish in [false, true] {
        assert_terminal_corruption(
            CompressedRecordDataDecoder::zstd(&zstd, ZstdWindowLimit::new(512 * 1024)?)?,
            record_data.len(),
            finish,
        )?;
    }
    Ok(())
}
