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

use bytes::Bytes;
use tansu_sans_io::{
    BatchAttribute, Compression, Error,
    record::{
        Record,
        compression::{
            CompressedRecordDataDecoder, Lz4BlockLimit, SnappyBlockLimit, ZstdWindowLimit,
        },
        deflated, inflated,
    },
};

const DECODED: &[u8] = b"one exact decoded byte stream";

fn xerial_snappy(value: &[u8]) -> Result<Vec<u8>, snap::Error> {
    let compressed = snap::raw::Encoder::new().compress_vec(value)?;
    let mut encoded = b"\x82SNAPPY\0".to_vec();
    encoded.extend_from_slice(&1i32.to_be_bytes());
    encoded.extend_from_slice(&1i32.to_be_bytes());
    encoded.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&compressed);
    Ok(encoded)
}

fn read_in_small_chunks(mut decoder: impl Read) -> io::Result<Vec<u8>> {
    let mut decoded = Vec::new();
    let mut chunk = [0; 3];
    loop {
        let read = decoder.read(&mut chunk)?;
        if read == 0 {
            assert_eq!(0, decoder.read(&mut chunk)?);
            return Ok(decoded);
        }
        decoded.extend_from_slice(&chunk[..read]);
    }
}

#[test]
fn every_variant_is_a_generic_exact_read_stream() -> Result<(), Box<dyn std::error::Error>> {
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gzip.write_all(DECODED)?;
    let gzip = gzip.finish()?;
    assert_eq!(
        DECODED,
        read_in_small_chunks(CompressedRecordDataDecoder::gzip(&gzip)?)?
    );

    let snappy = xerial_snappy(DECODED)?;
    let mut snappy_scratch = [0; 64];
    assert_eq!(
        DECODED,
        read_in_small_chunks(CompressedRecordDataDecoder::xerial_snappy(
            &snappy,
            &mut snappy_scratch,
            SnappyBlockLimit::new(64)?,
        )?)?
    );

    let mut lz4 = lz4::EncoderBuilder::new().build(Vec::new())?;
    lz4.write_all(DECODED)?;
    let (lz4, result) = lz4.finish();
    result?;
    assert_eq!(
        DECODED,
        read_in_small_chunks(CompressedRecordDataDecoder::lz4(
            &lz4,
            Lz4BlockLimit::KiB64,
        )?)?
    );

    let zstd = zstd::stream::encode_all(DECODED, 1)?;
    assert_eq!(
        DECODED,
        read_in_small_chunks(CompressedRecordDataDecoder::zstd(
            &zstd,
            ZstdWindowLimit::new(1024 * 1024)?,
        )?)?
    );
    Ok(())
}

fn owned_batch(compression: Compression) -> Result<deflated::Batch, Error> {
    inflated::Batch::builder()
        .attributes(BatchAttribute::default().compression(compression).into())
        .record(Record::builder().value(Some(Bytes::from_static(b"first"))))
        .record(Record::builder().value(Some(Bytes::from_static(b"second"))))
        .build()
        .and_then(deflated::Batch::try_from)
}

#[test]
fn default_owned_conversion_uses_every_bounded_reader() -> Result<(), Error> {
    for compression in [
        Compression::Gzip,
        Compression::Snappy,
        Compression::Lz4,
        Compression::Zstd,
    ] {
        let inflated = inflated::Batch::try_from(owned_batch(compression)?)?;
        assert_eq!(2, inflated.records.len());
        assert_eq!(
            Some(Bytes::from_static(b"first")),
            inflated.records[0].value
        );
        assert_eq!(
            Some(Bytes::from_static(b"second")),
            inflated.records[1].value
        );
    }
    Ok(())
}

#[test]
fn owned_conversion_rejects_trailing_decoded_record_data() -> Result<(), Error> {
    let mut batch = owned_batch(Compression::Gzip)?;
    batch.record_count = 1;
    assert!(matches!(
        inflated::Batch::try_from(batch),
        Err(Error::RecordDataNotExhausted)
    ));
    Ok(())
}
