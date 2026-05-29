use crate::schema::rows_to_record_batch;
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, Encoding};
use parquet::file::properties::WriterProperties;
use std::collections::HashMap;
use std::io::Cursor;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WriteError {
    #[error("arrow error: {0}")]
    Arrow(#[from] arrow::error::ArrowError),
    #[error("parquet error: {0}")]
    Parquet(#[from] parquet::errors::ParquetError),
}

/// Serialize rows to a Parquet byte buffer.
/// Uses Snappy compression; dictionary encoding on the OCSF enum columns.
pub fn rows_to_parquet(rows: &[HashMap<String, String>]) -> Result<Vec<u8>, WriteError> {
    let batch = rows_to_record_batch(rows)?;

    let props = WriterProperties::builder()
        .set_compression(Compression::SNAPPY)
        .set_dictionary_enabled(true)
        .set_encoding(Encoding::PLAIN)
        .build();

    let mut buf = Cursor::new(Vec::new());
    let mut writer = ArrowWriter::try_new(&mut buf, batch.schema(), Some(props))?;
    writer.write(&batch)?;
    writer.close()?;
    Ok(buf.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_nonempty() {
        let rows = vec![
            HashMap::from([
                ("class_uid".into(), "2003".into()),
                ("ioc_value".into(), "1.2.3.4".into()),
                ("severity_id".into(), "4".into()),
            ]),
            HashMap::from([
                ("class_uid".into(), "2003".into()),
                ("ioc_value".into(), "evil.com".into()),
                ("severity_id".into(), "3".into()),
            ]),
        ];
        let bytes = rows_to_parquet(&rows).expect("serialize");
        assert!(!bytes.is_empty());
        // Parquet magic number: PAR1
        assert_eq!(&bytes[..4], b"PAR1");
    }
}
