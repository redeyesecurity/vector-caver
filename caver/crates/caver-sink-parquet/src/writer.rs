use crate::schema::{rows_to_record_batch, rows_to_staging_record_batch};
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, Encoding, ZstdLevel};
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

/// Serialize rows to the caver_staging PARQUET-CONTRACT shape
/// (RES-splunk-caver#1800): typed columns (see
/// [`crate::schema::rows_to_staging_record_batch`]), zstd compression —
/// byte-contract parity with the Python collector's
/// `_to_staging_parquet_bytes`.
pub fn rows_to_staging_parquet(rows: &[HashMap<String, String>]) -> Result<Vec<u8>, WriteError> {
    let batch = rows_to_staging_record_batch(rows)?;

    let props = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::default()))
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
    use arrow::array::{Array, Float64Array, Int64Array, StringArray};
    use arrow::datatypes::DataType;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    #[test]
    fn staging_roundtrip_typed_columns() {
        let rows = vec![
            HashMap::from([
                ("_time".into(), "1765551845.25".into()),
                ("class_uid".into(), "4002".into()),
                ("class_name".into(), "Authentication".into()),
                ("index".into(), "main".into()),
                ("host".into(), "edge-01".into()),
                ("source".into(), "demo".into()),
                ("sourcetype".into(), "demo:json".into()),
                ("_raw".into(), "hello".into()),
                ("severity_id".into(), "3.9".into()),
                ("type_uid".into(), "400201".into()),
                ("metric_value".into(), "99.5".into()),
            ]),
            HashMap::from([
                ("_time".into(), "not-a-number".into()),
                ("class_uid".into(), "garbage".into()),
                ("class_name".into(), "Authentication".into()),
                ("index".into(), "main".into()),
                ("host".into(), "edge-01".into()),
                ("source".into(), "demo".into()),
                ("sourcetype".into(), "demo:json".into()),
                ("_raw".into(), "world".into()),
                // severity_id + extra_field missing on this row
                ("extra_field".into(), "only-row-2".into()),
            ]),
        ];
        let out = rows_to_staging_parquet(&rows).expect("serialize");
        assert_eq!(&out[..4], b"PAR1");

        let reader = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(out))
            .expect("parquet readable")
            .build()
            .expect("reader");
        let batches: Vec<_> = reader.collect::<Result<_, _>>().expect("read batches");
        let batch = &batches[0];
        let schema = batch.schema();

        // Columns are the sorted union of all row keys.
        let names: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "columns alphabetically sorted");
        assert!(names.contains(&"extra_field"), "union of all rows' keys");

        // Contract types.
        let f = |n: &str| schema.field_with_name(n).unwrap().data_type().clone();
        assert_eq!(f("_time"), DataType::Float64);
        assert_eq!(f("class_uid"), DataType::Int64);
        assert_eq!(f("severity_id"), DataType::Int64);
        assert_eq!(f("_raw"), DataType::Utf8);

        let col = |n: &str| batch.column(schema.index_of(n).unwrap()).clone();
        let times = col("_time");
        let times = times.as_any().downcast_ref::<Float64Array>().unwrap();
        assert_eq!(times.value(0), 1765551845.25);
        assert_eq!(times.value(1), 0.0, "unparseable float -> 0.0");

        let cuids = col("class_uid");
        let cuids = cuids.as_any().downcast_ref::<Int64Array>().unwrap();
        assert_eq!(cuids.value(0), 4002);
        assert_eq!(cuids.value(1), 0, "unparseable int -> 0");

        let sevs = col("severity_id");
        let sevs = sevs.as_any().downcast_ref::<Int64Array>().unwrap();
        assert_eq!(sevs.value(0), 3, "int(float(v)) truncation");
        assert_eq!(sevs.value(1), 0, "missing int -> 0");

        // The remaining typed contract columns share severity_id/_time's code
        // path but were never exercised (caver-collector#899 item 4).
        assert_eq!(f("type_uid"), DataType::Int64);
        let tuids = col("type_uid");
        let tuids = tuids.as_any().downcast_ref::<Int64Array>().unwrap();
        assert_eq!(tuids.value(0), 400201);
        assert_eq!(tuids.value(1), 0, "missing int -> 0");

        assert_eq!(f("metric_value"), DataType::Float64);
        let metrics = col("metric_value");
        let metrics = metrics.as_any().downcast_ref::<Float64Array>().unwrap();
        assert_eq!(metrics.value(0), 99.5);
        assert_eq!(metrics.value(1), 0.0, "missing float -> 0.0");

        let extra = col("extra_field");
        let extra = extra.as_any().downcast_ref::<StringArray>().unwrap();
        assert!(!extra.is_null(0), "missing string is \"\", not null");
        assert_eq!(extra.value(0), "");
        assert_eq!(extra.value(1), "only-row-2");
    }

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
