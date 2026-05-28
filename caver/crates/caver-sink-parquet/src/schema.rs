//! Arrow schema inference and Parquet serialization.
//!
//! Builds a dynamic Arrow `RecordBatch` from a slice of `serde_json::Value`
//! objects, then serializes to Parquet bytes (Snappy compression).
//!
//! Dictionary encoding is applied to the six high-cardinality-but-bounded
//! OCSF enum columns so downstream readers benefit from predicate pushdown:
//!   class_uid, category_uid, severity_id, activity_id, status_id, type_uid

use std::collections::HashMap;
use std::sync::Arc;

use arrow::array::{ArrayRef, DictionaryArray, Int32Array, StringArray};
use arrow::datatypes::{DataType, Field, Int32Type, Schema};
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;
use serde_json::Value;
use thiserror::Error;

/// Six OCSF enum columns that get dictionary encoding.
const DICT_COLS: &[&str] = &[
    "class_uid",
    "category_uid",
    "severity_id",
    "activity_id",
    "status_id",
    "type_uid",
];

#[derive(Debug, Error)]
pub enum SchemaError {
    #[error("arrow error: {0}")]
    Arrow(#[from] arrow::error::ArrowError),
    #[error("parquet error: {0}")]
    Parquet(#[from] parquet::errors::ParquetError),
    #[error("empty batch")]
    EmptyBatch,
}

/// Serialize `events` to Parquet bytes with Snappy compression.
///
/// Schema is inferred from the union of all keys across all events.
/// Missing values become null.  All non-numeric, non-boolean fields
/// are stored as UTF-8 strings so arbitrary OCSF extensions pass through.
pub fn events_to_parquet(events: &[Value]) -> Result<Vec<u8>, SchemaError> {
    if events.is_empty() {
        return Err(SchemaError::EmptyBatch);
    }

    // 1. Collect all column names in stable order (insertion order of first
    //    event wins for columns present in the first event; others appended).
    let mut col_names: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = Default::default();
    for ev in events {
        if let Value::Object(map) = ev {
            for k in map.keys() {
                if seen.insert(k.clone()) {
                    col_names.push(k.clone());
                }
            }
        }
    }

    // 2. Build per-column string vecs (nulls become empty Option).
    let mut columns: HashMap<&str, Vec<Option<String>>> =
        col_names.iter().map(|k| (k.as_str(), vec![None; events.len()])).collect();

    for (row, ev) in events.iter().enumerate() {
        if let Value::Object(map) = ev {
            for (k, v) in map {
                if let Some(col) = columns.get_mut(k.as_str()) {
                    col[row] = Some(json_to_string(v));
                }
            }
        }
    }

    // 3. Build Arrow fields + arrays.
    let mut fields: Vec<Field> = Vec::with_capacity(col_names.len());
    let mut arrays: Vec<ArrayRef> = Vec::with_capacity(col_names.len());

    let is_dict = |name: &str| DICT_COLS.contains(&name);

    for name in &col_names {
        let vals = &columns[name.as_str()];
        if is_dict(name) {
            // Dictionary-encoded Int32 → Utf8 for OCSF enum columns.
            let (field, arr) = make_dict_column(name, vals)?;
            fields.push(field);
            arrays.push(arr);
        } else {
            let arr: StringArray = vals.iter().map(|v| v.as_deref()).collect();
            fields.push(Field::new(name, DataType::Utf8, true));
            arrays.push(Arc::new(arr));
        }
    }

    let schema = Arc::new(Schema::new(fields));
    let batch = RecordBatch::try_new(schema.clone(), arrays)?;

    // 4. Serialize to Parquet with Snappy compression.
    let props = WriterProperties::builder()
        .set_compression(Compression::SNAPPY)
        .build();

    let mut buf: Vec<u8> = Vec::new();
    let mut writer = ArrowWriter::try_new(&mut buf, schema, Some(props))?;
    writer.write(&batch)?;
    writer.close()?;

    Ok(buf)
}

/// Build a dictionary-encoded (Int32 → Utf8) column.
fn make_dict_column(
    name: &str,
    vals: &[Option<String>],
) -> Result<(Field, ArrayRef), arrow::error::ArrowError> {
    // Collect unique values (order matters for the dictionary keys).
    let mut dict: Vec<String> = Vec::new();
    let mut dict_idx: HashMap<&str, i32> = HashMap::new();

    let indices: Vec<Option<i32>> = vals
        .iter()
        .map(|v| {
            v.as_deref().map(|s| {
                if let Some(&idx) = dict_idx.get(s) {
                    idx
                } else {
                    let idx = dict.len() as i32;
                    dict_idx.insert(unsafe {
                        // SAFETY: string lifetime is tied to `vals` which outlives this call.
                        std::mem::transmute::<&str, &str>(s)
                    }, idx);
                    dict.push(s.to_string());
                    idx
                }
            })
        })
        .collect();

    let keys = Int32Array::from(indices);
    let values = StringArray::from(dict);
    let arr = DictionaryArray::<Int32Type>::try_new(keys, Arc::new(values))?;

    let field = Field::new(
        name,
        DataType::Dictionary(Box::new(DataType::Int32), Box::new(DataType::Utf8)),
        true,
    );
    Ok((field, Arc::new(arr)))
}

fn json_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use serde_json::json;

    fn roundtrip(events: &[Value]) -> Vec<RecordBatch> {
        let bytes = events_to_parquet(events).expect("serialize");
        let reader = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .unwrap()
            .build()
            .unwrap();
        reader.collect::<Result<Vec<_>, _>>().unwrap()
    }

    #[test]
    fn basic_roundtrip() {
        let events = vec![
            json!({"class_uid": "4002", "severity_id": "2", "actor": {"user": {"name": "alice"}}}),
            json!({"class_uid": "4002", "severity_id": "3", "extra": "x"}),
        ];
        let batches = roundtrip(&events);
        assert_eq!(batches[0].num_rows(), 2);
    }

    #[test]
    fn dict_columns_present() {
        let events = vec![
            json!({"class_uid": "4002", "category_uid": "4", "severity_id": "2",
                   "activity_id": "1", "status_id": "1", "type_uid": "400201"}),
        ];
        let bytes = events_to_parquet(&events).unwrap();
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes)).unwrap();
        let schema = builder.schema().clone();
        let dict_fields: Vec<_> = schema
            .fields()
            .iter()
            .filter(|f| matches!(f.data_type(), DataType::Dictionary(_, _)))
            .map(|f| f.name().as_str())
            .collect();
        for col in DICT_COLS {
            assert!(dict_fields.contains(col), "missing dict col: {col}");
        }
    }

    #[test]
    fn empty_batch_errors() {
        assert!(matches!(events_to_parquet(&[]), Err(SchemaError::EmptyBatch)));
    }

    #[test]
    fn missing_fields_become_null() {
        let events = vec![
            json!({"class_uid": "4002", "only_in_first": "yes"}),
            json!({"class_uid": "4002"}),
        ];
        let batches = roundtrip(&events);
        // "only_in_first" column should exist with 1 non-null + 1 null row.
        let batch = &batches[0];
        let col_idx = batch.schema().index_of("only_in_first").unwrap();
        assert_eq!(batch.column(col_idx).null_count(), 1);
    }
}
