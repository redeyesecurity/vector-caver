use arrow::array::{ArrayRef, Float64Array, Int64Array, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

/// Columns that get dictionary encoding (high-cardinality-but-bounded OCSF enums).
pub const DICT_COLUMNS: &[&str] = &[
    "class_uid",
    "category_uid",
    "severity_id",
    "activity_id",
    "status_id",
    "type_uid",
];

/// Int64 columns per the caver_staging PARQUET-CONTRACT (RES-splunk-caver#1800):
/// required `class_uid` + the optional pushdown enums.
pub const STAGING_INT_COLUMNS: &[&str] = &[
    "class_uid",
    "category_uid",
    "severity_id",
    "activity_id",
    "status_id",
    "type_uid",
];

/// Float64 columns per the contract.
pub const STAGING_FLOAT_COLUMNS: &[&str] = &["_time", "metric_value"];

/// Columns the contract requires on every row (compactor schema check).
pub const STAGING_REQUIRED: &[&str] = &[
    "_time",
    "class_uid",
    "class_name",
    "index",
    "host",
    "source",
    "sourcetype",
    "_raw",
];

/// Parse a numeric cell like the Python writer's `float(v)`: tolerate
/// surrounding whitespace (Python `float(' 3.5 ')` == 3.5).
pub(crate) fn parse_f64(s: &str) -> Option<f64> {
    s.trim().parse::<f64>().ok()
}

/// `int(float(v))` semantics of the Python writer: parse as float then
/// truncate toward zero; missing/unparseable → 0. Non-finite values also
/// coerce to 0 (Python raises OverflowError and loses the batch; saturating
/// to i64::MAX in a pushdown enum column would be silent corruption).
fn as_i64(v: Option<&String>) -> i64 {
    v.and_then(|s| parse_f64(s))
        .filter(|f| f.is_finite())
        .map(|f| f as i64)
        .unwrap_or(0)
}

/// Missing/unparseable → 0.0, matching the Python writer's `_as_float`.
fn as_f64(v: Option<&String>) -> f64 {
    v.and_then(|s| parse_f64(s)).unwrap_or(0.0)
}

/// Build a caver_staging-typed Arrow RecordBatch, mirroring the Python
/// collector's `_to_staging_parquet_bytes`: alphabetically sorted columns,
/// `_time`/`metric_value` as Float64, the OCSF enum columns as Int64,
/// everything else Utf8 with missing values as `""` (not null).
pub fn rows_to_staging_record_batch(
    rows: &[HashMap<String, String>],
) -> Result<RecordBatch, arrow::error::ArrowError> {
    // BTreeSet iteration is lexicographically sorted — same column order as
    // the Python writer's `sorted(keys)`.
    let mut col_set: BTreeSet<String> = BTreeSet::new();
    for row in rows {
        for k in row.keys() {
            col_set.insert(k.clone());
        }
    }

    let int_set: std::collections::HashSet<&str> = STAGING_INT_COLUMNS.iter().copied().collect();
    let float_set: std::collections::HashSet<&str> =
        STAGING_FLOAT_COLUMNS.iter().copied().collect();

    let mut fields: Vec<Field> = Vec::with_capacity(col_set.len());
    let mut arrays: Vec<ArrayRef> = Vec::with_capacity(col_set.len());

    for col in &col_set {
        let (dtype, arr): (DataType, ArrayRef) = if float_set.contains(col.as_str()) {
            let vals: Vec<f64> = rows.iter().map(|r| as_f64(r.get(col))).collect();
            (DataType::Float64, Arc::new(Float64Array::from(vals)))
        } else if int_set.contains(col.as_str()) {
            let vals: Vec<i64> = rows.iter().map(|r| as_i64(r.get(col))).collect();
            (DataType::Int64, Arc::new(Int64Array::from(vals)))
        } else {
            let vals: Vec<&str> = rows
                .iter()
                .map(|r| r.get(col).map(String::as_str).unwrap_or(""))
                .collect();
            (DataType::Utf8, Arc::new(StringArray::from(vals)))
        };
        fields.push(Field::new(col, dtype, true));
        arrays.push(arr);
    }

    let schema = Arc::new(Schema::new(fields));
    RecordBatch::try_new(schema, arrays)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_coercion_python_parity() {
        let s = |v: &str| Some(v.to_string());
        assert_eq!(as_i64(s("3.9").as_ref()), 3, "int(float(v)) truncation");
        assert_eq!(as_i64(s(" 42 ").as_ref()), 42, "float(' 42 ') trims");
        assert_eq!(as_i64(s("garbage").as_ref()), 0);
        assert_eq!(as_i64(None), 0);
        // Non-finite: Python raises OverflowError and DLQs the batch; we
        // coerce to 0 instead of silently saturating to i64::MAX.
        assert_eq!(as_i64(s("inf").as_ref()), 0);
        assert_eq!(as_i64(s("-inf").as_ref()), 0);
        assert_eq!(as_i64(s("NaN").as_ref()), 0);
    }

    #[test]
    fn float_coercion_python_parity() {
        let s = |v: &str| Some(v.to_string());
        assert_eq!(as_f64(s(" 1.5 ").as_ref()), 1.5);
        assert_eq!(as_f64(s("nope").as_ref()), 0.0);
        assert_eq!(as_f64(None), 0.0);
        // Python float('inf') succeeds and stores inf — parity.
        assert!(as_f64(s("inf").as_ref()).is_infinite());
    }
}

/// Build an Arrow RecordBatch from a slice of flat string-valued rows.
/// All values are stored as Utf8 (string) with dictionary encoding on DICT_COLUMNS.
/// Unknown columns pass through as plain Utf8.
pub fn rows_to_record_batch(
    rows: &[HashMap<String, String>],
) -> Result<RecordBatch, arrow::error::ArrowError> {
    // Collect ordered column names (stable ordering via BTreeSet).
    let mut col_set: BTreeSet<String> = BTreeSet::new();
    for row in rows {
        for k in row.keys() {
            col_set.insert(k.clone());
        }
    }
    let col_names: Vec<String> = col_set.into_iter().collect();

    let dict_set: std::collections::HashSet<&str> = DICT_COLUMNS.iter().copied().collect();

    let mut fields: Vec<Field> = Vec::with_capacity(col_names.len());
    let mut arrays: Vec<ArrayRef> = Vec::with_capacity(col_names.len());

    for col in &col_names {
        let vals: Vec<Option<&str>> = rows
            .iter()
            .map(|row| row.get(col).map(|s| s.as_str()))
            .collect();

        let string_arr = StringArray::from(vals);

        if dict_set.contains(col.as_str()) {
            // Dictionary-encode.
            let dict_arr = arrow::compute::cast(
                &(Arc::new(string_arr) as ArrayRef),
                &DataType::Dictionary(Box::new(DataType::Int32), Box::new(DataType::Utf8)),
            )?;
            fields.push(Field::new(col, dict_arr.data_type().clone(), true));
            arrays.push(dict_arr);
        } else {
            let arr: ArrayRef = Arc::new(string_arr);
            fields.push(Field::new(col, DataType::Utf8, true));
            arrays.push(arr);
        }
    }

    let schema = Arc::new(Schema::new(fields));
    RecordBatch::try_new(schema, arrays)
}
