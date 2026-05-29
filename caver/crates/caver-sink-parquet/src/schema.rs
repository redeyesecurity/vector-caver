use arrow::array::{ArrayRef, StringArray};
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

/// Build an Arrow RecordBatch from a slice of flat string-valued rows.
/// All values are stored as Utf8 (string) with dictionary encoding on DICT_COLUMNS.
/// Unknown columns pass through as plain Utf8.
pub fn rows_to_record_batch(rows: &[HashMap<String, String>]) -> Result<RecordBatch, arrow::error::ArrowError> {
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
                &DataType::Dictionary(
                    Box::new(DataType::Int32),
                    Box::new(DataType::Utf8),
                ),
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
