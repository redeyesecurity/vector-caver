//! Enrichment table lookup for OTTL pipelines (caver-collector#86).
//!
//! An enrichment table is a JSON array of objects (in-memory sidecar):
//!   `[{"key_field": "value", "attr1": "...", "attr2": "..."}, ...]`
//!
//! Public API:
//!   `lookup(table, key_field, key_value)` → `Option<&Value>` — first matching row
//!   `enrich_event(event, table, key_field, copy_fields)` → `Value` — event with added fields
//!   `build_index(table, key_field)` → `Vec<(String, usize)>` — sorted lookup index

use serde_json::Value;

/// Find the first row in `table` where `row[key_field] == key_value`.
/// `table` must be a JSON array of objects.
pub fn lookup<'a>(table: &'a Value, key_field: &str, key_value: &str) -> Option<&'a Value> {
    table.as_array()?.iter().find(|row| {
        row.get(key_field)
            .and_then(Value::as_str)
            .is_some_and(|v| v == key_value)
    })
}

/// Enrich `event` by looking up `event[key_field]` in `table` and copying
/// fields from the matching row into the event.
///
/// `copy_fields`: which fields to copy from the matched row. Pass `&[]` to
/// copy all fields except `key_field` itself.
///
/// Returns the enriched event. If no match is found or the event is not an
/// object, returns the original event unchanged.
pub fn enrich_event(event: &Value, table: &Value, key_field: &str, copy_fields: &[&str]) -> Value {
    let obj = match event.as_object() {
        Some(o) => o,
        None => return event.clone(),
    };
    let key_value = match obj.get(key_field).and_then(Value::as_str) {
        Some(v) => v,
        None => return event.clone(),
    };
    let row = match lookup(table, key_field, key_value) {
        Some(r) => r,
        None => return event.clone(),
    };
    let row_obj = match row.as_object() {
        Some(o) => o,
        None => return event.clone(),
    };

    let mut enriched = obj.clone();
    for (k, v) in row_obj {
        if k == key_field {
            continue; // don't overwrite the key itself
        }
        if copy_fields.is_empty() || copy_fields.contains(&k.as_str()) {
            enriched.entry(k).or_insert_with(|| v.clone());
        }
    }
    Value::Object(enriched)
}

/// Build a sorted lookup index over `table` for the given `key_field`.
/// Returns a `Vec<(key_string, row_index)>` sorted by key for binary search.
///
/// This is useful when the same table is queried many times in a pipeline.
pub fn build_index(table: &Value, key_field: &str) -> Vec<(String, usize)> {
    let mut index: Vec<(String, usize)> = table
        .as_array()
        .map(|arr| {
            arr.iter()
                .enumerate()
                .filter_map(|(i, row)| {
                    row.get(key_field)
                        .and_then(Value::as_str)
                        .map(|k| (k.to_string(), i))
                })
                .collect()
        })
        .unwrap_or_default();
    index.sort_by(|(a, _), (b, _)| a.cmp(b));
    index
}

/// Look up a key in a pre-built index (binary search). Returns the row index if found.
pub fn index_lookup(index: &[(String, usize)], key: &str) -> Option<usize> {
    index
        .binary_search_by(|(k, _)| k.as_str().cmp(key))
        .ok()
        .map(|pos| index[pos].1)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_table() -> Value {
        json!([
            {"ip": "10.0.0.1", "hostname": "web1", "environment": "prod"},
            {"ip": "10.0.0.2", "hostname": "db1",  "environment": "prod"},
            {"ip": "192.168.1.1", "hostname": "router", "environment": "mgmt"},
        ])
    }

    #[test]
    fn lookup_hit() {
        let table = sample_table();
        let row = lookup(&table, "ip", "10.0.0.2").unwrap();
        assert_eq!(row["hostname"], "db1");
        assert_eq!(row["environment"], "prod");
    }

    #[test]
    fn lookup_miss_returns_none() {
        let table = sample_table();
        assert!(lookup(&table, "ip", "9.9.9.9").is_none());
    }

    #[test]
    fn lookup_empty_table() {
        let table = json!([]);
        assert!(lookup(&table, "ip", "10.0.0.1").is_none());
    }

    #[test]
    fn enrich_event_copies_all_fields() {
        let table = sample_table();
        let event = json!({"ip": "10.0.0.1", "bytes": 1024});
        let enriched = enrich_event(&event, &table, "ip", &[]);
        assert_eq!(enriched["hostname"], "web1");
        assert_eq!(enriched["environment"], "prod");
        assert_eq!(enriched["bytes"], 1024);
        assert_eq!(enriched["ip"], "10.0.0.1"); // key field preserved
    }

    #[test]
    fn enrich_event_selective_copy() {
        let table = sample_table();
        let event = json!({"ip": "10.0.0.1"});
        let enriched = enrich_event(&event, &table, "ip", &["hostname"]);
        assert_eq!(enriched["hostname"], "web1");
        assert!(enriched.get("environment").is_none());
    }

    #[test]
    fn enrich_event_no_match() {
        let table = sample_table();
        let event = json!({"ip": "1.2.3.4"});
        let enriched = enrich_event(&event, &table, "ip", &[]);
        assert_eq!(enriched, event); // unchanged
    }

    #[test]
    fn enrich_event_does_not_overwrite_existing() {
        let table = sample_table();
        // event already has "hostname" set
        let event = json!({"ip": "10.0.0.1", "hostname": "already-set"});
        let enriched = enrich_event(&event, &table, "ip", &[]);
        assert_eq!(enriched["hostname"], "already-set"); // not overwritten
    }

    #[test]
    fn enrich_non_object_unchanged() {
        let table = sample_table();
        let event = json!("not an object");
        assert_eq!(enrich_event(&event, &table, "ip", &[]), event);
    }

    #[test]
    fn build_and_search_index() {
        let table = sample_table();
        let index = build_index(&table, "ip");
        assert_eq!(index.len(), 3);

        let idx = index_lookup(&index, "10.0.0.2").unwrap();
        assert_eq!(table[idx]["hostname"], "db1");

        assert!(index_lookup(&index, "9.9.9.9").is_none());
    }

    #[test]
    fn index_lookup_sorted() {
        let table = sample_table();
        let index = build_index(&table, "ip");
        // Verify sorted order
        for i in 1..index.len() {
            assert!(index[i - 1].0 <= index[i].0);
        }
    }
}
