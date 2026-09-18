//! Response-array extraction.
//!
//! A pull endpoint rarely returns a bare JSON array; the records are nested
//! under a key (`value` for Microsoft Graph, `data`, `results`, `items`, ...)
//! and the rest of the body carries pagination metadata. [`extract_records`]
//! locates the array with an RFC 6901 JSON pointer and returns its elements so
//! each becomes its own event.

use serde_json::Value;

/// Errors locating the record array in a response body.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExtractError {
    /// The pointer did not resolve to any node in the body.
    #[error("records pointer `{0}` did not resolve to anything in the response")]
    NotFound(String),
    /// The pointer resolved to a node that is not an array (and could not be
    /// wrapped as one).
    #[error("records pointer `{pointer}` resolved to a {found}, not a JSON array")]
    NotArray {
        /// The pointer that was followed.
        pointer: String,
        /// The JSON type actually found there.
        found: &'static str,
    },
}

/// Extract the record array from `body` using a JSON pointer (RFC 6901).
///
/// * An empty pointer (`""`) selects the whole body, so a response that *is* a
///   bare array works with the default configuration.
/// * A non-empty pointer must begin with `/` (e.g. `/value`, `/data/items`).
/// * When `wrap_object` is `true`, a pointer that resolves to a single object
///   (not an array) yields a one-element vector. Some endpoints collapse a
///   one-record page to a bare object; this keeps that case from erroring.
pub fn extract_records(
    body: &Value,
    pointer: &str,
    wrap_object: bool,
) -> Result<Vec<Value>, ExtractError> {
    let target = body
        .pointer(pointer)
        .ok_or_else(|| ExtractError::NotFound(pointer.to_string()))?;

    match target {
        Value::Array(arr) => Ok(arr.clone()),
        Value::Object(_) if wrap_object => Ok(vec![target.clone()]),
        other => Err(ExtractError::NotArray {
            pointer: pointer.to_string(),
            found: json_type_name(other),
        }),
    }
}

/// The RFC 8259 type name of a JSON value, for error messages.
fn json_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_nested_array() {
        let body = json!({"value": [{"id": 1}, {"id": 2}], "@odata.nextLink": "u"});
        let recs = extract_records(&body, "/value", false).unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0], json!({"id": 1}));
    }

    #[test]
    fn empty_pointer_selects_whole_body_array() {
        let body = json!([{"id": 1}, {"id": 2}]);
        let recs = extract_records(&body, "", false).unwrap();
        assert_eq!(recs.len(), 2);
    }

    #[test]
    fn deep_pointer() {
        let body = json!({"data": {"items": [1, 2, 3]}});
        let recs = extract_records(&body, "/data/items", false).unwrap();
        assert_eq!(recs, vec![json!(1), json!(2), json!(3)]);
    }

    #[test]
    fn missing_pointer_is_not_found() {
        let body = json!({"value": []});
        let err = extract_records(&body, "/missing", false).unwrap_err();
        assert!(matches!(err, ExtractError::NotFound(p) if p == "/missing"));
    }

    #[test]
    fn non_array_without_wrap_errors() {
        let body = json!({"value": {"id": 1}});
        let err = extract_records(&body, "/value", false).unwrap_err();
        assert!(matches!(err, ExtractError::NotArray { found, .. } if found == "object"));
    }

    #[test]
    fn single_object_wrapped_when_enabled() {
        let body = json!({"value": {"id": 1}});
        let recs = extract_records(&body, "/value", true).unwrap();
        assert_eq!(recs, vec![json!({"id": 1})]);
    }

    #[test]
    fn scalar_never_wrapped() {
        let body = json!({"value": 42});
        let err = extract_records(&body, "/value", true).unwrap_err();
        assert!(matches!(err, ExtractError::NotArray { found, .. } if found == "number"));
    }

    #[test]
    fn empty_array_is_ok() {
        let body = json!({"value": []});
        let recs = extract_records(&body, "/value", false).unwrap();
        assert!(recs.is_empty());
    }
}
