//! VRL `Value` ⇄ `serde_json::Value` bridging.
//!
//! `vrl-caver-stdlib` is a pure serde_json crate; remap hands us VRL values.
//! The upstream `TryInto<serde_json::Value> for Value` impl errors on
//! non-UTF-8 bytes — a remap pipeline must never fail on that, so the
//! VRL → JSON direction here is *total*: non-UTF-8 bytes convert lossily
//! (U+FFFD replacement), timestamps to RFC 3339, regexes to their source.

use vrl::prelude::*;

/// Convert a VRL value to JSON. Total — no failure path.
pub(crate) fn vrl_to_json(value: &Value) -> serde_json::Value {
    use serde_json::Value as J;
    match value {
        Value::Bytes(b) => J::String(String::from_utf8_lossy(b).into_owned()),
        Value::Integer(i) => J::from(*i),
        // Non-finite floats (NotNan still admits ±inf) map to JSON null —
        // same policy as serde_json's own From<f64>.
        Value::Float(f) => J::from(f.into_inner()),
        Value::Boolean(b) => J::from(*b),
        Value::Timestamp(ts) => J::String(ts.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)),
        Value::Regex(r) => J::String(r.as_str().to_string()),
        Value::Object(map) => J::Object(
            map.iter()
                .map(|(k, v)| (k.to_string(), vrl_to_json(v)))
                .collect(),
        ),
        Value::Array(arr) => J::Array(arr.iter().map(vrl_to_json).collect()),
        Value::Null => J::Null,
    }
}

/// Convert JSON to a VRL value via the upstream `From` impl.
/// Total — JSON numbers cannot be NaN.
pub(crate) fn json_to_vrl(value: serde_json::Value) -> Value {
    value.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone as _, Utc};
    use vrl::prelude::Bytes;

    #[test]
    fn non_utf8_bytes_convert_lossily_instead_of_erroring() {
        let v = Value::Bytes(Bytes::from_static(b"ok\xff"));
        assert_eq!(
            vrl_to_json(&v),
            serde_json::Value::String("ok\u{fffd}".into())
        );
    }

    #[test]
    fn timestamps_convert_to_rfc3339() {
        let ts = Utc.with_ymd_and_hms(2026, 6, 12, 1, 2, 3).unwrap();
        assert_eq!(
            vrl_to_json(&Value::Timestamp(ts)),
            serde_json::Value::String("2026-06-12T01:02:03Z".into())
        );
    }

    #[test]
    fn nested_object_round_trips() {
        let json = serde_json::json!({"a": 1, "b": ["x", true, null], "c": {"d": 2.5}});
        assert_eq!(vrl_to_json(&json_to_vrl(json.clone())), json);
    }
}
