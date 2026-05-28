//! HEC event envelope formatting.
//!
//! Splunk HEC accepts newline-delimited JSON where each line is:
//! `{"event": <payload>, "sourcetype": "<type>", "time": <unix_epoch_secs>}`
//!
//! When the incoming event is already an OCSF object with a `time` field
//! (milliseconds), we extract it and convert to seconds for the HEC envelope.
//! The full event remains inside `"event"` unchanged.

use serde_json::{json, Value};

const SOURCETYPE_OCSF: &str = "ocsf";

/// Wrap a single event in a Splunk HEC envelope.
///
/// `time` is set from `event["time"]` (OCSF milliseconds → seconds) when
/// available, otherwise falls back to 0 (caver uses ingest time as fallback).
pub fn hec_envelope(event: &Value) -> Value {
    let time_secs = event
        .get("time")
        .and_then(Value::as_u64)
        .map(|ms| ms / 1000)
        .unwrap_or(0);

    json!({
        "event": event,
        "sourcetype": SOURCETYPE_OCSF,
        "time": time_secs,
    })
}

/// Serialize a slice of events into a newline-delimited HEC batch string.
///
/// Each event becomes one `{"event": ..., "sourcetype": ..., "time": ...}` line.
pub fn format_batch(events: &[Value]) -> Result<String, serde_json::Error> {
    let mut out = String::new();
    for ev in events {
        let envelope = hec_envelope(ev);
        out.push_str(&serde_json::to_string(&envelope)?);
        out.push('\n');
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn envelope_extracts_ocsf_time() {
        let ev = json!({"class_uid": 4002, "time": 1779962400000u64});
        let env = hec_envelope(&ev);
        assert_eq!(env["time"], 1779962400u64);
        assert_eq!(env["sourcetype"], SOURCETYPE_OCSF);
        assert_eq!(env["event"]["class_uid"], 4002);
    }

    #[test]
    fn envelope_missing_time_defaults_zero() {
        let ev = json!({"class_uid": 3001});
        let env = hec_envelope(&ev);
        assert_eq!(env["time"], 0);
    }

    #[test]
    fn format_batch_produces_newline_delimited_json() {
        let events = vec![
            json!({"class_uid": 4002, "time": 1779962400000u64}),
            json!({"class_uid": 3001, "time": 1779962500000u64}),
        ];
        let batch = format_batch(&events).unwrap();
        let lines: Vec<&str> = batch.trim_end_matches('\n').split('\n').collect();
        assert_eq!(lines.len(), 2);

        let l0: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(l0["sourcetype"], SOURCETYPE_OCSF);
        assert_eq!(l0["time"], 1779962400u64);

        let l1: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(l1["event"]["class_uid"], 3001);
    }

    #[test]
    fn format_empty_batch() {
        let batch = format_batch(&[]).unwrap();
        assert!(batch.is_empty());
    }
}
