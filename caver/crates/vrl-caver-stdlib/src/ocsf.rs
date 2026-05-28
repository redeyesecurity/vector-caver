//! OCSF classification and normalization (caver-collector#63).
//!
//! Public surface:
//!   `classify(event)` → OCSF class_uid (0 = unrecognised)
//!   `normalize(event)` → fully-formed OCSF JSON Value

use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Inspect a raw vendor event and return its OCSF class_uid, or 0 if unknown.
pub fn classify(event: &Value) -> u32 {
    let vendor = event.get("_vendor").and_then(Value::as_str).unwrap_or("");
    match vendor {
        "okta" => classify_okta(event),
        "nginx" => 3003,
        "sysmon" => classify_sysmon(event),
        _ => 0,
    }
}

/// Normalise a raw vendor event to a fully-formed OCSF JSON Value.
/// Returns `{"error": "..."}` if the event cannot be classified or mapped.
pub fn normalize(event: &Value) -> Value {
    let class_uid = classify(event);
    if class_uid == 0 {
        return json!({"error": "unclassified event — no _vendor match"});
    }
    let vendor = event.get("_vendor").and_then(Value::as_str).unwrap_or("");
    match (vendor, class_uid) {
        ("okta", 4002) => normalize_okta_auth(event),
        ("nginx", 3003) => normalize_nginx_http(event),
        ("sysmon", 5001) => normalize_sysmon_process(event),
        _ => json!({"error": "no normalizer registered for this vendor/class pair"}),
    }
}

/// Convert a severity string to `(severity_id, severity_name)`.
pub fn severity_id_name(s: &str) -> (u32, &'static str) {
    match s.to_uppercase().as_str() {
        "INFO" | "INFORMATIONAL" => (1, "Informational"),
        "LOW" => (2, "Low"),
        "MEDIUM" | "MODERATE" | "WARN" | "WARNING" => (3, "Medium"),
        "HIGH" | "ERROR" => (4, "High"),
        "CRITICAL" => (5, "Critical"),
        "FATAL" => (6, "Fatal"),
        _ => (0, "Unknown"),
    }
}

// ---------------------------------------------------------------------------
// Vendor classification helpers
// ---------------------------------------------------------------------------

fn classify_okta(event: &Value) -> u32 {
    let et = event.get("eventType").and_then(Value::as_str).unwrap_or("");
    if et.starts_with("user.authentication") {
        4002
    } else {
        0
    }
}

fn classify_sysmon(event: &Value) -> u32 {
    match event.get("EventID").and_then(Value::as_u64).unwrap_or(0) {
        1 => 5001, // Process Create
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Timestamp parsing (no external crate; handles the three formats used in
// golden fixtures)
// ---------------------------------------------------------------------------

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: u32) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(y) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Number of days from Unix epoch (1970-01-01) to the given date.
fn days_from_epoch(year: i64, month: u32, day: u32) -> i64 {
    let mut d = 0i64;
    for y in 1970..year {
        d += if is_leap(y) { 366 } else { 365 };
    }
    for m in 1..month {
        d += days_in_month(year, m);
    }
    d + (day as i64) - 1
}

fn to_epoch_ms(year: i64, month: u32, day: u32, h: u32, min: u32, sec: u32, ms: u32) -> i64 {
    days_from_epoch(year, month, day) * 86_400_000
        + (h as i64) * 3_600_000
        + (min as i64) * 60_000
        + (sec as i64) * 1_000
        + ms as i64
}

/// Parse ISO-8601 / RFC-3339: `2026-05-28T10:00:00.000Z`
fn parse_iso8601(s: &str) -> Option<i64> {
    let s = s.trim_end_matches('Z');
    let (date, time) = s.split_once('T')?;
    parse_ymd_hms(date, '-', time)
}

/// Parse Sysmon UTC timestamp: `2026-05-28 10:00:00.000`
fn parse_sysmon_ts(s: &str) -> Option<i64> {
    let (date, time) = s.split_once(' ')?;
    parse_ymd_hms(date, '-', time)
}

/// Shared date+time parser for ISO-8601 and Sysmon formats.
fn parse_ymd_hms(date: &str, sep: char, time: &str) -> Option<i64> {
    let mut dp = date.splitn(3, sep);
    let year: i64 = dp.next()?.parse().ok()?;
    let month: u32 = dp.next()?.parse().ok()?;
    let day: u32 = dp.next()?.parse().ok()?;

    let (time_base, ms_str) = time.split_once('.').unwrap_or((time, "0"));
    let ms: u32 = ms_str.parse().ok()?;
    let mut tp = time_base.splitn(3, ':');
    let h: u32 = tp.next()?.parse().ok()?;
    let min: u32 = tp.next()?.parse().ok()?;
    let sec: u32 = tp.next()?.parse().ok()?;

    Some(to_epoch_ms(year, month, day, h, min, sec, ms))
}

/// Parse nginx Common Log Format: `28/May/2026:10:00:00 +0000`
fn parse_clf(s: &str) -> Option<i64> {
    // Strip the timezone token; we treat everything as UTC.
    let s = s.split_whitespace().next()?;
    let mut parts = s.splitn(3, '/');
    let day: u32 = parts.next()?.parse().ok()?;
    let month: u32 = match parts.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    // remainder: "2026:10:00:00"
    let rest = parts.next()?;
    let (year_s, time_s) = rest.split_once(':')?;
    let year: i64 = year_s.parse().ok()?;
    let mut tp = time_s.splitn(3, ':');
    let h: u32 = tp.next()?.parse().ok()?;
    let min: u32 = tp.next()?.parse().ok()?;
    let sec: u32 = tp.next()?.parse().ok()?;

    Some(to_epoch_ms(year, month, day, h, min, sec, 0))
}

// ---------------------------------------------------------------------------
// Shared mapping helpers
// ---------------------------------------------------------------------------

fn outcome_to_status(result: &str) -> (u32, &'static str) {
    match result.to_uppercase().as_str() {
        "SUCCESS" => (1, "Success"),
        "FAILURE" | "FAILED" => (2, "Failure"),
        "PARTIAL_SUCCESS" => (3, "Other"),
        _ => (0, "Unknown"),
    }
}

fn http_status_to_ocsf(code: u32) -> (u32, &'static str) {
    match code {
        200..=299 => (1, "Success"),
        400..=499 | 500..=599 => (2, "Failure"),
        _ => (0, "Unknown"),
    }
}

fn windows_os_type_id(os_name: &str) -> u32 {
    let lower = os_name.to_lowercase();
    if lower.contains("windows") {
        100
    } else if lower.contains("linux") {
        200
    } else if lower.contains("mac") || lower.contains("darwin") {
        300
    } else {
        0
    }
}

fn windows_basename(path: &str) -> &str {
    path.rsplit(|c| c == '\\' || c == '/')
        .next()
        .unwrap_or(path)
}

// ---------------------------------------------------------------------------
// Vendor normalizers
// ---------------------------------------------------------------------------

fn normalize_okta_auth(event: &Value) -> Value {
    let time = event
        .get("published")
        .and_then(Value::as_str)
        .and_then(parse_iso8601)
        .unwrap_or(0);

    let sev_str = event
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("INFO");
    let (sev_id, sev_name) = severity_id_name(sev_str);

    let result = event
        .pointer("/outcome/result")
        .and_then(Value::as_str)
        .unwrap_or("");
    let (status_id, status_name) = outcome_to_status(result);

    let user_uid = event
        .pointer("/actor/id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let user_name = event
        .pointer("/actor/alternateId")
        .and_then(Value::as_str)
        .unwrap_or("");
    let user_full = event
        .pointer("/actor/displayName")
        .and_then(Value::as_str)
        .unwrap_or("");

    let src_ip = event
        .pointer("/client/ipAddress")
        .and_then(Value::as_str)
        .unwrap_or("");
    let os_name = event
        .pointer("/client/userAgent/os")
        .and_then(Value::as_str)
        .unwrap_or("");
    let os_type_id = windows_os_type_id(os_name);

    let app_uid = event
        .pointer("/target/0/id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let app_name = event
        .pointer("/target/0/displayName")
        .and_then(Value::as_str)
        .unwrap_or("");

    json!({
        "class_uid": 4002,
        "class_name": "Authentication",
        "category_uid": 3,
        "category_name": "Identity & Access Management",
        "activity_id": 1,
        "activity_name": "Logon",
        "type_uid": 400201,
        "time": time,
        "severity_id": sev_id,
        "severity": sev_name,
        "status_id": status_id,
        "status": status_name,
        "metadata": {
            "version": "1.3.0",
            "product": {
                "name": "Okta",
                "vendor_name": "Okta"
            },
            "profiles": ["security_control"]
        },
        "user": {
            "uid": user_uid,
            "name": user_name,
            "full_name": user_full,
            "type_id": 1
        },
        "src_endpoint": {
            "ip": src_ip,
            "os": {
                "name": os_name,
                "type_id": os_type_id
            }
        },
        "app": {
            "uid": app_uid,
            "name": app_name
        },
        "auth_protocol_id": 99,
        "logon_type_id": 99
    })
}

fn normalize_nginx_http(event: &Value) -> Value {
    let time = event
        .get("time_local")
        .and_then(Value::as_str)
        .and_then(parse_clf)
        .unwrap_or(0);

    let src_ip = event
        .get("remote_addr")
        .and_then(Value::as_str)
        .unwrap_or("");

    // "GET /api/v1/users HTTP/1.1"
    let request = event
        .get("request")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut rp = request.splitn(3, ' ');
    let method = rp.next().unwrap_or("").to_string();
    let path = rp.next().unwrap_or("/").to_string();
    let proto = rp.next().unwrap_or("HTTP/1.1");
    let version = proto.trim_start_matches("HTTP/").to_string();

    let status_code: u32 = event
        .get("status")
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let (status_id, status_name) = http_status_to_ocsf(status_code);

    let body_bytes: i64 = event
        .get("body_bytes_sent")
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let latency_ms: i64 = event
        .get("request_time")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<f64>().ok())
        .map(|f| (f * 1_000.0).round() as i64)
        .unwrap_or(0);

    let ua = event
        .get("http_user_agent")
        .and_then(Value::as_str)
        .unwrap_or("");
    let referer = event
        .get("http_referer")
        .and_then(Value::as_str)
        .unwrap_or("");

    let mut headers: Vec<Value> = Vec::new();
    if !ua.is_empty() {
        headers.push(json!({"name": "User-Agent", "value": ua}));
    }
    if !referer.is_empty() {
        headers.push(json!({"name": "Referer", "value": referer}));
    }

    json!({
        "class_uid": 3003,
        "class_name": "HTTP Activity",
        "category_uid": 4,
        "category_name": "Network Activity",
        "activity_id": 1,
        "activity_name": "Connect",
        "type_uid": 300301,
        "time": time,
        "severity_id": 1,
        "severity": "Informational",
        "status_id": status_id,
        "status": status_name,
        "metadata": {
            "version": "1.3.0",
            "product": {
                "name": "nginx",
                "vendor_name": "nginx"
            }
        },
        "src_endpoint": {
            "ip": src_ip
        },
        "http_request": {
            "url": {
                "path": path
            },
            "http_method": method,
            "http_headers": headers,
            "version": version
        },
        "http_response": {
            "code": status_code,
            "length": body_bytes,
            "latency": latency_ms
        },
        "traffic": {
            "bytes_out": body_bytes
        }
    })
}

fn normalize_sysmon_process(event: &Value) -> Value {
    let time = event
        .get("UtcTime")
        .and_then(Value::as_str)
        .and_then(parse_sysmon_ts)
        .unwrap_or(0);

    let image = event
        .get("Image")
        .and_then(Value::as_str)
        .unwrap_or("");
    let proc_uid = event
        .get("ProcessGuid")
        .and_then(Value::as_str)
        .unwrap_or("");
    let proc_pid: u64 = event
        .get("ProcessId")
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let cmd_line = event
        .get("CommandLine")
        .and_then(Value::as_str)
        .unwrap_or("");
    let file_ver_raw = event
        .get("FileVersion")
        .and_then(Value::as_str)
        .unwrap_or("");
    let file_ver = file_ver_raw.split_whitespace().next().unwrap_or("").to_string();
    let product_name = event
        .get("Product")
        .and_then(Value::as_str)
        .unwrap_or("");
    let company = event
        .get("Company")
        .and_then(Value::as_str)
        .unwrap_or("");
    let image_name = windows_basename(image).to_string();

    let parent_image = event
        .get("ParentImage")
        .and_then(Value::as_str)
        .unwrap_or("");
    let parent_uid = event
        .get("ParentProcessGuid")
        .and_then(Value::as_str)
        .unwrap_or("");
    let parent_pid: u64 = event
        .get("ParentProcessId")
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let parent_cmd = event
        .get("ParentCommandLine")
        .and_then(Value::as_str)
        .unwrap_or("");
    let parent_name = windows_basename(parent_image).to_string();

    let user_str = event
        .get("User")
        .and_then(Value::as_str)
        .unwrap_or("");
    let (actor_user_name, actor_user_domain) =
        if let Some((domain, name)) = user_str.split_once('\\') {
            (name.to_string(), Some(domain.to_string()))
        } else {
            (user_str.to_string(), None)
        };

    let mut actor_user = json!({"name": actor_user_name});
    if let Some(domain) = actor_user_domain {
        actor_user["domain"] = Value::String(domain);
    }

    json!({
        "class_uid": 5001,
        "class_name": "Process Activity",
        "category_uid": 2,
        "category_name": "System Activity",
        "activity_id": 1,
        "activity_name": "Launch",
        "type_uid": 500101,
        "time": time,
        "severity_id": 1,
        "severity": "Informational",
        "status_id": 1,
        "status": "Success",
        "metadata": {
            "version": "1.3.0",
            "product": {
                "name": "Sysmon",
                "vendor_name": "Microsoft"
            }
        },
        "actor": {
            "user": actor_user,
            "process": {
                "uid": parent_uid,
                "pid": parent_pid,
                "file": {
                    "path": parent_image,
                    "name": parent_name
                },
                "cmd_line": parent_cmd
            }
        },
        "process": {
            "uid": proc_uid,
            "pid": proc_pid,
            "file": {
                "path": image,
                "name": image_name,
                "product": {
                    "name": product_name,
                    "vendor_name": company,
                    "version": file_ver
                }
            },
            "cmd_line": cmd_line
        }
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_mappings() {
        assert_eq!(severity_id_name("INFO"), (1, "Informational"));
        assert_eq!(severity_id_name("info"), (1, "Informational"));
        assert_eq!(severity_id_name("HIGH"), (4, "High"));
        assert_eq!(severity_id_name("CRITICAL"), (5, "Critical"));
        assert_eq!(severity_id_name("UNKNOWN_VAL"), (0, "Unknown"));
    }

    #[test]
    fn epoch_2026_05_28_10z() {
        // 2026-05-28T10:00:00Z should be 1_779_962_400_000 ms
        let ms = to_epoch_ms(2026, 5, 28, 10, 0, 0, 0);
        assert_eq!(ms, 1_779_962_400_000);
    }

    #[test]
    fn parse_iso8601_roundtrip() {
        let ms = parse_iso8601("2026-05-28T10:00:00.000Z");
        assert_eq!(ms, Some(1_779_962_400_000));
    }

    #[test]
    fn parse_clf_roundtrip() {
        let ms = parse_clf("28/May/2026:10:00:00 +0000");
        assert_eq!(ms, Some(1_779_962_400_000));
    }

    #[test]
    fn parse_sysmon_ts_roundtrip() {
        let ms = parse_sysmon_ts("2026-05-28 10:00:00.000");
        assert_eq!(ms, Some(1_779_962_400_000));
    }

    #[test]
    fn classify_okta_sso() {
        let ev = json!({"_vendor": "okta", "eventType": "user.authentication.sso"});
        assert_eq!(classify(&ev), 4002);
    }

    #[test]
    fn classify_nginx() {
        let ev = json!({"_vendor": "nginx"});
        assert_eq!(classify(&ev), 3003);
    }

    #[test]
    fn classify_sysmon_event1() {
        let ev = json!({"_vendor": "sysmon", "EventID": 1});
        assert_eq!(classify(&ev), 5001);
    }

    #[test]
    fn classify_unknown_returns_zero() {
        let ev = json!({"_vendor": "unknown_vendor"});
        assert_eq!(classify(&ev), 0);
    }
}
