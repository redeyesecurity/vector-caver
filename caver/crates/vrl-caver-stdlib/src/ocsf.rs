//! OCSF classification and normalization (caver-collector#63, #897).
//!
//! Public surface:
//!   `classify(event)` → OCSF class_uid (0 = unrecognised)
//!   `normalize(event)` → fully-formed OCSF JSON Value
//!
//! The class/category tables and the flat output shapes mirror the Python
//! collector contract in caver-collector `src/caver_collector/transforms/`
//! (`ocsf_classify.py`, `suricata_normalize.py`, `zeek_normalize.py`,
//! `palo_alto_normalize.py`, `fortinet_normalize.py`) — that catalog, not
//! OCSF theory, is THE contract (#897). Vendors normalized here emit the
//! same OCSF-flat pushdown field names the Python transforms emit, so lake
//! columns (and every CAVERN detection that keys on them) are identical
//! regardless of which collector produced the event.

use serde_json::{json, Map, Value};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Inspect a raw vendor event and return its OCSF class_uid, or 0 if unknown.
pub fn classify(event: &Value) -> u32 {
    classify_full(event).0
}

/// Classify to the full `(class_uid, category_uid)` pair, or (0, 0).
fn classify_full(event: &Value) -> (u32, u32) {
    let vendor = event.get("_vendor").and_then(Value::as_str).unwrap_or("");
    match vendor {
        "okta" => classify_okta(event),
        "nginx" => (4002, 4),
        "sysmon" => classify_sysmon(event),
        "winevent" => classify_winevent(event),
        "suricata" => classify_suricata(event),
        "zeek" => zeek_class(&zeek_log_name(event)),
        "palo_alto" => classify_palo_alto(event),
        "fortinet" => classify_fortinet(event),
        _ => (0, 0),
    }
}

/// Normalise a raw vendor event to a fully-formed OCSF JSON Value.
/// Returns `{"error": "..."}` if the event cannot be classified or mapped.
pub fn normalize(event: &Value) -> Value {
    let (class_uid, category_uid) = classify_full(event);
    if class_uid == 0 {
        return json!({"error": "unclassified event — no _vendor match"});
    }
    let vendor = event.get("_vendor").and_then(Value::as_str).unwrap_or("");
    match vendor {
        "okta" => normalize_okta_auth(event),
        "nginx" => normalize_nginx_http(event),
        // Sysmon EventID 1 (ProcessCreate) has a full normalizer; every other
        // EventID mirrors Python ocsf_classify, which "writes only class_uid
        // and category_uid" onto the event.
        "sysmon" => {
            if event_id_of(event) == Some(1) {
                normalize_sysmon_process(event)
            } else {
                classify_passthrough(event, class_uid, category_uid)
            }
        }
        // winevent has no Python normalizer — classification-only passthrough.
        "winevent" => classify_passthrough(event, class_uid, category_uid),
        "suricata" => normalize_suricata(event),
        "zeek" => normalize_zeek(event),
        "palo_alto" => normalize_palo_alto(event),
        "fortinet" => normalize_fortinet(event),
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

/// EventID from either the raw `EventID` (Windows shape) or the
/// parse_winevent/parse_sysmon `event_id` key; numeric or numeric-string.
fn event_id_of(event: &Value) -> Option<u64> {
    for key in ["EventID", "event_id"] {
        if let Some(v) = event.get(key) {
            if let Some(n) = v.as_u64() {
                return Some(n);
            }
            if let Some(s) = v.as_str() {
                if let Ok(n) = s.trim().parse::<u64>() {
                    return Some(n);
                }
            }
        }
    }
    None
}

fn classify_okta(event: &Value) -> (u32, u32) {
    let et = event.get("eventType").and_then(Value::as_str).unwrap_or("");
    if et.starts_with("user.authentication") {
        (3002, 3) // Authentication / Identity & Access Management
    } else {
        (0, 0)
    }
}

/// Sysmon EventID → (class_uid, category_uid), mirroring the Python
/// `_SYSMON_EVENTID_CLASS` table (#780). Unmapped EventIDs fall through to
/// the coarse sysmon sourcetype mapping (1007, 1) — Process Activity.
fn classify_sysmon(event: &Value) -> (u32, u32) {
    match event_id_of(event) {
        Some(1) | Some(5) => (1007, 1), // ProcessCreate / ProcessTerminate
        Some(7) => (1005, 1),           // ImageLoad   -> Module Activity (T1574)
        Some(8) | Some(10) | Some(25) => (1004, 1), // injection/access/tampering -> Memory Activity
        Some(11) | Some(23) | Some(26) => (1001, 1), // file create/delete -> File System Activity
        Some(3) => (4001, 4),           // NetworkConnect -> Network Activity
        Some(22) => (4003, 4),          // DNSQuery -> DNS Activity
        _ => (1007, 1),                 // coarse fallback
    }
}

/// Windows Security-channel EventID → (class_uid, category_uid), mirroring
/// the Python `_SECURITY_EVENTID_CLASS` table (#780). Unmapped EventIDs fall
/// through to the coarse WinEventLog mapping (1007, 1).
fn classify_winevent(event: &Value) -> (u32, u32) {
    match event_id_of(event) {
        Some(4624) | Some(4625) | Some(4634) | Some(4647) => (3002, 3), // logon/logoff
        Some(4672) => (3003, 3), // special privileges -> Authorize Session (T1078)
        Some(4688) | Some(4697) => (1007, 1), // process create / service install
        Some(4720) | Some(4722) | Some(4723) | Some(4725) | Some(4726) | Some(4738) => (3001, 3),
        Some(4728) | Some(4732) | Some(4756) => (3001, 3), // group membership add
        _ => (1007, 1), // coarse fallback
    }
}

/// Every Suricata EVE record is network telemetry → 4001 Network Activity;
/// a record without an `event_type` discriminator is unclassifiable
/// (Python normalize() returns {} for it).
fn classify_suricata(event: &Value) -> (u32, u32) {
    let has_event_type = event
        .get("event_type")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty());
    if has_event_type {
        (4001, 4)
    } else {
        (0, 0)
    }
}

/// Zeek log name → OCSF class, mirroring Python `_LOG_TO_CLASS`.
fn zeek_class(log_name: &str) -> (u32, u32) {
    match log_name {
        "conn" => (4001, 4),
        "dns" => (4003, 4),
        "http" => (4002, 4),
        "ssl" => (4001, 4),
        "ssh" => (3002, 3),
        "rdp" => (4005, 4),
        "dhcp" => (4004, 4),
        "files" => (1006, 1),
        "notice" => (4001, 4),
        "weird" => (4001, 4),
        _ => (6003, 6),
    }
}

/// Discriminate the Zeek source log: `_path` / `stream` (modern JSON
/// deployments), the `log_type` set by our parse_zeek bridge, then the same
/// distinctive-field heuristics as Python zeek_normalize.
fn zeek_log_name(event: &Value) -> String {
    for key in ["_path", "stream", "log_type"] {
        if let Some(s) = event.get(key).and_then(Value::as_str) {
            if !s.is_empty() {
                return s.to_lowercase();
            }
        }
    }
    let has = |k: &str| event.get(k).is_some();
    if has("query") && (has("qtype") || has("qtype_name")) {
        "dns"
    } else if has("method") && has("uri") {
        "http"
    } else if has("server_name") || has("issuer") {
        "ssl"
    } else if has("filename") || has("mime_type") {
        "files"
    } else if has("note") && has("msg") {
        "notice"
    } else if has("security_protocol") && (has("cookie") || has("desktop_width")) {
        "rdp"
    } else if has("assigned_addr") || has("msg_types") {
        "dhcp"
    } else if has("duration") && has("orig_bytes") {
        "conn"
    } else {
        "unknown"
    }
    .to_string()
}

/// PAN-OS log `type` recognised by the Python `_is_panos` guard.
const PAN_TYPES: &[&str] = &[
    "TRAFFIC",
    "THREAT",
    "URL",
    "SYSTEM",
    "CONFIG",
    "AUTHENTICATION",
    "DATA",
    "WILDFIRE",
    "DECRYPTION",
    "GLOBALPROTECT",
    "HIPMATCH",
    "USERID",
];

fn is_panos(event: &Value) -> bool {
    let ftype = pick_string(event, &["type"]).to_uppercase();
    if !PAN_TYPES.contains(&ftype.as_str()) {
        return false;
    }
    if event.get("serial").is_some_and(is_truthy) || event.get("device_name").is_some_and(is_truthy)
    {
        return true;
    }
    event.get("vsys").is_some() || event.get("subtype").is_some()
}

/// PAN-OS `(class_uid, class_name, category_uid, activity_id)` routing,
/// mirroring Python `_class_for` (#335).
fn panos_class_for(event: &Value) -> (u32, &'static str, u32, u32) {
    let ftype = pick_string(event, &["type"]).to_uppercase();
    let subtype = pick_string(event, &["subtype"]).to_lowercase();
    match ftype.as_str() {
        "TRAFFIC" => (4001, "Network Activity", 4, 6),
        "URL" => (6005, "Application Activity", 6, 1),
        "THREAT" if subtype == "url" => (6005, "Application Activity", 6, 1),
        "THREAT" => (2004, "Detection Finding", 2, 1),
        "AUTHENTICATION" | "GLOBALPROTECT" => (3002, "Authentication", 3, 1),
        "SYSTEM" | "CONFIG" | "USERID" => (3005, "User Access Management", 3, 1),
        "WILDFIRE" | "DATA" => (2004, "Detection Finding", 2, 1),
        _ => (6003, "API Activity", 6, 1),
    }
}

fn classify_palo_alto(event: &Value) -> (u32, u32) {
    if !is_panos(event) {
        return (0, 0);
    }
    let (cls, _, cat, _) = panos_class_for(event);
    (cls, cat)
}

fn is_fortinet(event: &Value) -> bool {
    if event.get("logid").is_some() && event.get("type").is_some() {
        return true;
    }
    let devid = pick_string(event, &["devid"]).to_uppercase();
    if devid.starts_with("FG") || devid.starts_with("FORTI") {
        return true;
    }
    event.get("type").is_some() && event.get("subtype").is_some() && event.get("vd").is_some()
}

/// FortiGate `(class_uid, class_name, category_uid, activity_id)` routing,
/// mirroring Python `_class_for` (#334).
fn fortinet_class_for(event: &Value) -> (u32, &'static str, u32, u32) {
    let ftype = pick_string(event, &["type"]).to_lowercase();
    let subtype = pick_string(event, &["subtype"]).to_lowercase();
    let action = pick_string(event, &["action"]).to_lowercase();
    match ftype.as_str() {
        "traffic" => (4001, "Network Activity", 4, 6),
        "utm" | "anomaly" => {
            if subtype == "webfilter" || subtype == "web-filter" {
                (6005, "Application Activity", 6, 1)
            } else {
                (2004, "Detection Finding", 2, 1)
            }
        }
        "event" => {
            if subtype == "user"
                || subtype == "vpn"
                || action.contains("login")
                || action.contains("logout")
                || action.contains("auth")
            {
                (3002, "Authentication", 3, 1)
            } else {
                (3005, "User Access Management", 3, 1)
            }
        }
        _ => (6003, "API Activity", 6, 1),
    }
}

fn classify_fortinet(event: &Value) -> (u32, u32) {
    if !is_fortinet(event) {
        return (0, 0);
    }
    let (cls, _, cat, _) = fortinet_class_for(event);
    (cls, cat)
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
        400..=599 => (2, "Failure"),
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
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

// ---------------------------------------------------------------------------
// Python-mirror value coercion helpers
//
// The flat normalizers below replicate the exact field-presence semantics of
// the Python transforms: `if record.get(k):` (truthiness), `is not None`,
// `_get(record, *keys)` (skip None/""), `str(v)`, `int(v)`, `float(v)`.
// ---------------------------------------------------------------------------

/// Python truthiness for JSON values.
fn is_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::String(s) => !s.is_empty(),
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Python `str(v)` for scalar JSON values.
fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        other => other.to_string(),
    }
}

/// `event.get(key)` when truthy, as a string — mirrors `if (v := event.get(k)): str(v)`.
fn truthy_string(event: &Value, key: &str) -> Option<String> {
    event
        .get(key)
        .filter(|v| is_truthy(v))
        .map(value_to_string)
}

/// First truthy value among `keys` — mirrors `event.get(a) or event.get(b)`.
fn first_truthy<'a>(event: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter()
        .filter_map(|k| event.get(*k))
        .find(|v| is_truthy(v))
}

/// Python `_get(record, *keys)`: first key whose value is neither missing,
/// null, nor the empty string. (0 passes — unlike truthiness.)
fn pick_raw<'a>(event: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().filter_map(|k| event.get(*k)).find(|v| {
        !v.is_null() && v.as_str() != Some("")
    })
}

/// `str(_get(record, *keys))` with "" for no match.
fn pick_string(event: &Value, keys: &[&str]) -> String {
    pick_raw(event, keys).map(value_to_string).unwrap_or_default()
}

/// Python `int(v)` over a JSON number or numeric string.
fn any_i64(v: &Value) -> Option<i64> {
    if let Some(n) = v.as_i64() {
        return Some(n);
    }
    v.as_str().and_then(|s| s.trim().parse::<i64>().ok())
}

/// Python `float(v)` over a JSON number or numeric string.
fn any_f64(v: &Value) -> Option<f64> {
    if let Some(f) = v.as_f64() {
        return Some(f);
    }
    v.as_str().and_then(|s| s.trim().parse::<f64>().ok())
}

/// Mirror Python ocsf_classify for vendors without a dedicated normalizer:
/// the event passes through unchanged except for `class_uid` and
/// `category_uid`. The `_vendor` routing tag is internal and dropped.
fn classify_passthrough(event: &Value, class_uid: u32, category_uid: u32) -> Value {
    let mut map = match event {
        Value::Object(o) => o.clone(),
        _ => Map::new(),
    };
    map.remove("_vendor");
    map.insert("class_uid".into(), json!(class_uid));
    map.insert("category_uid".into(), json!(category_uid));
    Value::Object(map)
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
        "class_uid": 3002,
        "class_name": "Authentication",
        "category_uid": 3,
        "category_name": "Identity & Access Management",
        "activity_id": 1,
        "activity_name": "Logon",
        "type_uid": 300201,
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
    let request = event.get("request").and_then(Value::as_str).unwrap_or("");
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
        "class_uid": 4002,
        "class_name": "HTTP Activity",
        "category_uid": 4,
        "category_name": "Network Activity",
        "activity_id": 1,
        "activity_name": "Connect",
        "type_uid": 400201,
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

    let image = event.get("Image").and_then(Value::as_str).unwrap_or("");
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
    let file_ver = file_ver_raw
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string();
    let product_name = event.get("Product").and_then(Value::as_str).unwrap_or("");
    let company = event.get("Company").and_then(Value::as_str).unwrap_or("");
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

    let user_str = event.get("User").and_then(Value::as_str).unwrap_or("");
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
        "class_uid": 1007,
        "class_name": "Process Activity",
        "category_uid": 1,
        "category_name": "System Activity",
        "activity_id": 1,
        "activity_name": "Launch",
        "type_uid": 100701,
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
// OCSF-flat normalizers (Python transform mirrors, #897)
// ---------------------------------------------------------------------------

/// Mirror of caver-collector `suricata_normalize.normalize()`: every EVE
/// record → 4001 Network Activity with `suri_*` pushdown fields.
fn normalize_suricata(event: &Value) -> Value {
    let mut out = Map::new();
    out.insert("class_uid".into(), json!(4001));
    out.insert("class_name".into(), json!("Network Activity"));
    out.insert(
        "suri_event_type".into(),
        json!(event.get("event_type").and_then(Value::as_str).unwrap_or("")),
    );

    if let Some(p) = truthy_string(event, "proto") {
        out.insert("suri_proto".into(), json!(p));
    }
    if let Some(ap) = truthy_string(event, "app_proto") {
        out.insert("suri_app_proto".into(), json!(ap));
    }

    // connection 5-tuple
    if let Some(ip) = truthy_string(event, "src_ip") {
        out.insert("src_ip".into(), json!(ip));
        out.insert("src_endpoint.ip".into(), json!(ip));
    }
    if let Some(ip) = truthy_string(event, "dest_ip") {
        out.insert("dst_ip".into(), json!(ip));
        out.insert("dst_endpoint.ip".into(), json!(ip));
    }
    if let Some(sp) = event.get("src_port").and_then(any_i64) {
        out.insert("src_port".into(), json!(sp));
        out.insert("src_endpoint.port".into(), json!(sp));
    }
    if let Some(dp) = event.get("dest_port").and_then(any_i64) {
        out.insert("dst_port".into(), json!(dp));
        out.insert("dst_endpoint.port".into(), json!(dp));
    }

    if let Some(fid) = event.get("flow_id").filter(|v| !v.is_null()) {
        out.insert("suri_flow_id".into(), json!(value_to_string(fid)));
    }
    if let Some(iface) = truthy_string(event, "in_iface") {
        out.insert("suri_in_iface".into(), json!(iface));
    }

    // alert detection fields + severity
    // Suricata alert.severity is 1=high..3=low → OCSF 4/3/2 (default 3).
    if let Some(alert) = event.get("alert").filter(|a| a.is_object()) {
        if let Some(sig) = truthy_string(alert, "signature") {
            out.insert("suri_signature".into(), json!(sig));
        }
        if let Some(sid) = alert.get("signature_id").filter(|v| !v.is_null()) {
            out.insert("suri_signature_id".into(), json!(value_to_string(sid)));
        }
        if let Some(cat) = truthy_string(alert, "category") {
            out.insert("suri_category".into(), json!(cat));
        }
        if let Some(act) = truthy_string(alert, "action") {
            out.insert("suri_action".into(), json!(act));
        }
        let sev = alert.get("severity").filter(|v| !v.is_null());
        if let Some(s) = sev {
            out.insert("suri_severity".into(), s.clone());
        }
        let sev_id = match sev.and_then(any_i64) {
            Some(1) => 4,
            Some(2) => 3,
            Some(3) => 2,
            _ => 3,
        };
        out.insert("severity_id".into(), json!(sev_id));
        out.insert("activity_id".into(), json!(6)); // Traffic / detection
    } else {
        out.insert("severity_id".into(), json!(1)); // informational telemetry
    }

    // protocol detail lifts
    if let Some(http) = event.get("http").filter(|h| h.is_object()) {
        if let Some(host) = truthy_string(http, "hostname") {
            out.insert("suri_http_host".into(), json!(host));
        }
        if let Some(url) = truthy_string(http, "url") {
            out.insert("suri_http_url".into(), json!(url));
        }
    }
    if let Some(q) = event
        .get("dns")
        .filter(|d| d.is_object())
        .and_then(|d| truthy_string(d, "rrname"))
    {
        out.insert("suri_dns_query".into(), json!(q));
    }
    if let Some(sni) = event
        .get("tls")
        .filter(|t| t.is_object())
        .and_then(|t| truthy_string(t, "sni"))
    {
        out.insert("suri_tls_sni".into(), json!(sni));
    }

    Value::Object(out)
}

/// Insert `out[name] = str(v)` when `event[key]` is truthy.
fn lift_str(out: &mut Map<String, Value>, event: &Value, key: &str, name: &str) {
    if let Some(s) = truthy_string(event, key) {
        out.insert(name.into(), json!(s));
    }
}

/// Insert `out[name] = int(v)` when `event[key]` is present and coercible.
fn lift_int(out: &mut Map<String, Value>, event: &Value, key: &str, name: &str) {
    if let Some(n) = event.get(key).filter(|v| !v.is_null()).and_then(any_i64) {
        out.insert(name.into(), json!(n));
    }
}

/// Mirror of caver-collector `zeek_normalize.normalize()`: per-log OCSF class
/// with `zk_*` / dotted `dns.` `http.` `tls.` `file.` pushdown fields.
fn normalize_zeek(event: &Value) -> Value {
    let log_name = zeek_log_name(event);
    let (class_uid, _) = zeek_class(&log_name);
    let severity_id = match log_name.as_str() {
        "notice" => 3, // Zeek's curated detection signal
        "weird" => 2,  // interesting but not necessarily bad
        _ => 1,        // raw telemetry
    };

    let mut out = Map::new();
    out.insert("zk_log".into(), json!(log_name));
    out.insert("class_uid".into(), json!(class_uid));
    out.insert("severity_id".into(), json!(severity_id));

    if let Some(uid) = truthy_string(event, "uid") {
        out.insert("zk_uid".into(), json!(uid));
    }
    if let Some(p) = truthy_string(event, "proto") {
        out.insert("network_protocol".into(), json!(p));
    }
    if let Some(s) = truthy_string(event, "service") {
        out.insert("network_service".into(), json!(s));
    }

    // Conn-tuple: dotted-flat first, then nested `id`, then the parse_zeek
    // bridge shape (src_ip/dest_ip/src_port/dest_port).
    lift_str(&mut out, event, "id.orig_h", "src_ip");
    lift_str(&mut out, event, "id.resp_h", "dst_ip");
    lift_int(&mut out, event, "id.orig_p", "src_port");
    lift_int(&mut out, event, "id.resp_p", "dst_port");
    if !out.contains_key("src_ip") {
        if let Some(idobj) = event.get("id").filter(|v| v.is_object()) {
            lift_str(&mut out, idobj, "orig_h", "src_ip");
            lift_str(&mut out, idobj, "resp_h", "dst_ip");
            lift_int(&mut out, idobj, "orig_p", "src_port");
            lift_int(&mut out, idobj, "resp_p", "dst_port");
        }
    }
    if !out.contains_key("src_ip") {
        lift_str(&mut out, event, "src_ip", "src_ip");
        lift_str(&mut out, event, "dest_ip", "dst_ip");
        lift_int(&mut out, event, "src_port", "src_port");
        lift_int(&mut out, event, "dest_port", "dst_port");
    }

    match log_name.as_str() {
        "conn" => {
            if let Some(d) = event.get("duration").filter(|v| !v.is_null()).and_then(any_f64) {
                out.insert("zk_duration".into(), json!(d));
            }
            lift_int(&mut out, event, "orig_bytes", "zk_orig_bytes");
            lift_int(&mut out, event, "resp_bytes", "zk_resp_bytes");
        }
        "dns" => {
            lift_str(&mut out, event, "query", "dns.query");
            if let Some(v) = first_truthy(event, &["qtype_name", "qtype"]) {
                out.insert("dns.query_type".into(), json!(value_to_string(v)));
            }
            if let Some(v) = first_truthy(event, &["rcode_name", "rcode"]) {
                out.insert("dns.response_code".into(), json!(value_to_string(v)));
            }
        }
        "http" => {
            lift_str(&mut out, event, "method", "http.method");
            lift_str(&mut out, event, "host", "http.host");
            lift_str(&mut out, event, "uri", "http.url");
            lift_str(&mut out, event, "user_agent", "http.user_agent");
            lift_int(&mut out, event, "status_code", "http.status_code");
        }
        "ssl" => {
            lift_str(&mut out, event, "server_name", "tls.sni");
            lift_str(&mut out, event, "version", "tls.version");
            lift_str(&mut out, event, "issuer", "tls.issuer");
        }
        "files" => {
            if let Some(v) = first_truthy(event, &["filename", "name"]) {
                out.insert("file.name".into(), json!(value_to_string(v)));
            }
            if let Some(n) = first_truthy(event, &["total_bytes", "size"]).and_then(any_i64) {
                out.insert("file.size".into(), json!(n));
            }
            lift_str(&mut out, event, "md5", "file.md5");
            lift_str(&mut out, event, "sha1", "file.sha1");
            lift_str(&mut out, event, "sha256", "file.sha256");
            lift_str(&mut out, event, "mime_type", "file.mime_type");
        }
        "notice" => {
            lift_str(&mut out, event, "msg", "zk_notice_msg");
            lift_str(&mut out, event, "note", "zk_notice_note");
            lift_str(&mut out, event, "sub", "zk_notice_sub");
        }
        "rdp" => {
            lift_str(&mut out, event, "cookie", "zk_rdp_cookie");
            lift_str(&mut out, event, "result", "zk_rdp_result");
            lift_str(&mut out, event, "security_protocol", "zk_rdp_security_protocol");
            lift_str(&mut out, event, "client_name", "zk_rdp_client_name");
            lift_str(&mut out, event, "client_build", "zk_rdp_client_build");
            lift_str(&mut out, event, "client_dig_product_id", "zk_rdp_client_product_id");
            lift_str(&mut out, event, "keyboard_layout", "zk_rdp_keyboard_layout");
            lift_str(&mut out, event, "encryption_level", "zk_rdp_encryption_level");
            lift_str(&mut out, event, "encryption_method", "zk_rdp_encryption_method");
            lift_str(&mut out, event, "cert_type", "zk_rdp_cert_type");
            lift_int(&mut out, event, "cert_count", "zk_rdp_cert_count");
            lift_int(&mut out, event, "desktop_width", "zk_rdp_desktop_width");
            lift_int(&mut out, event, "desktop_height", "zk_rdp_desktop_height");
            lift_str(&mut out, event, "requested_color_depth", "zk_rdp_color_depth");
        }
        "dhcp" => {
            lift_str(&mut out, event, "mac", "zk_dhcp_mac");
            lift_str(&mut out, event, "host_name", "zk_dhcp_host_name");
            lift_str(&mut out, event, "client_fqdn", "zk_dhcp_client_fqdn");
            lift_str(&mut out, event, "assigned_addr", "zk_dhcp_assigned_addr");
            lift_str(&mut out, event, "requested_addr", "zk_dhcp_requested_addr");
            lift_str(&mut out, event, "client_addr", "zk_dhcp_client_addr");
            lift_str(&mut out, event, "server_addr", "zk_dhcp_server_addr");
            lift_str(&mut out, event, "domain", "zk_dhcp_domain");
            if let Some(t) = event.get("lease_time").filter(|v| !v.is_null()).and_then(any_f64) {
                out.insert("zk_dhcp_lease_time".into(), json!(t));
            }
            if let Some(v) = event.get("msg_types").filter(|v| is_truthy(v)) {
                let joined = match v {
                    Value::Array(items) => items
                        .iter()
                        .map(value_to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                    other => value_to_string(other),
                };
                out.insert("zk_dhcp_msg_types".into(), json!(joined));
            }
        }
        _ => {}
    }

    Value::Object(out)
}

/// PAN-OS severity: the `severity` field map, base 2 when absent (TRAFFIC
/// carries no severity), bumped to ≥3 on block actions.
const PAN_BLOCK_ACTIONS: &[&str] = &[
    "deny",
    "drop",
    "reset-both",
    "reset-client",
    "reset-server",
    "block",
    "block-url",
    "block-ip",
    "sinkhole",
    "blocked",
];

fn panos_severity(event: &Value) -> i64 {
    let sev = pick_string(event, &["severity"]).to_lowercase();
    let base = match sev.as_str() {
        "critical" => Some(5),
        "high" => Some(4),
        "medium" => Some(3),
        "low" => Some(2),
        "informational" | "info" => Some(1),
        _ => None,
    };
    let mut base = base.unwrap_or(2);
    let action = pick_string(event, &["action"]).to_lowercase();
    if PAN_BLOCK_ACTIONS.contains(&action.as_str()) {
        base = base.max(3);
    }
    base
}

/// Mirror of caver-collector `palo_alto_normalize.normalize()` (#335).
fn normalize_palo_alto(event: &Value) -> Value {
    let (cls_uid, cls_name, cat_uid, act_id) = panos_class_for(event);

    let user = pick_string(event, &["srcuser", "user", "dstuser", "admin"]);
    let src_ip = pick_string(event, &["src", "srcip"]);
    let dst_ip = pick_string(event, &["dst", "dstip"]);

    let mut out = Map::new();
    out.insert("class_uid".into(), json!(cls_uid));
    out.insert("class_name".into(), json!(cls_name));
    out.insert("category_uid".into(), json!(cat_uid));
    out.insert("activity_id".into(), json!(act_id));
    out.insert("type_uid".into(), json!(cls_uid * 100 + act_id));
    out.insert("severity_id".into(), json!(panos_severity(event)));
    out.insert("panos_type".into(), json!(pick_string(event, &["type"])));
    out.insert("panos_subtype".into(), json!(pick_string(event, &["subtype"])));
    out.insert("panos_action".into(), json!(pick_string(event, &["action"])));
    out.insert("panos_serial".into(), json!(pick_string(event, &["serial"])));
    out.insert(
        "panos_device_name".into(),
        json!(pick_string(event, &["device_name", "devicename"])),
    );
    out.insert("panos_vsys".into(), json!(pick_string(event, &["vsys"])));
    out.insert("panos_rule".into(), json!(pick_string(event, &["rule", "rule_name"])));
    out.insert("panos_app".into(), json!(pick_string(event, &["app", "application"])));
    out.insert("panos_proto".into(), json!(pick_string(event, &["proto", "protocol"])));
    out.insert(
        "panos_threatid".into(),
        json!(pick_string(event, &["threatid", "threat_name", "tid"])),
    );
    out.insert("panos_severity".into(), json!(pick_string(event, &["severity"])));
    out.insert(
        "panos_category".into(),
        json!(pick_string(event, &["category", "url_category_list"])),
    );
    out.insert("panos_msg".into(), json!(pick_string(event, &["opaque", "msg", "eventid"])));

    if !user.is_empty() {
        out.insert("panos_user".into(), json!(user));
        out.insert("actor.user.name".into(), json!(user));
    }
    if !src_ip.is_empty() {
        out.insert("src_endpoint.ip".into(), json!(src_ip));
        if let Some(sp) = pick_raw(event, &["sport", "srcport"]) {
            out.insert("src_endpoint.port".into(), sp.clone());
        }
    }
    if !dst_ip.is_empty() {
        out.insert("dst_endpoint.ip".into(), json!(dst_ip));
        if let Some(dp) = pick_raw(event, &["dport", "dstport"]) {
            out.insert("dst_endpoint.port".into(), dp.clone());
        }
    }
    let url = pick_string(event, &["url", "misc", "filename"]);
    if !url.is_empty() {
        out.insert("panos_url".into(), json!(url));
    }

    Value::Object(out)
}

/// FortiGate severity: UTM `crseverity`/`severity` map first, else the syslog
/// `level` map (default 2), bumped to ≥3 on deny/blocked actions.
const FORTI_BLOCK_ACTIONS: &[&str] = &[
    "deny", "blocked", "block", "dropped", "drop", "reset", "quarantine",
];

fn fortinet_severity(event: &Value) -> i64 {
    let utm_sev = pick_string(event, &["crseverity", "severity"]).to_lowercase();
    let base = match utm_sev.as_str() {
        "critical" => Some(5),
        "high" => Some(4),
        "medium" => Some(3),
        "low" => Some(2),
        "info" | "informational" => Some(1),
        _ => None,
    };
    let mut base = base.unwrap_or_else(|| {
        match pick_string(event, &["level"]).to_lowercase().as_str() {
            "emergency" | "alert" | "critical" => 5,
            "error" => 4,
            "warning" => 3,
            "notice" | "information" | "info" => 2,
            "debug" => 1,
            _ => 2,
        }
    });
    let action = pick_string(event, &["action"]).to_lowercase();
    if FORTI_BLOCK_ACTIONS.contains(&action.as_str()) {
        base = base.max(3);
    }
    base
}

/// Mirror of caver-collector `fortinet_normalize.normalize()` (#334).
fn normalize_fortinet(event: &Value) -> Value {
    let (cls_uid, cls_name, cat_uid, act_id) = fortinet_class_for(event);

    let user = pick_string(event, &["user", "srcuser", "unauthuser", "admin"]);
    let src_ip = pick_string(event, &["srcip", "src"]);
    let dst_ip = pick_string(event, &["dstip", "dst"]);

    let mut out = Map::new();
    out.insert("class_uid".into(), json!(cls_uid));
    out.insert("class_name".into(), json!(cls_name));
    out.insert("category_uid".into(), json!(cat_uid));
    out.insert("activity_id".into(), json!(act_id));
    out.insert("type_uid".into(), json!(cls_uid * 100 + act_id));
    out.insert("severity_id".into(), json!(fortinet_severity(event)));
    out.insert("fortinet_type".into(), json!(pick_string(event, &["type"])));
    out.insert("fortinet_subtype".into(), json!(pick_string(event, &["subtype"])));
    out.insert("fortinet_action".into(), json!(pick_string(event, &["action"])));
    out.insert("fortinet_logid".into(), json!(pick_string(event, &["logid"])));
    out.insert(
        "fortinet_devname".into(),
        json!(pick_string(event, &["devname", "devid"])),
    );
    out.insert("fortinet_vd".into(), json!(pick_string(event, &["vd", "vdom"])));
    out.insert("fortinet_level".into(), json!(pick_string(event, &["level"])));
    out.insert("fortinet_service".into(), json!(pick_string(event, &["service"])));
    out.insert("fortinet_proto".into(), json!(pick_string(event, &["proto"])));
    out.insert("fortinet_app".into(), json!(pick_string(event, &["app", "appcat"])));
    out.insert(
        "fortinet_attack".into(),
        json!(pick_string(event, &["attack", "virus", "eventtype"])),
    );
    out.insert("fortinet_msg".into(), json!(pick_string(event, &["msg", "logdesc"])));
    out.insert("fortinet_policyid".into(), json!(pick_string(event, &["policyid"])));

    if !user.is_empty() {
        out.insert("fortinet_user".into(), json!(user));
        out.insert("actor.user.name".into(), json!(user));
    }
    if !src_ip.is_empty() {
        out.insert("src_endpoint.ip".into(), json!(src_ip));
        if let Some(sp) = pick_raw(event, &["srcport"]) {
            out.insert("src_endpoint.port".into(), sp.clone());
        }
    }
    if !dst_ip.is_empty() {
        out.insert("dst_endpoint.ip".into(), json!(dst_ip));
        if let Some(dp) = pick_raw(event, &["dstport"]) {
            out.insert("dst_endpoint.port".into(), dp.clone());
        }
    }
    // Web-filter URL/host for the 6005 case.
    let url = pick_string(event, &["url", "hostname"]);
    if !url.is_empty() {
        out.insert("fortinet_url".into(), json!(url));
    }

    Value::Object(out)
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
        // okta auth = 3002 Authentication, per the Python collector contract
        // (ocsf_classify SOURCETYPE_MAP "okta" -> (3002, 3)).
        let ev = json!({"_vendor": "okta", "eventType": "user.authentication.sso"});
        assert_eq!(classify(&ev), 3002);
    }

    #[test]
    fn classify_nginx() {
        // nginx access = 4002 HTTP Activity ("nginx:access" -> (4002, 4)).
        let ev = json!({"_vendor": "nginx"});
        assert_eq!(classify(&ev), 4002);
    }

    #[test]
    fn classify_sysmon_eventids() {
        // _SYSMON_EVENTID_CLASS refinement (#780), default = coarse 1007.
        for (eid, cls) in [
            (1u64, 1007u32),
            (5, 1007),
            (7, 1005),
            (8, 1004),
            (10, 1004),
            (25, 1004),
            (11, 1001),
            (23, 1001),
            (26, 1001),
            (3, 4001),
            (22, 4003),
            (255, 1007), // unmapped -> coarse fallback
        ] {
            let ev = json!({"_vendor": "sysmon", "EventID": eid});
            assert_eq!(classify(&ev), cls, "sysmon EventID {eid}");
        }
        // parse_sysmon bridge shape uses event_id
        let ev = json!({"_vendor": "sysmon", "event_id": 22});
        assert_eq!(classify(&ev), 4003);
    }

    #[test]
    fn classify_winevent_security_eventids() {
        for (eid, cls) in [
            (4624u64, 3002u32),
            (4625, 3002),
            (4634, 3002),
            (4647, 3002),
            (4672, 3003),
            (4688, 1007),
            (4697, 1007),
            (4720, 3001),
            (4738, 3001),
            (4756, 3001),
            (5156, 1007), // unmapped -> coarse fallback
        ] {
            let ev = json!({"_vendor": "winevent", "event_id": eid});
            assert_eq!(classify(&ev), cls, "winevent EventID {eid}");
        }
    }

    #[test]
    fn classify_suricata_requires_event_type() {
        let ev = json!({"_vendor": "suricata", "event_type": "alert"});
        assert_eq!(classify(&ev), 4001);
        let ev = json!({"_vendor": "suricata", "event_type": "flow"});
        assert_eq!(classify(&ev), 4001);
        let ev = json!({"_vendor": "suricata"});
        assert_eq!(classify(&ev), 0);
    }

    #[test]
    fn classify_zeek_logs() {
        for (log, cls) in [
            ("conn", 4001u32),
            ("dns", 4003),
            ("http", 4002),
            ("ssl", 4001),
            ("ssh", 3002),
            ("rdp", 4005),
            ("dhcp", 4004),
            ("files", 1006),
            ("notice", 4001),
            ("weird", 4001),
            ("x509", 6003), // unmapped -> 6003 API Activity
        ] {
            let ev = json!({"_vendor": "zeek", "_path": log});
            assert_eq!(classify(&ev), cls, "zeek log {log}");
        }
        // heuristic fallback without _path/stream/log_type
        let ev = json!({"_vendor": "zeek", "query": "example.com", "qtype_name": "A"});
        assert_eq!(classify(&ev), 4003);
    }

    #[test]
    fn classify_palo_alto_types() {
        let traffic = json!({"_vendor": "palo_alto", "type": "TRAFFIC", "serial": "0011"});
        assert_eq!(classify(&traffic), 4001);
        let threat = json!({"_vendor": "palo_alto", "type": "THREAT",
                            "subtype": "vulnerability", "serial": "0011"});
        assert_eq!(classify(&threat), 2004);
        let url = json!({"_vendor": "palo_alto", "type": "THREAT",
                         "subtype": "url", "serial": "0011"});
        assert_eq!(classify(&url), 6005);
        let auth = json!({"_vendor": "palo_alto", "type": "AUTHENTICATION", "vsys": "vsys1"});
        assert_eq!(classify(&auth), 3002);
        let system = json!({"_vendor": "palo_alto", "type": "SYSTEM", "serial": "0011"});
        assert_eq!(classify(&system), 3005);
        // not a PAN-OS record -> 0
        let nope = json!({"_vendor": "palo_alto", "type": "TRAFFIC"});
        assert_eq!(classify(&nope), 0);
    }

    #[test]
    fn classify_fortinet_types() {
        let traffic = json!({"_vendor": "fortinet", "logid": "0000000013", "type": "traffic"});
        assert_eq!(classify(&traffic), 4001);
        let ips = json!({"_vendor": "fortinet", "logid": "0419016384", "type": "utm",
                         "subtype": "ips"});
        assert_eq!(classify(&ips), 2004);
        let webfilter = json!({"_vendor": "fortinet", "logid": "0316013056", "type": "utm",
                               "subtype": "webfilter"});
        assert_eq!(classify(&webfilter), 6005);
        let login = json!({"_vendor": "fortinet", "logid": "0100032001", "type": "event",
                           "subtype": "system", "action": "login"});
        assert_eq!(classify(&login), 3002);
        let admin = json!({"_vendor": "fortinet", "logid": "0100044546", "type": "event",
                           "subtype": "system", "action": "Edit"});
        assert_eq!(classify(&admin), 3005);
        // not a FortiGate record -> 0
        let nope = json!({"_vendor": "fortinet", "subtype": "forward"});
        assert_eq!(classify(&nope), 0);
    }

    #[test]
    fn classify_unknown_returns_zero() {
        let ev = json!({"_vendor": "unknown_vendor"});
        assert_eq!(classify(&ev), 0);
    }

    #[test]
    fn normalize_winevent_is_classification_passthrough() {
        let ev = json!({"_vendor": "winevent", "event_id": 4625,
                        "computer": "DESKTOP-ABC", "channel": "Security"});
        let out = normalize(&ev);
        assert_eq!(out["class_uid"], 3002);
        assert_eq!(out["category_uid"], 3);
        assert_eq!(out["computer"], "DESKTOP-ABC");
        assert_eq!(out["channel"], "Security");
        assert!(out.get("_vendor").is_none(), "_vendor routing tag must be dropped");
    }

    #[test]
    fn normalize_sysmon_non_eid1_is_classification_passthrough() {
        let ev = json!({"_vendor": "sysmon", "event_id": 3,
                        "computer": "DESKTOP-ABC", "src_ip": "10.0.0.1"});
        let out = normalize(&ev);
        assert_eq!(out["class_uid"], 4001);
        assert_eq!(out["category_uid"], 4);
        assert_eq!(out["src_ip"], "10.0.0.1");
        assert!(out.get("_vendor").is_none());
    }

    #[test]
    fn normalize_suricata_non_alert_severity() {
        let ev = json!({"_vendor": "suricata", "event_type": "flow",
                        "proto": "TCP", "src_ip": "10.0.0.1", "src_port": 1234});
        let out = normalize(&ev);
        assert_eq!(out["class_uid"], 4001);
        assert_eq!(out["severity_id"], 1);
        assert_eq!(out["suri_event_type"], "flow");
        assert_eq!(out["src_endpoint.ip"], "10.0.0.1");
        assert_eq!(out["src_endpoint.port"], 1234);
        assert!(out.get("activity_id").is_none(), "activity_id is alert-only");
    }

    #[test]
    fn normalize_suricata_alert_severity_map() {
        // Suricata severity 1=high..3=low -> OCSF 4/3/2
        for (suri, ocsf) in [(1i64, 4i64), (2, 3), (3, 2)] {
            let ev = json!({"_vendor": "suricata", "event_type": "alert",
                            "alert": {"severity": suri, "signature": "x", "signature_id": 7}});
            let out = normalize(&ev);
            assert_eq!(out["severity_id"], ocsf, "suricata severity {suri}");
            assert_eq!(out["suri_severity"], suri);
            assert_eq!(out["suri_signature_id"], "7"); // stringified like Python str()
            assert_eq!(out["activity_id"], 6);
        }
    }

    #[test]
    fn normalize_zeek_dns_dotted_fields() {
        let ev = json!({"_vendor": "zeek", "_path": "dns", "uid": "C99",
                        "id.orig_h": "10.0.0.5", "id.orig_p": 53533,
                        "id.resp_h": "9.9.9.9", "id.resp_p": 53, "proto": "udp",
                        "query": "evil.example.com", "qtype_name": "A", "rcode_name": "NOERROR"});
        let out = normalize(&ev);
        assert_eq!(out["class_uid"], 4003);
        assert_eq!(out["zk_log"], "dns");
        assert_eq!(out["dns.query"], "evil.example.com");
        assert_eq!(out["dns.query_type"], "A");
        assert_eq!(out["dns.response_code"], "NOERROR");
        assert_eq!(out["src_ip"], "10.0.0.5");
        assert_eq!(out["dst_port"], 53);
    }

    #[test]
    fn normalize_zeek_accepts_parser_bridge_shape() {
        // parse_zeek output: log_type + src_ip/dest_ip/src_port/dest_port
        let ev = json!({"_vendor": "zeek", "log_type": "conn", "uid": "C77",
                        "src_ip": "10.0.0.1", "src_port": 54321,
                        "dest_ip": "1.2.3.4", "dest_port": 443, "proto": "tcp",
                        "duration": 0.5, "orig_bytes": 1024, "resp_bytes": 2048});
        let out = normalize(&ev);
        assert_eq!(out["class_uid"], 4001);
        assert_eq!(out["src_ip"], "10.0.0.1");
        assert_eq!(out["dst_ip"], "1.2.3.4");
        assert_eq!(out["dst_port"], 443);
        assert_eq!(out["zk_duration"], 0.5);
        assert_eq!(out["zk_orig_bytes"], 1024);
    }

    #[test]
    fn normalize_palo_alto_severity_bump_on_block() {
        // TRAFFIC has no severity field; deny action bumps base 2 -> 3
        let ev = json!({"_vendor": "palo_alto", "type": "TRAFFIC", "subtype": "deny",
                        "serial": "0011", "action": "deny",
                        "src": "10.0.0.1", "dst": "1.2.3.4", "sport": 54321, "dport": 445});
        let out = normalize(&ev);
        assert_eq!(out["class_uid"], 4001);
        assert_eq!(out["type_uid"], 400106);
        assert_eq!(out["severity_id"], 3);
        assert_eq!(out["src_endpoint.ip"], "10.0.0.1");
        assert_eq!(out["src_endpoint.port"], 54321); // raw value, not coerced
        assert_eq!(out["panos_action"], "deny");
    }

    #[test]
    fn normalize_fortinet_utm_severity_and_user() {
        let ev = json!({"_vendor": "fortinet", "logid": "0419016384", "type": "utm",
                        "subtype": "ips", "severity": "high", "action": "dropped",
                        "user": "alice", "srcip": "10.0.0.2", "dstip": "8.8.8.8",
                        "attack": "Backdoor.Rev.Shell"});
        let out = normalize(&ev);
        assert_eq!(out["class_uid"], 2004);
        assert_eq!(out["type_uid"], 200401);
        assert_eq!(out["severity_id"], 4); // "high", already >= block bump
        assert_eq!(out["fortinet_user"], "alice");
        assert_eq!(out["actor.user.name"], "alice");
        assert_eq!(out["fortinet_attack"], "Backdoor.Rev.Shell");
    }
}
