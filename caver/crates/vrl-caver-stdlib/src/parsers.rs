//! Security parser functions (caver-collector#65).
//!
//! Fully implemented:
//!   `parse_suricata_eve`  — Suricata EVE JSON → structured Value
//!   `parse_zeek`          — Zeek JSON log → structured Value
//!   `parse_winevent`      — Windows Event XML → structured Value
//!   `parse_sysmon`        — Sysmon event object → structured Value
//!   `entity_id`           — FNV-1a stable entity hash
//!   `redact_pii`          — regex-free PII redaction (email, SSN, phone)
//!
//! Stub (interface defined; needs external tooling):
//!   `hash_imphash`        — PE import hash (needs PE format parsing)
//!   `dns_resolve_cached`  — DNS resolution (needs async runtime + TTL cache)

use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// parse_suricata_eve
// ---------------------------------------------------------------------------

/// Parse a Suricata EVE JSON line into a structured event object.
/// Extracts alert, http, dns sub-objects and normalises common fields.
pub fn parse_suricata_eve(raw: &str) -> Value {
    let ev: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => return json!({"error": format!("invalid JSON: {e}")}),
    };

    let event_type = ev.get("event_type").and_then(Value::as_str).unwrap_or("");
    let mut out = json!({
        "event_type": event_type,
        "timestamp":  ev.get("timestamp").and_then(Value::as_str).unwrap_or(""),
        "src_ip":     ev.get("src_ip").and_then(Value::as_str).unwrap_or(""),
        "dest_ip":    ev.get("dest_ip").and_then(Value::as_str).unwrap_or(""),
        "proto":      ev.get("proto").and_then(Value::as_str).unwrap_or(""),
    });

    if let Some(p) = ev.get("src_port").and_then(Value::as_u64) {
        out["src_port"] = json!(p);
    }
    if let Some(p) = ev.get("dest_port").and_then(Value::as_u64) {
        out["dest_port"] = json!(p);
    }
    if let Some(id) = ev.get("flow_id").and_then(Value::as_u64) {
        out["flow_id"] = json!(id);
    }

    match event_type {
        "alert" => {
            if let Some(a) = ev.get("alert") {
                out["alert"] = json!({
                    "action":       a.get("action").and_then(Value::as_str).unwrap_or(""),
                    "gid":          a.get("gid").and_then(Value::as_u64),
                    "signature_id": a.get("signature_id").and_then(Value::as_u64),
                    "rev":          a.get("rev").and_then(Value::as_u64),
                    "signature":    a.get("signature").and_then(Value::as_str).unwrap_or(""),
                    "category":     a.get("category").and_then(Value::as_str).unwrap_or(""),
                    "severity":     a.get("severity").and_then(Value::as_u64),
                });
            }
        }
        "http" => {
            if let Some(h) = ev.get("http") {
                out["http"] = json!({
                    "hostname":        h.get("hostname").and_then(Value::as_str).unwrap_or(""),
                    "url":             h.get("url").and_then(Value::as_str).unwrap_or(""),
                    "http_method":     h.get("http_method").and_then(Value::as_str).unwrap_or(""),
                    "status":          h.get("status").and_then(Value::as_u64),
                    "http_user_agent": h.get("http_user_agent").and_then(Value::as_str).unwrap_or(""),
                });
            }
        }
        "dns" => {
            if let Some(d) = ev.get("dns") {
                out["dns"] = json!({
                    "type":   d.get("type").and_then(Value::as_str).unwrap_or(""),
                    "id":     d.get("id").and_then(Value::as_u64),
                    "rrname": d.get("rrname").and_then(Value::as_str).unwrap_or(""),
                    "rrtype": d.get("rrtype").and_then(Value::as_str).unwrap_or(""),
                    "rcode":  d.get("rcode").and_then(Value::as_str).unwrap_or(""),
                });
            }
        }
        "flow" => {
            if let Some(f) = ev.get("flow") {
                out["flow"] = json!({
                    "pkts_toserver":  f.get("pkts_toserver").and_then(Value::as_u64),
                    "pkts_toclient":  f.get("pkts_toclient").and_then(Value::as_u64),
                    "bytes_toserver": f.get("bytes_toserver").and_then(Value::as_u64),
                    "bytes_toclient": f.get("bytes_toclient").and_then(Value::as_u64),
                    "start":          f.get("start").and_then(Value::as_str).unwrap_or(""),
                    "end":            f.get("end").and_then(Value::as_str).unwrap_or(""),
                    "state":          f.get("state").and_then(Value::as_str).unwrap_or(""),
                    "reason":         f.get("reason").and_then(Value::as_str).unwrap_or(""),
                });
            }
        }
        _ => {}
    }

    out
}

// ---------------------------------------------------------------------------
// parse_zeek
// ---------------------------------------------------------------------------

/// Parse a Zeek log line. Supports JSON output (recommended) and basic TSV for
/// the most common log types (conn, dns, http).
///
/// `log_type`: "conn" | "dns" | "http" | "files" | "ssl" — used for TSV column mapping.
/// If the line parses as JSON, `log_type` is informational only.
pub fn parse_zeek(line: &str, log_type: &str) -> Value {
    // Prefer JSON format
    if line.trim_start().starts_with('{') {
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            return normalise_zeek_json(v, log_type);
        }
    }
    // Fall back to TSV
    parse_zeek_tsv(line, log_type)
}

fn normalise_zeek_json(v: Value, log_type: &str) -> Value {
    // Zeek JSON already has named fields; just ensure ts is numeric and pull
    // common fields into the top level for uniform downstream consumption.
    let ts = v.get("ts").and_then(Value::as_f64).unwrap_or(0.0);
    let uid = v.get("uid").and_then(Value::as_str).unwrap_or("");
    let orig_h = v.get("id.orig_h").and_then(Value::as_str).unwrap_or("");
    let orig_p = v.get("id.orig_p").and_then(Value::as_u64).unwrap_or(0);
    let resp_h = v.get("id.resp_h").and_then(Value::as_str).unwrap_or("");
    let resp_p = v.get("id.resp_p").and_then(Value::as_u64).unwrap_or(0);
    let proto = v.get("proto").and_then(Value::as_str).unwrap_or("");

    let mut out = json!({
        "log_type": log_type,
        "ts":       ts,
        "uid":      uid,
        "src_ip":   orig_h,
        "src_port": orig_p,
        "dest_ip":  resp_h,
        "dest_port": resp_p,
        "proto":    proto,
    });

    match log_type {
        "conn" => {
            out["service"]     = v.get("service").cloned().unwrap_or(Value::Null);
            out["duration"]    = v.get("duration").cloned().unwrap_or(Value::Null);
            out["orig_bytes"]  = v.get("orig_bytes").cloned().unwrap_or(Value::Null);
            out["resp_bytes"]  = v.get("resp_bytes").cloned().unwrap_or(Value::Null);
            out["conn_state"]  = v.get("conn_state").cloned().unwrap_or(Value::Null);
            out["missed_bytes"]= v.get("missed_bytes").cloned().unwrap_or(Value::Null);
        }
        "dns" => {
            out["query"]  = v.get("query").cloned().unwrap_or(Value::Null);
            out["qtype"]  = v.get("qtype_name").cloned().unwrap_or(Value::Null);
            out["rcode"]  = v.get("rcode_name").cloned().unwrap_or(Value::Null);
            out["answers"]= v.get("answers").cloned().unwrap_or(Value::Null);
        }
        "http" => {
            out["method"]      = v.get("method").cloned().unwrap_or(Value::Null);
            out["host"]        = v.get("host").cloned().unwrap_or(Value::Null);
            out["uri"]         = v.get("uri").cloned().unwrap_or(Value::Null);
            out["status_code"] = v.get("status_code").cloned().unwrap_or(Value::Null);
            out["user_agent"]  = v.get("user_agent").cloned().unwrap_or(Value::Null);
            out["request_body_len"]  = v.get("request_body_len").cloned().unwrap_or(Value::Null);
            out["response_body_len"] = v.get("response_body_len").cloned().unwrap_or(Value::Null);
        }
        "ssl" => {
            out["server_name"] = v.get("server_name").cloned().unwrap_or(Value::Null);
            out["version"]     = v.get("version").cloned().unwrap_or(Value::Null);
            out["cipher"]      = v.get("cipher").cloned().unwrap_or(Value::Null);
            out["established"] = v.get("established").cloned().unwrap_or(Value::Null);
        }
        _ => {}
    }

    out
}

/// Minimal TSV parser for Zeek conn.log, dns.log, http.log.
/// Skips comment lines (starting with #). Returns an error object for
/// unknown log types or mismatched column counts.
fn parse_zeek_tsv(line: &str, log_type: &str) -> Value {
    if line.starts_with('#') {
        return json!({"error": "header/comment line"});
    }
    let fields: Vec<&str> = line.split('\t').collect();

    match log_type {
        "conn" if fields.len() >= 21 => {
            json!({
                "log_type":    "conn",
                "ts":          fields[0].parse::<f64>().ok(),
                "uid":         fields[1],
                "src_ip":      fields[2],
                "src_port":    fields[3].parse::<u16>().ok(),
                "dest_ip":     fields[4],
                "dest_port":   fields[5].parse::<u16>().ok(),
                "proto":       fields[6],
                "service":     if fields[7] == "-" { Value::Null } else { json!(fields[7]) },
                "duration":    fields[8].parse::<f64>().ok(),
                "orig_bytes":  fields[9].parse::<u64>().ok(),
                "resp_bytes":  fields[10].parse::<u64>().ok(),
                "conn_state":  fields[11],
            })
        }
        "dns" if fields.len() >= 22 => {
            json!({
                "log_type":  "dns",
                "ts":        fields[0].parse::<f64>().ok(),
                "uid":       fields[1],
                "src_ip":    fields[2],
                "src_port":  fields[3].parse::<u16>().ok(),
                "dest_ip":   fields[4],
                "dest_port": fields[5].parse::<u16>().ok(),
                "proto":     fields[6],
                "query":     fields[9],
                "qtype":     fields[13],
                "rcode":     fields[15],
            })
        }
        "http" if fields.len() >= 26 => {
            json!({
                "log_type":    "http",
                "ts":          fields[0].parse::<f64>().ok(),
                "uid":         fields[1],
                "src_ip":      fields[2],
                "src_port":    fields[3].parse::<u16>().ok(),
                "dest_ip":     fields[4],
                "dest_port":   fields[5].parse::<u16>().ok(),
                "method":      fields[7],
                "host":        fields[8],
                "uri":         fields[9],
                "user_agent":  fields[12],
                "status_code": fields[15].parse::<u16>().ok(),
            })
        }
        _ => json!({"error": format!("unsupported TSV log_type '{log_type}' or wrong column count")}),
    }
}

// ---------------------------------------------------------------------------
// parse_winevent
// ---------------------------------------------------------------------------

/// Parse Windows Event Log XML into a structured JSON object.
/// Extracts System fields and EventData key/value pairs.
pub fn parse_winevent(raw: &str) -> Value {
    let mut out = json!({});

    // System section
    out["event_id"]   = extract_xml_text(raw, "EventID").map_or(Value::Null, |s| {
        s.parse::<u64>().map(|n| json!(n)).unwrap_or(json!(s))
    });
    out["time_created"] = extract_xml_attr(raw, "TimeCreated", "SystemTime")
        .map_or(Value::Null, |s| json!(s));
    out["computer"]   = extract_xml_text(raw, "Computer").map_or(Value::Null, |s| json!(s));
    out["channel"]    = extract_xml_text(raw, "Channel").map_or(Value::Null, |s| json!(s));
    out["provider"]   = extract_xml_attr(raw, "Provider", "Name")
        .map_or(Value::Null, |s| json!(s));
    out["level"]      = extract_xml_text(raw, "Level").map_or(Value::Null, |s| {
        s.parse::<u64>().map(|n| json!(n)).unwrap_or(json!(s))
    });
    out["task"]       = extract_xml_text(raw, "Task").map_or(Value::Null, |s| {
        s.parse::<u64>().map(|n| json!(n)).unwrap_or(json!(s))
    });
    out["activity_id"] = extract_xml_attr(raw, "Correlation", "ActivityID")
        .map_or(Value::Null, |s| json!(s));

    // EventData section: collect all <Data Name="field">value</Data> pairs
    let event_data = extract_event_data(raw);
    if !event_data.is_empty() {
        out["event_data"] = json!(event_data);
    }

    out
}

/// Extract the text content of `<TagName>text</TagName>`.
fn extract_xml_text<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim())
}

/// Extract an attribute value from `<TagName AttrName="value" ...>`.
fn extract_xml_attr<'a>(xml: &'a str, tag: &str, attr: &str) -> Option<&'a str> {
    let tag_start = format!("<{} ", tag);
    let tag_pos = xml.find(&tag_start)?;
    let attr_key = format!("{}=\"", attr);
    let attr_pos = xml[tag_pos..].find(&attr_key)? + tag_pos + attr_key.len();
    let end = xml[attr_pos..].find('"')? + attr_pos;
    Some(&xml[attr_pos..end])
}

/// Extract all `<Data Name="key">value</Data>` pairs from the EventData section.
fn extract_event_data(xml: &str) -> serde_json::Map<String, Value> {
    let mut map = serde_json::Map::new();
    let mut rest = xml;
    while let Some(pos) = rest.find("<Data Name=\"") {
        rest = &rest[pos + 12..]; // skip past `<Data Name="`
        let name_end = match rest.find('"') {
            Some(p) => p,
            None => break,
        };
        let name = rest[..name_end].to_string();
        rest = &rest[name_end + 2..]; // skip past `">`
        let val_end = match rest.find("</Data>") {
            Some(p) => p,
            None => break,
        };
        let val = rest[..val_end].trim().to_string();
        map.insert(name, json!(val));
        rest = &rest[val_end + 7..]; // skip past `</Data>`
    }
    map
}

// ---------------------------------------------------------------------------
// parse_sysmon
// ---------------------------------------------------------------------------

/// Extract structured fields from a Sysmon event object.
/// Input may be a pre-parsed JSON object (from Vector's `parse_windows_eventlog`
/// or equivalent) or a raw XML string. Detects format automatically.
pub fn parse_sysmon(event: &Value) -> Value {
    // If it's a string, delegate to parse_winevent then re-parse.
    if let Some(raw) = event.as_str() {
        let parsed = parse_winevent(raw);
        return parse_sysmon_object(&parsed);
    }
    parse_sysmon_object(event)
}

fn parse_sysmon_object(ev: &Value) -> Value {
    // Support both flat keys (from Vector EventData extraction) and
    // nested event_data object (from our parse_winevent).
    let ed = ev.get("event_data");

    let get = |key: &str| -> Option<&str> {
        // Try flat first, then nested event_data
        ev.get(key)
            .or_else(|| ed.and_then(|e| e.get(key)))
            .and_then(Value::as_str)
    };

    let event_id: u64 = ev.get("event_id")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let mut out = json!({
        "event_id": event_id,
        "computer": ev.get("computer").and_then(Value::as_str).unwrap_or(""),
        "time_created": ev.get("time_created").and_then(Value::as_str).unwrap_or(""),
    });

    match event_id {
        // ProcessCreate
        1 => {
            let hashes = get("Hashes").map_or(Value::Null, parse_sysmon_hashes);
            out["process"] = json!({
                "guid":        get("ProcessGuid"),
                "pid":         get("ProcessId").and_then(|s| s.parse::<u64>().ok()),
                "image":       get("Image"),
                "command_line": get("CommandLine"),
                "current_directory": get("CurrentDirectory"),
                "user":        get("User"),
                "file_version": get("FileVersion"),
                "description": get("Description"),
                "product":     get("Product"),
                "company":     get("Company"),
                "hashes":      hashes,
            });
            out["parent_process"] = json!({
                "guid":         get("ParentProcessGuid"),
                "pid":          get("ParentProcessId").and_then(|s| s.parse::<u64>().ok()),
                "image":        get("ParentImage"),
                "command_line": get("ParentCommandLine"),
            });
        }
        // FileCreateTime
        2 => {
            out["target_filename"] = get("TargetFilename").map_or(Value::Null, |s| json!(s));
            out["creation_utc_time"] = get("CreationUtcTime").map_or(Value::Null, |s| json!(s));
            out["previous_creation_utc_time"] =
                get("PreviousCreationUtcTime").map_or(Value::Null, |s| json!(s));
        }
        // NetworkConnect
        3 => {
            out["src_ip"]    = get("SourceIp").map_or(Value::Null, |s| json!(s));
            out["src_port"]  = get("SourcePort").and_then(|s| s.parse::<u16>().ok()).map_or(Value::Null, |p| json!(p));
            out["dest_ip"]   = get("DestinationIp").map_or(Value::Null, |s| json!(s));
            out["dest_port"] = get("DestinationPort").and_then(|s| s.parse::<u16>().ok()).map_or(Value::Null, |p| json!(p));
            out["protocol"]  = get("Protocol").map_or(Value::Null, |s| json!(s));
            out["dest_hostname"] = get("DestinationHostname").map_or(Value::Null, |s| json!(s));
        }
        // DriverLoad (6) / ImageLoad (7)
        6 | 7 => {
            out["image_loaded"] = get("ImageLoaded").map_or(Value::Null, |s| json!(s));
            out["hashes"]       = get("Hashes").map_or(Value::Null, parse_sysmon_hashes);
            out["signed"]       = get("Signed").map(|s| json!(s.eq_ignore_ascii_case("true"))).unwrap_or(Value::Null);
            out["signature"]    = get("Signature").map_or(Value::Null, |s| json!(s));
        }
        // CreateRemoteThread (8)
        8 => {
            out["source_image"]  = get("SourceImage").map_or(Value::Null, |s| json!(s));
            out["target_image"]  = get("TargetImage").map_or(Value::Null, |s| json!(s));
            out["start_address"] = get("StartAddress").map_or(Value::Null, |s| json!(s));
        }
        _ => {}
    }

    out
}

/// Parse Sysmon hash string "MD5=abc123,SHA256=def456,IMPHASH=ghi789" into object.
fn parse_sysmon_hashes(raw: &str) -> Value {
    let mut map = serde_json::Map::new();
    for pair in raw.split(',') {
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(k.to_lowercase(), json!(v));
        }
    }
    Value::Object(map)
}

// ---------------------------------------------------------------------------
// entity_id
// ---------------------------------------------------------------------------

/// Generate a stable, content-addressed entity identifier using FNV-1a 64-bit.
/// `kind`: "host" | "user" | "file" | "process" (selects which fields matter).
/// Returns a 16-character lowercase hex string.
pub fn entity_id(fields: &Value, kind: &str) -> String {
    let mut parts: Vec<String> = vec![format!("kind={kind}")];

    if let Some(obj) = fields.as_object() {
        let relevant: &[&str] = match kind {
            "host" => &["hostname", "ip", "mac", "fqdn", "domain"],
            "user" => &["name", "domain", "uid", "email", "upn"],
            "file" => &["path", "hash_md5", "hash_sha256", "name"],
            "process" => &["pid", "guid", "image", "command_line"],
            _ => &[],
        };

        // Sort keys for stability
        let mut kvs: Vec<(&String, &Value)> = if relevant.is_empty() {
            obj.iter().collect()
        } else {
            obj.iter()
                .filter(|(k, _)| relevant.contains(&k.as_str()))
                .collect()
        };
        kvs.sort_by_key(|(k, _)| k.as_str());

        for (k, v) in kvs {
            parts.push(format!("{}={}", k, json_to_stable_string(v)));
        }
    }

    fnv1a_hex(parts.join("|").as_bytes())
}

fn json_to_stable_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        _ => v.to_string(),
    }
}

fn fnv1a_hex(data: &[u8]) -> String {
    const INIT: u64 = 14_695_981_039_346_656_037;
    const PRIME: u64 = 1_099_511_628_211;
    let mut hash = INIT;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    format!("{hash:016x}")
}

// ---------------------------------------------------------------------------
// redact_pii
// ---------------------------------------------------------------------------

/// Redact PII from all string values in a JSON event object (recursive).
/// `profile`: "email" | "ssn" | "phone" | "all"
pub fn redact_pii(event: &Value, profile: &str) -> Value {
    match event {
        Value::String(s) => Value::String(redact_string(s, profile)),
        Value::Object(map) => {
            let new_map: serde_json::Map<String, Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), redact_pii(v, profile)))
                .collect();
            Value::Object(new_map)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(|v| redact_pii(v, profile)).collect()),
        other => other.clone(),
    }
}

fn redact_string(s: &str, profile: &str) -> String {
    let mut result = s.to_string();
    if matches!(profile, "email" | "all") {
        result = redact_emails(&result);
    }
    if matches!(profile, "ssn" | "all") {
        result = redact_ssns(&result);
    }
    if matches!(profile, "phone" | "all") {
        result = redact_phones(&result);
    }
    result
}

/// Replace email-like patterns (`word@word.tld`) with `[REDACTED-EMAIL]`.
fn redact_emails(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'@' && i > 0 {
            // Find start of local-part (walk left over word chars + dots + plus + minus)
            let mut start = i;
            while start > 0 && is_email_local_char(bytes[start - 1]) {
                start -= 1;
            }
            // Find end of domain (walk right over word chars + dots + hyphens)
            let mut end = i + 1;
            let mut saw_dot = false;
            while end < bytes.len() && (is_email_domain_char(bytes[end])) {
                if bytes[end] == b'.' { saw_dot = true; }
                end += 1;
            }
            if start < i && saw_dot {
                // Remove the local part already written
                let written_len = out.len();
                let local_len = i - start;
                out.truncate(written_len - local_len);
                out.push_str("[REDACTED-EMAIL]");
                i = end;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn is_email_local_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-')
}

fn is_email_domain_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')
}

/// Replace `DDD-DD-DDDD` SSN patterns with `[REDACTED-SSN]`.
fn redact_ssns(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i + 10 < bytes.len() {
        // Pattern: 3 digits, dash, 2 digits, dash, 4 digits
        if bytes[i..i+3].iter().all(|b| b.is_ascii_digit())
            && bytes[i+3] == b'-'
            && bytes[i+4..i+6].iter().all(|b| b.is_ascii_digit())
            && bytes[i+6] == b'-'
            && bytes[i+7..i+11].iter().all(|b| b.is_ascii_digit())
        {
            // Ensure not preceded or followed by a digit (avoid matching in longer numbers)
            let before_ok = i == 0 || !bytes[i-1].is_ascii_digit();
            let after_ok = i + 11 >= bytes.len() || !bytes[i+11].is_ascii_digit();
            if before_ok && after_ok {
                out.push_str("[REDACTED-SSN]");
                i += 11;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    // Flush remainder
    if i <= bytes.len().saturating_sub(1) {
        out.push_str(&s[i..]);
    }
    out
}

/// Replace common US phone number formats with `[REDACTED-PHONE]`.
/// Patterns: (DDD) DDD-DDDD | DDD-DDD-DDDD | DDD.DDD.DDDD
fn redact_phones(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        // Try "(DDD) DDD-DDDD"
        if bytes[i] == b'(' && i + 14 < bytes.len() {
            let slice = &bytes[i..i+14];
            if slice[0] == b'('
                && slice[1..4].iter().all(|b| b.is_ascii_digit())
                && slice[4] == b')'
                && slice[5] == b' '
                && slice[6..9].iter().all(|b| b.is_ascii_digit())
                && slice[9] == b'-'
                && slice[10..14].iter().all(|b| b.is_ascii_digit())
            {
                out.push_str("[REDACTED-PHONE]");
                i += 14;
                continue;
            }
        }
        // Try "DDD-DDD-DDDD" or "DDD.DDD.DDDD"
        if i + 12 <= bytes.len() && bytes[i].is_ascii_digit() {
            let slice = &bytes[i..i+12];
            let sep = slice[3];
            if (sep == b'-' || sep == b'.')
                && slice[0..3].iter().all(|b| b.is_ascii_digit())
                && slice[4..7].iter().all(|b| b.is_ascii_digit())
                && slice[7] == sep
                && slice[8..12].iter().all(|b| b.is_ascii_digit())
            {
                let before_ok = i == 0 || !bytes[i-1].is_ascii_digit();
                let after_ok = i + 12 >= bytes.len() || !bytes[i+12].is_ascii_digit();
                if before_ok && after_ok {
                    out.push_str("[REDACTED-PHONE]");
                    i += 12;
                    continue;
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Stub functions
// ---------------------------------------------------------------------------

/// Compute the PE import hash from raw PE bytes.
/// Stub: returns None. Requires PE format parsing.
pub fn hash_imphash(_pe_bytes: &[u8]) -> Option<String> {
    None
}

/// Resolve a hostname via DNS with TTL-aware caching.
/// Stub: returns empty vec. Requires async runtime + cache.
pub fn dns_resolve_cached(_name: &str) -> Vec<String> {
    vec![]
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suricata_alert_parse() {
        let raw = r#"{
            "timestamp": "2026-05-28T10:00:00.000Z",
            "flow_id": 12345,
            "event_type": "alert",
            "src_ip": "10.0.0.1",
            "src_port": 54321,
            "dest_ip": "1.2.3.4",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "action": "blocked",
                "gid": 1,
                "signature_id": 2100498,
                "rev": 7,
                "signature": "GPL ATTACK_RESPONSE id check returned root",
                "category": "Potentially Bad Traffic",
                "severity": 2
            }
        }"#;
        let v = parse_suricata_eve(raw);
        assert_eq!(v["event_type"], "alert");
        assert_eq!(v["src_ip"], "10.0.0.1");
        assert_eq!(v["alert"]["signature_id"], 2100498u64);
        assert_eq!(v["alert"]["action"], "blocked");
    }

    #[test]
    fn suricata_invalid_json() {
        let v = parse_suricata_eve("not json");
        assert!(v["error"].is_string());
    }

    #[test]
    fn zeek_conn_json() {
        let line = r#"{"ts":1748426400.0,"uid":"C1234","id.orig_h":"10.0.0.1","id.orig_p":54321,"id.resp_h":"1.2.3.4","id.resp_p":443,"proto":"tcp","service":"ssl","duration":0.5,"orig_bytes":1024,"resp_bytes":2048,"conn_state":"SF","missed_bytes":0}"#;
        let v = parse_zeek(line, "conn");
        assert_eq!(v["log_type"], "conn");
        assert_eq!(v["src_ip"], "10.0.0.1");
        assert_eq!(v["dest_port"], 443u64);
        assert_eq!(v["conn_state"], "SF");
    }

    #[test]
    fn parse_winevent_eventid() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Microsoft-Windows-Security-Auditing"/>
            <EventID>4625</EventID>
            <Level>0</Level>
            <TimeCreated SystemTime="2026-05-28T10:00:00.000000000Z"/>
            <Computer>DESKTOP-ABC</Computer>
            <Channel>Security</Channel>
          </System>
          <EventData>
            <Data Name="TargetUserName">alice</Data>
            <Data Name="SubjectUserSid">S-1-0-0</Data>
          </EventData>
        </Event>"#;
        let v = parse_winevent(xml);
        assert_eq!(v["event_id"], 4625u64);
        assert_eq!(v["computer"], "DESKTOP-ABC");
        assert_eq!(v["provider"], "Microsoft-Windows-Security-Auditing");
        assert_eq!(v["event_data"]["TargetUserName"], "alice");
    }

    #[test]
    fn parse_sysmon_event1() {
        let ev = json!({
            "event_id": 1,
            "computer": "DESKTOP-ABC",
            "time_created": "2026-05-28T10:00:00Z",
            "event_data": {
                "ProcessGuid": "{12345678-abcd-1234-abcd-123456789012}",
                "ProcessId": "4892",
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c whoami",
                "User": "DESKTOP-ABC\\alice",
                "ParentImage": "C:\\Windows\\System32\\powershell.exe",
                "ParentProcessId": "2344",
                "Hashes": "MD5=abc123,SHA256=def456"
            }
        });
        let v = parse_sysmon(&ev);
        assert_eq!(v["event_id"], 1u64);
        assert_eq!(v["process"]["pid"], 4892u64);
        assert_eq!(v["process"]["image"], "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(v["process"]["hashes"]["md5"], "abc123");
        assert_eq!(v["parent_process"]["pid"], 2344u64);
    }

    #[test]
    fn entity_id_stable() {
        let f1 = json!({"hostname": "server1", "ip": "10.0.0.1"});
        let f2 = json!({"ip": "10.0.0.1", "hostname": "server1"});
        assert_eq!(entity_id(&f1, "host"), entity_id(&f2, "host"));
    }

    #[test]
    fn entity_id_differs_by_kind() {
        let f = json!({"name": "alice"});
        assert_ne!(entity_id(&f, "user"), entity_id(&f, "host"));
    }

    #[test]
    fn entity_id_hex_length() {
        let f = json!({"hostname": "x"});
        let id = entity_id(&f, "host");
        assert_eq!(id.len(), 16);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn redact_email_in_string() {
        let v = json!({"user": "Contact alice@example.com for help"});
        let out = redact_pii(&v, "email");
        assert_eq!(out["user"], "Contact [REDACTED-EMAIL] for help");
    }

    #[test]
    fn redact_ssn_in_string() {
        let v = json!({"note": "SSN is 123-45-6789 on file"});
        let out = redact_pii(&v, "ssn");
        assert_eq!(out["note"], "SSN is [REDACTED-SSN] on file");
    }

    #[test]
    fn redact_phone_dash_format() {
        let v = json!({"contact": "Call 555-867-5309 now"});
        let out = redact_pii(&v, "phone");
        assert_eq!(out["contact"], "Call [REDACTED-PHONE] now");
    }

    #[test]
    fn redact_nested_values() {
        let v = json!({"user": {"email": "bob@test.org", "id": 42}});
        let out = redact_pii(&v, "email");
        assert_eq!(out["user"]["email"], "[REDACTED-EMAIL]");
        assert_eq!(out["user"]["id"], 42);
    }

    #[test]
    fn redact_all_profile() {
        let v = json!({"text": "SSN 123-45-6789 email foo@bar.com phone 555-123-4567"});
        let out = redact_pii(&v, "all");
        let s = out["text"].as_str().unwrap();
        assert!(s.contains("[REDACTED-SSN]"));
        assert!(s.contains("[REDACTED-EMAIL]"));
        assert!(s.contains("[REDACTED-PHONE]"));
    }

    #[test]
    fn stubs_return_expected_shapes() {
        assert_eq!(hash_imphash(b"fake"), None);
        assert_eq!(dns_resolve_cached("example.com"), Vec::<String>::new());
    }
}
