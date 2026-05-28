//! ATT&CK + CVE + threat-intel functions (caver-collector#64).
//!
//! Fully implemented (no external data required):
//!   `is_internal_ip`        — RFC 1918 / RFC 6598 / link-local / loopback / docs
//!   `attack_tactic_lookup`  — static MITRE ATT&CK Enterprise tactic table
//!
//! Stub (interface defined; needs external data feed):
//!   `attack_technique_match` — rule_id → technique_ids (needs rule DB)
//!   `cve_enrich`             — CVE → CVSS/KEV/EPSS (needs NVD/CISA API)
//!   `threat_indicator_match` — IOC match (needs SLAM indicator feeds)
//!   `geoip_caver`            — IP geolocation (needs MaxMind GeoLite2)
//!   `asn_lookup`             — IP → ASN (needs ASN database)

use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// is_internal_ip
// ---------------------------------------------------------------------------

/// Return `true` if `ip` belongs to an RFC-1918 / RFC-4291 / RFC-6598 /
/// RFC-5737 / loopback / link-local / documentation range.
/// Returns `false` for unparse-able input.
pub fn is_internal_ip(ip: &str) -> bool {
    let ip = ip.trim();
    if let Some(v4) = parse_ipv4(ip) {
        is_private_v4(v4)
    } else if let Some(v6) = parse_ipv6(ip) {
        is_private_v6(v6)
    } else {
        false
    }
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p.parse().ok()?;
    }
    Some(out)
}

fn is_private_v4(ip: [u8; 4]) -> bool {
    let [a, b, c, _d] = ip;
    // 10.0.0.0/8
    if a == 10 { return true; }
    // 172.16.0.0/12
    if a == 172 && (16..=31).contains(&b) { return true; }
    // 192.168.0.0/16
    if a == 192 && b == 168 { return true; }
    // 127.0.0.0/8 — loopback
    if a == 127 { return true; }
    // 169.254.0.0/16 — link-local (APIPA)
    if a == 169 && b == 254 { return true; }
    // 100.64.0.0/10 — shared address space (RFC 6598 / CGNAT)
    if a == 100 && (64..=127).contains(&b) { return true; }
    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 — documentation (RFC 5737)
    if a == 192 && b == 0 && c == 2 { return true; }
    if a == 198 && b == 51 && c == 100 { return true; }
    if a == 203 && b == 0 && c == 113 { return true; }
    // 0.0.0.0/8 — "this" network
    if a == 0 { return true; }
    // 255.255.255.255 — limited broadcast
    if ip == [255, 255, 255, 255] { return true; }
    false
}

fn parse_ipv6(s: &str) -> Option<[u16; 8]> {
    // Handle "::1", "::", and full forms; skip mapped IPv4 for now.
    if s == "::1" {
        return Some([0, 0, 0, 0, 0, 0, 0, 1]);
    }
    if s == "::" {
        return Some([0u16; 8]);
    }
    // Try simple full form (no compression).
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() == 8 {
        let mut out = [0u16; 8];
        for (i, p) in parts.iter().enumerate() {
            out[i] = u16::from_str_radix(p, 16).ok()?;
        }
        return Some(out);
    }
    // Handle :: compressed form.
    if s.contains("::") {
        let halves: Vec<&str> = s.splitn(2, "::").collect();
        let left: Vec<&str> = if halves[0].is_empty() {
            vec![]
        } else {
            halves[0].split(':').collect()
        };
        let right: Vec<&str> = if halves.get(1).map_or(true, |r| r.is_empty()) {
            vec![]
        } else {
            halves[1].split(':').collect()
        };
        let zeros = 8 - left.len() - right.len();
        let mut out = [0u16; 8];
        for (i, p) in left.iter().enumerate() {
            out[i] = u16::from_str_radix(p, 16).ok()?;
        }
        for (i, p) in right.iter().enumerate() {
            out[left.len() + zeros + i] = u16::from_str_radix(p, 16).ok()?;
        }
        return Some(out);
    }
    None
}

fn is_private_v6(ip: [u16; 8]) -> bool {
    // ::1 — loopback
    if ip == [0, 0, 0, 0, 0, 0, 0, 1] { return true; }
    // :: — unspecified
    if ip == [0u16; 8] { return true; }
    // fc00::/7 — Unique Local Address (ULA)
    if (ip[0] & 0xFE00) == 0xFC00 { return true; }
    // fe80::/10 — link-local
    if (ip[0] & 0xFFC0) == 0xFE80 { return true; }
    false
}

// ---------------------------------------------------------------------------
// attack_tactic_lookup
// ---------------------------------------------------------------------------

/// MITRE ATT&CK Enterprise technique-to-tactic static table.
/// Returns the *primary* tactic for a technique ID (e.g. "T1059" → TA0002 Execution).
/// Multi-tactic techniques return the first listed in ATT&CK order.
/// Returns `null` JSON value for unknown technique IDs.
pub fn attack_tactic_lookup(technique_id: &str) -> Value {
    // Normalise: strip sub-technique suffix (.001 etc.) for lookup
    let tid = technique_id
        .trim()
        .to_uppercase()
        .split('.')
        .next()
        .unwrap_or("")
        .to_string();

    if let Some((_, tactic_id, tactic_name)) = TECHNIQUE_TO_TACTIC.iter().find(|(t, _, _)| *t == tid) {
        json!({
            "tactic_id": tactic_id,
            "tactic_name": tactic_name,
            "technique_id": technique_id
        })
    } else {
        Value::Null
    }
}

/// Static mapping of common ATT&CK Enterprise techniques to their primary tactic.
/// Source: MITRE ATT&CK Enterprise v15 (subset of well-known techniques).
static TECHNIQUE_TO_TACTIC: &[(&str, &str, &str)] = &[
    // TA0001 Initial Access
    ("T1190", "TA0001", "Initial Access"),
    ("T1133", "TA0001", "Initial Access"),
    ("T1566", "TA0001", "Initial Access"),
    ("T1195", "TA0001", "Initial Access"),
    ("T1078", "TA0001", "Initial Access"),
    ("T1091", "TA0001", "Initial Access"),
    ("T1200", "TA0001", "Initial Access"),
    ("T1199", "TA0001", "Initial Access"),
    // TA0002 Execution
    ("T1059", "TA0002", "Execution"),
    ("T1106", "TA0002", "Execution"),
    ("T1053", "TA0002", "Execution"),
    ("T1569", "TA0002", "Execution"),
    ("T1204", "TA0002", "Execution"),
    ("T1047", "TA0002", "Execution"),
    ("T1129", "TA0002", "Execution"),
    // TA0003 Persistence
    ("T1098", "TA0003", "Persistence"),
    ("T1136", "TA0003", "Persistence"),
    ("T1197", "TA0003", "Persistence"),
    ("T1547", "TA0003", "Persistence"),
    ("T1543", "TA0003", "Persistence"),
    ("T1574", "TA0003", "Persistence"),
    ("T1546", "TA0003", "Persistence"),
    ("T1037", "TA0003", "Persistence"),
    ("T1542", "TA0003", "Persistence"),
    // TA0004 Privilege Escalation
    ("T1055", "TA0004", "Privilege Escalation"),
    ("T1134", "TA0004", "Privilege Escalation"),
    ("T1548", "TA0004", "Privilege Escalation"),
    ("T1484", "TA0004", "Privilege Escalation"),
    // TA0005 Defense Evasion
    ("T1027", "TA0005", "Defense Evasion"),
    ("T1070", "TA0005", "Defense Evasion"),
    ("T1562", "TA0005", "Defense Evasion"),
    ("T1564", "TA0005", "Defense Evasion"),
    ("T1036", "TA0005", "Defense Evasion"),
    ("T1218", "TA0005", "Defense Evasion"),
    ("T1620", "TA0005", "Defense Evasion"),
    // TA0006 Credential Access
    ("T1003", "TA0006", "Credential Access"),
    ("T1558", "TA0006", "Credential Access"),
    ("T1110", "TA0006", "Credential Access"),
    ("T1555", "TA0006", "Credential Access"),
    ("T1552", "TA0006", "Credential Access"),
    ("T1111", "TA0006", "Credential Access"),
    ("T1539", "TA0006", "Credential Access"),
    // TA0007 Discovery
    ("T1082", "TA0007", "Discovery"),
    ("T1083", "TA0007", "Discovery"),
    ("T1033", "TA0007", "Discovery"),
    ("T1069", "TA0007", "Discovery"),
    ("T1087", "TA0007", "Discovery"),
    ("T1135", "TA0007", "Discovery"),
    ("T1046", "TA0007", "Discovery"),
    ("T1057", "TA0007", "Discovery"),
    ("T1018", "TA0007", "Discovery"),
    // TA0008 Lateral Movement
    ("T1021", "TA0008", "Lateral Movement"),
    ("T1080", "TA0008", "Lateral Movement"),
    ("T1534", "TA0008", "Lateral Movement"),
    ("T1550", "TA0008", "Lateral Movement"),
    // TA0009 Collection
    ("T1560", "TA0009", "Collection"),
    ("T1114", "TA0009", "Collection"),
    ("T1056", "TA0009", "Collection"),
    ("T1113", "TA0009", "Collection"),
    ("T1115", "TA0009", "Collection"),
    ("T1530", "TA0009", "Collection"),
    // TA0010 Exfiltration
    ("T1041", "TA0010", "Exfiltration"),
    ("T1048", "TA0010", "Exfiltration"),
    ("T1052", "TA0010", "Exfiltration"),
    ("T1567", "TA0010", "Exfiltration"),
    // TA0011 Command and Control
    ("T1071", "TA0011", "Command and Control"),
    ("T1090", "TA0011", "Command and Control"),
    ("T1095", "TA0011", "Command and Control"),
    ("T1572", "TA0011", "Command and Control"),
    ("T1132", "TA0011", "Command and Control"),
    ("T1001", "TA0011", "Command and Control"),
    ("T1008", "TA0011", "Command and Control"),
    ("T1105", "TA0011", "Command and Control"),
    // TA0040 Impact
    ("T1485", "TA0040", "Impact"),
    ("T1486", "TA0040", "Impact"),
    ("T1489", "TA0040", "Impact"),
    ("T1490", "TA0040", "Impact"),
    ("T1491", "TA0040", "Impact"),
    ("T1498", "TA0040", "Impact"),
    ("T1499", "TA0040", "Impact"),
    ("T1529", "TA0040", "Impact"),
    // TA0042 Resource Development
    ("T1583", "TA0042", "Resource Development"),
    ("T1584", "TA0042", "Resource Development"),
    ("T1585", "TA0042", "Resource Development"),
    ("T1586", "TA0042", "Resource Development"),
    ("T1587", "TA0042", "Resource Development"),
    ("T1588", "TA0042", "Resource Development"),
    // TA0043 Reconnaissance
    ("T1595", "TA0043", "Reconnaissance"),
    ("T1596", "TA0043", "Reconnaissance"),
    ("T1597", "TA0043", "Reconnaissance"),
    ("T1598", "TA0043", "Reconnaissance"),
    ("T1589", "TA0043", "Reconnaissance"),
    ("T1590", "TA0043", "Reconnaissance"),
    ("T1591", "TA0043", "Reconnaissance"),
    ("T1592", "TA0043", "Reconnaissance"),
    ("T1593", "TA0043", "Reconnaissance"),
    ("T1594", "TA0043", "Reconnaissance"),
];

// ---------------------------------------------------------------------------
// Stub functions (interface defined; external data required)
// ---------------------------------------------------------------------------

/// Map a RES detection rule_id to its ATT&CK technique IDs.
/// Stub: returns empty array. Needs the caver rule DB.
pub fn attack_technique_match(_rule_id: &str) -> Value {
    json!([])
}

/// Enrich a CVE ID with CVSS score, KEV status, and EPSS probability.
/// Stub: returns null. Needs NVD/CISA API integration or bundled DB.
pub fn cve_enrich(_cve_id: &str) -> Value {
    Value::Null
}

/// Match a value against SLAM-fed threat indicators.
/// Stub: returns `{"matched": false}`. Needs SLAM indicator feeds.
pub fn threat_indicator_match(_value: &str, _indicator_type: &str) -> Value {
    json!({"matched": false, "source": null, "confidence": null})
}

/// Geo-locate an IP address.
/// Stub: returns null. Needs MaxMind GeoLite2 or IPinfo.
pub fn geoip_caver(_ip: &str) -> Value {
    Value::Null
}

/// Look up the Autonomous System for an IP.
/// Stub: returns null. Needs an ASN database.
pub fn asn_lookup(_ip: &str) -> Value {
    Value::Null
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_rfc1918() {
        assert!(is_internal_ip("10.0.0.1"));
        assert!(is_internal_ip("172.16.0.1"));
        assert!(is_internal_ip("172.31.255.255"));
        assert!(is_internal_ip("192.168.1.100"));
    }

    #[test]
    fn internal_loopback_linklocal() {
        assert!(is_internal_ip("127.0.0.1"));
        assert!(is_internal_ip("127.1.2.3"));
        assert!(is_internal_ip("169.254.0.1"));
        assert!(is_internal_ip("::1"));
    }

    #[test]
    fn internal_cgnat_rfc6598() {
        assert!(is_internal_ip("100.64.0.1"));
        assert!(is_internal_ip("100.127.255.255"));
    }

    #[test]
    fn internal_documentation_rfc5737() {
        assert!(is_internal_ip("192.0.2.1"));
        assert!(is_internal_ip("198.51.100.42"));
        assert!(is_internal_ip("203.0.113.10"));
    }

    #[test]
    fn public_ips_not_internal() {
        assert!(!is_internal_ip("8.8.8.8"));
        assert!(!is_internal_ip("1.1.1.1"));
        assert!(!is_internal_ip("93.184.216.34"));
        assert!(!is_internal_ip("2001:4860:4860::8888"));
    }

    #[test]
    fn invalid_ip_returns_false() {
        assert!(!is_internal_ip("not-an-ip"));
        assert!(!is_internal_ip("999.0.0.1"));
        assert!(!is_internal_ip(""));
    }

    #[test]
    fn attack_tactic_known_technique() {
        let v = attack_tactic_lookup("T1059");
        assert_eq!(v["tactic_id"], "TA0002");
        assert_eq!(v["tactic_name"], "Execution");
    }

    #[test]
    fn attack_tactic_subtechnique_stripped() {
        let v = attack_tactic_lookup("T1059.001");
        assert_eq!(v["tactic_id"], "TA0002");
    }

    #[test]
    fn attack_tactic_unknown_returns_null() {
        let v = attack_tactic_lookup("T9999");
        assert_eq!(v, Value::Null);
    }

    #[test]
    fn attack_tactic_case_insensitive() {
        let v = attack_tactic_lookup("t1190");
        assert_eq!(v["tactic_id"], "TA0001");
    }

    #[test]
    fn stubs_return_expected_shapes() {
        assert_eq!(attack_technique_match("RES-0001"), json!([]));
        assert_eq!(cve_enrich("CVE-2024-1234"), Value::Null);
        let ti = threat_indicator_match("8.8.8.8", "ip");
        assert_eq!(ti["matched"], false);
        assert_eq!(geoip_caver("8.8.8.8"), Value::Null);
        assert_eq!(asn_lookup("8.8.8.8"), Value::Null);
    }

    #[test]
    fn ipv6_ula() {
        assert!(is_internal_ip("fc00::1"));
        assert!(is_internal_ip("fd12:3456:789a::1"));
    }

    #[test]
    fn ipv6_link_local() {
        assert!(is_internal_ip("fe80::1"));
        assert!(is_internal_ip("fe80::abcd:ef01"));
    }
}
