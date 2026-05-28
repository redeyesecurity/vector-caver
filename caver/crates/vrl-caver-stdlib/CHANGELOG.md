# Changelog — vrl-caver-stdlib

## [0.3.0] — 2026-05-28

### Added (caver-collector#64: ATT&CK + CVE + threat-intel functions)
- `threat_intel::is_internal_ip()` — RFC 1918/4193/5737/6598 + loopback + link-local + docs ranges;
  IPv4 and compressed IPv6 (ULA, link-local, loopback)
- `threat_intel::attack_tactic_lookup()` — static MITRE ATT&CK Enterprise tactic table
  covering ~90 well-known techniques across all 14 tactics (v15 subset); sub-technique stripping + case folding
- Stubs with defined interfaces: `attack_technique_match`, `cve_enrich`,
  `threat_indicator_match`, `geoip_caver`, `asn_lookup`

### Added (caver-collector#65: security parser functions)
- `parsers::parse_suricata_eve()` — Suricata EVE JSON normalisation (alert, http, dns, flow)
- `parsers::parse_zeek()` — Zeek JSON + TSV (conn, dns, http, ssl) to structured Value
- `parsers::parse_winevent()` — Windows Event Log XML tag extraction (EventID, TimeCreated,
  Provider, EventData key/value pairs)
- `parsers::parse_sysmon()` — Sysmon EventID-aware field extraction (EventID 1/2/3/6/7/8)
  with hash map parsing and parent process extraction
- `parsers::entity_id()` — FNV-1a 64-bit stable entity hash (host/user/file/process kinds)
- `parsers::redact_pii()` — regex-free recursive PII redaction: email, SSN (DDD-DD-DDDD),
  US phone (DDD-DDD-DDDD / (DDD) DDD-DDDD / DDD.DDD.DDDD); profiles: email/ssn/phone/all
- Stubs: `hash_imphash`, `dns_resolve_cached`

## [0.2.0] — 2026-05-28

### Added
- `ocsf` module with `classify()` and `normalize()` public functions (caver-collector#63)
- OCSF normalization for three initial vendors: Okta (class 4002 Authentication),
  nginx (class 3003 HTTP Activity), Sysmon EventID 1 (class 5001 Process Activity)
- `severity_id_name()` helper for severity string to OCSF id/name mapping
- Timestamp parsers for ISO-8601/RFC-3339, nginx CLF, and Sysmon UTC formats
- Golden-fixture snapshot tests in `tests/golden.rs` (`golden_4002`, `golden_3003`, `golden_5001`)
- 9 unit tests covering classification, severity mapping, and timestamp parsing

### Fixed
- Golden fixture `out.json` timestamps corrected from 2025-05-28 epoch to 2026-05-28 epoch

## [0.1.0] — initial scaffold
- Workspace scaffold; `lib.rs` stub only
