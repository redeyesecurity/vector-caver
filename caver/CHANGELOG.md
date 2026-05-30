# Changelog

## [0.6.0] - 2026-05-28

### Added
- `caver-ops`: Operational helpers crate (mTLS enforcement, config-reload monitoring, OPAMP identity)
  - `tls::TlsPolicy` — `Required` rejects HTTP/gRPC plaintext; `Permissive` allows (dev/test default)
  - `reload::validate_config` — shells out to `vector validate`; returns `ReloadEvent::Passed` or `Failed`
  - `reload::ReloadEvent` — structured outcome with `should_apply()` + `summary()` for logging/alerting
  - `opamp::AgentIdentity` — agent UUID, tenant_id, site, pool (Edge/Aggregator/Replay), version
  - `opamp::AgentIdentity::to_attributes()` — serializes for OPAMP `AgentDescription.identifying_attributes`
  - 15 tests (14 unit + 1 doc) all passing

## [0.5.0] - 2026-05-28

### Added
- `caver-sink-search-peer`: HEC-backed sink for pushing OCSF events to RES-splunk-caver
  - `Config`: url, token_env, batch_size, timeout_ms with sane defaults
  - `Client::from_config` — resolves HEC token from env at build time
  - `Client::push_events` — splits into `batch_size` chunks, POSTs each as newline-delimited HEC JSON
  - `format_batch` — wraps events in `{"event": ..., "sourcetype": "ocsf", "time": <secs>}`
  - OCSF `time` field (ms) auto-extracted to HEC envelope seconds
  - 9 tests (8 unit + 1 doc) all passing

## [0.4.0] - 2026-05-28

### Added
- `caver-ottl-funcs`: OTTL extension functions crate with three modules
  - `hmac`: SHA-256 + HMAC-SHA256 + `hmac_token` 16-char pseudonym (RustCrypto sha2/hmac)
  - `enrich`: enrichment table lookup with build_index + binary-search index_lookup
  - `ocsf`: required-field validation + class registry for 18 OCSF 1.3 classes

## [0.3.0] - 2026-05-28

### Added
- `vrl-caver-stdlib/threat_intel`: ATT&CK tactic lookup, IP range classification, stubs for CVE/GeoIP/ASN
- `vrl-caver-stdlib/parsers`: Suricata EVE, Zeek TSV/JSON, WinEvent XML, Sysmon, entity_id, PII redaction

## [0.2.0] - 2026-05-28

### Added
- `vrl-caver-stdlib/ocsf`: OCSF normalization (classify, normalize) with golden fixture tests
- Vendor normalizers: Okta SSO, nginx access log, Sysmon EventID 1

## [0.1.0] - 2026-05-28

### Added
- Rust workspace scaffold: vrl-caver-stdlib, caver-source-uf-compat, caver-sink-search-peer, caver-ottl-funcs
- Golden fixture harness for OCSF class 3003/4002/5001 normalization testing
