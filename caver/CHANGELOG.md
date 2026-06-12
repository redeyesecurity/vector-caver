# Changelog

## [0.8.0] - 2026-06-12

### Added
- **`caver_parquet` is a registered Vector sink** (caver-collector#894): the root
  vector binary now wires `caver-sink-parquet` in as a first-class component
  behind the `sinks-caver_parquet` feature (in the `sinks-logs` umbrella)
  - `src/sinks/caver_parquet/` — `SinkConfig` impl mapping Vector config to the
    crate's `Config` + `S3Config` (bucket, sensor_id, class_uid_field, batch_size,
    dlq_path, endpoint, region, credential env-var names, retry/timeout knobs)
  - Build fails fast on missing credential env vars or a bad endpoint
  - All inner-sink interaction (batching, Parquet encode, signed PUT with retry
    backoff) runs under `spawn_blocking` — a slow object store cannot stall the
    async topology
  - Logs are flattened to dotted-key string rows via `all_event_fields`;
    scalar-root logs ship keyed as `message` instead of being dropped
  - PUT/encode failures are surfaced at the Vector layer: the crate's
    `dropped`/`put_errors` counters are diffed after every blocking call and
    increments are logged at error level + emitted as
    `component_discarded_events_total` (events ack at batch-accept time, so
    this is the only failure signal)
  - `build()` validates `batch_size >= 1` and `sensor_id` charset
    (`[A-Za-z0-9._-]+`, it is embedded in the object key), and warns when
    acknowledgements are enabled without a `dlq_path`
  - `vector list` shows `caver_parquet`; a config naming it boots (CI runs
    full `vector validate`, so `build()` is exercised; root build is
    `--locked`)

### Changed
- `caver-sink-parquet` no longer uses workspace-inherited `version`/`edition`/
  `license` (explicit, kept in lockstep with `workspace.package`): the crate is
  now also a path dependency of the root vector workspace, and cargo resolves
  inheritance against root there. Root `[workspace]` excludes `caver/`.

## [0.7.0] - 2026-06-12

### Added
- `caver-sink-parquet`: built-in S3/MinIO transport (caver-collector#895)
  - `transport::S3Config` — endpoint (MinIO/path-style or AWS-default), region,
    credentials via env-var **names** (`access_key_env`/`secret_key_env`/optional
    `session_token_env`, search-peer `token_env` convention), retry knobs, timeout
  - `transport::S3Transport::put` — signed path-style PutObject; only 2xx is
    success — 3xx (AWS 307/301 redirects, not followed for PUT) and 5xx/transport
    errors retry with exponential backoff (capped 30s), 4xx fails immediately;
    re-signs each attempt; endpoint validated/normalized via `url` at build time
  - `transport::s3_put_fn` — builds a ready `PutFn` for `ParquetSink::new`
  - `sigv4` — minimal AWS Signature V4 (header auth, service=s3), pinned against
    both official AWS doc examples (GET + PUT `test$file.text`); header values
    canonicalized (trim + space-run folding)
  - 13 new tests (sigv4 vectors incl. space-folding, mockito wire tests incl.
    retry/no-retry-4xx/307-as-failure, endpoint parsing, DLQ path)

### Changed
- `caver-sink-parquet`: **`PutFn` is now fallible** — `Fn(&str, &str, Vec<u8>) -> Result<(), String>`.
  A failed put no longer counts as a flush: the batch goes to `dlq_path` as ndjson,
  events are counted in `dropped`, and a new `put_errors` stat is exposed.

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
