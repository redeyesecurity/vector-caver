# Changelog

## [0.13.0] - 2026-06-12

### Added
- **Real sink healthcheck** (caver-collector#898): the `caver_parquet`
  healthcheck now issues a signed `HEAD` on the bucket
  (`S3Transport::head_bucket`, run on the blocking pool) instead of
  `future::ok(())` — boot and `vector validate` catch wrong credentials
  (403 hint), missing buckets (404 hint), and wrong-region redirects
  before events flow
- **`put_deadline_ms`** (default 45000): total wall-clock budget for one
  PUT *including* every retry and backoff sleep. Bounds the final
  shutdown flush — with the retry defaults the unbounded worst case was
  ~121s, longer than vector's `graceful_shutdown_limit_secs` default of
  60s, so an already-acknowledged final batch could be force-killed
  mid-retry and lost without reaching the DLQ. The per-request timeout
  shrinks to the remaining budget; exhaustion routes the batch to the DLQ
  with `put_deadline_ms=<n> exhausted` appended to the error
- **DLQ reason sidecar**: each `dlq-*.ndjson` now gets a same-stem
  `.reason` file recording why the batch landed there (`put: …` /
  `serialize: …`), so triage doesn't have to correlate timestamps with
  collector logs; the ndjson stays pure rows for replay tooling

### Fixed
- **Native-layout partition values are key-charset sanitized**
  (carried from the vector-caver#20 review): `sensor_id` is sanitized in
  `ParquetSink::new` (fallback `collector`) and the event-derived
  `class_uid` in the Native key path falls back to `0000` when key-unsafe
  — a `/` or `..` there broke the SigV4 canonical path and 403'd (→ DLQ)
  the whole batch

### Changed
- arrow/parquet 55 → 56, sharing the root vector workspace's copy
  (codecs are already on 56) instead of dragging a second full arrow
  stack into the build
- CI: protoc is now a pinned 25.3 release download instead of
  `brew install protobuf`; the expensive vector-component job is
  path-filtered (docs-only changes skip it, safe default = run); the
  validate config sets `healthcheck.enabled = false` because its
  endpoint is intentionally unreachable

## [0.12.0] - 2026-06-12

### Fixed
- **caver_staging hardening follow-ups from the #896/#897 reviews**
  (caver-collector#899):
  - staging `_time` is now schema-aware and full-precision: the wrapper
    captures the native `Value::Timestamp` BEFORE flattening (honoring
    `log_schema.timestamp_key` and the Vector-namespace timestamp meaning)
    and renders microseconds — previously the RFC 3339 flatten truncated
    to milliseconds and only the literal `timestamp` key was recognized;
    string timestamps still fall back to the flat-row alias parse
  - default hostname (`HOSTNAME` env / `/etc/hostname`) is key-charset
    sanitized before use as the staging `source` path segment; corrupted
    hostnames (non-ASCII, slashes) fall back to `collector` instead of
    producing malformed object keys
  - `ParquetSink::new` now enforces the key contract for direct crate
    consumers (sanitize-with-fallback): key-unsafe `source`/`sensor_id`
    fall through the resolution chain, key-unsafe or
    non-ASCII-alpha-leading `writer_name` falls back to `collector`, and a
    `staging_prefix` with empty or key-unsafe segments falls back to
    `uf/ocsf` — the Vector config layer still rejects these loudly at boot
- DLQ docs: `caver_staging` DLQ rows are post-preparation (string-typed
  `_time`, injected defaults) while `native` rows are the raw maps —
  replay tooling must handle both shapes

### Added
- CI now runs the wrapper sink unit tests (`sinks::caver_parquet` in the
  root vector workspace) in the vector-component job — previously only
  build + registration + config-validate were exercised there
- typed-column coverage for the remaining contract columns: `type_uid`
  (Int64) and `metric_value` (Float64) round-trip + missing-value defaults

## [0.11.0] - 2026-06-12

### Fixed
- **Contract-fidelity follow-ups from the #897 adversarial review**
  (caver-collector#900) — eight divergences from the Python collector
  transforms pinned byte-for-byte, each with a regression test:
  - winevent: Security EventID table is now Security-channel-gated
    (provider contains "security" OR channel is Security); other channels
    classify coarse (1007, 1) like `_winevent_refine`
  - winevent: EventID lookup is a truthiness or-chain (`EventID` 0 falls
    through to `event_id`) with strict-int parse (float EventID → coarse)
  - suricata: `event_type` gate is Python-truthiness (numeric 5 classifies,
    0 does not); `suri_event_type` rendered via `str()` semantics
  - classify passthrough: a pre-set truthy `class_uid` is a no-op;
    `class_uid: 0` does NOT suppress classification
  - fortinet: severity lookups are truthiness chains — `crseverity: 0`
    falls through to `severity` (no more High → default downgrade)
  - zeek files: `total_bytes`-or-`size` chain matches Python (`size: 0`
    still emits `file.size: 0`)
  - `value_to_string` renders like Python `str()`: `True`/`False`/`None`,
    containers via repr punctuation (`[1, 'a']`, `{'k': 'v'}`)
  - `parse_ymd_hms`/`parse_clf` clamp the year to 1970..=9999 so a forged
    timestamp can't spin `days_from_epoch` ~10^10 iterations
- `normalise_zeek_json` no longer fabricates `src_ip: ""`/`src_port: 0` —
  connection-tuple keys are omitted when absent from the input
- golden tests: hand-listed per-fixture snapshot tests replaced by a
  directory-derived suite (new fixtures are covered automatically)

## [0.10.0] - 2026-06-12

### Added
- **Vendor classify/normalize registry mirroring the Python collector
  transforms** (caver-collector#897): `ocsf::normalize()` now routes on a
  `_vendor` tag and ports the exact contract of the caver-collector Python
  `transforms/` for suricata, zeek, palo_alto, and fortinet (flat OCSF
  output: class/severity/type_uid tables, truthiness gates, raw-passthrough
  port semantics, `or`-chain field fallbacks)
  - Parsers (`parse_suricata_eve`, `normalise_zeek_json`, `parse_zeek_tsv`,
    `parse_winevent`, `parse_sysmon`) stamp `_vendor` so parsed events route
    without a separate hint; the tag is dropped from normalized output
  - `classify()` covers the full `ocsf_classify.py` tables: sysmon EventID →
    class map, Windows Security EventID map, okta, nginx, suricata, zeek
    (path/stream + content heuristics), PAN-OS and FortiGate type detection
  - winevent and non-EID-1 sysmon events pass through with classification
    only, matching the Python collector (no normalizer exists upstream)
  - Golden fixtures are now vendor-keyed (`<vendor>_<scenario>/`); the 7 new
    fixture snapshots were **generated by the Python transforms themselves**,
    so the suite proves Rust↔Python contract parity by construction

## [0.9.0] - 2026-06-12

### Added
- **`caver_parquet` writes the caver_staging PARQUET-CONTRACT by default**
  (caver-collector#896, contract: RES-splunk-caver#1800): collector output is
  now served by the Caver lake out of the box, matching the Python sink's
  default (caver-collector#843)
  - New `layout` config: `caver_staging` (default) | `native` (the original
    `<class_uid>/dt=` all-string layout, for non-Caver consumers only)
  - Staging keys: `<staging_prefix>/<source>/year=YYYY/month=MM/day=DD/`
    `<writer_name>_YYYYMMDD_HHMMSS_<id8>.parquet`, partitioned by the first
    row's event time; new `source` (default: `sensor_id` → `collector`),
    `writer_name` (default `collector`), `staging_prefix` (default `uf/ocsf`)
    config fields, all charset-validated in `build()`
  - Typed columns per the contract: `_time`/`metric_value` Float64,
    `class_uid`/`category_uid`/`severity_id`/`activity_id`/`status_id`/
    `type_uid` Int64 (`int(float(v))` truncation, unparseable → 0), everything
    else Utf8 with missing values as `""` (not null); alphabetically sorted
    column union; zstd compression
  - Row prep parity with the Python sink: `_time` defaults to now,
    `index` → `main`, `class_uid` empty-or-missing → `0`, required string
    columns (`class_name`, `host`, `source`, `sourcetype`, `_raw`) → `""`
  - Vector log conventions aliased onto the contract at the wrapper layer
    (staging only, never clobbering explicit values): `timestamp` (RFC 3339)
    → `_time` (epoch seconds), `message` → `_raw`

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
