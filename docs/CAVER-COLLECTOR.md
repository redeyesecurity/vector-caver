# Caver Collector (Rust)

This fork builds the **Caver collector** — a lean, Rust log/security-data collector on a
Vector base. Product name is "Caver collector"; `vector-caver` is just this repo's name.

Full engineering reference (architecture, ecosystem, current state) lives in the
RES-splunk-caver wiki: **Caver-Collector-Rust-Rebuild**. This doc is the build/run quickref.

## Design: lean collector + apps

Ships lean (core + sources + the OCSF VRL framework + core caver sinks). Vendor-specific OCSF
normalizers are **apps** added on demand (Splunk-UF model) — not baked into the default
package. The Python collector's vendor normalizers become apps over time (`caver-collector#890`),
distributed via the deployment server (`caver-collector#844` / `RES-splunk-caver#2317`) and
catalogued in the App Store (`RES-splunk-caver#3134`). None of that is required to ship the collector.

## Layout

- `caver/` — a **separate Cargo workspace** (root `Cargo.toml` has `exclude = ["caver"]`),
  CI'd by `.github/workflows/caver-ci.yml`. Domain crates (pure logic): `vrl-caver-stdlib`,
  `caver-sink-parquet`, `caver-sink-search-peer`, `caver-source-uf-compat`, `caver-ottl-funcs`,
  `caver-ops`.
- `lib/vector-vrl/caver-stdlib` — the **adapter crate** (`vector-vrl-caver-stdlib`) that wraps
  the pure `vrl-caver-stdlib` helpers in `vrl::compiler::Function` impls and registers them at
  `vector_vrl_functions::all()`. Sinks plug in via optional deps + features in the root
  `Cargo.toml` (e.g. `sinks-caver_parquet`).

## OCSF normalization — default-on (`caver-collector#904`)

The OCSF VRL framework is **registered by default in the shipped binary — no feature flag**.
A `remap`, VRL condition, or the `vector vrl` REPL can call: `ocsf_classify`, `ocsf_normalize`,
`parse_suricata_eve`, `parse_zeek`, `parse_winevent`, `parse_sysmon`, `caver_entity_id`,
`redact_pii`, `is_internal_ip`, `attack_tactic_lookup`. The functions are **infallible** (total
VRL→JSON conversion; parse failures return `{"error": ...}`) — so do **not** wrap them in
`?? default` (VRL rejects coalescing an infallible call). Interface-only stubs
(`cve_enrich`, `geoip_caver`, `asn_lookup`, `threat_indicator_match`, `attack_technique_match`,
`hash_imphash`, `dns_resolve_cached`) are deliberately not registered until their backends land.

See `config/examples/caver_lean_collector.yaml` for the out-of-the-box base-normalize pipeline
(`caver-collector#906`): vendor parse → `ocsf_classify` → `ocsf_normalize` (merged to root) →
staging contract fields → `caver_entity_id`/`is_internal_ip` enrichment → `caver_parquet`. A
source with no parser yet ships `class_uid = 0` but stays fully queryable by
index/source/sourcetype/host/`_time`.

## Build

Prereqs: Rust (rustup stable), `protoc`, `cmake`, a C compiler.

```bash
cargo build --release --bin vector --no-default-features \
  --features "sources-host_metrics,sources-exec,sources-file,sources-internal_metrics,\
transforms-remap,sinks-caver_parquet,sinks-console"
```
The OCSF functions are default-on, so **no `caver` feature flag is needed**. Heavy (~600+
crates). On RAM-constrained boxes: `CARGO_BUILD_JOBS=4 CARGO_PROFILE_RELEASE_LTO=false`.

> Gotcha: building different `--features` sets back-to-back in the **same `target/` dir** can
> incrementally miscompile the binary (observed: a startup `SIGILL` in `init_logging`). If a
> fresh binary crashes at startup, `cargo clean --release -p vector -p vector-vrl-functions`
> and rebuild. On macOS, ad-hoc re-sign after copying (`codesign --force --sign - <bin>`) or
> launchd kills it with `OS_REASON_CODESIGNING`.

## Send config (the `caver_parquet` sink)

Open Parquet → S3/MinIO lake in `caver_staging` layout (no Splunk HEC needed):

```yaml
sinks:
  lake:
    type: caver_parquet
    inputs: ["base_normalize"]
    bucket: "splunk-events"
    sensor_id: "edge-01"        # drives the staging path segment uf/ocsf/<sensor_id>/...
    source: "edge-01"
    endpoint: "http://<minio-host>:9000"   # omit for AWS s3.<region>.amazonaws.com
    region: "us-east-1"
    access_key_env: "LAKE_ACCESS_KEY"       # creds read from NAMED env vars
    secret_key_env: "LAKE_SECRET_KEY"
```
`sensor_id` (not `source`) sets the path segment. The sink maps the event `timestamp`
field → `_time`; defaults `_time`→now, `_raw`→"", `index`→`main`.
