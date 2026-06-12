# Caver Collector (Rust)

This fork builds the **Caver collector** — a lean, Rust log/security-data collector on a
Vector base. Product name is "Caver collector"; `vector-caver` is just this repo's name.

Full engineering reference (architecture, ecosystem, current state) lives in the
RES-splunk-caver wiki: **Caver-Collector-Rust-Rebuild**. This doc is the build/run quickref.

## Design: lean collector + apps

Ships lean (core + sources + OCSF VRL framework + core caver sinks). Vendor-specific OCSF
normalizers are **apps** added on demand (Splunk-UF model) — not baked into the default
package. The 163 Python vendor normalizers become apps over time (`caver-collector#890` re-scope),
distributed via the deployment server (`caver-collector#844` / `RES-splunk-caver#2317`) and
catalogued in the App Store (`RES-splunk-caver#3134`). None of that is required to ship the collector.

## Layout

- `caver/` — a **separate Cargo workspace** (root `Cargo.toml` has `exclude = ["caver"]`),
  CI'd by `.github/workflows/caver-ci.yml` (fmt + clippy-deny + `cargo test --workspace`).
  Crates: `caver-sink-parquet`, `caver-sink-search-peer`, `caver-source-uf-compat`,
  `caver-ottl-funcs`, `caver-ops`, `vrl-caver-stdlib`.
- caver components plug into the runnable `vector` binary via **optional deps + Cargo features**
  in the root `Cargo.toml` (e.g. `sinks-caver_parquet = ["dep:caver-sink-parquet"]`,
  registered in `src/sinks/mod.rs`).

## Build

Prereqs: Rust (rustup stable), `protoc`, `cmake`, a C compiler.

```bash
cargo build --release --bin vector --no-default-features \
  --features "sources-host_metrics,sources-exec,sources-file,sources-internal_metrics,\
transforms-remap,sinks-caver_parquet,sinks-console"
```
Heavy (~600+ crates). On RAM-constrained boxes:
`CARGO_BUILD_JOBS=4 CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16`.

## Send config (the `caver_parquet` sink)

Open Parquet → S3/MinIO lake in `caver_staging` layout (no Splunk HEC needed):

```yaml
sinks:
  lake:
    type: caver_parquet
    inputs: ["shape"]
    bucket: "splunk-events"
    sensor_id: "macos_133"      # drives the staging path segment uf/ocsf/<sensor_id>/...
    source: "macos_133"
    endpoint: "http://<minio-host>:9000"   # omit for AWS s3.<region>.amazonaws.com
    region: "us-east-1"
    access_key_env: "LAKE_ACCESS_KEY"       # creds read from NAMED env vars
    secret_key_env: "LAKE_SECRET_KEY"
```
`sensor_id` (not `source`) sets the path segment. The sink maps the event `timestamp`
field → `_time`; defaults `_time`→now, `_raw`→"".

## Known gap: OCSF normalization not wired in (`caver-collector#906`)

`vrl-caver-stdlib` is **plain Rust** (depends only on `serde_json`; no `vrl::compiler::Function`
impls), so its `ocsf::classify`/`ocsf::normalize` helpers can't be called from a `remap` yet, and
the runnable binary excludes the `caver/` workspace. The collector therefore ships
contract-correct parquet but with `class_uid = 0` (no classification) and isn't surfaced in
caver search. Fix = write VRL `Function` wrappers + aggregate `vrl_caver_stdlib::vrl_functions()`
+ wire into `lib/vector-vrl/functions` behind a `caver` feature + ship a default base-normalize
`remap`. Mirror `lib/vector-vrl/dnstap-parser`.
