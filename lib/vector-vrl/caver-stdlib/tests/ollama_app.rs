//! The Ollama app's collector payload (caver/apps/ollama/collector/ollama.yaml,
//! CAVER-3555). Both remap programs are read out of the shipped YAML, so this
//! tests the config a node runs, not a copy of it.
//!
//! The server-log lines are the ones caver-collector#2389 captured from the
//! live log on 192.168.1.188 (2026-11-04), and the row shape is that closed
//! Python transform's. The API bodies in fixtures/ollama were fetched from the
//! same server's /api/ps and /api/tags (Ollama 0.40.11, 2026-11-09).

use vrl::compiler::runtime::{Runtime, Terminate};
use vrl::compiler::{TargetValue, compile};
use vrl::prelude::TimeZone;
use vrl::value;
use vrl::value::{Secrets, Value};

const APP: &str = include_str!("../../../../caver/apps/ollama/collector/ollama.yaml");

/// The `source` of a transform in the app YAML, with the environment
/// variables Vector interpolates at load resolved the way it would.
fn program(transform: &str, dest: &str) -> String {
    let doc: serde_yaml::Value = serde_yaml::from_str(APP).expect("app yaml parses");
    let src = doc["transforms"][transform]["source"]
        .as_str()
        .unwrap_or_else(|| panic!("transform {transform} has a source"))
        .to_string();
    let src = src
        .replace("${CAVER_OLLAMA_DEST:-}", dest)
        .replace("${HOSTNAME}", "ollama-host")
        .replace(
            "${CAVER_OLLAMA_URL:-http://127.0.0.1:11434}",
            "http://127.0.0.1:11434",
        );
    // Anything else `${...}` or `$word` would be interpolated (or refused) by
    // Vector and never reach VRL as written.
    for (i, _) in src.match_indices('$') {
        let next = src[i + 1..].chars().next();
        assert!(
            !matches!(next, Some(c) if c == '{' || c == '$' || c.is_alphanumeric() || c == '_'),
            "{transform}: uninterpolated `$` at byte {i}"
        );
    }
    src
}

/// Run a transform on one event. `None` when the program aborts (the remap
/// has `drop_on_abort: true`, so that event is dropped).
// vector_vrl_functions::all() depends on this crate, so the tests assemble the
// same set (Caver functions plus the VRL stdlib) here.
#[allow(clippy::disallowed_methods)]
fn run(transform: &str, dest: &str, event: Value) -> Option<Value> {
    let mut functions = vector_vrl_caver_stdlib::all();
    functions.extend(vrl::stdlib::all());
    let source = program(transform, dest);
    let program = match compile(&source, &functions) {
        Ok(result) => result.program,
        Err(diagnostics) => panic!(
            "{transform} must compile:\n{}",
            vrl::diagnostic::Formatter::new(&source, diagnostics)
        ),
    };
    let mut target = TargetValue {
        value: event,
        metadata: value!({}),
        secrets: Secrets::default(),
    };
    match Runtime::default().resolve(&mut target, &program, &TimeZone::default()) {
        Ok(_) => Some(target.value),
        Err(Terminate::Abort(_)) => None,
        Err(err) => panic!("{transform} failed at runtime: {err}"),
    }
}

fn log_line(line: &str) -> Value {
    value!({"message": line, "host": "file-source-host", "timestamp": "2026-11-04T15:51:46Z"})
}

fn server_log(line: &str) -> Option<Value> {
    run("ollama_server_log", "", log_line(line))
}

fn get<'a>(v: &'a Value, path: &str) -> &'a Value {
    let mut cur = v;
    for key in path.split('.') {
        cur = cur
            .as_object()
            .and_then(|o| o.get(key))
            .unwrap_or_else(|| panic!("no {path} in {v:?}"));
    }
    cur
}

const GIN: &str =
    r#"[GIN] 2026/11/04 - 09:51:46 | 200 |  442.584µs |    192.168.1.18 | GET      "/api/ps""#;
const GIN_CHAT: &str =
    r#"[GIN] 2026/11/04 - 10:02:11 | 500 |  2m3s |    192.168.1.30 | POST     "/api/chat""#;
const GIN_GEN: &str =
    r#"[GIN] 2026/11/04 - 10:02:11 | 200 | 12.5s |    192.168.1.30 | POST     "/api/generate""#;
const LOAD: &str = concat!(
    "time=2026-10-28T23:04:31.027-05:00 level=INFO source=llama_server.go:1088 ",
    r#"msg="loading model via llama-server" model=/Users/mattt/.ollama/models/blobs/"#,
    "sha256-13576eb6dd8d9d04b4da04d015ff343968628d3c2984195569d9d3585651d4f1"
);
const FTYPE: &str = "print_info: file type   = Q4_K - Medium";

#[test]
fn request_line_is_http_activity_with_the_dashboard_fields() {
    let out = run("ollama_server_log", "MacBook-Air", log_line(GIN)).expect("kept");
    assert_eq!(get(&out, "class_uid"), &value!(4002));
    assert_eq!(get(&out, "src_ip"), &value!("192.168.1.18"));
    assert_eq!(get(&out, "dest"), &value!("MacBook-Air"));
    assert_eq!(get(&out, "dest_port"), &value!(11434));
    assert_eq!(get(&out, "http_method"), &value!("GET"));
    assert_eq!(get(&out, "url_path"), &value!("/api/ps"));
    assert_eq!(get(&out, "http_status"), &value!(200));
    assert_eq!(get(&out, "latency_ms"), &value!(0.443));
    assert_eq!(get(&out, "operation"), &value!("api"));
    assert_eq!(get(&out, "status_id"), &value!(1));
    assert_eq!(get(&out, "src_endpoint.ip"), &value!("192.168.1.18"));
    assert_eq!(get(&out, "dst_endpoint.port"), &value!(11434));
    assert_eq!(get(&out, "http_response.code"), &value!(200));
    assert_eq!(get(&out, "metadata.product.name"), &value!("Ollama"));
    assert_eq!(get(&out, "app.name"), &value!("ollama"));
    assert_eq!(get(&out, "index"), &value!("on_prem_inference"));
    assert_eq!(get(&out, "sourcetype"), &value!("ollama:server"));
    // The raw line and the read time ride through to _raw and _time.
    assert_eq!(get(&out, "message"), &value!(GIN));
    assert_eq!(get(&out, "timestamp"), &value!("2026-11-04T15:51:46Z"));
}

#[test]
fn inference_paths_and_go_duration_units() {
    let g = server_log(GIN_GEN).expect("kept");
    assert_eq!(get(&g, "operation"), &value!("inference"));
    assert_eq!(get(&g, "latency_ms"), &value!(12500.0));
    let c = server_log(GIN_CHAT).expect("kept");
    assert_eq!(get(&c, "operation"), &value!("inference"));
    assert_eq!(get(&c, "latency_ms"), &value!(123000.0));
    assert_eq!(get(&c, "http_status"), &value!(500));
    assert_eq!(get(&c, "status_id"), &value!(2));

    let pull = server_log(
        r#"[GIN] 2026/11/04 - 10:02:11 | 200 |  1h2m |  127.0.0.1 | POST     "/api/pull""#,
    )
    .expect("kept");
    assert_eq!(get(&pull, "operation"), &value!("pull"));
    assert_eq!(get(&pull, "latency_ms"), &value!(3720000.0));
    let ns = server_log(r#"[GIN] 2026/11/04 - 10:02:11 | 200 |  850ns |  127.0.0.1 | POST     "/v1/chat/completions?x=1""#)
        .expect("kept");
    assert_eq!(get(&ns, "operation"), &value!("inference"));
    assert_eq!(get(&ns, "url_path"), &value!("/v1/chat/completions?x=1"));
    assert_eq!(get(&ns, "latency_ms"), &value!(0.001));
}

#[test]
fn load_request_carries_the_blob_digest() {
    let out = server_log(LOAD).expect("kept");
    assert_eq!(get(&out, "class_uid"), &value!(6005));
    assert_eq!(get(&out, "operation"), &value!("load_request"));
    assert_eq!(
        get(&out, "model_digest"),
        &value!("13576eb6dd8d9d04b4da04d015ff343968628d3c2984195569d9d3585651d4f1")
    );
}

#[test]
fn file_type_line_is_the_load_model_event() {
    let out = server_log(FTYPE).expect("kept");
    assert_eq!(get(&out, "operation"), &value!("load_model"));
    assert_eq!(get(&out, "quantisation"), &value!("q4_k_m"));
    assert_eq!(get(&out, "quantisation_raw"), &value!("Q4_K - Medium"));
}

#[test]
fn quantisation_spellings_match_the_dashboard() {
    let cases = [
        ("F16", "fp16"),
        ("F32", "fp32"),
        ("all F32", "fp32"),
        ("mostly F16", "fp16"),
        ("BF16", "bf16"),
        ("Q8_0", "q8_0"),
        ("Q4_K - Small", "q4_k_s"),
        ("MXFP4 MoE", "mxfp4_moe"),
        // what llama-server prints for gpt-oss:20b on .188
        ("unknown, may not work", "unknown"),
    ];
    for (raw, want) in cases {
        let out = server_log(&format!("print_info: file type   = {raw}")).expect("kept");
        assert_eq!(get(&out, "quantisation"), &value!(want), "{raw}");
    }
}

#[test]
fn chatter_is_dropped() {
    for line in [
        r#"time=... level=INFO msg="waiting for llama-server to become available""#,
        "ggml_metal_library_compile_all: loaded 36 libraries",
        "print_info: model type            = 12B",
        "",
        "   ",
    ] {
        assert_eq!(server_log(line), None, "{line:?}");
    }
    assert_eq!(run("ollama_server_log", "", value!({"foo": "bar"})), None);
}

#[test]
fn dest_defaults_to_this_host() {
    let out = server_log(GIN).expect("kept");
    assert_eq!(get(&out, "dest"), &value!("ollama-host"));
}

fn api_body(fixture: &str) -> Value {
    let json: serde_json::Value = serde_json::from_str(fixture).expect("fixture is json");
    let mut body = Value::from(json);
    match &mut body {
        Value::Object(o) => {
            o.insert("timestamp".into(), value!("2026-11-09T20:26:01Z"));
        }
        other => panic!("fixture is an object: {other:?}"),
    }
    body
}

fn api_rows(fixture: &str) -> Vec<Value> {
    match run("ollama_api", "", api_body(fixture)).expect("kept") {
        Value::Array(rows) => rows,
        other => panic!("ollama_api emits an array of events: {other:?}"),
    }
}

#[test]
fn api_ps_is_one_running_row_per_loaded_model() {
    let rows = api_rows(include_str!("fixtures/ollama/api_ps.json"));
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!(get(r, "operation"), &value!("model_running"));
    assert_eq!(get(r, "ollama_event_type"), &value!("heartbeat"));
    assert_eq!(get(r, "class_uid"), &value!(6005));
    assert_eq!(get(r, "model_name"), &value!("gpt-oss-low:20b"));
    assert_eq!(get(r, "ollama_model_size"), &value!(12843441191_i64));
    assert_eq!(get(r, "ollama_size_vram"), &value!(12843441191_i64));
    assert_eq!(get(r, "ollama_family"), &value!("gpt-oss"));
    assert_eq!(get(r, "ollama_param_size"), &value!("20.9B"));
    assert_eq!(get(r, "ollama_quant"), &value!("unknown"));
    assert_eq!(
        get(r, "ollama_server_url"),
        &value!("http://127.0.0.1:11434")
    );
    assert_eq!(get(r, "dest"), &value!("ollama-host"));
    assert_eq!(get(r, "index"), &value!("on_prem_inference"));
    assert_eq!(get(r, "sourcetype"), &value!("ollama:model"));
    assert_eq!(get(r, "timestamp"), &value!("2026-11-09T20:26:01Z"));
    assert_eq!(get(r, "metadata.product.vendor_name"), &value!("Ollama"));
}

#[test]
fn api_tags_is_one_available_row_per_model_on_disk() {
    let rows = api_rows(include_str!("fixtures/ollama/api_tags.json"));
    let names: Vec<&Value> = rows.iter().map(|r| get(r, "model_name")).collect();
    assert_eq!(names, [&value!("qwen3-coder:30b"), &value!("dolphin3:8b")]);
    let r = &rows[0];
    assert_eq!(get(r, "operation"), &value!("model_available"));
    assert_eq!(get(r, "ollama_event_type"), &value!("available"));
    assert_eq!(get(r, "ollama_size_vram"), &value!(0));
    assert_eq!(get(r, "ollama_quant"), &value!("Q4_K_M"));
    assert_eq!(
        get(r, "ollama_model_digest"),
        &value!("06c1097efce0431c2045fe7b2e5108366e43bee1b4603a7aded8f21689e90bca")
    );
}

#[test]
fn api_empty_or_unnamed_models_emit_nothing() {
    assert_eq!(api_rows(r#"{"models":[]}"#), Vec::<Value>::new());
    assert_eq!(api_rows(r#"{"models":[{"size":1}]}"#), Vec::<Value>::new());
    assert_eq!(api_rows(r#"{"error":"boom"}"#), Vec::<Value>::new());
}
