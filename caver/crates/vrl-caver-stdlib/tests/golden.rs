//! Golden-fixture tests for vrl-caver-stdlib OCSF normalization.
//!
//! Two test suites:
//!   golden_fixtures_are_valid — structural lint (all fixtures have required fields)
//!   golden_{class_uid} — snapshot tests that call normalize() and diff vs out.json
//!
//! Run with: cargo test --manifest-path caver/Cargo.toml

use std::path::PathBuf;
use vrl_caver_stdlib::ocsf;

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // crates/
        .unwrap()
        .parent() // caver/
        .unwrap()
        .join("tests/golden")
}

/// Parses the file at `path` as JSON and returns the parsed value.
/// Panics with a descriptive message on failure.
fn load_json(path: &PathBuf) -> serde_json::Value {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", path.display(), e));
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("invalid JSON in {}: {}", path.display(), e))
}

/// Required top-level OCSF fields in every out.json.
const REQUIRED_OUT_FIELDS: &[&str] = &[
    "class_uid",
    "category_uid",
    "activity_id",
    "time",
    "severity_id",
    "status_id",
    "metadata",
];

#[test]
fn golden_fixtures_are_valid() {
    let dir = golden_dir();
    assert!(
        dir.exists(),
        "golden fixture directory not found: {}",
        dir.display()
    );

    let mut checked = 0u32;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap();
        let class_dir = entry.path();
        if !class_dir.is_dir() {
            continue;
        }
        let class_uid = class_dir
            .file_name()
            .unwrap()
            .to_string_lossy()
            .parse::<u32>()
            .unwrap_or_else(|_| panic!("{} is not a numeric OCSF class_uid", class_dir.display()));

        let in_path = class_dir.join("in.json");
        let out_path = class_dir.join("out.json");

        assert!(
            in_path.exists(),
            "missing in.json for class_uid {class_uid}"
        );
        assert!(
            out_path.exists(),
            "missing out.json for class_uid {class_uid}"
        );

        load_json(&in_path);

        let out = load_json(&out_path);
        for field in REQUIRED_OUT_FIELDS {
            assert!(
                out.get(field).is_some(),
                "out.json for class_uid {class_uid} is missing required field \"{field}\""
            );
        }
        assert_eq!(
            out["class_uid"].as_u64(),
            Some(class_uid as u64),
            "out.json class_uid mismatch for directory {class_uid}"
        );

        checked += 1;
    }

    assert!(
        checked > 0,
        "no fixture directories found under {}",
        dir.display()
    );
    println!("golden: validated {checked} OCSF class fixture(s)");
}

// ---------------------------------------------------------------------------
// Snapshot tests — call normalize() and assert output matches out.json
// ---------------------------------------------------------------------------

fn run_normalize_snapshot(class_uid: u32) {
    let dir = golden_dir().join(class_uid.to_string());
    let in_val = load_json(&dir.join("in.json"));
    let expected = load_json(&dir.join("out.json"));
    let actual = ocsf::normalize(&in_val);
    assert_eq!(
        actual,
        expected,
        "normalize() mismatch for class_uid {class_uid}\n\
         actual:\n{}\n\
         expected:\n{}",
        serde_json::to_string_pretty(&actual).unwrap(),
        serde_json::to_string_pretty(&expected).unwrap(),
    );
}

#[test]
fn golden_4002_okta_authentication() {
    run_normalize_snapshot(4002);
}

#[test]
fn golden_3003_nginx_http_activity() {
    run_normalize_snapshot(3003);
}

#[test]
fn golden_5001_sysmon_process_activity() {
    run_normalize_snapshot(5001);
}
