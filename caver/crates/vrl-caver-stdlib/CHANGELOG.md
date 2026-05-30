# Changelog — vrl-caver-stdlib

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
  (1748426400000 → 1779962400000)

## [0.1.0] — initial scaffold

- Workspace scaffold; `lib.rs` stub only
