//! Security log parsers (`vrl_caver_stdlib::parsers`).
//!
//! Each parser returns a structured object with `_vendor` set, ready to feed
//! `ocsf_classify` / `ocsf_normalize`. Parse failures return an
//! `{"error": ...}` object instead of failing the VRL program — these
//! functions are infallible by design, mirroring the Python collector
//! transform chain which never drops an event on a parse error.

use crate::conv::{json_to_vrl, vrl_to_json};
use vrl::prelude::*;

// ---------------------------------------------------------------------------
// parse_suricata_eve
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct ParseSuricataEve;

impl Function for ParseSuricataEve {
    fn identifier(&self) -> &'static str {
        "parse_suricata_eve"
    }

    fn usage(&self) -> &'static str {
        "Parses a Suricata EVE JSON line into a structured event object (`_vendor: suricata`). Invalid JSON returns an `{\"error\": ...}` object."
    }

    fn category(&self) -> &'static str {
        "Parse"
    }

    fn return_kind(&self) -> u16 {
        kind::OBJECT
    }

    fn parameters(&self) -> &'static [Parameter] {
        const PARAMETERS: &[Parameter] = &[Parameter::required(
            "value",
            kind::BYTES,
            "The raw EVE JSON line.",
        )];
        PARAMETERS
    }

    fn examples(&self) -> &'static [Example] {
        &[example! {
            title: "Parse an EVE flow record",
            source: r#"parse_suricata_eve(s'{"event_type": "flow", "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "proto": "TCP", "timestamp": "2026-06-12T00:00:00.000000+0000"}')"#,
            result: Ok(r#"{"_vendor": "suricata", "event_type": "flow"}"#),
            deterministic: false,
        }]
    }

    fn compile(
        &self,
        _state: &TypeState,
        _ctx: &mut FunctionCompileContext,
        arguments: ArgumentList,
    ) -> Compiled {
        let value = arguments.required("value");
        Ok(ParseSuricataEveFn { value }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct ParseSuricataEveFn {
    value: Box<dyn Expression>,
}

impl FunctionExpression for ParseSuricataEveFn {
    fn resolve(&self, ctx: &mut Context) -> Resolved {
        let value = self.value.resolve(ctx)?;
        let raw = value.try_bytes_utf8_lossy()?;
        Ok(json_to_vrl(vrl_caver_stdlib::parsers::parse_suricata_eve(
            &raw,
        )))
    }

    fn type_def(&self, _: &TypeState) -> TypeDef {
        TypeDef::object(Collection::any()).infallible()
    }
}

// ---------------------------------------------------------------------------
// parse_zeek
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct ParseZeek;

impl Function for ParseZeek {
    fn identifier(&self) -> &'static str {
        "parse_zeek"
    }

    fn usage(&self) -> &'static str {
        "Parses a Zeek log line (JSON, or TSV for conn/dns/http) into a structured event object (`_vendor: zeek`)."
    }

    fn category(&self) -> &'static str {
        "Parse"
    }

    fn return_kind(&self) -> u16 {
        kind::OBJECT
    }

    fn parameters(&self) -> &'static [Parameter] {
        const PARAMETERS: &[Parameter] = &[
            Parameter::required("value", kind::BYTES, "The raw Zeek log line."),
            Parameter::required(
                "log_type",
                kind::BYTES,
                "The Zeek log name (`conn`, `dns`, `http`, `files`, `ssl`, ...). Drives TSV column mapping; informational for JSON lines.",
            ),
        ];
        PARAMETERS
    }

    fn examples(&self) -> &'static [Example] {
        &[example! {
            title: "Parse a Zeek conn log JSON line",
            source: r#"parse_zeek(s'{"ts": 1718150400.0, "uid": "C1234", "proto": "tcp", "id.orig_h": "10.0.0.1"}', "conn")"#,
            result: Ok(r#"{"_vendor": "zeek", "log_type": "conn"}"#),
            deterministic: false,
        }]
    }

    fn compile(
        &self,
        _state: &TypeState,
        _ctx: &mut FunctionCompileContext,
        arguments: ArgumentList,
    ) -> Compiled {
        let value = arguments.required("value");
        let log_type = arguments.required("log_type");
        Ok(ParseZeekFn { value, log_type }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct ParseZeekFn {
    value: Box<dyn Expression>,
    log_type: Box<dyn Expression>,
}

impl FunctionExpression for ParseZeekFn {
    fn resolve(&self, ctx: &mut Context) -> Resolved {
        let value = self.value.resolve(ctx)?;
        let raw = value.try_bytes_utf8_lossy()?;
        let log_type = self.log_type.resolve(ctx)?;
        let log_type = log_type.try_bytes_utf8_lossy()?;
        Ok(json_to_vrl(vrl_caver_stdlib::parsers::parse_zeek(
            &raw, &log_type,
        )))
    }

    fn type_def(&self, _: &TypeState) -> TypeDef {
        TypeDef::object(Collection::any()).infallible()
    }
}

// ---------------------------------------------------------------------------
// parse_winevent
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct ParseWinevent;

impl Function for ParseWinevent {
    fn identifier(&self) -> &'static str {
        "parse_winevent"
    }

    fn usage(&self) -> &'static str {
        "Parses Windows Event Log XML into a structured event object (`_vendor: winevent`): System fields plus EventData key/value pairs."
    }

    fn category(&self) -> &'static str {
        "Parse"
    }

    fn return_kind(&self) -> u16 {
        kind::OBJECT
    }

    fn parameters(&self) -> &'static [Parameter] {
        const PARAMETERS: &[Parameter] = &[Parameter::required(
            "value",
            kind::BYTES,
            "The raw event XML.",
        )];
        PARAMETERS
    }

    fn examples(&self) -> &'static [Example] {
        &[example! {
            title: "Parse a Windows Security event",
            source: r#"parse_winevent(s'<Event><System><EventID>4624</EventID><Computer>HOST01</Computer></System></Event>')"#,
            result: Ok(r#"{"_vendor": "winevent", "event_id": 4624, "computer": "HOST01"}"#),
            deterministic: false,
        }]
    }

    fn compile(
        &self,
        _state: &TypeState,
        _ctx: &mut FunctionCompileContext,
        arguments: ArgumentList,
    ) -> Compiled {
        let value = arguments.required("value");
        Ok(ParseWineventFn { value }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct ParseWineventFn {
    value: Box<dyn Expression>,
}

impl FunctionExpression for ParseWineventFn {
    fn resolve(&self, ctx: &mut Context) -> Resolved {
        let value = self.value.resolve(ctx)?;
        let raw = value.try_bytes_utf8_lossy()?;
        Ok(json_to_vrl(vrl_caver_stdlib::parsers::parse_winevent(&raw)))
    }

    fn type_def(&self, _: &TypeState) -> TypeDef {
        TypeDef::object(Collection::any()).infallible()
    }
}

// ---------------------------------------------------------------------------
// parse_sysmon
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct ParseSysmon;

impl Function for ParseSysmon {
    fn identifier(&self) -> &'static str {
        "parse_sysmon"
    }

    fn usage(&self) -> &'static str {
        "Restructures a parsed Sysmon event object (e.g. `parse_winevent` output) into the bridge shape (`_vendor: sysmon`, fields nested under `process`/`parent_process`)."
    }

    fn category(&self) -> &'static str {
        "Parse"
    }

    fn return_kind(&self) -> u16 {
        kind::OBJECT
    }

    fn parameters(&self) -> &'static [Parameter] {
        const PARAMETERS: &[Parameter] = &[Parameter::required(
            "value",
            kind::OBJECT,
            "The Sysmon event object.",
        )];
        PARAMETERS
    }

    fn examples(&self) -> &'static [Example] {
        &[example! {
            title: "Restructure a Sysmon process-create event",
            source: r#"parse_sysmon({"event_id": 1, "Image": "C:\\Windows\\System32\\cmd.exe"})"#,
            result: Ok(r#"{"_vendor": "sysmon", "event_id": 1}"#),
            deterministic: false,
        }]
    }

    fn compile(
        &self,
        _state: &TypeState,
        _ctx: &mut FunctionCompileContext,
        arguments: ArgumentList,
    ) -> Compiled {
        let value = arguments.required("value");
        Ok(ParseSysmonFn { value }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct ParseSysmonFn {
    value: Box<dyn Expression>,
}

impl FunctionExpression for ParseSysmonFn {
    fn resolve(&self, ctx: &mut Context) -> Resolved {
        let value = self.value.resolve(ctx)?;
        Ok(json_to_vrl(vrl_caver_stdlib::parsers::parse_sysmon(
            &vrl_to_json(&value),
        )))
    }

    fn type_def(&self, _: &TypeState) -> TypeDef {
        TypeDef::object(Collection::any()).infallible()
    }
}

// ---------------------------------------------------------------------------
// caver_entity_id
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct CaverEntityId;

impl Function for CaverEntityId {
    fn identifier(&self) -> &'static str {
        "caver_entity_id"
    }

    fn usage(&self) -> &'static str {
        "Returns a stable 16-hex-char FNV-1a entity identifier from the kind-relevant fields of an object. Unknown kinds hash all fields."
    }

    fn category(&self) -> &'static str {
        "Enrichment"
    }

    fn return_kind(&self) -> u16 {
        kind::BYTES
    }

    fn parameters(&self) -> &'static [Parameter] {
        const PARAMETERS: &[Parameter] = &[
            Parameter::required(
                "value",
                kind::OBJECT,
                "The object holding the entity's fields.",
            ),
            Parameter::required(
                "kind",
                kind::BYTES,
                "The entity kind: `host`, `user`, `file`, or `process` (selects which fields matter).",
            ),
        ];
        PARAMETERS
    }

    fn examples(&self) -> &'static [Example] {
        &[example! {
            title: "Stable host identity",
            source: r#"caver_entity_id({"hostname": "web01"}, "host")"#,
            result: Ok("693947118b3e34c5"),
        }]
    }

    fn compile(
        &self,
        _state: &TypeState,
        _ctx: &mut FunctionCompileContext,
        arguments: ArgumentList,
    ) -> Compiled {
        let value = arguments.required("value");
        let kind = arguments.required("kind");
        Ok(CaverEntityIdFn { value, kind }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct CaverEntityIdFn {
    value: Box<dyn Expression>,
    kind: Box<dyn Expression>,
}

impl FunctionExpression for CaverEntityIdFn {
    fn resolve(&self, ctx: &mut Context) -> Resolved {
        let value = self.value.resolve(ctx)?;
        let kind = self.kind.resolve(ctx)?;
        let kind = kind.try_bytes_utf8_lossy()?;
        Ok(Value::from(vrl_caver_stdlib::parsers::entity_id(
            &vrl_to_json(&value),
            &kind,
        )))
    }

    fn type_def(&self, _: &TypeState) -> TypeDef {
        TypeDef::bytes().infallible()
    }
}

// ---------------------------------------------------------------------------
// redact_pii
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct RedactPii;

impl Function for RedactPii {
    fn identifier(&self) -> &'static str {
        "redact_pii"
    }

    fn usage(&self) -> &'static str {
        "Redacts PII (emails, SSNs, phone numbers) from all string values, recursing into objects and arrays. Unknown profiles redact nothing."
    }

    fn category(&self) -> &'static str {
        "Enrichment"
    }

    fn return_kind(&self) -> u16 {
        kind::ANY
    }

    fn parameters(&self) -> &'static [Parameter] {
        const PARAMETERS: &[Parameter] = &[
            Parameter::required(
                "value",
                kind::ANY,
                "The value to redact (recurses into objects and arrays).",
            ),
            Parameter::required(
                "profile",
                kind::BYTES,
                "What to redact: `email`, `ssn`, `phone`, or `all`.",
            ),
        ];
        PARAMETERS
    }

    fn examples(&self) -> &'static [Example] {
        &[example! {
            title: "Redact emails",
            source: r#"redact_pii({"msg": "contact bob@example.com"}, "email")"#,
            result: Ok(r#"{"msg": "contact [REDACTED-EMAIL]"}"#),
        }]
    }

    fn compile(
        &self,
        _state: &TypeState,
        _ctx: &mut FunctionCompileContext,
        arguments: ArgumentList,
    ) -> Compiled {
        let value = arguments.required("value");
        let profile = arguments.required("profile");
        Ok(RedactPiiFn { value, profile }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct RedactPiiFn {
    value: Box<dyn Expression>,
    profile: Box<dyn Expression>,
}

impl FunctionExpression for RedactPiiFn {
    fn resolve(&self, ctx: &mut Context) -> Resolved {
        let value = self.value.resolve(ctx)?;
        let profile = self.profile.resolve(ctx)?;
        let profile = profile.try_bytes_utf8_lossy()?;
        Ok(json_to_vrl(vrl_caver_stdlib::parsers::redact_pii(
            &vrl_to_json(&value),
            &profile,
        )))
    }

    fn type_def(&self, _: &TypeState) -> TypeDef {
        TypeDef::any().infallible()
    }
}
