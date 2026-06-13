//! Threat-intel enrichment (`vrl_caver_stdlib::threat_intel`).
//!
//! Only the *implemented* functions are exposed. The crate's interface-only
//! stubs (`attack_technique_match`, `cve_enrich`, `threat_indicator_match`,
//! `geoip_caver`, `asn_lookup`) are deliberately NOT registered — a VRL
//! function that always returns an empty value would be a silent lie in a
//! detection pipeline. They get registered when their backends land.

use vrl::prelude::*;

use crate::conv::json_to_vrl;

// ---------------------------------------------------------------------------
// is_internal_ip
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct IsInternalIp;

impl Function for IsInternalIp {
    fn identifier(&self) -> &'static str {
        "is_internal_ip"
    }

    fn usage(&self) -> &'static str {
        "Returns true if the IP is in an RFC-1918 / RFC-4193 / RFC-6598 / loopback / link-local / documentation range. Unparseable input returns false."
    }

    fn category(&self) -> &'static str {
        "IP"
    }

    fn return_kind(&self) -> u16 {
        kind::BOOLEAN
    }

    fn parameters(&self) -> &'static [Parameter] {
        const PARAMETERS: &[Parameter] = &[Parameter::required(
            "value",
            kind::BYTES,
            "The IPv4 or IPv6 address string.",
        )];
        PARAMETERS
    }

    fn examples(&self) -> &'static [Example] {
        &[
            example! {
                title: "RFC-1918 address",
                source: r#"is_internal_ip("10.1.2.3")"#,
                result: Ok("true"),
            },
            example! {
                title: "Public address",
                source: r#"is_internal_ip("8.8.8.8")"#,
                result: Ok("false"),
            },
        ]
    }

    fn compile(
        &self,
        _state: &TypeState,
        _ctx: &mut FunctionCompileContext,
        arguments: ArgumentList,
    ) -> Compiled {
        let value = arguments.required("value");
        Ok(IsInternalIpFn { value }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct IsInternalIpFn {
    value: Box<dyn Expression>,
}

impl FunctionExpression for IsInternalIpFn {
    fn resolve(&self, ctx: &mut Context) -> Resolved {
        let value = self.value.resolve(ctx)?;
        let ip = value.try_bytes_utf8_lossy()?;
        Ok(Value::from(vrl_caver_stdlib::threat_intel::is_internal_ip(
            &ip,
        )))
    }

    fn type_def(&self, _: &TypeState) -> TypeDef {
        TypeDef::boolean().infallible()
    }
}

// ---------------------------------------------------------------------------
// attack_tactic_lookup
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct AttackTacticLookup;

impl Function for AttackTacticLookup {
    fn identifier(&self) -> &'static str {
        "attack_tactic_lookup"
    }

    fn usage(&self) -> &'static str {
        "Returns the primary MITRE ATT&CK tactic for a technique ID (sub-technique suffixes are stripped for lookup), or null if unknown."
    }

    fn category(&self) -> &'static str {
        "Enrichment"
    }

    fn return_kind(&self) -> u16 {
        kind::OBJECT | kind::NULL
    }

    fn parameters(&self) -> &'static [Parameter] {
        const PARAMETERS: &[Parameter] = &[Parameter::required(
            "value",
            kind::BYTES,
            "The ATT&CK technique ID (e.g. `T1059` or `T1059.001`).",
        )];
        PARAMETERS
    }

    fn examples(&self) -> &'static [Example] {
        &[
            example! {
                title: "Look up a technique's tactic",
                source: r#"attack_tactic_lookup("T1059.001")"#,
                result: Ok(r#"{"tactic_id": "TA0002", "tactic_name": "Execution", "technique_id": "T1059.001"}"#),
            },
            example! {
                title: "Unknown techniques return null",
                source: r#"attack_tactic_lookup("T9999")"#,
                result: Ok("null"),
            },
        ]
    }

    fn compile(
        &self,
        _state: &TypeState,
        _ctx: &mut FunctionCompileContext,
        arguments: ArgumentList,
    ) -> Compiled {
        let value = arguments.required("value");
        Ok(AttackTacticLookupFn { value }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct AttackTacticLookupFn {
    value: Box<dyn Expression>,
}

impl FunctionExpression for AttackTacticLookupFn {
    fn resolve(&self, ctx: &mut Context) -> Resolved {
        let value = self.value.resolve(ctx)?;
        let technique_id = value.try_bytes_utf8_lossy()?;
        Ok(json_to_vrl(
            vrl_caver_stdlib::threat_intel::attack_tactic_lookup(&technique_id),
        ))
    }

    fn type_def(&self, _: &TypeState) -> TypeDef {
        TypeDef::object(Collection::any()).add_null().infallible()
    }
}
