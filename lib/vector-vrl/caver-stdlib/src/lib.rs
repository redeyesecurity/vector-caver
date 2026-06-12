//! VRL bindings for `vrl-caver-stdlib` (caver-collector#904).
//!
//! The domain logic lives in `caver/crates/vrl-caver-stdlib` — a pure
//! serde_json crate (no vrl dependency) shared with non-Vector consumers.
//! This crate is the Vector-side adapter: it wraps those functions in
//! `vrl::compiler::Function` impls so they resolve from `remap` transforms,
//! VRL conditions, and the `vector vrl` REPL.
//!
//! Registered unconditionally via `vector-vrl-functions` — the OCSF VRL
//! *framework* ships in the default lean binary (caver-collector#890 scope);
//! per-vendor normalizer *apps* (deployment-server content) do not live here.
//!
//! Layering note: the adapter must live in the root workspace, not in
//! `caver/`, because `Box<dyn vrl::compiler::Function>` only unifies when the
//! adapter and the binary compile against the exact same `vrl` crate — root
//! pins vrl by git branch, and the excluded `caver/` workspace resolving its
//! own copy would produce incompatible trait objects.

#![deny(warnings)]

mod conv;
mod ocsf;
mod parsers;
mod threat_intel;

use vrl::compiler::Function;

/// All Caver VRL functions.
pub fn all() -> Vec<Box<dyn Function>> {
    vec![
        Box::new(ocsf::OcsfClassify) as _,
        Box::new(ocsf::OcsfNormalize) as _,
        Box::new(parsers::ParseSuricataEve) as _,
        Box::new(parsers::ParseZeek) as _,
        Box::new(parsers::ParseWinevent) as _,
        Box::new(parsers::ParseSysmon) as _,
        Box::new(parsers::CaverEntityId) as _,
        Box::new(parsers::RedactPii) as _,
        Box::new(threat_intel::IsInternalIp) as _,
        Box::new(threat_intel::AttackTacticLookup) as _,
    ]
}

#[cfg(test)]
mod tests {
    use vrl::compiler::runtime::Runtime;
    use vrl::compiler::{TargetValue, compile};
    use vrl::prelude::TimeZone;
    use vrl::value;
    use vrl::value::{Secrets, Value};

    /// Compile `source` against the Caver functions + the VRL stdlib (the
    /// same combination `vector_vrl_functions::all()` produces) and resolve
    /// it against an empty event.
    fn run(source: &str) -> Value {
        let mut functions = super::all();
        functions.extend(vrl::stdlib::all());
        let program = compile(source, &functions)
            .expect("program must compile")
            .program;
        let mut target = TargetValue {
            value: value!({}),
            metadata: value!({}),
            secrets: Secrets::default(),
        };
        Runtime::default()
            .resolve(&mut target, &program, &TimeZone::default())
            .expect("program must resolve")
    }

    fn field(value: &Value, key: &str) -> Value {
        value
            .as_object()
            .unwrap_or_else(|| panic!("expected object, got {value:?}"))
            .get(key)
            .cloned()
            .unwrap_or(Value::Null)
    }

    #[test]
    fn ocsf_classify_routes_on_vendor() {
        assert_eq!(run(r#"ocsf_classify({"_vendor": "nginx"})"#), value!(4002));
        assert_eq!(
            run(r#"ocsf_classify({"_vendor": "suricata", "event_type": "alert"})"#),
            value!(4001)
        );
    }

    #[test]
    fn ocsf_classify_unknown_vendor_is_zero() {
        assert_eq!(run(r#"ocsf_classify({"message": "hello"})"#), value!(0));
    }

    #[test]
    fn ocsf_normalize_unclassified_returns_error_object() {
        let out = run(r#"ocsf_normalize({"message": "hello"})"#);
        assert!(
            !field(&out, "error").is_null(),
            "expected error object: {out:?}"
        );
    }

    #[test]
    fn ocsf_normalize_nginx_emits_class_uid() {
        let out = run(
            r#"ocsf_normalize({"_vendor": "nginx", "request": "GET /index.html HTTP/1.1", "status": "200", "remote_addr": "203.0.113.9"})"#,
        );
        assert_eq!(field(&out, "class_uid"), value!(4002));
    }

    #[test]
    fn parse_suricata_eve_sets_vendor() {
        let out = run(r#"parse_suricata_eve(s'{"event_type": "alert", "src_ip": "10.0.0.1"}')"#);
        assert_eq!(field(&out, "_vendor"), value!("suricata"));
        assert_eq!(field(&out, "event_type"), value!("alert"));
    }

    #[test]
    fn parse_suricata_eve_invalid_json_returns_error_object_not_failure() {
        let out = run(r#"parse_suricata_eve("not json")"#);
        assert!(
            !field(&out, "error").is_null(),
            "expected error object: {out:?}"
        );
    }

    #[test]
    fn parse_zeek_json_line() {
        let out = run(
            r#"parse_zeek(s'{"ts": 1718150400.0, "uid": "C1", "proto": "tcp", "id.orig_h": "10.0.0.1"}', "conn")"#,
        );
        assert_eq!(field(&out, "_vendor"), value!("zeek"));
        assert_eq!(field(&out, "src_ip"), value!("10.0.0.1"));
    }

    #[test]
    fn parse_winevent_extracts_system_fields() {
        let out = run(
            r#"parse_winevent(s'<Event><System><EventID>4624</EventID><Computer>HOST01</Computer></System></Event>')"#,
        );
        assert_eq!(field(&out, "_vendor"), value!("winevent"));
        assert_eq!(field(&out, "event_id"), value!(4624));
        assert_eq!(field(&out, "computer"), value!("HOST01"));
    }

    #[test]
    fn parse_sysmon_sets_vendor() {
        let out = run(r#"parse_sysmon({"event_id": 1})"#);
        assert_eq!(field(&out, "_vendor"), value!("sysmon"));
    }

    #[test]
    fn caver_entity_id_is_stable_and_field_order_independent() {
        // Hash pinned independently (FNV-1a 64 of "kind=host|hostname=web01")
        // — also the doc example; a change here is a cross-collector
        // entity-identity break, not a test refresh.
        assert_eq!(
            run(r#"caver_entity_id({"hostname": "web01"}, "host")"#),
            value!("693947118b3e34c5")
        );
        // Irrelevant fields for the kind don't change the identity.
        assert_eq!(
            run(r#"caver_entity_id({"hostname": "web01", "uptime": 123}, "host")"#),
            value!("693947118b3e34c5")
        );
    }

    #[test]
    fn redact_pii_redacts_emails_recursively() {
        let out = run(r#"redact_pii({"msg": "contact bob@example.com"}, "email")"#);
        assert_eq!(field(&out, "msg"), value!("contact [REDACTED-EMAIL]"));
    }

    #[test]
    fn is_internal_ip_classifies() {
        assert_eq!(run(r#"is_internal_ip("10.1.2.3")"#), value!(true));
        assert_eq!(run(r#"is_internal_ip("8.8.8.8")"#), value!(false));
        assert_eq!(run(r#"is_internal_ip("not an ip")"#), value!(false));
    }

    #[test]
    fn attack_tactic_lookup_strips_subtechnique() {
        let out = run(r#"attack_tactic_lookup("T1059.001")"#);
        assert_eq!(field(&out, "tactic_id"), value!("TA0002"));
        assert_eq!(field(&out, "technique_id"), value!("T1059.001"));
        assert_eq!(run(r#"attack_tactic_lookup("T9999")"#), Value::Null);
    }

    #[test]
    fn full_chain_parse_classify_normalize() {
        // The shape a real remap pipeline uses: parse → classify → normalize.
        let out = run(r#"
            ev = parse_suricata_eve(s'{"event_type": "alert", "src_ip": "10.0.0.1", "dest_ip": "8.8.8.8", "proto": "TCP", "alert": {"signature": "TEST", "severity": 2}}')
            ocsf_normalize(ev)
            "#);
        assert_eq!(field(&out, "class_uid"), value!(4001));
    }

    #[test]
    fn all_identifiers_are_unique_and_do_not_shadow_the_stdlib() {
        let caver: Vec<&str> = super::all().iter().map(|f| f.identifier()).collect();
        let mut sorted = caver.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), caver.len(), "duplicate caver identifiers");
        for f in vrl::stdlib::all() {
            assert!(
                !caver.contains(&f.identifier()),
                "caver function shadows vrl stdlib function {}",
                f.identifier()
            );
        }
    }
}
