// caver/crates/vrl-caver-stdlib/src/vrl_fns/cve_enrich.rs
use std::sync::LazyLock;

use vrl::prelude::*;

use super::json_to_vrl;

static PARAMETERS: LazyLock<Vec<Parameter>> = LazyLock::new(|| {
    vec![Parameter::required(
        "cve_id",
        kind::BYTES,
        "The CVE identifier to enrich (e.g. \"CVE-2024-1234\").",
    )]
});

#[derive(Clone, Copy, Debug)]
pub struct CveEnrich;

impl Function for CveEnrich {
    fn identifier(&self) -> &'static str { "cve_enrich" }
    fn usage(&self) -> &'static str {
        "Enrich a CVE ID with CVSS score, KEV status, and EPSS probability (stub: returns null)."
    }
    fn category(&self) -> &'static str { Category::Convert.as_ref() }
    fn return_kind(&self) -> u16 { kind::OBJECT }
    fn parameters(&self) -> &'static [Parameter] { &PARAMETERS }
    fn examples(&self) -> &'static [Example] { &[] }

    fn compile(
        &self,
        _state: &TypeState,
        _ctx: &mut FunctionCompileContext,
        arguments: ArgumentList,
    ) -> Compiled {
        let cve_id = arguments.required("cve_id");
        Ok(CveEnrichFn { cve_id }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct CveEnrichFn {
    cve_id: Box<dyn Expression>,
}

impl FunctionExpression for CveEnrichFn {
    fn resolve(&self, ctx: &mut Context<'_>) -> Resolved {
        let cve_id = self.cve_id.resolve(ctx)?;
        let cve_id = cve_id.try_bytes_utf8_lossy()?;
        let enriched = crate::threat_intel::cve_enrich(&cve_id);
        Ok(json_to_vrl(enriched))
    }

    fn type_def(&self, _state: &TypeState) -> TypeDef {
        TypeDef::object(Collection::any()).or_null().fallible()
    }
}
