// caver/crates/vrl-caver-stdlib/src/vrl_fns/attack_tactic_lookup.rs
use std::sync::LazyLock;

use vrl::prelude::*;

use super::json_to_vrl;

static PARAMETERS: LazyLock<Vec<Parameter>> = LazyLock::new(|| {
    vec![Parameter::required(
        "technique_id",
        kind::BYTES,
        "The MITRE ATT&CK technique ID to look up (e.g. \"T1059\" or \"T1059.001\").",
    )]
});

#[derive(Clone, Copy, Debug)]
pub struct AttackTacticLookup;

impl Function for AttackTacticLookup {
    fn identifier(&self) -> &'static str { "attack_tactic_lookup" }
    fn usage(&self) -> &'static str {
        "Look up the primary MITRE ATT&CK tactic for a technique ID. \
         Returns an object `{tactic_id, tactic_name, technique_id}`, or `null` for unknown IDs."
    }
    fn category(&self) -> &'static str { Category::Convert.as_ref() }
    fn return_kind(&self) -> u16 { kind::OBJECT | kind::NULL }
    fn parameters(&self) -> &'static [Parameter] { &PARAMETERS }
    fn examples(&self) -> &'static [Example] { &[] }

    fn compile(
        &self,
        _state: &TypeState,
        _ctx: &mut FunctionCompileContext,
        arguments: ArgumentList,
    ) -> Compiled {
        let technique_id = arguments.required("technique_id");
        Ok(AttackTacticLookupFn { technique_id }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct AttackTacticLookupFn {
    technique_id: Box<dyn Expression>,
}

impl FunctionExpression for AttackTacticLookupFn {
    fn resolve(&self, ctx: &mut Context<'_>) -> Resolved {
        let technique_id = self.technique_id.resolve(ctx)?;
        let technique_id = technique_id.try_bytes_utf8_lossy()?;
        let result = crate::threat_intel::attack_tactic_lookup(&technique_id);
        Ok(json_to_vrl(result))
    }

    fn type_def(&self, _state: &TypeState) -> TypeDef {
        TypeDef::object(Collection::any()).or_null().fallible()
    }
}
