// caver/crates/vrl-caver-stdlib/src/vrl_fns/attack_technique_match.rs
use std::sync::LazyLock;

use vrl::prelude::*;

use super::json_to_vrl;

static PARAMETERS: LazyLock<Vec<Parameter>> = LazyLock::new(|| {
    vec![Parameter::required(
        "rule_id",
        kind::BYTES,
        "The RES detection rule_id to map to its ATT&CK technique IDs.",
    )]
});

#[derive(Clone, Copy, Debug)]
pub struct AttackTechniqueMatch;

impl Function for AttackTechniqueMatch {
    fn identifier(&self) -> &'static str { "attack_technique_match" }
    fn usage(&self) -> &'static str {
        "Map a RES detection `rule_id` to its ATT&CK technique IDs (array)."
    }
    fn category(&self) -> &'static str { Category::Convert.as_ref() }
    fn return_kind(&self) -> u16 { kind::ARRAY }
    fn parameters(&self) -> &'static [Parameter] { &PARAMETERS }
    fn examples(&self) -> &'static [Example] { &[] }

    fn compile(
        &self,
        _state: &TypeState,
        _ctx: &mut FunctionCompileContext,
        arguments: ArgumentList,
    ) -> Compiled {
        let rule_id = arguments.required("rule_id");
        Ok(AttackTechniqueMatchFn { rule_id }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct AttackTechniqueMatchFn {
    rule_id: Box<dyn Expression>,
}

impl FunctionExpression for AttackTechniqueMatchFn {
    fn resolve(&self, ctx: &mut Context<'_>) -> Resolved {
        let rule_id = self.rule_id.resolve(ctx)?;
        let rule_id = rule_id.try_bytes_utf8_lossy()?;
        let matched = crate::threat_intel::attack_technique_match(&rule_id);
        Ok(json_to_vrl(matched))
    }

    fn type_def(&self, _state: &TypeState) -> TypeDef {
        TypeDef::array(Collection::any()).fallible()
    }
}
