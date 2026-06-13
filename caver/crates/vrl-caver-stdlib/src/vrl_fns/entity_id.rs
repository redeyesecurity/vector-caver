// caver/crates/vrl-caver-stdlib/src/vrl_fns/entity_id.rs
use std::sync::LazyLock;

use vrl::prelude::*;

use super::vrl_to_json;

static PARAMETERS: LazyLock<Vec<Parameter>> = LazyLock::new(|| {
    vec![
        Parameter::required(
            "object",
            kind::OBJECT,
            "The entity fields object from which to derive a stable identifier.",
        ),
        Parameter::required(
            "kind",
            kind::BYTES,
            "The entity kind: \"host\" | \"user\" | \"file\" | \"process\".",
        ),
    ]
});

#[derive(Clone, Copy, Debug)]
pub struct EntityId;

impl Function for EntityId {
    fn identifier(&self) -> &'static str { "entity_id" }
    fn usage(&self) -> &'static str {
        "Generate a stable, content-addressed entity identifier (16-character lowercase hex) \
         from an `object` of entity fields and an entity `kind`."
    }
    fn category(&self) -> &'static str { Category::Convert.as_ref() }
    fn return_kind(&self) -> u16 { kind::BYTES }
    fn parameters(&self) -> &'static [Parameter] { &PARAMETERS }
    fn examples(&self) -> &'static [Example] { &[] }

    fn compile(
        &self,
        _state: &TypeState,
        _ctx: &mut FunctionCompileContext,
        arguments: ArgumentList,
    ) -> Compiled {
        let object = arguments.required("object");
        let kind = arguments.required("kind");
        Ok(EntityIdFn { object, kind }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct EntityIdFn {
    object: Box<dyn Expression>,
    kind: Box<dyn Expression>,
}

impl FunctionExpression for EntityIdFn {
    fn resolve(&self, ctx: &mut Context<'_>) -> Resolved {
        let object = self.object.resolve(ctx)?;
        let json = vrl_to_json(object)?;
        let kind = self.kind.resolve(ctx)?;
        let kind = kind.try_bytes_utf8_lossy()?.into_owned();
        let id = crate::parsers::entity_id(&json, &kind);
        Ok(Value::from(id))
    }

    fn type_def(&self, _state: &TypeState) -> TypeDef {
        TypeDef::bytes().fallible()
    }
}
