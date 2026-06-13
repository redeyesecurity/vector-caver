// caver/crates/vrl-caver-stdlib/src/vrl_fns/hash_imphash.rs

use std::sync::LazyLock;

use vrl::prelude::*;

static PARAMETERS: LazyLock<Vec<Parameter>> = LazyLock::new(|| {
    vec![Parameter::required(
        "pe_bytes",
        kind::BYTES,
        "Raw PE (Portable Executable) bytes to compute the import hash from.",
    )]
});

#[derive(Clone, Copy, Debug)]
pub struct HashImphash;

impl Function for HashImphash {
    fn identifier(&self) -> &'static str { "hash_imphash" }
    fn usage(&self) -> &'static str {
        "Compute the PE import hash (imphash) from raw PE `pe_bytes`. Returns null when no hash can be derived."
    }
    fn category(&self) -> &'static str { Category::Checksum.as_ref() }
    fn return_kind(&self) -> u16 { kind::BYTES | kind::NULL }
    fn parameters(&self) -> &'static [Parameter] { &PARAMETERS }
    fn examples(&self) -> &'static [Example] { &[] }

    fn compile(
        &self,
        _state: &TypeState,
        _ctx: &mut FunctionCompileContext,
        arguments: ArgumentList,
    ) -> Compiled {
        let pe_bytes = arguments.required("pe_bytes");
        Ok(HashImphashFn { pe_bytes }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct HashImphashFn {
    pe_bytes: Box<dyn Expression>,
}

impl FunctionExpression for HashImphashFn {
    fn resolve(&self, ctx: &mut Context<'_>) -> Resolved {
        let pe_bytes = self.pe_bytes.resolve(ctx)?;
        let bytes = pe_bytes.try_bytes()?;
        match crate::parsers::hash_imphash(&bytes) {
            Some(s) => Ok(Value::from(s)),
            None => Ok(Value::Null),
        }
    }

    fn type_def(&self, _state: &TypeState) -> TypeDef {
        TypeDef::bytes().add_null().fallible()
    }
}
