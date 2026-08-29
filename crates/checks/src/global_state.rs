//! Detects `static mut` items in Soroban contracts (mutable global state).

use crate::{Check, Finding, Severity};
use syn::{File, ImplItem, Item, ItemStatic, Stmt};

const CHECK_NAME: &str = "mutable-global-state";

pub struct MutableGlobalStateCheck;

impl Check for MutableGlobalStateCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut statics = Vec::new();
        collect_static_items(&file.items, false, &mut statics);

        statics
            .into_iter()
            .filter_map(|ItemStatic { mutability, ident, .. }| {
                if matches!(mutability, syn::StaticMutability::Mut(_)) {
                    return Some(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::High,
                        file_path: String::new(),
                        line: ident.span().start().line,
                        function_name: String::new(),
                        description: format!(
                            "`static mut {ident}` introduces mutable global state. \
                             In Soroban, contract instances are stateless between \
                             invocations — `static mut` is unsafe and its value is \
                             not persisted on-chain."
                        ),
                        rule_url: Some(
                            "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#mutable-global-state-high"
                                .to_string(),
                        ),
                        suggestion: Some(
                            "Replace `static mut` with `env.storage().persistent()` or `env.storage().instance()` for on-chain state."
                                .to_string(),
                        ),
                    });
                }
                None
            })
            .collect()
    }
}

/// Returns `true` when `attrs` contains `#[cfg(test)]`.
fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("cfg") {
            return false;
        }
        attr.parse_args::<syn::Ident>()
            .map(|id| id == "test")
            .unwrap_or(false)
    })
}

/// Every `static` item in the file, recursing into nested `mod` blocks and
/// `impl` method bodies. Skips `#[cfg(test)]` modules and modules named
/// `tests` or `test`.
fn collect_static_items<'a>(items: &'a [Item], in_test_mod: bool, out: &mut Vec<&'a ItemStatic>) {
    for item in items {
        match item {
            Item::Mod(m) => {
                // Skip test modules entirely — mirrors util::collect_contractimpl_fns.
                let is_test = in_test_mod
                    || is_cfg_test(&m.attrs)
                    || m.ident == "tests"
                    || m.ident == "test";
                if let Some((_, nested)) = &m.content {
                    collect_static_items(nested, is_test, out);
                }
            }
            Item::Static(item_static) if !in_test_mod => out.push(item_static),
            Item::Impl(item_impl) if !in_test_mod => {
                // Descend into impl method bodies to catch local `static mut` declarations.
                for impl_item in &item_impl.items {
                    if let ImplItem::Fn(method) = impl_item {
                        collect_static_items_from_stmts(&method.block.stmts, out);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Walk a list of statements collecting any `static` items declared inline.
fn collect_static_items_from_stmts<'a>(stmts: &'a [Stmt], out: &mut Vec<&'a ItemStatic>) {
    for stmt in stmts {
        if let Stmt::Item(Item::Static(item_static)) = stmt {
            out.push(item_static);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_static_mut() {
        let file = parse_file("static mut COUNT: u32 = 0;").unwrap();
        let hits = MutableGlobalStateCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert!(hits[0].description.contains("COUNT"));
    }

    #[test]
    fn ignores_immutable_static() {
        let file = parse_file("static COUNT: u32 = 0;").unwrap();
        let hits = MutableGlobalStateCheck.run(&file, "");
        assert!(hits.is_empty());
    }

    #[test]
    fn flags_static_mut_inside_contractimpl_method() {
        let src = r#"
#[contractimpl]
impl MyContract {
    pub fn risky(_env: Env) {
        static mut COUNTER: u32 = 0;
        unsafe { COUNTER += 1; }
    }
}
"#;
        let file = parse_file(src).unwrap();
        let hits = MutableGlobalStateCheck.run(&file, "");
        assert_eq!(hits.len(), 1, "should flag local static mut inside impl method");
        assert!(hits[0].description.contains("COUNTER"));
        assert_eq!(hits[0].severity, Severity::High);
    }

    #[test]
    fn ignores_static_mut_inside_cfg_test_module() {
        let src = r#"
#[cfg(test)]
mod tests {
    static mut COUNTER: u32 = 0;
}
"#;
        let file = parse_file(src).unwrap();
        let hits = MutableGlobalStateCheck.run(&file, "");
        assert!(hits.is_empty(), "should not flag static mut inside #[cfg(test)] module");
    }

    #[test]
    fn ignores_static_mut_inside_module_named_tests() {
        let src = r#"
mod tests {
    static mut COUNTER: u32 = 0;
}
"#;
        let file = parse_file(src).unwrap();
        let hits = MutableGlobalStateCheck.run(&file, "");
        assert!(hits.is_empty(), "should not flag static mut inside module named `tests`");
    }
}
