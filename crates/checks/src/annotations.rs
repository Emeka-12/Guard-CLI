//! Detect `#[contractimpl]` blocks without a corresponding `#[contract]` struct in the same file.

use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::{Attribute, File, Item};

const CHECK_NAME: &str = "missing-contract-annotation";

pub struct MissingContractAnnotationCheck;

fn has_attr(attrs: &[Attribute], name: &str) -> bool {
    attrs.iter().any(|a| {
        let segs = &a.path().segments;
        // Matches `#[contract]` or `#[soroban_sdk::contract]`
        segs.last().map(|s| s.ident == name).unwrap_or(false)
    })
}

/// Walk `items` (recursing into inline modules) collecting every `#[contract]` struct
/// name and every `#[contractimpl]` block's target type name with its source line.
fn collect_items(
    items: &[Item],
    structs: &mut std::collections::HashSet<String>,
    impls: &mut Vec<(String, usize)>,
) {
    for item in items {
        match item {
            Item::Mod(m) => {
                if let Some((_, nested)) = &m.content {
                    collect_items(nested, structs, impls);
                }
            }
            Item::Struct(s) => {
                if has_attr(&s.attrs, "contract") {
                    structs.insert(s.ident.to_string());
                }
            }
            Item::Impl(imp) => {
                if has_attr(&imp.attrs, "contractimpl") {
                    let type_name = match &*imp.self_ty {
                        syn::Type::Path(tp) => tp
                            .path
                            .get_ident()
                            .map(|i| i.to_string())
                            .unwrap_or_else(|| "unknown".to_string()),
                        _ => "unknown".to_string(),
                    };
                    impls.push((type_name, imp.span().start().line));
                }
            }
            _ => {}
        }
    }
}

impl Check for MissingContractAnnotationCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut contract_struct_names: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut contractimpls: Vec<(String, usize)> = Vec::new();
        collect_items(&file.items, &mut contract_struct_names, &mut contractimpls);

        // Report every `#[contractimpl]` block whose type lacks a matching `#[contract]` struct.
        contractimpls
            .into_iter()
            .filter_map(|(type_name, line)| {
                if contract_struct_names.contains(&type_name) {
                    return None;
                }
                Some(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line,
                    function_name: type_name.clone(),
                    description: format!(
                        "`#[contractimpl]` found for `{type_name}` but no `#[contract]` \
                         struct exists in this file. This is likely a copy-paste error; \
                         add `#[contract]` to the struct definition."
                    ),
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#missing-contract-annotation-low"
                            .to_string(),
                    ),
                    suggestion: None,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).expect("parse");
        MissingContractAnnotationCheck.run(&file, src)
    }

    #[test]
    fn passes_when_contract_and_contractimpl_present() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Env};
#[contract]
pub struct MyContract;
#[contractimpl]
impl MyContract {
    pub fn hello(_env: Env) {}
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn flags_contractimpl_without_contract_struct() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct MyContract;
#[contractimpl]
impl MyContract {
    pub fn hello(_env: Env) {}
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        assert_eq!(hits[0].function_name, "MyContract");
    }

    #[test]
    fn passes_when_no_contractimpl_at_all() {
        let hits = run(r#"
pub struct Foo;
impl Foo {
    pub fn bar() {}
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn flags_soroban_sdk_contractimpl_path() {
        let hits = run(r#"
pub struct MyContract;
#[soroban_sdk::contractimpl]
impl MyContract {
    pub fn go(_env: soroban_sdk::Env) {}
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
    }

    #[test]
    fn flags_contractimpl_in_nested_module_without_struct() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
mod contract {
    use super::*;
    pub struct C;
    #[contractimpl]
    impl C {
        pub fn hello(_env: Env) {}
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "C");
    }

    #[test]
    fn passes_when_contract_struct_in_nested_module() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Env};
mod contract {
    use super::*;
    #[contract]
    pub struct C;
    #[contractimpl]
    impl C {
        pub fn hello(_env: Env) {}
    }
}
"#);
        assert!(hits.is_empty());
    }
}
