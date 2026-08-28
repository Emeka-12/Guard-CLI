//! Flags `#[contractimpl]` methods that read a Vec from storage, push to it, and write it
//! back without any length cap, which can brick the contract once the ledger entry size
//! limit is exceeded.

use crate::util::{contractimpl_functions_excluding_test, receiver_chain_contains_storage};
use crate::{Check, Finding, Severity};
use std::collections::HashSet;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "unbounded-vec-growth";

pub struct UnboundedVecGrowthCheck;

impl Check for UnboundedVecGrowthCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let mut scan = BodyScan::default();
            scan.visit_block(&method.block);
            if scan.has_storage_get
                && scan.has_push_or_append
                && scan.has_storage_set
                && !scan.has_len_check()
            {
                let line = scan
                    .push_line
                    .unwrap_or_else(|| method.sig.ident.span().start().line);
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Function `{fn_name}` reads a Vec from storage, appends to it, and writes \
                         it back without a length cap. The ledger entry will eventually exceed \
                         Soroban's size limit, bricking the contract."
                    ),
                    rule_url: Some(
                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unbounded-vec-growth-medium"
                            .to_string(),
                    ),
                    suggestion: Some(
                        "Enforce a maximum length before pushing, e.g. \
                         `require!(vec.len() < MAX_SIZE, \"capacity exceeded\");`."
                            .to_string(),
                    ),
                });
            }
        }
        out
    }
}

#[derive(Default)]
struct BodyScan {
    has_storage_get: bool,
    has_push_or_append: bool,
    has_storage_set: bool,
    push_receivers: HashSet<String>,
    len_receivers: HashSet<String>,
    push_line: Option<usize>,
}

impl BodyScan {
    /// A length check only counts if a `.len()` call targets the same receiver that is
    /// actually being pushed to — an unrelated `.len()` must not suppress the finding.
    fn has_len_check(&self) -> bool {
        !self.push_receivers.is_disjoint(&self.len_receivers)
    }
}

fn receiver_key(e: &Expr) -> String {
    use quote::ToTokens;
    e.to_token_stream().to_string()
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let method = i.method.to_string();
        if method == "get" && receiver_chain_contains_storage(&i.receiver) {
            self.has_storage_get = true;
        }
        if method == "set" && receiver_chain_contains_storage(&i.receiver) {
            self.has_storage_set = true;
        }
        if matches!(method.as_str(), "push" | "push_back" | "append") {
            self.has_push_or_append = true;
            self.push_receivers.insert(receiver_key(&i.receiver));
            if self.push_line.is_none() {
                self.push_line = Some(i.method.span().start().line);
            }
        }
        if method == "len" {
            self.len_receivers.insert(receiver_key(&i.receiver));
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).expect("parse");
        UnboundedVecGrowthCheck.run(&file, src)
    }

    #[test]
    fn flags_unbounded_push_despite_unrelated_len_call() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn add(env: Env, other: Vec<u32>) {
        let mut entries: Vec<u32> = env.storage().instance().get(&0).unwrap().unwrap();
        entries.push(1u32);
        let _ = other.len();
        env.storage().instance().set(&0, &entries);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, CHECK_NAME);
    }

    #[test]
    fn passes_when_len_check_targets_pushed_receiver() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn add(env: Env, max: u32) {
        let mut entries: Vec<u32> = env.storage().instance().get(&0).unwrap().unwrap();
        entries.push(1u32);
        if entries.len() >= max {
            panic!("capacity exceeded");
        }
        env.storage().instance().set(&0, &entries);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn flags_when_no_length_check_at_all() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn add(env: Env) {
        let mut entries: Vec<u32> = env.storage().instance().get(&0).unwrap().unwrap();
        entries.push(1u32);
        env.storage().instance().set(&0, &entries);
    }
}
"#);
        assert_eq!(hits.len(), 1);
    }
}
