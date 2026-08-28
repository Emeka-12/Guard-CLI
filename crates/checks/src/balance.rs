//! Flags token `transfer`/`transfer_from` calls in `#[contractimpl]` methods that lack
//! a preceding `balance()` or `authorized()` check.

use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use syn::visit::{self, Visit};
use syn::{ExprMethodCall, File};

const CHECK_NAME: &str = "missing-balance-check";

pub struct MissingBalanceCheck;

impl Check for MissingBalanceCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions_excluding_test(file) {
            let fn_name = method.sig.ident.to_string();
            let mut scan = BodyScan::default();
            scan.visit_block(&method.block);

            // Evaluate each transfer call site independently: a finding is emitted
            // for every transfer that has no balance()/authorized() call between the
            // previous transfer (exclusive) and this one (exclusive).  A single check
            // at the function top does not "cover" every subsequent transfer because
            // each transfer changes the balance.
            let mut prev_transfer_line: usize = 0; // sentinel: start of function
            for transfer_line in &scan.transfer_lines {
                let guarded = scan
                    .balance_lines
                    .iter()
                    .any(|bl| *bl > prev_transfer_line && bl < transfer_line);
                if !guarded {
                    out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::High,
                        file_path: String::new(),
                        line: *transfer_line,
                        function_name: fn_name.clone(),
                        description: format!(
                            "Function `{fn_name}` calls `transfer` or `transfer_from` without a \
                             preceding `balance()` or `authorized()` check. An invalid transfer may \
                             cause a runtime panic that disrupts multi-step atomic operations."
                        ),
                        rule_url: Some(
                            "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#missing-balance-check-high"
                                .to_string(),
                        ),
                        suggestion: Some(
                            "Call `token_client.balance(&sender)` before transferring and verify \
                             the sender holds sufficient funds."
                                .to_string(),
                        ),
                    });
                }
                prev_transfer_line = *transfer_line;
            }
        }
        out
    }
}

/// Accumulates the source lines of every `transfer`/`transfer_from` call and
/// every `balance`/`authorized` call seen in a function body.  Per-call-site
/// evaluation is done in the caller after the visitor has finished the walk.
#[derive(Default)]
struct BodyScan {
    /// Source line of each `transfer` or `transfer_from` call (in visit order).
    transfer_lines: Vec<usize>,
    /// Source line of each `balance` or `authorized` call (in visit order).
    balance_lines: Vec<usize>,
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let method = i.method.to_string();
        match method.as_str() {
            "transfer" | "transfer_from" => {
                self.transfer_lines.push(i.method.span().start().line);
            }
            "balance" | "authorized" => {
                self.balance_lines.push(i.method.span().start().line);
            }
            _ => {}
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    // Helper: run the check and collect the reported line numbers.
    fn finding_lines(src: &str) -> Vec<usize> {
        let file = parse_file(src).unwrap();
        let mut hits = MissingBalanceCheck.run(&file, "");
        hits.sort_by_key(|f| f.line);
        hits.into_iter().map(|f| f.line).collect()
    }

    #[test]
    fn no_finding_when_balance_check_precedes_transfer() {
        let src = r#"
#[contractimpl]
impl Token {
    pub fn send(env: Env) {
        let bal = token.balance(&sender);
        token.transfer(&env, &sender, &recv, &amount);
    }
}
"#;
        assert!(finding_lines(src).is_empty());
    }

    #[test]
    fn finding_when_no_balance_check() {
        let src = r#"
#[contractimpl]
impl Token {
    pub fn send(env: Env) {
        token.transfer(&env, &sender, &recv, &amount);
    }
}
"#;
        assert_eq!(finding_lines(src).len(), 1);
    }

    /// Regression test for #364: two transfers in one function, only the first
    /// is balance-guarded.  A finding must be emitted for the second transfer.
    #[test]
    fn second_unguarded_transfer_is_flagged_when_first_is_guarded() {
        let src = r#"
#[contractimpl]
impl Token {
    pub fn double_send(env: Env) {
        // First transfer: guarded — should NOT produce a finding.
        let bal = token.balance(&sender);
        token.transfer(&env, &sender, &recv, &amount);

        // Second transfer: no balance check before it — MUST produce a finding.
        token.transfer(&env, &sender, &recv2, &amount2);
    }
}
"#;
        let lines = finding_lines(src);
        assert_eq!(lines.len(), 1, "only the second (unguarded) transfer should be flagged; got lines: {lines:?}");
    }

    /// Both transfers unguarded → two findings.
    #[test]
    fn both_unguarded_transfers_flagged() {
        let src = r#"
#[contractimpl]
impl Token {
    pub fn double_send(env: Env) {
        token.transfer(&env, &sender, &recv, &amount);
        token.transfer(&env, &sender, &recv2, &amount2);
    }
}
"#;
        let lines = finding_lines(src);
        assert_eq!(lines.len(), 2, "both unguarded transfers should be flagged; got lines: {lines:?}");
    }
}
