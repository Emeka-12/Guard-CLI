//! Flags token `transfer`/`transfer_from` calls in `#[contractimpl]` methods that lack
//! a preceding `balance()` or `authorized()` check.
//!
//! Calls are qualified by receiver: only `transfer` / `balance` / `authorized` invoked on
//! a local binding initialised from `token::Client::new(...)` (or `TokenClient::new(...)`)
//! count. A same-named method on an unrelated type (`self.ownership.transfer(...)`,
//! `self.ledger.balance()`) is ignored, in either direction.

use crate::util::contractimpl_functions_excluding_test;
use crate::{Check, Finding, Severity};
use std::collections::HashSet;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Pat, Stmt};

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

            let mut transfers = scan.transfers;
            transfers.sort_unstable();
            let mut balances = scan.balances;
            balances.sort_unstable();

            // Evaluate each transfer call site independently: a finding is emitted for
            // every transfer that has no balance()/authorized() call between the previous
            // transfer (exclusive) and this one (exclusive). A single check at the function
            // top does not "cover" every subsequent transfer because each transfer changes
            // the balance. Positions are `(line, column)` so a balance and a transfer on the
            // same source line are still ordered correctly.
            let mut prev_transfer: (usize, usize) = (0, 0);
            for &transfer_pos in &transfers {
                let guarded = balances
                    .iter()
                    .any(|&bal| bal > prev_transfer && bal < transfer_pos);
                if !guarded {
                    out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::High,
                        file_path: String::new(),
                        line: transfer_pos.0,
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
                prev_transfer = transfer_pos;
            }
        }
        out
    }
}

/// Accumulates the `(line, column)` position of every token-client `transfer`/`transfer_from`
/// call and every token-client `balance`/`authorized` call in a function body. Per-call-site
/// evaluation is done in the caller after the walk finishes.
#[derive(Default)]
struct BodyScan {
    /// Local bindings initialised from `token::Client::new(...)` / `TokenClient::new(...)`.
    token_bindings: HashSet<String>,
    transfers: Vec<(usize, usize)>,
    balances: Vec<(usize, usize)>,
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        // Collect token-client bindings in source order so later calls resolve against
        // them. Re-binding the same name to something else clears the entry.
        if let Stmt::Local(local) = stmt {
            if let (Some(name), Some(init)) = (binding_ident(&local.pat), &local.init) {
                if expr_is_token_client_ctor(&init.expr) {
                    self.token_bindings.insert(name);
                } else {
                    self.token_bindings.remove(&name);
                }
            }
        }
        visit::visit_stmt(self, stmt);
    }

    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let method = i.method.to_string();
        let on_token_client = ident_of(&i.receiver)
            .map(|r| self.token_bindings.contains(&r))
            .unwrap_or(false);
        if on_token_client {
            let start = i.method.span().start();
            let pos = (start.line, start.column);
            match method.as_str() {
                "transfer" | "transfer_from" => self.transfers.push(pos),
                "balance" | "authorized" => self.balances.push(pos),
                _ => {}
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

/// Name bound by a `let` pattern, digging through an explicit type annotation.
fn binding_ident(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(pi) => Some(pi.ident.to_string()),
        Pat::Type(pt) => binding_ident(&pt.pat),
        _ => None,
    }
}

/// Identifier behind a plain path (`x`) or a reference to one (`&x`, `&mut x`).
fn ident_of(e: &Expr) -> Option<String> {
    match e {
        Expr::Reference(r) => ident_of(&r.expr),
        Expr::Path(p) => p.path.get_ident().map(|i| i.to_string()),
        _ => None,
    }
}

/// Is `expr` a call to `token::Client::new(...)`, `TokenClient::new(...)`, or any path
/// ending in `Client::new` / `TokenClient::new`? Also looks through a leading `&`.
fn expr_is_token_client_ctor(expr: &Expr) -> bool {
    match expr {
        Expr::Reference(r) => expr_is_token_client_ctor(&r.expr),
        Expr::Call(call) => {
            let Expr::Path(p) = &*call.func else {
                return false;
            };
            let segs = &p.path.segments;
            let n = segs.len();
            if n < 2 || segs[n - 1].ident != "new" {
                return false;
            }
            let ty = &segs[n - 2].ident;
            ty == "Client" || ty == "TokenClient"
        }
        _ => false,
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
        let token = token::Client::new(&env, &id);
        let bal = token.balance(&sender);
        token.transfer(&sender, &recv, &amount);
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
        let token = token::Client::new(&env, &id);
        token.transfer(&sender, &recv, &amount);
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
        let token = token::Client::new(&env, &id);

        // First transfer: guarded — should NOT produce a finding.
        let bal = token.balance(&sender);
        token.transfer(&sender, &recv, &amount);

        // Second transfer: no balance check before it — MUST produce a finding.
        token.transfer(&sender, &recv2, &amount2);
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
        let token = token::Client::new(&env, &id);
        token.transfer(&sender, &recv, &amount);
        token.transfer(&sender, &recv2, &amount2);
    }
}
"#;
        let lines = finding_lines(src);
        assert_eq!(lines.len(), 2, "both unguarded transfers should be flagged; got lines: {lines:?}");
    }

    /// #403 false positive: a non-token `transfer` method on an unrelated type.
    #[test]
    fn ignores_transfer_on_non_token_receiver() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn transfer_ownership(env: Env, new_owner: Address) {
        self.ownership.transfer(&new_owner);
    }
}
"#;
        assert!(finding_lines(src).is_empty());
    }

    /// #403 false negative: an unrelated `.balance()` must not silence a real finding.
    #[test]
    fn unrelated_balance_does_not_suppress_finding() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn payout(env: Env, to: Address, amount: i128) {
        let token = token::Client::new(&env, &id);
        let _ = self.ledger.balance();
        token.transfer(&from, &to, &amount);
    }
}
"#;
        assert_eq!(finding_lines(src).len(), 1);
    }

    /// #403 precision: a balance check and the transfer on the same source line.
    #[test]
    fn same_line_balance_check_counts_as_preceding() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn send(env: Env) {
        let token = token::Client::new(&env, &id);
        if token.balance(&sender) >= amount { token.transfer(&sender, &recv, &amount); }
    }
}
"#;
        assert!(finding_lines(src).is_empty());
    }
}
