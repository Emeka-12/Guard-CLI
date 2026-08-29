# Check precision fixes: vec-growth, balance-check, dedup, dead code

Four related precision and hygiene fixes across the `checks` and `analyzer` crates.
Each is a self-contained commit.

## #402 - `unbounded-vec-growth` fires on three unrelated operations

`crates/checks/src/vec_growth.rs` decided to fire by ANDing four function-scoped
booleans (`has_storage_get && has_push_or_append && has_storage_set && !has_len_check`).
Nothing tied the three positive signals to the same value, so a config read, a push to
an unrelated scratch `Vec`, and any storage write in the same function together produced
a `Medium` finding. Reading config and writing a balance in one function is about as
common as Soroban code gets, so the false-positive rate on real contracts was high.

**Change:** replaced the booleans with per-binding taint tracking, mirroring the
statement-ordered visitor in `xc_input.rs`:

- `get_bindings` - `let <ident> = <expr>` whose initializer transitively contains a
  `.get()` on a `.storage()` receiver chain (covers `...get(&k).unwrap_or(default)`).
  Re-binding the name to a non-storage value clears the entry.
- `grown` - a binding that is the receiver of `push` / `push_back` / `append`.
- `written_back` - a binding passed by value or reference into a storage `.set(...)`.
- `len_checked` - a binding that is the receiver of `.len()`.

A finding is emitted only for a binding present in `get_bindings ∩ grown ∩ written_back`
and absent from `len_checked`.

**Tests:** the three existing tests still hold; added
`does_not_flag_unrelated_get_local_push_and_set` (the exact shape from the issue,
asserts no finding) and `flags_when_same_binding_flows_get_push_set`.

**Trade-off:** a `Vec` read into `a` then written back through a renamed alias `b`
(`let b = a;`) is no longer flagged. This matches the check's documented heuristic
nature and the approach the issue asked for.

## #403 - `missing-balance-check` matched by method name alone

`crates/checks/src/balance.rs` classified calls purely by method name with no receiver
check, so `self.ownership.transfer(&new_owner)` was a false positive and an unrelated
`self.ledger.balance()` was a false-negative silencer on a High-severity money-movement
rule. A balance check and a transfer on the same source line were also not counted as
ordered, because the precedence test compared line numbers with strict `<`.

**Change:**

- Statement-ordered visitor tracks `token_bindings` - locals initialised from
  `token::Client::new(...)` / `TokenClient::new(...)` (any path ending `Client::new`
  or `TokenClient::new`).
- `transfer` / `transfer_from` and `balance` / `authorized` are recorded only when
  the receiver resolves to a token-client binding.
- Call positions are `(line, column)` tuples, so a `balance()` earlier on the same
  line as the `transfer()` is correctly counted as preceding it.
- The per-call-site loop and the #364 regression semantics are unchanged.

**Tests:** existing fixtures updated to bind the client via `token::Client::new`;
added `ignores_transfer_on_non_token_receiver`, `unrelated_balance_does_not_suppress_finding`,
and `same_line_balance_check_counts_as_preceding`.

## #404 - `explain_details` duplicated verbatim; analyzer copy is dead code

`explain_details` existed character-for-character identical in
`crates/analyzer/src/lib.rs` and `crates/cli/src/main.rs`. Only the CLI copy is
reachable (it backs `soroban-guard explain`); the analyzer copy is a private `fn`
called from nowhere, so `cargo clippy --workspace -- -D warnings` (CI) turns its
`dead_code` warning into a build failure.

**Change:** deleted the dead copy from the analyzer crate. The analyzer exposes no
other check-metadata API, so making it `pub` and re-exporting would be gratuitous.
One definition remains, in the CLI.

## #405 - `dedup_findings` discards distinct same-line findings

`crates/analyzer/src/lib.rs` deduplicated on `(file_path, line, check_name)`, which
collapses any two findings from the same check on the same line however different their
content. Checks like `unchecked-arithmetic` legitimately emit one finding per operator,
so `let c = a + b * d - e;` lost two of three findings, and which survived depended on
visit order.

**Change:** widened the key to
`(file_path, line, check_name, function_name, description, severity)` and added `Hash`
to the `Severity` derive (a `Copy` fieldless enum). Genuinely identical duplicates
(the `DuplicatingCheck` test) still collapse.

**Tests:** added `keeps_distinct_findings_on_the_same_line`; the existing
`deduplicates_findings_with_same_file_line_check` still passes.

## Verification

- `cargo test -p soroban-guard-checks` - 137 passed
- `cargo test -p soroban-guard-analyzer` - 11 passed
- `cargo clippy -p soroban-guard-checks -p soroban-guard-analyzer --all-targets` -
  no new warnings in the touched files

Note: `main` currently does not build the `soroban-guard-cli` crate (see #393, an
unrelated stray fixture in `crates/cli/src/config.rs`) and `Cargo.lock` is at
lockfile version 4, so full-workspace CI is red independently of this change. The
`checks` and `analyzer` crates build and test cleanly.

Closes #402
Closes #403
Closes #404
Closes #405
