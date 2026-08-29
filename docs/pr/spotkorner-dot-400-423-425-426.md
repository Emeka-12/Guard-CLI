# checks-crate fixes: auth-order Address form, unused imports, rule_url anchor

Four small `checks`-crate issues. Each is a self-contained commit except #426, which
needs no change (see below).

## #400 - `auth-after-storage-write` missed `<address>.require_auth()`

`crates/checks/src/auth_order.rs` recognized an authorization call only when the
receiver was the `Env` parameter (`env.require_auth()`). The idiomatic Soroban form
authorizes an `Address` (`from.require_auth()`, `admin.require_auth()`), which
`Address::require_auth` exists for and which the sibling check `auth.rs` already
handles - so the ordering hazard was invisible for every contract that authorizes an
`Address`.

**Change (`auth_order.rs` only):**
- Added `type_is_address` / `address_param_names` (same shape as the `type_is_env` /
  `env_param_name` helpers already in the file, mirroring `auth.rs`).
- `is_env_require_auth` -> `is_require_auth_call(m, env_name, address_names)`: the
  receiver may be the `Env` param **or** any `Address` param. Threaded `address_params`
  through `run` -> `first_require_auth_line` -> `FirstRequireAuth`.
- Finding text is now receiver-neutral (`calls \`require_auth()\``), since it may be
  an `Address`.
- Tests added (the file had none): `flags_address_require_auth_after_storage_write`,
  `passes_when_address_require_auth_precedes_storage_write`,
  `still_flags_env_require_auth_after_storage_write`.
- `test-contracts/auth-order-vulnerable` gains a `set_for(env, from: Address, value)`
  method exercising the `Address`-receiver form.

## #423 - unused imports that fail `clippy -D warnings`

Removed the unused imports still present on `main`:

| File | Import |
| --- | --- |
| `crates/checks/src/admin.rs` | `Expr` |
| `crates/checks/src/events.rs` | `Expr` |
| `crates/checks/src/reinit.rs` | `Expr` |
| `crates/checks/src/missing_input_length_bound.rs` | `PatType` |
| `crates/checks/src/unchecked_token_amount.rs` | `syn::spanned::Spanned` |

The issue also listed `ttl.rs` and `vec_growth.rs`; both were already cleaned on `main`,
so five of the seven remained. `cargo build -p soroban-guard-checks` now reports no
`unused_imports`.

## #425 - `overflow.rs` `rule_url` anchor

`crates/checks/src/overflow.rs` linked to `docs/checks.md#unchecked-arithmetic`, but the
heading is `## \`unchecked-arithmetic\` (High / Medium / Low)`, for which GitHub
generates `#unchecked-arithmetic-high--medium--low`. `unchecked-arithmetic` is the only
check that emits three severities, which is why its heading (and anchor) differ from the
`#<name>-<severity>` form the other checks use. Updated the link to the generated anchor.

A test asserting every `rule_url` anchor resolves to a `docs/checks.md` heading (the
issue's suggested drift guard) is noted as a follow-up - it needs a GitHub-slug
implementation and is broader than this fix.

## #426 - `BodyScan::balance_line` dead field - already resolved

The issue describes `crates/checks/src/balance.rs` with a `BodyScan` struct carrying
`has_transfer`, `has_balance_check`, `transfer_line`, `balance_line`, where `balance_line`
is written and never read. On current `main` that struct no longer exists - `balance.rs`
was refactored to `BodyScan { transfer_lines: Vec<usize>, balance_lines: Vec<usize> }`
(both fields consumed by `run`). There is no `balance_line` field. Verified:
`cargo clippy -p soroban-guard-checks --all-targets -- -D warnings` reports no `dead_code`
diagnostic for `BodyScan`. No code change required.

## Verification

- `cargo test -p soroban-guard-checks` - 135 passed (132 + 3 new `auth_order` tests)
- `cargo test -p soroban-guard-analyzer` - 12 passed
- `cargo build -p soroban-guard-checks` - no `unused_imports` warnings
- `test-contracts/auth-order-vulnerable` - `cargo check` passes

Note: repo `main` does not build the `cli` crate (stray fixture in `config.rs`, issue
#393) and `Cargo.lock` is at v4 vs the CI-pinned toolchain 1.74, so full-workspace CI is
red independently of this change. The `checks` and `analyzer` crates build and test
cleanly. Pre-existing `clippy` style lints (`collapsible_if`, `len_zero`,
`items_after_test_module`) remain in files outside these four issues' scope.

Closes #400
Closes #423
Closes #425
Closes #426
