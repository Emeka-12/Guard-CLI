## Summary

Four self-contained fixes across the `analyzer` and `cli` crates: two analyzer
correctness/hygiene fixes and two CLI accuracy fixes. One commit per issue.

## Changes

### #407 - one unreadable `.rs` file aborts the whole scan

`collect_rust_paths` called `has_generated_file_header(path)?`, so any IO error
while sniffing a file's first lines (a `0600` file in a shared checkout, a broken
symlink, a file removed after `WalkDir` listed it) propagated out and aborted
`scan_directory` / the whole CLI run with exit code 2, discarding findings for every
readable file.

- Added `ScanError::IoRead { path, source }` so propagated read errors name the file.
- `collect_rust_paths` now `match`es on `has_generated_file_header`: on `Err` it
  prints `warning: <path-carrying error>, skipping file` and continues, mirroring the
  existing warn-and-continue precedent for `CheckPanic`. Permission errors are
  reported through the previously dead `ScanError::PermissionDenied { path }` variant.
- `run_checks_for_file`'s `read_to_string` now attaches the path via `IoRead` instead
  of a bare `?`.

### #427 - glob compile/match logic copy-pasted three times

Extracted two helpers in `crates/analyzer/src/lib.rs` and routed all sites through them:

- `compile_globs(&[String]) -> Result<Vec<glob::Pattern>, ScanError>` - replaces the
  three hand-rolled compile loops (excludes and includes in `collect_rust_paths`,
  excludes in `scan_files`).
- `glob_matches(&[glob::Pattern], label, path) -> bool` - replaces the three
  `matches_path(label) || matches_path(path)` predicates.

No behaviour change; exclude and include filters now share one implementation.

### #428 - `describe_check` reported `uninitialized-storage-read` as `medium`

The check emits only `Severity::High` and `docs/checks.md` documents it as High, but
`describe_check` returned `("medium", ...)`, so `list-checks` and `explain` disagreed
with actual scan output and with the `--fail-on high` gate.

- Corrected the entry to `("high", ...)`.
- Audited the other 33 documented entries against `docs/checks.md` and the check
  modules: no other drift. `unchecked-arithmetic` shows `medium` in the table while
  docs say "High / Medium / Low", but that check's `infer_severity` genuinely returns
  a per-call-site severity with `Medium` as its base case, so it is left as-is.
- Added `describe_check_severity_matches_docs`, which parses the `## \`name\` (Severity)`
  headers in `docs/checks.md` and asserts `describe_check`'s severity string agrees for
  every default check (skipping the one inherently multi-severity check).

### #429 - `--quiet` help text described the wrong rule

The doc comment said "Suppress all output when there are zero High findings", but the
implementation gates on `--fail-on` (default `high`): output is shown whenever a
finding meets the configured threshold, so `--quiet --fail-on low` prints on any
finding.

- Reworded the `--quiet` doc comment and the matching sentence in `README.md` to
  "unless a finding meets the `--fail-on` threshold". (`docs/integrations.md` has no
  `--quiet` reference to correct.)
- Extracted the gate into `should_print_results(quiet, should_fail)` used at both
  call sites in `run_scan`.
- Added `quiet_still_prints_when_low_finding_meets_fail_on_low`.

## Testing done

- `cargo test -p soroban-guard-analyzer` - 11 passed, including the new
  `unreadable_file_does_not_abort_scan` (Unix-only; self-skips when run as root).
- `cargo clippy -p soroban-guard-analyzer` - no new warnings in the touched file.
- CLI: `main` does not build the `soroban-guard-cli` crate on `main` - a stray
  `#[contractimpl] impl VulnerableContract` block in `crates/cli/src/config.rs`
  (issue #393), unrelated to this PR - so `cargo test --workspace` cannot run. With
  that block temporarily removed locally, the `soroban-guard` bin unit tests pass
  including the two new tests here; the two pre-existing failures
  (`describe_check_covers_all_default_checks`, `check_name_styling_is_bold_for_high_and_dimmed_for_low`)
  are unrelated to this change and reproduce on a clean `main`.

## Related issues

Closes #407
Closes #427
Closes #428
Closes #429

## Checklist

- [ ] Code builds (`cargo build --workspace`) - blocked by pre-existing #393; `analyzer` and `checks` build
- [ ] Tests pass (`cargo test --workspace`) - blocked by pre-existing #393; `analyzer` tests pass, CLI tests pass with #393 patched locally
- [x] Commit messages follow Conventional Commits style
- [x] Documentation is updated (README `--quiet` wording)
- [x] Examples are updated or added (if applicable) - n/a, no new checks
- [x] No panics introduced (errors are propagated, not panicked)
