//! Walk Rust sources, parse with `syn`, and run registered checks.
//!
//! Each [`Check`](soroban_guard_checks::Check) runs independently on the same parsed file;
//! findings are concatenated with no shared mutable state between checks.

use rayon::prelude::*;
use soroban_guard_checks::util::contractimpl_functions_with_type_excluding_test;
use soroban_guard_checks::{default_checks, Check, Finding};
use std::collections::HashSet;
use std::io::BufRead;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use syn::spanned::Spanned;
use thiserror::Error;
use walkdir::WalkDir;

const SUPPRESSION_PREFIX: &str = "// soroban-guard: allow(";

/// The source line range of one `#[contractimpl]` method, paired with its enclosing type's
/// name — used to scope function-level suppressions to the specific `impl` block they were
/// written above, instead of matching any same-named method anywhere in the file.
struct FnSpan {
    impl_type: String,
    function_name: String,
    start_line: usize,
    end_line: usize,
}

fn explain_details(name: &str) -> &'static str {
    match name {
        "missing-require-auth" => {
            "Reports contract methods that mutate storage without calling require_auth or require_auth_for_args."
        }
        "unchecked-arithmetic" => {
            "Reports wrapping +, -, *, and compound arithmetic in contract methods; prefer checked_* or saturating_* APIs."
        }
        "unprotected-admin" => {
            "Reports public admin-like entrypoints such as set_owner, pause, migrate, or upgrade when they lack an auth gate."
        }
        "unsafe-storage-patterns" => {
            "Reports temporary storage mutations and dynamic Symbol keys that may expire unexpectedly or collide."
        }
        "missing-ttl-extension" => {
            "Reports persistent storage writes that do not extend TTL in the same function."
        }
        "forbidden-std-imports" => {
            "Reports std imports in Soroban contract files because deployable contracts must compile for no_std WASM."
        }
        "hardcoded-address" => {
            "Reports Stellar public-key-shaped string literals embedded directly in source."
        }
        "unsafe-cross-contract-input" => {
            "Reports invoke_contract return values stored directly without local validation."
        }
        "missing-contract-annotation" => {
            "Reports contractimpl blocks without a sibling struct annotated with #[contract]."
        }
        "delegate-call-risk" => {
            "Reports storage-derived cross-contract callees that can redirect execution if storage is poisoned."
        }
        "integer-division-truncation" => {
            "Reports integer division where truncation may silently change financial or accounting results."
        }
        "missing-event-emission" => {
            "Reports state-mutating functions that do not publish events for off-chain indexers."
        }
        "symbol-key-collision" => {
            "Reports duplicate symbol_short! keys in the same impl block."
        }
        "self-transfer" => {
            "Reports transfer-like functions that do not guard against sender and recipient being equal."
        }
        "missing-zero-address-check" => {
            "Reports Address parameters stored or used without checking for default or zero-address values."
        }
        "mutable-global-state" => {
            "Reports static mut items, which are unsafe and not valid persistent contract state."
        }
        "re-initialization-risk" => {
            "Reports initializer-like methods that write state without checking whether initialization already happened."
        }
        "unchecked-invoke-return" => {
            "Reports bare invoke_contract statements whose return values are discarded."
        }
        "missing-balance-check" => {
            "Reports token transfer calls that lack a preceding balance or authorization check."
        }
        "unbounded-vec-growth" => {
            "Reports storage-backed Vec values pushed and written back without an apparent length cap."
        }
        "unsafe-randomness" => {
            "Reports ledger timestamp or sequence usage as a randomness source."
        }
        "unchecked-divisor" => {
            "Reports division by runtime values without an apparent non-zero guard."
        }
        _ => "No detailed explanation is available for this custom check.",
    }
}

fn build_fn_spans(file: &syn::File) -> Vec<FnSpan> {
    contractimpl_functions_with_type_excluding_test(file)
        .into_iter()
        .map(|(impl_type, method)| FnSpan {
            impl_type,
            function_name: method.sig.ident.to_string(),
            start_line: method.sig.ident.span().start().line,
            end_line: method.block.span().end().line,
        })
        .collect()
}

#[derive(Error, Debug)]
pub enum ScanError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Permission denied reading {path}")]
    PermissionDenied { path: PathBuf },
    #[error("Failed to parse {path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("Check `{check}` panicked on {path}: {message}")]
    CheckPanic {
        check: String,
        path: PathBuf,
        message: String,
    },
    #[error("Invalid glob pattern `{pattern}`: {reason}")]
    InvalidGlobPattern { pattern: String, reason: String },
}

#[derive(Default)]
struct Suppressions {
    line_checks: HashSet<(usize, String)>,
    /// Keyed on `(impl_type, function_name, check_name)` so a suppression above one
    /// `#[contractimpl]` method doesn't also silence a same-named method on a different type.
    function_checks: HashSet<(String, String, String)>,
}

fn has_generated_file_header(path: &Path) -> Result<bool, std::io::Error> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let mut line = String::new();

    for _ in 0..5 {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with("// @generated")
            || trimmed.starts_with("// Code generated")
            || trimmed.starts_with("// DO NOT EDIT")
        {
            return Ok(true);
        }
    }

    Ok(false)
}

fn parse_allow_checks(line: &str) -> Option<Vec<String>> {
    let trimmed = line.trim_start();
    let rest = trimmed.strip_prefix(SUPPRESSION_PREFIX)?;
    let (inside, _) = rest.split_once(')')?;
    let checks: Vec<String> = inside
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    (!checks.is_empty()).then_some(checks)
}

fn function_name_from_line(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let fn_pos = trimmed.find("fn ")?;
    let after_fn = &trimmed[fn_pos + 3..];
    let name: String = after_fn
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

fn parse_suppressions(source: &str, fn_spans: &[FnSpan]) -> Suppressions {
    let lines: Vec<&str> = source.lines().collect();
    let mut suppressions = Suppressions::default();

    for (idx, line) in lines.iter().enumerate() {
        let Some(checks) = parse_allow_checks(line) else {
            continue;
        };
        let target_idx = idx + 1;
        let Some(target_line) = lines.get(target_idx) else {
            continue;
        };
        if let Some(function_name) = function_name_from_line(target_line) {
            let target_line_number = target_idx + 1;
            let impl_type = fn_spans
                .iter()
                .find(|s| s.start_line == target_line_number && s.function_name == function_name)
                .map(|s| s.impl_type.clone())
                .unwrap_or_default();
            for check in checks {
                suppressions
                    .function_checks
                    .insert((impl_type.clone(), function_name.clone(), check));
            }
        } else {
            let target_line_number = target_idx + 1;
            for check in checks {
                suppressions.line_checks.insert((target_line_number, check));
            }
        }
    }

    suppressions
}

fn is_suppressed(finding: &Finding, suppressions: &Suppressions, fn_spans: &[FnSpan]) -> bool {
    if suppressions
        .line_checks
        .contains(&(finding.line, finding.check_name.clone()))
    {
        return true;
    }
    let impl_type = fn_spans
        .iter()
        .find(|s| {
            s.function_name == finding.function_name
                && s.start_line <= finding.line
                && finding.line <= s.end_line
        })
        .map(|s| s.impl_type.clone())
        .unwrap_or_default();
    suppressions.function_checks.contains(&(
        impl_type,
        finding.function_name.clone(),
        finding.check_name.clone(),
    ))
}

fn dedup_findings(findings: &mut Vec<Finding>) {
    let mut seen = HashSet::new();
    findings.retain(|f| seen.insert((f.file_path.clone(), f.line, f.check_name.clone())));
}

/// Compile glob source strings into patterns, surfacing the first invalid one as
/// `ScanError::InvalidGlobPattern`. Shared by every scan entry point so exclude and
/// include filters compile identically.
fn compile_globs(patterns: &[String]) -> Result<Vec<glob::Pattern>, ScanError> {
    let mut compiled = Vec::with_capacity(patterns.len());
    for p in patterns {
        match glob::Pattern::new(p) {
            Ok(pattern) => compiled.push(pattern),
            Err(e) => {
                return Err(ScanError::InvalidGlobPattern {
                    pattern: p.clone(),
                    reason: e.to_string(),
                })
            }
        }
    }
    Ok(compiled)
}

/// Result of applying the shared source-file filter to one candidate path.
enum PathVerdict {
    /// A `.rs` file that passed every filter and should be scanned.
    Scan,
    /// A `.rs` file omitted because it carries a generated-file header.
    GeneratedSkip,
    /// Not a `.rs` file, or excluded by an exclude/include glob.
    Reject,
}

fn glob_hit(patterns: &[glob::Pattern], label: &Path, path: &Path) -> bool {
    patterns
        .iter()
        .any(|p| p.matches_path(label) || p.matches_path(path))
}

/// The single filter every scan entry point applies to a candidate source file:
/// `.rs` extension, exclude globs, include globs (when non-empty), then the
/// generated-file header check. `label` is the path relative to the scan root.
fn classify_rust_path(
    path: &Path,
    label: &Path,
    exclude_patterns: &[glob::Pattern],
    include_patterns: &[glob::Pattern],
) -> Result<PathVerdict, ScanError> {
    if path.extension().and_then(|e| e.to_str()) != Some("rs") {
        return Ok(PathVerdict::Reject);
    }
    if glob_hit(exclude_patterns, label, path) {
        return Ok(PathVerdict::Reject);
    }
    if !include_patterns.is_empty() && !glob_hit(include_patterns, label, path) {
        return Ok(PathVerdict::Reject);
    }
    if has_generated_file_header(path)? {
        return Ok(PathVerdict::GeneratedSkip);
    }
    Ok(PathVerdict::Scan)
}

/// Collect `.rs` paths under `root`, applying exclude/include glob filters and skipping
/// files that carry a generated-file header. Returns `(paths, files_skipped)` where
/// `files_skipped` is the count of files omitted due to the generated-file header.
fn collect_rust_paths(
    root: &Path,
    excludes: &[String],
    includes: &[String],
) -> Result<(Vec<PathBuf>, usize), ScanError> {
    let exclude_patterns = compile_globs(excludes)?;
    let include_patterns = compile_globs(includes)?;

    if root.is_file() {
        return Ok((vec![root.to_path_buf()], 0));
    }

    let mut files_skipped = 0;
    let mut paths = Vec::new();
    for entry in WalkDir::new(root).follow_links(false).into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path
            .components()
            .any(|c| matches!(c.as_os_str().to_str(), Some("target" | ".git")))
        {
            continue;
        }
        let label = path.strip_prefix(root).unwrap_or(path);
        match classify_rust_path(path, label, &exclude_patterns, &include_patterns)? {
            PathVerdict::Scan => paths.push(path.to_path_buf()),
            PathVerdict::GeneratedSkip => files_skipped += 1,
            PathVerdict::Reject => {}
        }
    }

    Ok((paths, files_skipped))
}

fn run_checks_for_file(
    path: &Path,
    root: &Path,
    checks: &[Box<dyn Check + Send + Sync>],
) -> Result<Vec<Finding>, ScanError> {
    let content = std::fs::read_to_string(path)?;
    let syn_file = syn::parse_file(&content).map_err(|e| ScanError::Parse {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    let file_label = if root.is_file() {
        path.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string()
    } else {
        path.strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string()
    };
    let fn_spans = build_fn_spans(&syn_file);
    let suppressions = parse_suppressions(&content, &fn_spans);

    let mut findings: Vec<Finding> = checks
        .iter()
        .flat_map(|check| {
            let check_name = check.name().to_string();
            match catch_unwind(AssertUnwindSafe(|| check.run(&syn_file, &content))) {
                Ok(mut hits) => {
                    for finding in &mut hits {
                        finding.file_path.clone_from(&file_label);
                    }
                    hits
                }
                Err(payload) => {
                    let message = if let Some(msg) = payload.downcast_ref::<&str>() {
                        msg.to_string()
                    } else if let Some(msg) = payload.downcast_ref::<String>() {
                        msg.clone()
                    } else {
                        "panic payload was not a string".to_string()
                    };
                    eprintln!(
                        "warning: {}",
                        ScanError::CheckPanic {
                            check: check_name,
                            path: path.to_path_buf(),
                            message,
                        }
                    );
                    Vec::new()
                }
            }
        })
        .filter(|finding| !is_suppressed(finding, &suppressions, &fn_spans))
        .collect();

    findings.sort_by_key(|f| f.line);
    dedup_findings(&mut findings);
    Ok(findings)
}

/// Findings for a single source file.
#[derive(Debug)]
pub struct FileScanResult {
    pub file_path: String,
    pub findings: Vec<Finding>,
}

/// Recursively scan `.rs` files under `root` and aggregate findings from every default check.
///
/// `root` may be a directory **or a single `.rs` file**. When a file path is given it is scanned
/// directly without any directory walk.
///
/// `excludes` are glob patterns (e.g. `vendor/**`, `**/generated/*.rs`) matched against each
/// file's path relative to `root`; matching files are skipped entirely.
///
/// `includes` are glob patterns; when non-empty only files matching at least one pattern are
/// scanned. When `includes` is empty all `.rs` files (minus excludes and generated-file
/// headers) are scanned.
///
/// Returns `(findings, files_scanned, files_skipped)` where `files_skipped` counts files
/// omitted because they carry a generated-file header.
pub fn scan_directory(
    root: &Path,
    excludes: &[String],
    includes: &[String],
) -> Result<(Vec<Finding>, usize, usize), ScanError> {
    let root = root.canonicalize()?;
    let checks = default_checks();
    let (paths, files_skipped) = collect_rust_paths(&root, excludes, includes)?;
    let files_scanned = paths.len();

    let mut findings: Vec<Finding> = paths
        .par_iter()
        .map(|path| run_checks_for_file(path, &root, &checks))
        .collect::<Result<Vec<Vec<Finding>>, ScanError>>()?
        .into_iter()
        .flatten()
        .collect();

    findings.sort_by(|a, b| {
        a.file_path
            .cmp(&b.file_path)
            .then_with(|| a.line.cmp(&b.line))
    });
    dedup_findings(&mut findings);
    Ok((findings, files_scanned, files_skipped))
}

/// Like [`scan_directory`] but runs `checks` instead of [`default_checks`].
///
/// Returns `(results, files_scanned, files_skipped)` where each element of `results` groups
/// findings by source file, and `files_skipped` counts files omitted due to generated-file
/// headers (see [`scan_directory`]).
pub fn scan_directory_with_checks(
    root: &Path,
    excludes: &[String],
    includes: &[String],
    checks: &[Box<dyn Check + Send + Sync>],
) -> Result<(Vec<FileScanResult>, usize, usize), ScanError> {
    let root = root.canonicalize()?;
    let (paths, files_skipped) = collect_rust_paths(&root, excludes, includes)?;
    let files_scanned = paths.len();

    let mut results: Vec<FileScanResult> = paths
        .par_iter()
        .map(|path| {
            let findings = run_checks_for_file(path, &root, checks)?;
            let file_label = if root.is_file() {
                path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string()
            } else {
                path.strip_prefix(&root)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .to_string()
            };
            Ok(FileScanResult { file_path: file_label, findings })
        })
        .collect::<Result<Vec<_>, ScanError>>()?;

    results.sort_by(|a, b| a.file_path.cmp(&b.file_path));
    Ok((results, files_scanned, files_skipped))
}

/// Scan an explicit list of `.rs` file paths and aggregate findings from every default check.
///
/// Applies the same per-file filter as [`scan_directory`] via [`classify_rust_path`]:
/// non-`.rs` paths and paths matching an exclude glob (or, when `includes` is non-empty,
/// not matching any include glob) are dropped; files carrying a generated-file header are
/// counted in `files_skipped` and not scanned. Findings are deduplicated before returning.
///
/// `root` is used to compute the relative label matched against the globs and shown in
/// findings. The one difference from [`scan_directory`] is that this does not walk a
/// directory: only the paths passed in are considered.
///
/// Returns `(findings, files_scanned, files_skipped)`.
pub fn scan_files(
    paths: &[PathBuf],
    root: &Path,
    excludes: &[String],
    includes: &[String],
) -> Result<(Vec<Finding>, usize, usize), ScanError> {
    let root = root.canonicalize()?;
    let exclude_patterns = compile_globs(excludes)?;
    let include_patterns = compile_globs(includes)?;

    let mut selected: Vec<PathBuf> = Vec::new();
    let mut files_skipped = 0;
    for path in paths {
        let path_canon = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let label = path_canon.strip_prefix(&root).unwrap_or(&path_canon);
        match classify_rust_path(&path_canon, label, &exclude_patterns, &include_patterns)? {
            PathVerdict::Scan => selected.push(path_canon),
            PathVerdict::GeneratedSkip => files_skipped += 1,
            PathVerdict::Reject => {}
        }
    }

    let files_scanned = selected.len();
    let checks = default_checks();

    let mut findings: Vec<Finding> = selected
        .par_iter()
        .map(|path| run_checks_for_file(path, &root, &checks))
        .collect::<Result<Vec<Vec<Finding>>, ScanError>>()?
        .into_iter()
        .flatten()
        .collect();

    findings.sort_by(|a, b| {
        a.file_path
            .cmp(&b.file_path)
            .then_with(|| a.line.cmp(&b.line))
    });
    dedup_findings(&mut findings);

    Ok((findings, files_scanned, files_skipped))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn scan_single_rs_file_directly() {
        let dir = std::env::temp_dir().join(format!(
            "soroban-guard-singlefile-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("lib.rs");
        fs::write(&file_path, "pub fn f() {}").unwrap();

        let (_, files_scanned, files_skipped) = scan_directory(&file_path, &[], &[]).unwrap();
        assert_eq!(files_scanned, 1);
        assert_eq!(files_skipped, 0);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn scan_error_check_panic_format() {
        let err = ScanError::CheckPanic {
            check: "example-check".to_string(),
            path: PathBuf::from("src/lib.rs"),
            message: "unexpected AST shape".to_string(),
        };

        assert_eq!(
            err.to_string(),
            "Check `example-check` panicked on src/lib.rs: unexpected AST shape"
        );
    }

    #[test]
    fn reports_scanned_rust_file_count_after_filters() {
        let root = std::env::temp_dir().join(format!(
            "soroban-guard-analyzer-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("target")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn included() {}").unwrap();
        fs::write(root.join("src/excluded.rs"), "pub fn excluded() {}").unwrap();
        fs::write(root.join("target/generated.rs"), "pub fn generated() {}").unwrap();
        fs::write(root.join("README.md"), "not Rust").unwrap();

        let (_, files_scanned, files_skipped) =
            scan_directory(&root, &["src/excluded.rs".to_string()], &[]).unwrap();

        assert_eq!(files_scanned, 1);
        assert_eq!(files_skipped, 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn include_filter_limits_scanned_files() {
        let root = std::env::temp_dir().join(format!(
            "soroban-guard-include-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn a() {}").unwrap();
        fs::write(root.join("src/other.rs"), "pub fn b() {}").unwrap();

        let (_, files_scanned, files_skipped) =
            scan_directory(&root, &[], &["src/lib.rs".to_string()]).unwrap();

        assert_eq!(files_scanned, 1);
        assert_eq!(files_skipped, 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn skips_generated_files_with_header() {
        let root = std::env::temp_dir().join(format!(
            "soroban-guard-generated-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("src/lib.rs"),
            "// @generated\npub fn generated() {}\n",
        )
        .unwrap();

        let (_, files_scanned, files_skipped) = scan_directory(&root, &[], &[]).unwrap();

        assert_eq!(files_scanned, 0);
        assert_eq!(files_skipped, 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scan_files_returns_findings_for_explicit_paths() {
        let root = std::env::temp_dir().join(format!(
            "soroban-guard-scan-files-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        let included = root.join("src/lib.rs");
        let excluded = root.join("src/other.rs");
        fs::write(&included, "pub fn a() {}").unwrap();
        fs::write(&excluded, "pub fn b() {}").unwrap();

        let (_, files_scanned, files_skipped) =
            scan_files(&[included.clone(), excluded.clone()], &root, &[], &[]).unwrap();
        assert_eq!(files_scanned, 2);
        assert_eq!(files_skipped, 0);

        // Exclude one file via glob
        let (_, files_scanned, _) =
            scan_files(&[excluded], &root, &["src/other.rs".to_string()], &[]).unwrap();
        assert_eq!(files_scanned, 0);

        // includes now compose the same way as scan_directory
        let (_, files_scanned, _) =
            scan_files(&[included], &root, &[], &["src/other*.rs".to_string()]).unwrap();
        assert_eq!(files_scanned, 0);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scan_files_matches_scan_directory_findings_and_filters_generated() {
        let root = std::env::temp_dir().join(format!(
            "soroban-guard-scan-files-parity-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        let vulnerable = root.join("src/lib.rs");
        let generated = root.join("src/generated.rs");
        fs::write(
            &vulnerable,
            "#[contract]\npub struct C;\n#[contractimpl]\nimpl C {\n    pub fn bump(env: Env) {\n        env.storage().instance().set(&1u32, &2u32);\n    }\n}\n",
        )
        .unwrap();
        fs::write(
            &generated,
            "// @generated\n#[contractimpl]\nimpl G {\n    pub fn go(env: Env) { env.storage().instance().set(&1u32, &2u32); }\n}\n",
        )
        .unwrap();

        let (dir_findings, _, dir_skipped) = scan_directory(&root, &[], &[]).unwrap();
        let (file_findings, files_scanned, file_skipped) =
            scan_files(&[vulnerable, generated], &root, &[], &[]).unwrap();

        assert_eq!(files_scanned, 1, "the generated file must not be scanned");
        assert_eq!(file_skipped, 1);
        assert_eq!(file_skipped, dir_skipped);

        let names = |fs: &[Finding]| {
            let mut v: Vec<(String, usize)> =
                fs.iter().map(|f| (f.check_name.clone(), f.line)).collect();
            v.sort();
            v
        };
        assert!(
            !file_findings.is_empty(),
            "expected findings from the readable file"
        );
        assert_eq!(names(&file_findings), names(&dir_findings));
    }

    #[test]
    fn scan_directory_rejects_invalid_exclude_glob() {
        let root = std::env::temp_dir().join(format!(
            "soroban-guard-invalid-glob-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn f() {}").unwrap();

        let result = scan_directory(&root, &["src/[foo.rs".to_string()], &[]);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Invalid glob pattern") || err_msg.contains("src/[foo.rs"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scan_directory_rejects_invalid_include_glob() {
        let root = std::env::temp_dir().join(format!(
            "soroban-guard-invalid-include-glob-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn f() {}").unwrap();

        let result = scan_directory(&root, &[], &["src/[invalid.rs".to_string()]);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Invalid glob pattern") || err_msg.contains("src/[invalid.rs"));

        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod dedup_tests {
    use super::*;
    use soroban_guard_checks::{Finding, Severity};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// A check that always returns two identical findings for every file it sees.
    struct DuplicatingCheck;
    impl soroban_guard_checks::Check for DuplicatingCheck {
        fn name(&self) -> &str { "dup-check" }
        fn run(&self, _file: &syn::File, _src: &str) -> Vec<Finding> {
            let f = Finding {
                check_name: "dup-check".into(),
                severity: Severity::Low,
                file_path: String::new(),
                line: 1,
                function_name: "f".into(),
                description: "duplicate".into(),
                rule_url: None,
                suggestion: None,
            };
            vec![f.clone(), f]
        }
    }

    #[test]
    fn deduplicates_findings_with_same_file_line_check() {
        let root = std::env::temp_dir().join(format!(
            "soroban-guard-dedup-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn f() {}").unwrap();

        let checks: Vec<Box<dyn soroban_guard_checks::Check + Send + Sync>> =
            vec![Box::new(DuplicatingCheck)];
        let (results, _, _) = scan_directory_with_checks(&root, &[], &[], &checks).unwrap();

        let total: usize = results.iter().map(|r| r.findings.len()).sum();
        assert_eq!(total, 1, "expected 1 finding after dedup, got {}", total);

        fs::remove_dir_all(root).unwrap();
    }

    /// A check that returns two findings at different lines, intentionally reversed.
    struct ReversedCheck;
    impl soroban_guard_checks::Check for ReversedCheck {
        fn name(&self) -> &str { "reversed-check" }
        fn run(&self, _file: &syn::File, _src: &str) -> Vec<Finding> {
            vec![
                Finding {
                    check_name: "reversed-check".into(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line: 20,
                    function_name: "b".into(),
                    description: "second".into(),
                    rule_url: None,
                    suggestion: None,
                },
                Finding {
                    check_name: "reversed-check".into(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line: 5,
                    function_name: "a".into(),
                    description: "first".into(),
                    rule_url: None,
                    suggestion: None,
                },
            ]
        }
    }

    #[test]
    fn findings_sorted_by_file_path_then_line() {
        let root = std::env::temp_dir().join(format!(
            "soroban-guard-sort-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        // Two files — rayon may process them in any order.
        fs::write(root.join("src/b_module.rs"), "pub fn b() {}").unwrap();
        fs::write(root.join("src/a_module.rs"), "pub fn a() {}").unwrap();

        let checks: Vec<Box<dyn soroban_guard_checks::Check + Send + Sync>> =
            vec![Box::new(ReversedCheck)];
        let (results, _, _) = scan_directory_with_checks(&root, &[], &[], &checks).unwrap();

        // Files must be in lexicographic order.
        let file_paths: Vec<&str> = results.iter().map(|r| r.file_path.as_str()).collect();
        assert!(
            file_paths.windows(2).all(|w| w[0] <= w[1]),
            "files not in sorted order: {:?}",
            file_paths
        );

        // Within each file, findings must be sorted by line.
        for r in &results {
            let lines: Vec<usize> = r.findings.iter().map(|f| f.line).collect();
            assert!(
                lines.windows(2).all(|w| w[0] <= w[1]),
                "findings in {} not sorted by line: {:?}",
                r.file_path,
                lines
            );
        }

        fs::remove_dir_all(root).unwrap();
    }
}
