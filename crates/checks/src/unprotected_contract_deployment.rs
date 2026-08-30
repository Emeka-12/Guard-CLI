use crate::util::{self, env_param_name, receiver_chain_contains, receiver_chain_contains_storage};
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, ImplItem, ItemImpl, Pat};

const CHECK_NAME: &str = "unprotected-contract-deployment";

pub struct UnprotectedContractDeploymentCheck;

impl Check for UnprotectedContractDeploymentCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &syn::File, _source: &str) -> Vec<Finding> {
        let mut visitor = DeploymentVisitor::default();
        visit::visit_file(&mut visitor, file);
        visitor.findings
    }
}

#[derive(Default)]
struct DeploymentVisitor {
    findings: Vec<Finding>,
}

impl<'ast> Visit<'ast> for DeploymentVisitor {
    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        if has_contractimpl_attr(&node.attrs) {
            for item in &node.items {
                if let ImplItem::Fn(method) = item {
                    if matches!(method.vis, syn::Visibility::Public(_)) {
                        let (has_deployer, line) = has_deployer_call(&method.block);
                        if has_deployer {
                            let env_name =
                                env_param_name(&method.sig).unwrap_or_else(|| "env".to_string());
                            let address_names = util::address_param_names(&method.sig);
                            let auth_line = first_valid_auth_line(method, &env_name, &address_names);

                            let unprotected = match auth_line {
                                Some(auth) => auth >= line,
                                None => true,
                            };

                            if unprotected {
                                self.findings.push(Finding {
                                    check_name: CHECK_NAME.to_string(),
                                    severity: Severity::High,
                                    file_path: String::new(),
                                    line,
                                    function_name: method.sig.ident.to_string(),
                                    description:
                                        "Contract deployment call lacks valid require_auth protection"
                                            .to_string(),
                                    rule_url: Some(
                                        "https://github.com/SorobanGuard/Guard-CLI/blob/main/docs/checks.md#unprotected-contract-deployment-high"
                                            .to_string(),
                                    ),
                                    suggestion: Some(
                                        "Add env.require_auth() before deployment operations"
                                            .to_string(),
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }
        visit::visit_item_impl(self, node);
    }
}

fn has_contractimpl_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if let syn::Meta::Path(path) = &attr.meta {
            path.segments
                .last()
                .map(|seg| seg.ident == "contractimpl")
                .unwrap_or(false)
        } else {
            false
        }
    })
}

fn has_deployer_call(block: &syn::Block) -> (bool, usize) {
    let mut visitor = DeployerVisitor::default();
    visit::visit_block(&mut visitor, block);
    (visitor.found_deployer, visitor.line)
}

#[derive(Default)]
struct DeployerVisitor {
    found_deployer: bool,
    line: usize,
}

impl<'ast> Visit<'ast> for DeployerVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "deployer" {
            self.found_deployer = true;
            self.line = node.span().start().line;
        }
        visit::visit_expr_method_call(self, node);
    }
}

fn first_valid_auth_line(
    method: &syn::ImplItemFn,
    env_name: &str,
    _address_names: &[String],
) -> Option<usize> {
    let mut scanner = AuthScanner::new(env_name.to_string(), _address_names.to_vec());
    scanner.visit_block(&method.block);
    scanner.first_valid_auth_line
}

struct AuthScanner {
    env_name: String,
    address_names: Vec<String>,
    admin_vars: std::collections::HashSet<String>,
    first_valid_auth_line: Option<usize>,
}

impl AuthScanner {
    fn new(env_name: String, address_names: Vec<String>) -> Self {
        Self {
            env_name,
            address_names,
            admin_vars: std::collections::HashSet::new(),
            first_valid_auth_line: None,
        }
    }
}

impl<'ast> Visit<'ast> for AuthScanner {
    fn visit_stmt(&mut self, node: &'ast syn::Stmt) {
        if let syn::Stmt::Local(local) = node {
            if let Some(init) = &local.init {
                if receiver_chain_contains_storage(&init.expr)
                    && receiver_chain_contains(&init.expr, "get")
                {
                    if let Some(var_name) = pat_ident_name(&local.pat) {
                        if var_name.to_lowercase().contains("admin") || var_name.to_lowercase().contains("authority") {
                            self.admin_vars.insert(var_name);
                        }
                    }
                }
            }
        }
        visit::visit_stmt(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if self.first_valid_auth_line.is_none() {
            if is_valid_auth_call(node, &self.env_name, &self.address_names, &self.admin_vars) {
                self.first_valid_auth_line = Some(node.span().start().line);
            }
        }
        visit::visit_expr_method_call(self, node);
    }
}

fn pat_ident_name(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(ident) => Some(ident.ident.to_string()),
        Pat::Type(pat_type) => pat_ident_name(&pat_type.pat),
        _ => None,
    }
}

fn is_valid_auth_call(
    method_call: &ExprMethodCall,
    env_name: &str,
    _address_names: &[String],
    admin_vars: &std::collections::HashSet<String>,
) -> bool {
    if method_call.method != "require_auth" && method_call.method != "require_auth_for_args" {
        return false;
    }
    match &*method_call.receiver {
        Expr::Path(p) => {
            if p.path.is_ident(env_name) {
                return true;
            }
            if let Some(ident) = p.path.get_ident() {
                let name = ident.to_string();
                if admin_vars.contains(&name) {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_unprotected_deployer() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn upload(env: Env, wasm: Bytes) {
        env.deployer().upload_contract_wasm(&wasm);
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UnprotectedContractDeploymentCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        Ok(())
    }

    #[test]
    fn ignores_unrelated_require_auth_on_address() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn upload(env: Env, to: Address, wasm: Bytes) {
        to.require_auth();
        env.deployer().upload_contract_wasm(&wasm);
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UnprotectedContractDeploymentCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        Ok(())
    }

    #[test]
    fn flags_auth_after_deployer() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn upload(env: Env, wasm: Bytes) {
        env.deployer().upload_contract_wasm(&wasm);
        env.require_auth();
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UnprotectedContractDeploymentCheck;
        let findings = check.run(&file, src);
        assert_eq!(findings.len(), 1);
        Ok(())
    }

    #[test]
    fn passes_when_env_require_auth_precedes_deployer() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn upload(env: Env, wasm: Bytes) {
        env.require_auth();
        env.deployer().upload_contract_wasm(&wasm);
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UnprotectedContractDeploymentCheck;
        let findings = check.run(&file, src);
        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn passes_when_stored_admin_require_auth_precedes_deployer() -> Result<(), syn::Error> {
        let src = r#"
#[contractimpl]
impl C {
    pub fn upload(env: Env, wasm: Bytes) {
        let admin: Address = env.storage().instance().get(&0).unwrap();
        admin.require_auth();
        env.deployer().upload_contract_wasm(&wasm);
    }
}
        "#;
        let file = parse_file(src)?;
        let check = UnprotectedContractDeploymentCheck;
        let findings = check.run(&file, src);
        assert!(findings.is_empty());
        Ok(())
    }
}
