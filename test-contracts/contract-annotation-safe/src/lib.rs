#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

// Both #[contract] and #[contractimpl] present — should pass `missing-contract-annotation`.
#[contract]
pub struct AnnotationSafe;

#[contractimpl]
impl AnnotationSafe {
    pub fn hello(_env: Env) -> u32 {
        42
    }
}



#[contractimpl]
impl DelegateSafe {
    /// ✅ The callee address comes from the caller, not from storage.
    /// No delegate-call-risk finding should be produced.
    pub fn forward(env: Env, callee: Address) {
        env.invoke_contract::<()>(
            &callee,
            &symbol_short!("ping"),
            soroban_sdk::vec![&env],
        );
    }
}
