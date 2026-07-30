#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct PanicVulnerable;

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


#[contractimpl]
impl PanicVulnerable {
    /// Uses unwrap() — should trigger `panic-in-contract` (Medium).
    pub fn get_value(env: Env) -> u32 {
        env.storage()
            .instance()
            .get::<_, u32>(&symbol_short!("val"))
            .unwrap() // ❌ panics with unhelpful error if key is absent
    }
}
