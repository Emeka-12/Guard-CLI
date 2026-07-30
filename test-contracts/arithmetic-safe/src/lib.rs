#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct ArithmeticSafe;

#[contractimpl]
impl ArithmeticSafe {
    /// Uses `checked_add` — should not trigger `unchecked-arithmetic`.
    pub fn total(_env: Env, a: i128, b: i128) -> Option<i128> {
        a.checked_add(b)
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
