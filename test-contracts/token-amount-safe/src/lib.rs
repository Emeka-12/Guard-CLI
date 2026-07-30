#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct TokenAmountSafe;

#[contractimpl]
impl TokenAmountSafe {
    pub fn transfer_safe(env: Env, to: Address, amount: u128) {
        if amount > 0 {
            let token = soroban_sdk::token::Client::new(&env, &Address::default());
            token.transfer(&to, &amount);
        }
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
