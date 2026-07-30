#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};

#[contract]
pub struct UninitializedStorageReadVulnerable;

const BALANCE_KEY: Symbol = symbol_short!("balance");

#[contractimpl]
impl UninitializedStorageReadVulnerable {
    /// ❌ Reads from storage and immediately unwraps — panics if key never initialized
    pub fn get_balance(env: Env) -> u128 {
        env.storage().persistent().get(&BALANCE_KEY).unwrap()
    }

    /// ❌ Reads from storage and immediately expects — panics if key never initialized
    pub fn get_balance_expect(env: Env) -> u128 {
        env.storage().instance().get(&BALANCE_KEY).expect("balance not found")
    }
}
