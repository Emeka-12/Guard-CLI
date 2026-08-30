#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};

#[contract]
pub struct UninitializedStorageReadSafe;

const BALANCE_KEY: Symbol = symbol_short!("balance");

#[contractimpl]
impl UninitializedStorageReadSafe {
    /// ✅ Guards with has() before reading, then reads safely
    pub fn get_balance(env: Env) -> u128 {
        if !env.storage().persistent().has(&BALANCE_KEY) {
            return 0;
        }
        env.storage().persistent().get(&BALANCE_KEY).unwrap_or_default()
    }

    /// ✅ Uses unwrap_or_default() to safely handle uninitialized storage
    pub fn get_balance_default(env: Env) -> u128 {
        env.storage().instance().get(&BALANCE_KEY).unwrap_or_default()
    }

    /// ✅ Uses unwrap_or() with a fallback value
    pub fn get_balance_fallback(env: Env) -> u128 {
        env.storage().persistent().get(&BALANCE_KEY).unwrap_or(0)
    }
}
