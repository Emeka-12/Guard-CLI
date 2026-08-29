#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct AuthOrderVulnerable;

#[contractimpl]
impl AuthOrderVulnerable {
    /// Storage write happens before `env.require_auth()` — should trigger
    /// `auth-after-storage-write` (High).
    pub fn set_value(env: Env, value: i128) {
        env.storage().persistent().set(&symbol_short!("val"), &value);
        env.require_auth();
    }

    /// Storage write happens before `from.require_auth()` — the idiomatic Soroban
    /// form, where authorization is on an `Address` rather than the `Env`. Should
    /// also trigger `auth-after-storage-write` (High).
    pub fn set_for(env: Env, from: Address, value: i128) {
        env.storage().persistent().set(&symbol_short!("val"), &value);
        from.require_auth();
    }
}
