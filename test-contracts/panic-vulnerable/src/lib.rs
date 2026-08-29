#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct PanicVulnerable;

#[contractimpl]
impl PanicVulnerable {
    /// Uses unwrap() — should trigger `panic-in-contract` (Medium).
    pub fn get_value(_env: Env) -> u32 {
        Some(7u32).unwrap() // ❌ panics with an unhelpful error
    }
}
