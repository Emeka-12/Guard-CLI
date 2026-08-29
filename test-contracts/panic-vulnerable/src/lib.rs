#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct PanicVulnerable;

#[contractimpl]
impl PanicVulnerable {
    /// Uses panic!() directly — triggers `panic-in-contract`.
    pub fn force(_env: Env, flag: bool) -> u32 {
        if flag {
            panic!("flag is set");
        }
        0
    }

    /// Uses unwrap() on a non-storage Option — triggers `panic-in-contract`.
    pub fn get_value(_env: Env, maybe: Option<u32>) -> u32 {
        maybe.unwrap()
    }
}
