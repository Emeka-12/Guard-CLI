#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct HardcodedAddressVulnerable;

#[contractimpl]
impl HardcodedAddressVulnerable {
    // ❌ Stellar Ed25519 public key (G-prefixed) baked into source — triggers hardcoded-address
    pub fn get_admin(env: Env) -> Address {
        Address::from_str(&env, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF")
    }

    // ❌ Soroban contract address (C-prefixed) baked into source — triggers hardcoded-address
    pub fn get_token(env: Env) -> Address {
        Address::from_str(&env, "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB5C")
    }
}
