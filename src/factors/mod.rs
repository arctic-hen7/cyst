mod ephemeral;
mod keyfile;
mod passphrase;
mod shamir;

use crate::factor::{Factor, FactorRegistry};
use ephemeral::EphemeralFactor;
use keyfile::KeyfileFactor;
use passphrase::PassphraseFactor;
use shamir::ShamirFactor;

pub fn get_factors() -> FactorRegistry {
    let mut factors = FactorRegistry::new();
    factors.insert(PassphraseFactor::name(), Box::new(PassphraseFactor));
    factors.insert(EphemeralFactor::name(), Box::new(EphemeralFactor));
    factors.insert(ShamirFactor::name(), Box::new(ShamirFactor));
    factors.insert(KeyfileFactor::name(), Box::new(KeyfileFactor));
    factors
}
