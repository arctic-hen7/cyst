mod ephemeral;
mod passphrase;
mod shamir;

use crate::factor::{Factor, FactorRegistry};
use ephemeral::EphemeralFactor;
use passphrase::PassphraseFactor;
use shamir::ShamirFactor;

pub fn get_factors() -> FactorRegistry {
    let mut factors = FactorRegistry::new();
    factors.insert(PassphraseFactor::name(), Box::new(PassphraseFactor));
    factors.insert(EphemeralFactor::name(), Box::new(EphemeralFactor));
    factors.insert(ShamirFactor::name(), Box::new(ShamirFactor));
    factors
}
