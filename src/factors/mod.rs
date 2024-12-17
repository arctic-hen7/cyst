mod passphrase;

use crate::factor::{Factor, FactorRegistry};
use passphrase::PassphraseFactor;

pub fn get_factors() -> FactorRegistry {
    let mut factors = FactorRegistry::new();
    factors.insert(PassphraseFactor::name(), Box::new(PassphraseFactor));
    factors
}
