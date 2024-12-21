use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An encryption factor. Multiple factors may be combined in a single encryption *option*. For
/// example, there might be three options to decrypt a file: a passphrase, some random data read
/// from a keyfile, or a combination of a hardware token and a PIN. The first two options are
/// single-factor options, but the third has two factors. In essence, the options are the "OR"
/// disjunctions, and the factors are the "AND" conjunctions.
pub trait Factor {
    /// The data this factor produces during creation, which it needs for later derivation. This
    /// might be something like a salt, a nonce, or something similar. Some factors will have no
    /// data.
    type Data: Serialize + for<'de> Deserialize<'de>;
    /// The key this factor produces, which is run through a KDF with all other factors in an
    /// option to produce a symmetric key. In general, this should be around 32 bytes long, but
    /// it's allowed to be defined to avoid unnecessary heap allocation.
    type Key: AsRef<[u8]>;

    /// Gets the name of this factor, which will be given to the user in prompting them which
    /// factors they want to choose. This must be globally unique among all factors.
    fn name() -> &'static str;
    /// Creates an instance of this factor by prompting the user, returning the data we'll need to
    /// derive this factor in future and a key.
    fn create() -> Result<(Self::Data, Self::Key)>;
    /// Derives this factor from the data it was created with. This should prompt the user as
    /// necessary to derive the same key as it originally created.
    fn derive(data: Self::Data) -> Result<Self::Key>;
}

/// A type-erased version of [`Factor`] that returns raw serialised data and keys.
pub trait BoxedFactor {
    fn name(&self) -> &'static str;
    fn create(&self) -> Result<(Vec<u8>, Vec<u8>)>;
    fn derive(&self, data: &[u8]) -> Result<Vec<u8>>;
}
impl<F: Factor> BoxedFactor for F {
    fn name(&self) -> &'static str {
        F::name()
    }

    fn create(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let (data, key) = F::create()?;
        let data_bytes = bincode::serialize(&data)?;
        let key_bytes = key.as_ref().to_vec();
        Ok((data_bytes, key_bytes))
    }

    fn derive(&self, data_bytes: &[u8]) -> Result<Vec<u8>> {
        let data: F::Data = bincode::deserialize(data_bytes)?;
        Ok(F::derive(data)?.as_ref().to_vec())
    }
}

/// A registry of many different factors, indexed by their names.
pub type FactorRegistry = HashMap<&'static str, Box<dyn BoxedFactor>>;
