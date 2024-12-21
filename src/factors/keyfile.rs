use crate::factor::Factor;
use anyhow::{bail, Context, Result};
use dialoguer::Input;
use rand::{rngs::OsRng, Rng};

/// An encryption factor using a keyfile.
pub struct KeyfileFactor;
impl Factor for KeyfileFactor {
    type Data = ();
    type Key = [u8; 32];

    fn name() -> &'static str {
        "Keyfile"
    }
    fn create() -> Result<(Self::Data, Self::Key)> {
        // Generate random data
        let key = OsRng.gen::<[u8; 32]>();
        // Prompt the user for a path to write to
        let path: String = Input::new()
            .with_prompt("Enter a path to write the keyfile to")
            .interact()
            .unwrap();
        std::fs::write(&path, &key).with_context(|| "failed to write to given path")?;

        Ok(((), key))
    }
    fn derive(_: Self::Data) -> Result<Self::Key> {
        // Get the path from the user
        let path: String = Input::new()
            .with_prompt("Enter the path to the keyfile")
            .interact()
            .unwrap();

        let raw_key = std::fs::read(&path).with_context(|| "failed to read from given path")?;
        if raw_key.len() != 32 {
            bail!("keyfile had incorrect length (corrupted)");
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&raw_key);

        Ok(key)
    }
}
