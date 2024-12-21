use crate::factor::Factor;
use anyhow::{bail, Context, Result};
use dialoguer::Input;
use rand::{rngs::OsRng, Rng};
use shamirsecretsharing::{combine_shares, create_shares, DATA_SIZE as SHAMIR_DATA_SIZE};

/// A factor based on Shamir secret sharing, whereby a random secret is split into the
/// user-provided number of shares, which are outputted. A quorum of these can then be brought back
/// together to decrypt the data.
pub struct ShamirFactor;
impl Factor for ShamirFactor {
    type Data = u8;
    type Key = Vec<u8>;

    fn name() -> &'static str {
        "Shamir secret sharing"
    }
    fn create() -> Result<(Self::Data, Self::Key)> {
        let num_shares: u8 = Input::new()
            .with_prompt("How many shares do you want to create?")
            .interact()
            .unwrap();
        let num_quorum: u8 = Input::new()
            .with_prompt("How many of these shares should be required to decrypt the data?")
            .interact()
            .unwrap();

        let mut secret = [0u8; SHAMIR_DATA_SIZE];
        OsRng.fill(&mut secret);
        let shares = create_shares(&secret, num_shares, num_quorum)
            .with_context(|| "failed to split into shares")?;

        // Convert each share to hex and print it
        for (i, share) in shares.iter().enumerate() {
            println!("Share #{}: {}", i + 1, hex::encode(share));
        }

        Ok((num_quorum, secret.to_vec()))
    }
    fn derive(num_quorum: Self::Data) -> Result<Self::Key> {
        let mut shares = Vec::new();
        for i in 0..num_quorum {
            let share_hex: String = Input::new()
                .with_prompt(&format!("Enter share #{}", i + 1))
                .interact()
                .unwrap();
            let share = hex::decode(share_hex.trim())
                .with_context(|| "failed to decode share (are you sure it's correct?)")?;
            shares.push(share);
        }

        let secret = combine_shares(&shares).with_context(|| "failed to combine shares")?;
        if let Some(secret) = secret {
            Ok(secret)
        } else {
            bail!("failed to combine secrets (some are likely corrupted)");
        }
    }
}
