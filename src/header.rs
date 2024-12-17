use crate::factor::FactorRegistry;
use anyhow::{anyhow, Result};
use argon2::Argon2;
use chacha20poly1305::{
    aead::{
        stream::{DecryptorBE32, Encryptor, EncryptorBE32},
        Aead,
    },
    AeadCore, ChaCha20Poly1305, KeyInit,
};
use dialoguer::{Confirm, Input, Select};
use rand::{rngs::OsRng, Rng};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs::File, io::Read};

/// A header for data encrypted using Cyst.
#[derive(Serialize, Deserialize)]
pub struct Header {
    /// All the options available for decrypting the file, indexed by their user-provided names.
    options: HashMap<String, OptionData>,
    /// The nonce used to encrypt the file's contents.
    ///
    /// Don't ask me why this is size 7, it's got something to do with the encryptor parameters for
    /// the STREAM construction but it's horribly documented and I'm just going off failing
    /// assertions screaming 7 at me.
    nonce: [u8; 7],
}
impl Header {
    /// Creates a new header by prompting the user to set up the encryption options they want. This
    /// returns the header and an encryptor ready to encrypt the data chunk-by-chunk.
    pub fn new(registry: &FactorRegistry) -> Result<(Self, EncryptorBE32<ChaCha20Poly1305>)> {
        // Generate a nonce (used to actually encrypt the data)
        let primary_key = OsRng.gen::<[u8; 32]>();
        let nonce = OsRng.gen::<[u8; 7]>();

        // Prompt the user for a series of options
        let mut is_first = true;
        let mut options = HashMap::new();
        loop {
            // Always prompt for a first option, and otherwise confirm with the user first
            if is_first
                || Confirm::new()
                    .with_prompt("Add another encryption option?")
                    .interact()
                    .unwrap()
            {
                is_first = false;
                let (name, option_data) = prompt_option(&primary_key, registry)?;
                options.insert(name, option_data);
            } else {
                break;
            }
        }

        let cipher = ChaCha20Poly1305::new(primary_key.as_ref().into());
        let encryptor = Encryptor::from_aead(cipher, nonce.as_ref().into());

        Ok((Self { options, nonce }, encryptor))
    }

    /// Derives a decryptor from this header by prompting the user to provide details to satisfy
    /// one of the decryption options.
    pub fn to_decryptor(
        &self,
        registry: &FactorRegistry,
    ) -> Result<DecryptorBE32<ChaCha20Poly1305>> {
        // Prompt the user for which option they want to take
        let mut options = self.options.keys().collect::<Vec<_>>();
        options.sort();
        let option_idx = Select::new()
            .with_prompt("Choose an option for decryption")
            .items(&options)
            .interact()
            .unwrap();
        let option_data = &self.options[options[option_idx]];

        // Prompt the user for each factor in the option
        let mut total_key = Vec::new();
        for (factor_name, factor_data) in &option_data.factors {
            println!("Please follow the prompts for factor '{}':", factor_name);
            let factor = &registry
                .get(factor_name.as_str())
                .ok_or(anyhow!("unknown factor '{factor_name}'"))?;
            // Hand over to the factor's prompting process to derive its key
            let key = factor.derive(&factor_data)?;
            total_key.extend(key);
        }

        // Derive the option key from the total key and the salt
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(&total_key, &option_data.salt, &mut key)
            .unwrap();
        // And use that to decrypt the primary key
        let cipher = ChaCha20Poly1305::new(key.as_ref().into());
        let primary_key = cipher
            .decrypt(
                &option_data.primary_key_nonce.into(),
                option_data.primary_key_ciphertext.as_ref(),
            )
            .map_err(|_| anyhow!("decryption failed"))?;

        let cipher = ChaCha20Poly1305::new(primary_key.as_slice().into());
        Ok(DecryptorBE32::from_aead(cipher, self.nonce.as_ref().into()))
    }

    /// Writes this header to bytes, including a length prefix to allow it to be read back later.
    /// Raw ciphertext can be written directly after this.
    pub fn to_bytes(&self) -> Vec<u8> {
        let header_bytes = bincode::serialize(self).unwrap();
        let header_len = header_bytes.len() as u64;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&header_len.to_le_bytes());
        bytes.extend_from_slice(&header_bytes);

        bytes
    }

    /// Reads a header from the given file, returning it and leaving the file's cursor directly
    /// after the headerv (presumably at the beginning of ciphertext).
    pub fn from_file(file: &mut File) -> Result<Self> {
        // Read the length of the header, then read that many bytes
        let mut header_len_bytes = [0u8; 8];
        file.read_exact(&mut header_len_bytes)?;
        let header_len = u64::from_le_bytes(header_len_bytes);
        let mut header_bytes = vec![0u8; header_len as usize];
        file.read_exact(&mut header_bytes)?;

        // Deserialise the header
        let header: Self = bincode::deserialize(&header_bytes)?;

        Ok(header)
    }
}

/// The data associated with an encryption option. From this, and the user's responses to factor
/// prompts, a decryption key can be derived.
#[derive(Serialize, Deserialize)]
struct OptionData {
    /// The randomly-generated salt used to derive the final key from all the factor keys.
    salt: [u8; 32],
    /// All the factors used in this option, and their respective data.
    factors: Vec<(String, Vec<u8>)>,
    /// The nonce used for encrypting the primary key.
    primary_key_nonce: [u8; 12],
    /// The primary key, encrypted with this option's key.
    primary_key_ciphertext: Vec<u8>,
}

/// Prompts the user for a single factor, returning its name, data, and key.
fn prompt_factor(registry: &FactorRegistry) -> Result<(&'static str, Vec<u8>, Vec<u8>)> {
    // Prompt the user to select a factor
    let mut factor_names = registry.keys().collect::<Vec<_>>();
    factor_names.sort();
    let factor_idx = Select::new()
        .with_prompt("Choose an encryption factor to use")
        .items(&factor_names)
        .interact()
        .unwrap();
    let factor = &registry[factor_names[factor_idx]];
    // Enter that factor's prompting process and get its data and a key
    let (data, key) = factor.create()?;
    Ok((factor.name(), data, key))
}

/// Prompts the user for a series of factors, encrypting the given primary key and returning the
/// data needed to decrypt the resulting ciphertext, along with the user-provided name of the
/// option.
fn prompt_option(
    primary_key: &[u8; 32],
    registry: &FactorRegistry,
) -> Result<(String, OptionData)> {
    let name: String = Input::new()
        .with_prompt("Enter a name for this encryption option")
        .interact_text()
        .unwrap();

    let mut is_first = true;
    let mut factors = Vec::new();
    let mut total_key = Vec::new();
    loop {
        // Always prompt for a first factor, and otherwise confirm with the user first
        if is_first
            || Confirm::new()
                .with_prompt("Add another factor?")
                .interact()
                .unwrap()
        {
            is_first = false;
            let (name, data, key) = prompt_factor(registry)?;
            // Save the factor's details and extend the all-factors key
            factors.push((name.to_string(), data));
            total_key.extend(key);
        } else {
            break;
        }
    }

    // Derive a proper symmetric key using a random salt
    let salt = OsRng.gen::<[u8; 32]>();
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(&total_key, &salt, &mut key)
        .unwrap();

    // Encrypt the primary key with that
    let cipher = ChaCha20Poly1305::new(key.as_ref().into());
    let nonce = ChaCha20Poly1305::generate_nonce(OsRng);
    let primary_key_ciphertext = cipher.encrypt(&nonce, primary_key.as_ref()).unwrap();

    Ok((
        name,
        OptionData {
            salt,
            factors,
            primary_key_nonce: nonce.into(),
            primary_key_ciphertext,
        },
    ))
}
