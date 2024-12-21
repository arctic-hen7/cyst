use crate::header::Header;
use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::stream::{DecryptorBE32, EncryptorBE32},
    ChaCha20Poly1305,
};
use std::{
    fs::File,
    io::{Read, Seek, Write},
    path::Path,
};

/// The size of buffer used for streaming encryption and decryption.
const BUF_SIZE: u64 = 4096;

/// Encrypts the given path, writing the data encrypted with the given stream encryptor to the
/// output path. The provided header will be written as well.
pub fn encrypt_file(
    input_path: &Path,
    output_path: Option<&Path>,
    header: Header,
    mut encryptor: EncryptorBE32<ChaCha20Poly1305>,
) -> Result<()> {
    let mut output: Box<dyn Write> = if let Some(output_path) = output_path {
        Box::new(File::create(output_path)?)
    } else {
        Box::new(std::io::stdout().lock())
    };
    // Write the header immediately
    output.write_all(&header.to_bytes())?;

    // Encrypt chunks of the input file and write them directly to the output file
    let mut input = File::open(input_path)?;
    let input_size = input.metadata()?.len();
    let mut buffer = [0; BUF_SIZE as usize];
    loop {
        // If we have more bytes left than the buffer size, we aren't at the last chunk (handled
        // specially by the algorithm)
        let bytes_left = input_size - input.stream_position()?;
        if bytes_left > BUF_SIZE {
            input.read(&mut buffer)?;
            let encrypted = encryptor
                .encrypt_next(buffer.as_ref())
                .map_err(|_| anyhow!("encryption failed"))?;
            output.write_all(&encrypted)?;
        } else {
            let read = input.read(&mut buffer)?;
            let encrypted = encryptor
                .encrypt_last(&buffer[..read])
                .map_err(|_| anyhow!("encryption failed"))?;
            output.write_all(&encrypted)?;

            break;
        }
    }

    Ok(())
}

/// Decrypts the given file using the provided decryptor. It is assumed that the given [`File`]
/// will be at the start of the ciphertext (after the header).
pub fn decrypt_file(
    input: &mut File,
    output_path: Option<&Path>,
    mut decryptor: DecryptorBE32<ChaCha20Poly1305>,
) -> Result<()> {
    let mut output: Box<dyn Write> = if let Some(output_path) = output_path {
        Box::new(File::create(output_path)?)
    } else {
        Box::new(std::io::stdout().lock())
    };

    // Decrypt chunks of the input file and write them directly to the output file
    let input_size = input.metadata()?.len();
    let mut buffer = [0; BUF_SIZE as usize];
    loop {
        // If we have more bytes left than the buffer size, we aren't at the last chunk (handled
        // specially by the algorithm)
        let bytes_left = input_size - input.stream_position()?;
        if bytes_left > BUF_SIZE {
            input.read(&mut buffer)?;
            let decrypted = decryptor
                .decrypt_next(buffer.as_ref())
                .map_err(|_| anyhow!("encryption failed"))?;
            output.write_all(&decrypted)?;
        } else {
            let read = input.read(&mut buffer)?;
            let decrypted = decryptor
                .decrypt_last(&buffer[..read])
                .map_err(|_| anyhow!("encryption failed"))?;
            output.write_all(&decrypted)?;

            break;
        }
    }

    Ok(())
}
