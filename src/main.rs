use anyhow::Result;
use clap::{Parser, Subcommand};
use factors::get_factors;
use file::{decrypt_file, encrypt_file};
use header::Header;
use std::{fs::File, path::PathBuf};

mod factor;
mod factors;
mod file;
mod header;

fn main() -> Result<()> {
    let opts = Opts::parse();
    let factors = get_factors();
    match opts.command {
        Command::Encrypt { input, output } => {
            let (header, encryptor) = Header::new(&factors)?;
            encrypt_file(&input, output.as_deref(), header, encryptor)?;

            if let Some(output) = output {
                eprintln!("Encryption successful! Output written to {output:?}.");
            }
        }
        Command::Decrypt { input, output } => {
            let mut input = File::open(&input)?;
            let header = Header::from_file(&mut input)?;
            let decryptor = header.to_decryptor(&factors)?;
            decrypt_file(&mut input, output.as_deref(), decryptor)?;

            if let Some(output) = output {
                eprintln!("Decryption successful! Output written to {output:?}.");
            }
        }
    }

    Ok(())
}

/// A utility for encrypting and decrypting files with multiple factors.
#[derive(Parser)]
struct Opts {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt a file
    Encrypt {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Decrypt a previously encrypted file
    Decrypt {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}
