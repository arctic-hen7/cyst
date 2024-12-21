use crate::factor::Factor;
use anyhow::{bail, Result};
use rand::{rngs::OsRng, Rng};
use serde::{Deserialize, Serialize};

/// A factor for ephemeral random data, made by uploading a keyfile to a temporary file hosting
/// service. Once this expires, the option it's part of will entirely cease functioning!
pub struct EphemeralFactor;
impl Factor for EphemeralFactor {
    type Data = EphemeralFactorData;
    type Key = [u8; 32];

    fn name() -> &'static str {
        "Ephemeral data"
    }
    fn create() -> Result<(Self::Data, Self::Key)> {
        // Generate random data
        let data = OsRng.gen::<[u8; 32]>();
        // Prompt the user for the expiry
        let expiry = dialoguer::Input::<u64>::new()
            .with_prompt("How many minutes do you want this ephemeral factor to be valid for?")
            .interact()
            .unwrap();
        // Upload it to a temporary file hosting service (disabling short URL generation to prevent
        // brute-forcing)
        println!("Uploading ephemeral data to the cloud...");
        let resp = ureq::put(&format!("https://oshi.at/?expire={expiry}&shorturl=0"))
            .set("Content-Type", "application/octet-stream")
            .send_bytes(&data)?;
        if resp.status() == 200 {
            println!("Upload successful!");
            let resp_str = resp.into_string()?;
            let lines = resp_str
                .lines()
                .filter(|line| !line.trim().is_empty())
                .collect::<Vec<_>>();
            if lines.len() != 3 {
                bail!("unexpected response from ephemeral data service");
            }
            // Line 1 is the admin, line 2 is the download, and line 3 is the Tor download
            let download_line = lines[1].trim();
            // The URL is that up to the first space
            let url = download_line.split_whitespace().next().unwrap();

            Ok((
                EphemeralFactorData {
                    url: url.to_string(),
                },
                data,
            ))
        } else {
            bail!("failed to upload ephemeral data: {}", resp.into_string()?);
        }
    }
    fn derive(data: Self::Data) -> Result<Self::Key> {
        // Download the file
        println!("Downloading ephemeral data from the cloud...");
        let resp = ureq::get(&data.url).call()?;
        if resp.status() == 200 {
            println!("Download successful!");
            let mut data = [0u8; 32];
            resp.into_reader().read_exact(&mut data)?;
            Ok(data)
        } else {
            bail!(
                "failed to download ephemeral data (may have expired): {}",
                resp.into_string()?
            );
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct EphemeralFactorData {
    url: String,
}
