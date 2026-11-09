//! Reading one address of a registry, told apart into "not there", "down"
//! and "here": a package's metadata into memory, held to a small cap, and
//! a package's archive straight to a file on disk, hashed as it arrives
//! and held to the most a bundle may weigh.

use std::path::Path;

use ianua_domain::domains::workflows::sandbox::build::MAX_BUNDLE_BYTES;
use reqwest::StatusCode;
use sha2::{Digest as _, Sha256, Sha512};
use tokio::io::AsyncWriteExt as _;

/// The most bytes one version's metadata may hold.
const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;

/// What one address of a registry answered.
#[derive(Debug)]
pub(super) enum Answer<T> {
    /// What it held.
    Body(T),
    /// The registry has nothing there.
    Missing,
    /// More than may be read, so it was not read to the end.
    TooLarge,
    /// The registry could not be reached, failed, or the file could not be
    /// written, as this says.
    Down(String),
}

/// What a fetched archive hashes to.
#[derive(Debug)]
pub(super) struct Hashes {
    /// Its SHA-256.
    pub(super) sha256: Vec<u8>,
    /// Its SHA-512.
    pub(super) sha512: Vec<u8>,
}

/// The metadata `client` reads at `url`.
pub(super) async fn metadata(client: &reqwest::Client, url: &str) -> Answer<Vec<u8>> {
    let mut response = match opened(client, url).await {
        Answer::Body(response) => response,
        Answer::Missing => return Answer::Missing,
        Answer::TooLarge => return Answer::TooLarge,
        Answer::Down(why) => return Answer::Down(why),
    };
    let mut body = Vec::new();
    loop {
        let chunk = match response.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => return Answer::Body(body),
            Err(error) => return Answer::Down(error.without_url().to_string()),
        };
        body.extend_from_slice(&chunk);
        if u64::try_from(body.len()).unwrap_or(u64::MAX) > MAX_METADATA_BYTES {
            return Answer::TooLarge;
        }
    }
}

/// The archive `client` reads at `url`, written to `into` as it arrives.
pub(super) async fn archive(client: &reqwest::Client, url: &str, into: &Path) -> Answer<Hashes> {
    let mut response = match opened(client, url).await {
        Answer::Body(response) => response,
        Answer::Missing => return Answer::Missing,
        Answer::TooLarge => return Answer::TooLarge,
        Answer::Down(why) => return Answer::Down(why),
    };
    let mut file = match tokio::fs::File::create(into).await {
        Ok(file) => file,
        Err(error) => return Answer::Down(format!("the archive cannot be written: {error}")),
    };
    write_archive(&mut response, &mut file).await
}

/// Streams a response into the archive, bounding its size and hashing the written bytes.
async fn write_archive(
    response: &mut reqwest::Response,
    file: &mut tokio::fs::File,
) -> Answer<Hashes> {
    let (mut sha256, mut sha512, mut bytes) = (Sha256::new(), Sha512::new(), 0_u64);
    loop {
        let chunk = match response.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(error) => return Answer::Down(error.without_url().to_string()),
        };
        bytes = bytes.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        if bytes > MAX_BUNDLE_BYTES {
            return Answer::TooLarge;
        }
        sha256.update(&chunk);
        sha512.update(&chunk);
        if let Err(error) = file.write_all(&chunk).await {
            return Answer::Down(format!("the archive cannot be written: {error}"));
        }
    }
    if let Err(error) = file.flush().await {
        return Answer::Down(format!("the archive cannot be written: {error}"));
    }
    Answer::Body(Hashes {
        sha256: sha256.finalize().to_vec(),
        sha512: sha512.finalize().to_vec(),
    })
}

/// The response `client` gets at `url`, once it says something is there.
async fn opened(client: &reqwest::Client, url: &str) -> Answer<reqwest::Response> {
    let response = match client.get(url).send().await {
        Ok(response) => response,
        Err(error) => return Answer::Down(error.without_url().to_string()),
    };
    match response.status() {
        StatusCode::OK => Answer::Body(response),
        StatusCode::NOT_FOUND | StatusCode::GONE => Answer::Missing,
        status => Answer::Down(format!("the registry answered {status}")),
    }
}
