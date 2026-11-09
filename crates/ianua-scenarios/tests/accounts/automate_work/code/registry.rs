//! A stand-in npm registry: each package's metadata for one exact version,
//! with the fingerprint it publishes, and its tarball, packed as npm packs
//! them.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use flate2::Compression;
use flate2::write::GzEncoder;
use ianua_scenarios::upstreams::{Canned, CannedApp};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha512};

/// One package the registry serves.
pub(crate) struct Package {
    /// Its name, such as `@acme/pad`.
    pub(crate) name: &'static str,
    /// Its one version.
    pub(crate) version: &'static str,
    /// Its files, by their path inside the package, and what they hold.
    pub(crate) files: &'static [(&'static str, &'static str)],
    /// The packages it says it needs.
    pub(crate) needs: &'static [&'static str],
}

/// Whether the registry publishes each tarball's true fingerprint.
#[derive(Clone, Copy)]
pub(crate) enum Fingerprints {
    /// Each tarball's own.
    True,
    /// Another tarball's, as a tampered mirror would serve.
    Tampered,
}

/// The registry serving `packages`, with fingerprints as `fingerprints`
/// says.
///
/// # Panics
///
/// When the stand-in cannot listen.
pub(crate) async fn registry(packages: &[Package], fingerprints: Fingerprints) -> CannedApp {
    let answers: Vec<(String, Canned)> = packages
        .iter()
        .flat_map(|package| answers_for(package, fingerprints))
        .collect();
    CannedApp::start(
        answers
            .iter()
            .map(|(path, canned)| (path.as_str(), canned.clone())),
    )
    .await
    .expect("the registry stand-in starts")
}

/// Where the registry answers `package`'s metadata.
pub(crate) fn metadata_path(package: &Package) -> String {
    format!("/{}/{}", package.name, package.version)
}

/// Where the registry keeps `package`'s tarball, as npm lays it out.
pub(crate) fn tarball_path(package: &Package) -> String {
    let last = package.name.rsplit('/').next().unwrap_or(package.name);
    format!("/{}/-/{last}-{}.tgz", package.name, package.version)
}

fn answers_for(package: &Package, fingerprints: Fingerprints) -> [(String, Canned); 2] {
    let tarball = tarball_of(package);
    let fingerprinted = match fingerprints {
        Fingerprints::True => tarball.clone(),
        Fingerprints::Tampered => b"another tarball".to_vec(),
    };
    let needs: Map<String, Value> = package
        .needs
        .iter()
        .map(|name| ((*name).to_owned(), json!("^1.0.0")))
        .collect();
    let metadata = json!({
        "name": package.name,
        "version": package.version,
        "dist": { "integrity": format!("sha512-{}", STANDARD.encode(Sha512::digest(&fingerprinted))) },
        "dependencies": needs,
    });
    [
        (metadata_path(package), Canned::json(&metadata)),
        (tarball_path(package), Canned::file(tarball)),
    ]
}

/// `package`'s files under `package/`, as npm packs a tarball.
fn tarball_of(package: &Package) -> Vec<u8> {
    let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
    for (path, body) in package.files {
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header
            .set_path(format!("package/{path}"))
            .expect("a path inside the package");
        header.set_cksum();
        builder
            .append(&header, body.as_bytes())
            .expect("the file is packed");
    }
    builder
        .into_inner()
        .and_then(GzEncoder::finish)
        .expect("the tarball is packed")
}
