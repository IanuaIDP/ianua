//! A package from an npm registry: its metadata for one exact version, its
//! tarball, checked against the SHA-512 the registry published, and the
//! packages it says it needs.
//!
//! The tarball's address is made here, as npm lays tarballs out, never
//! taken from the metadata, so a registry's answer cannot send the fetch to
//! another host. A package that runs a script when it is installed, or
//! builds native code, is refused: nothing a package holds runs here.

use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ianua_domain::domains::workflows::sandbox::build::BuildFailure;
use ianua_domain::domains::workflows::sandbox::package::PinnedPackage;
use serde::Deserialize;

use crate::packages::download::{Answer, archive, metadata};
use crate::packages::{Downloaded, Fetched, Layout, RunsUnder, too_large};

/// The scripts npm runs when a package is installed.
const INSTALL_SCRIPTS: [&str; 3] = ["preinstall", "install", "postinstall"];

/// What the registry says of one version of a package.
#[derive(Deserialize)]
struct Metadata {
    dist: Dist,
    #[serde(default)]
    scripts: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    dependencies: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    gypfile: bool,
    #[serde(default)]
    engines: serde_json::Value,
}

/// Where the tarball's fingerprint is.
#[derive(Deserialize)]
struct Dist {
    integrity: String,
}

/// Fetches the tarball of `pinned` from the registry at `base` into the
/// file `into`, once it matches its published fingerprint.
pub(super) async fn fetch(
    client: &reqwest::Client,
    base: &str,
    pinned: &PinnedPackage,
    into: &Path,
) -> Fetched {
    let name = pinned.name();
    let metadata = match metadata_of(client, base, pinned).await {
        Ok(metadata) => metadata,
        Err(fetched) => return fetched,
    };
    if runs_when_installed(&metadata) {
        return Fetched::Refused(BuildFailure::InstallScript(name.clone()));
    }
    let Some(expected) = sha512_of(&metadata.dist.integrity) else {
        return Fetched::Refused(BuildFailure::FingerprintMismatch(name.clone()));
    };
    let hashes = match archive(client, &tarball_url(base, pinned), into).await {
        Answer::Body(hashes) => hashes,
        Answer::Missing => return Fetched::Refused(BuildFailure::NotFound(name.clone())),
        Answer::TooLarge => return Fetched::Refused(too_large()),
        Answer::Down(why) => return Fetched::Down(why),
    };
    if hashes.sha512 != expected {
        return Fetched::Refused(BuildFailure::FingerprintMismatch(name.clone()));
    }
    let runs_under = node_range(&metadata.engines);
    Fetched::Got(Downloaded {
        layout: Layout::NodeModule(format!("node_modules/{name}")),
        needs: metadata.dependencies.into_keys().collect(),
        runs_under,
    })
}

/// The Node versions `engines` says the package runs under. Any other
/// shape of `engines`, which old packages use, says nothing.
fn node_range(engines: &serde_json::Value) -> RunsUnder {
    engines
        .get("node")
        .and_then(serde_json::Value::as_str)
        .map_or(RunsUnder::Any, |range| RunsUnder::Node(range.to_owned()))
}

/// What the registry at `base` says of `pinned`, or what fetching it came
/// to when it says nothing usable.
async fn metadata_of(
    client: &reqwest::Client,
    base: &str,
    pinned: &PinnedPackage,
) -> Result<Metadata, Fetched> {
    let url = format!("{base}/{}/{}", pinned.name(), pinned.version());
    match metadata(client, &url).await {
        Answer::Body(body) => serde_json::from_slice(&body)
            .map_err(|error| Fetched::Down(format!("unreadable metadata: {error}"))),
        Answer::Missing => Err(Fetched::Refused(BuildFailure::NotFound(
            pinned.name().clone(),
        ))),
        Answer::TooLarge => Err(Fetched::Down("metadata too large".to_owned())),
        Answer::Down(why) => Err(Fetched::Down(why)),
    }
}

/// Whether installing the package would run code of its own.
fn runs_when_installed(metadata: &Metadata) -> bool {
    metadata.gypfile
        || INSTALL_SCRIPTS
            .iter()
            .any(|script| metadata.scripts.contains_key(*script))
}

/// The SHA-512 an npm `integrity` names, or `None` when it names another
/// hash or none that can be read.
fn sha512_of(integrity: &str) -> Option<Vec<u8>> {
    integrity
        .split_whitespace()
        .find_map(|one| one.strip_prefix("sha512-"))
        .and_then(|encoded| STANDARD.decode(encoded).ok())
}

/// Where npm keeps the tarball of `pinned`: under the package, named for
/// its last part and version.
fn tarball_url(base: &str, pinned: &PinnedPackage) -> String {
    let name = pinned.name().as_str();
    let last = name.rsplit('/').next().unwrap_or(name);
    format!("{base}/{name}/-/{last}-{}.tgz", pinned.version())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::sandbox::package::{PackageName, PackageVersion};
    use ianua_domain::domains::workflows::sandbox::runtime::Language;

    use super::*;

    fn pinned(name: &str) -> PinnedPackage {
        PinnedPackage::new(
            PackageName::new(Language::JavaScript, name).unwrap(),
            PackageVersion::new(Language::JavaScript, "1.2.3").unwrap(),
        )
    }

    /// A scoped package's tarball sits under its full name and is named for
    /// its last part, as npm lays it out.
    #[test]
    fn a_tarball_is_where_npm_lays_it_out() {
        assert_eq!(
            tarball_url("https://registry.test", &pinned("@acme/tools")),
            "https://registry.test/@acme/tools/-/tools-1.2.3.tgz"
        );
        assert_eq!(
            tarball_url("https://registry.test", &pinned("lodash")),
            "https://registry.test/lodash/-/lodash-1.2.3.tgz"
        );
    }

    /// An integrity naming only SHA-1 has no SHA-512 to check against, so
    /// none is read from it.
    #[test]
    fn only_a_sha512_is_checked_against() {
        assert!(sha512_of("sha1-abc").is_none());
        assert_eq!(sha512_of("sha512-AAAA"), Some(vec![0, 0, 0]));
    }
}
