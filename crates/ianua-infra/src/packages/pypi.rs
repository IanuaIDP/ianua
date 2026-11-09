//! A package from a Python package index: its JSON for one exact version,
//! a wheel that runs on any machine, checked against the SHA-256 the index
//! published, and the packages it says it needs.
//!
//! Only a wheel is taken, never source to build, since building runs the
//! package's own code. A wheel's address comes from the index, so it is
//! fetched only over HTTPS from a host the operator lists for the index's
//! files.

use std::path::Path;

use ianua_domain::domains::workflows::sandbox::build::BuildFailure;
use ianua_domain::domains::workflows::sandbox::package::PinnedPackage;
use reqwest::Url;
use serde::Deserialize;

use crate::packages::download::{Answer, archive, metadata};
use crate::packages::{Downloaded, Fetched, Layout, RunsUnder, too_large};

/// What the index says of one version of a package.
#[derive(Deserialize)]
struct Release {
    info: Info,
    urls: Vec<ReleaseFile>,
}

#[derive(Deserialize)]
struct Info {
    #[serde(default)]
    requires_dist: Option<Vec<String>>,
    #[serde(default)]
    requires_python: Option<String>,
}

/// Index metadata used to select a portable wheel and verify its download.
#[derive(Deserialize)]
struct ReleaseFile {
    filename: String,
    packagetype: String,
    digests: Digests,
    url: String,
}

#[derive(Deserialize)]
struct Digests {
    sha256: String,
}

/// Where the index is, and the hosts its files may be fetched from.
pub(super) struct Index<'a> {
    pub(super) base: &'a str,
    pub(super) file_hosts: &'a [String],
}

/// Fetches the wheel of `pinned` from `index` into the file `into`, once it
/// matches its published fingerprint.
pub(super) async fn fetch(
    client: &reqwest::Client,
    index: &Index<'_>,
    pinned: &PinnedPackage,
    into: &Path,
) -> Fetched {
    let name = pinned.name();
    let release = match release_of(client, index.base, pinned).await {
        Ok(release) => release,
        Err(fetched) => return fetched,
    };
    let Some(wheel) = release.urls.iter().find(|file| runs_anywhere(file)) else {
        return Fetched::Refused(BuildFailure::NoWheel(name.clone()));
    };
    if !fetched_from_a_listed_host(&wheel.url, index.file_hosts) {
        return Fetched::Down(format!(
            "{} is not a listed host for the index's files",
            wheel.url
        ));
    }
    let hashes = match archive(client, &wheel.url, into).await {
        Answer::Body(hashes) => hashes,
        Answer::Missing => return Fetched::Refused(BuildFailure::NotFound(name.clone())),
        Answer::TooLarge => return Fetched::Refused(too_large()),
        Answer::Down(why) => return Fetched::Down(why),
    };
    if hex_of(&hashes.sha256) != wheel.digests.sha256.to_ascii_lowercase() {
        return Fetched::Refused(BuildFailure::FingerprintMismatch(name.clone()));
    }
    Fetched::Got(downloaded(release.info))
}

/// Retains the wheel's unconditional dependencies and declared Python versions.
fn downloaded(info: Info) -> Downloaded {
    Downloaded {
        layout: Layout::Wheel,
        needs: needed(info.requires_dist.unwrap_or_default()),
        runs_under: info
            .requires_python
            .map_or(RunsUnder::Any, RunsUnder::Python),
    }
}

/// What the index at `base` says of `pinned`, or what fetching it came to
/// when it says nothing usable.
async fn release_of(
    client: &reqwest::Client,
    base: &str,
    pinned: &PinnedPackage,
) -> Result<Release, Fetched> {
    let url = format!("{base}/pypi/{}/{}/json", pinned.name(), pinned.version());
    match metadata(client, &url).await {
        Answer::Body(body) => serde_json::from_slice(&body)
            .map_err(|error| Fetched::Down(format!("unreadable release: {error}"))),
        Answer::Missing => Err(Fetched::Refused(BuildFailure::NotFound(
            pinned.name().clone(),
        ))),
        Answer::TooLarge => Err(Fetched::Down("release too large".to_owned())),
        Answer::Down(why) => Err(Fetched::Down(why)),
    }
}

/// Whether `file` is a wheel for any machine running Python 3: its tags
/// name no ABI and any platform, and a Python 3 interpreter.
fn runs_anywhere(file: &ReleaseFile) -> bool {
    let Some(stem) = file.filename.strip_suffix(".whl") else {
        return false;
    };
    let mut tags = stem.rsplit('-');
    let (Some(platform), Some(abi), Some(python)) = (tags.next(), tags.next(), tags.next()) else {
        return false;
    };
    file.packagetype == "bdist_wheel"
        && platform == "any"
        && abi == "none"
        && python.split('.').any(|tag| tag == "py3")
}

/// Whether `url` is HTTPS on one of `hosts`.
fn fetched_from_a_listed_host(url: &str, hosts: &[String]) -> bool {
    Url::parse(url).is_ok_and(|url| {
        url.scheme() == "https"
            && url
                .host_str()
                .is_some_and(|host| hosts.iter().any(|listed| listed == host))
    })
}

/// The packages `requires` names that every install needs: a requirement
/// marked for an extra is left out, since nothing here asks for extras.
fn needed(requires: Vec<String>) -> Vec<String> {
    requires
        .into_iter()
        .filter(|requirement| !requirement.replace(' ', "").contains("extra=="))
        .filter_map(|requirement| {
            let name: String = requirement
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                .collect();
            (!name.is_empty()).then_some(name)
        })
        .collect()
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(filename: &str) -> ReleaseFile {
        ReleaseFile {
            filename: filename.to_owned(),
            packagetype: "bdist_wheel".to_owned(),
            digests: Digests {
                sha256: String::new(),
            },
            url: String::new(),
        }
    }

    /// A pure Python 3 wheel runs anywhere; one built for Linux on x86, a
    /// Python 2 only wheel and the source archive do not.
    #[test]
    fn only_a_wheel_for_any_machine_runs_anywhere() {
        assert!(runs_anywhere(&file("requests-2.31.0-py3-none-any.whl")));
        assert!(runs_anywhere(&file("six-1.16.0-py2.py3-none-any.whl")));
        assert!(!runs_anywhere(&file(
            "numpy-2.0.0-cp312-cp312-manylinux_2_17_x86_64.whl"
        )));
        assert!(!runs_anywhere(&file("legacy-1.0-py2-none-any.whl")));
        assert!(!runs_anywhere(&file("requests-2.31.0.tar.gz")));
    }

    /// `requests` needs `idna` and `urllib3` on every install, and `PySocks`
    /// only for its `socks` extra, which is left out.
    #[test]
    fn a_requirement_for_an_extra_is_left_out() {
        let needs = needed(vec![
            "idna (<4,>=2.5)".to_owned(),
            "urllib3<3,>=1.21.1".to_owned(),
            "PySocks!=1.5.7,>=1.5.6; extra == \"socks\"".to_owned(),
        ]);

        assert_eq!(needs, ["idna", "urllib3"]);
    }

    /// Wheel URLs pass the host check only over HTTPS on the configured host;
    /// another host and plain HTTP both fail.
    #[test]
    fn a_wheel_is_fetched_only_over_https_from_a_listed_host() {
        let hosts = vec!["files.pythonhosted.org".to_owned()];

        assert!(fetched_from_a_listed_host(
            "https://files.pythonhosted.org/packages/r.whl",
            &hosts
        ));
        assert!(!fetched_from_a_listed_host(
            "https://evil.test/r.whl",
            &hosts
        ));
        assert!(!fetched_from_a_listed_host(
            "http://files.pythonhosted.org/r.whl",
            &hosts
        ));
    }
}
