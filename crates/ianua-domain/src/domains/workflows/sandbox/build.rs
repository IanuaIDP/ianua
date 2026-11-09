//! What building a version's package bundle came to, or scanning its own
//! image: under way, ready, or failed with a reason a person can act on.

use crate::domains::workflows::sandbox::image::{LesserFindings, VulnerabilityId};
use crate::domains::workflows::sandbox::package::{PackageName, Packages};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::{Charset, TextValue, Validator, text_value};

/// The largest bundle one version may have, in bytes.
pub const MAX_BUNDLE_BYTES: u64 = 200 * 1024 * 1024;

/// The most files one bundle may hold.
pub const MAX_BUNDLE_FILES: usize = 50_000;

text_value! {
    /// The SHA-256 of a bundle, as 64 lowercase hex digits.
    pub struct BundleDigest;
}

impl TextValue for BundleDigest {
    const FIELD: &'static str = "bundle_digest";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .length(64..=64)
            .charset(Charset::DIGIT | Charset::HEX_LETTER)
    }
}

/// A version's packages, fetched, checked against their published
/// fingerprints and stored as one bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    digest: BundleDigest,
    bytes: u64,
    unlisted: Vec<PackageName>,
}

impl Bundle {
    /// A bundle of `bytes` hashing to `digest`. `unlisted` names the
    /// packages a pinned one says it needs that the version does not pin;
    /// they are not in the bundle, and the person is told.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it is larger than
    ///   [`MAX_BUNDLE_BYTES`].
    pub fn new(
        digest: BundleDigest,
        bytes: u64,
        unlisted: Vec<PackageName>,
    ) -> Result<Self, DomainError> {
        if bytes > MAX_BUNDLE_BYTES {
            return Err(DomainError::invalid(message!(
                "workflows-a-bundle-may-be-at-most",
                format!("a bundle may be at most {MAX_BUNDLE_BYTES} bytes")
            )));
        }
        Ok(Self {
            digest,
            bytes,
            unlisted,
        })
    }

    /// What it hashes to.
    #[must_use]
    pub fn digest(&self) -> &BundleDigest {
        &self.digest
    }

    /// How large it is, in bytes.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// The packages a pinned one needs that the version does not pin.
    #[must_use]
    pub fn unlisted(&self) -> &[PackageName] {
        &self.unlisted
    }

    /// Whether it could be the bundle of `packages`: nothing it names as
    /// unlisted is pinned after all.
    pub(super) fn fits(&self, packages: &Packages) -> bool {
        self.unlisted.iter().all(|name| !packages.pins(name))
    }
}

/// Why a version's bundle could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildFailure {
    /// The registry has no such package at that version.
    NotFound(PackageName),
    /// What the registry sent does not match the fingerprint it published,
    /// so it is not what the version names.
    FingerprintMismatch(PackageName),
    /// The package runs a script when it is installed, which could do
    /// anything on the machine building the bundle.
    InstallScript(PackageName),
    /// The Python package has no wheel that runs on any machine, only ones
    /// built for particular machines or source to compile.
    NoWheel(PackageName),
    /// The package's archive could not be read, or holds what no bundle
    /// takes: a path climbing out of its folder, a link, a file twice, or
    /// more files than a bundle may hold.
    BadArchive(PackageName),
    /// The package says it does not run under the version's runtime, such
    /// as one that needs Python 3.13 in a version saved under 3.11.
    WrongRuntime(PackageName),
    /// The bundle came to more than [`MAX_BUNDLE_BYTES`].
    TooLarge {
        /// How large it came to.
        bytes: u64,
    },
    /// The registry could not be reached, every time it was tried.
    RegistryUnavailable,
    /// Scanning the company's image found these critical known
    /// vulnerabilities, so it never runs.
    CriticalVulnerabilities(Vec<VulnerabilityId>),
    /// No vulnerability scanner is set up, so no company image is cleared
    /// to run.
    NotScanned,
    /// The scanner could not scan the image, every time it was tried.
    ScannerUnavailable,
    /// The image's registry is no longer on the tenant's list.
    RegistryNotAllowed,
    /// The installation does not run companies' own images.
    OwnImagesOff,
}

impl BuildFailure {
    /// A stable name for the kind of failure.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotFound(_) => "not_found",
            Self::FingerprintMismatch(_) => "fingerprint_mismatch",
            Self::InstallScript(_) => "install_script",
            Self::NoWheel(_) => "no_wheel",
            Self::BadArchive(_) => "bad_archive",
            Self::WrongRuntime(_) => "wrong_runtime",
            Self::TooLarge { .. } => "too_large",
            Self::RegistryUnavailable => "registry_unavailable",
            Self::CriticalVulnerabilities(_) => "critical_vulnerabilities",
            Self::NotScanned => "not_scanned",
            Self::ScannerUnavailable => "scanner_unavailable",
            Self::RegistryNotAllowed => "registry_not_allowed",
            Self::OwnImagesOff => "own_images_off",
        }
    }

    /// The package it is about, how large the bundle came to, or the
    /// critical findings, comma-separated; empty when there is nothing more
    /// to say.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::NotFound(name)
            | Self::FingerprintMismatch(name)
            | Self::InstallScript(name)
            | Self::NoWheel(name)
            | Self::BadArchive(name)
            | Self::WrongRuntime(name) => name.as_str().to_owned(),
            Self::TooLarge { bytes } => bytes.to_string(),
            Self::CriticalVulnerabilities(found) => found
                .iter()
                .map(VulnerabilityId::as_str)
                .collect::<Vec<_>>()
                .join(", "),
            Self::RegistryUnavailable
            | Self::NotScanned
            | Self::ScannerUnavailable
            | Self::RegistryNotAllowed
            | Self::OwnImagesOff => String::new(),
        }
    }
}

/// How far building a version's bundle, or scanning its own image, got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Build {
    /// The packages are being fetched and checked, or the image scanned.
    Building,
    /// The bundle is ready.
    Ready(Bundle),
    /// The company's image was scanned and found nothing critical; it runs,
    /// and what was found below that is shown beside it.
    Cleared(LesserFindings),
    /// It could not be built, for this reason.
    Failed(BuildFailure),
}

impl Build {
    /// A stable name for where it stands: a cleared image is as ready as a
    /// built bundle.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Building => "building",
            Self::Ready(_) | Self::Cleared(_) => "ready",
            Self::Failed(_) => "failed",
        }
    }

    /// Whether the version may run: its bundle built, or its image cleared.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_) | Self::Cleared(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest() -> BundleDigest {
        BundleDigest::new("a".repeat(64)).unwrap()
    }

    /// A digest of 64 lowercase hex digits is taken; one in capitals, or
    /// one digit short, is refused.
    #[test]
    fn a_digest_is_sixty_four_lowercase_hex_digits() {
        assert!(BundleDigest::new("A".repeat(64)).is_err());
        assert!(BundleDigest::new("a".repeat(63)).is_err());
        assert_eq!(digest().as_str().len(), 64);
    }

    /// A bundle of 200 MiB is taken; one byte more is refused.
    #[test]
    fn a_bundle_keeps_to_its_size() {
        assert!(Bundle::new(digest(), MAX_BUNDLE_BYTES, Vec::new()).is_ok());
        assert!(Bundle::new(digest(), MAX_BUNDLE_BYTES + 1, Vec::new()).is_err());
    }
}
