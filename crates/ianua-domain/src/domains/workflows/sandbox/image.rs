//! A company's own container image, which a sandbox version may run in
//! place of code under one of the offered runtimes: the registry it comes
//! from, the exact digest a version keeps, and what scanning it for known
//! vulnerabilities found.
//!
//! Ann names `registry.acme.example/tools/codegen:1.4`. Saving her version
//! asks the registry what that tag points to now and keeps the digest, so a
//! push to `1.4` next week never changes the version she saved. Before its
//! first run the image is scanned; one critical finding refuses it.

use crate::domains::workflows::sandbox::network::AllowedHost;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::{Charset, Rule, TextValue, ValidationError, Validator, text_value};

/// The largest image a version may run, in bytes, as its registry counts
/// the layers it is pulled in. A pull is bounded by it.
pub const MAX_IMAGE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// The most critical findings a refused image names; the rest are counted.
pub(crate) const MAX_NAMED_FINDINGS: usize = 20;

text_value! {
    /// The registry an image comes from, as its DNS name with an optional
    /// port, such as `registry.acme.example` or `ghcr.io:443`. Never an
    /// address written as numbers, so the platform looks the name up and
    /// refuses one that leads somewhere private.
    pub struct RegistryHost;
}

impl TextValue for RegistryHost {
    const FIELD: &'static str = "registry";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .length(3..=259)
            .charset(
                Charset::LOWERCASE
                    | Charset::DIGIT
                    | Charset::HYPHEN
                    | Charset::DOT
                    | Charset::COLON,
            )
            .rule(&RegistryAddress)
    }

    fn normalized(value: String) -> String {
        value.to_ascii_lowercase()
    }
}

text_value! {
    /// The path of an image inside its registry, such as `tools/codegen`:
    /// parts of lowercase letters and digits joined by `.`, `_` or `-`.
    pub struct ImageRepository;
}

impl TextValue for ImageRepository {
    const FIELD: &'static str = "repository";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .length(1..=255)
            .charset(
                Charset::LOWERCASE
                    | Charset::DIGIT
                    | Charset::HYPHEN
                    | Charset::DOT
                    | Charset::UNDERSCORE
                    | Charset::SLASH,
            )
            .rule(&PlainParts)
    }
}

text_value! {
    /// A tag an image is pushed under, such as `1.4` or `latest`. It may
    /// move to another image at any time, so a version never keeps one.
    pub struct ImageTag;
}

impl TextValue for ImageTag {
    const FIELD: &'static str = "tag";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .length(1..=128)
            .charset(
                Charset::LOWERCASE
                    | Charset::UPPERCASE
                    | Charset::DIGIT
                    | Charset::HYPHEN
                    | Charset::DOT
                    | Charset::UNDERSCORE,
            )
            .rule(&StartsPlain)
    }
}

text_value! {
    /// The SHA-256 of an image's manifest, as `sha256:` and 64 lowercase
    /// hex digits: what names the image by its content.
    pub struct ImageDigest;
}

impl TextValue for ImageDigest {
    const FIELD: &'static str = "digest";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.length(71..=71).rule(&Sha256Named)
    }
}

/// What a person names an image by: its registry, its path there and the
/// tag or digest it is read at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageName {
    registry: RegistryHost,
    repository: ImageRepository,
    reference: ImageReference,
}

/// Where in a repository an image name points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageReference {
    /// A tag, which the registry is asked about when the version is saved.
    Tag(ImageTag),
    /// A digest, kept as it is.
    Digest(ImageDigest),
}

impl ImageName {
    /// The image `text` names, such as `registry.acme.example/tools/codegen:1.4`
    /// or `ghcr.io/acme/codegen@sha256:…`. A name with neither a tag nor a
    /// digest points at `latest`, as container engines read it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it names no registry first, or a
    ///   part is not one an image name holds.
    pub fn parse(text: &str) -> Result<Self, DomainError> {
        let Some((registry, rest)) = text.split_once('/') else {
            return Err(no_registry());
        };
        let registry = RegistryHost::new(registry).map_err(|_| no_registry())?;
        let (repository, reference) = match rest.split_once('@') {
            Some((repository, digest)) => (
                repository,
                ImageReference::Digest(ImageDigest::new(digest)?),
            ),
            None => split_tag(rest)?,
        };
        Ok(Self {
            registry,
            repository: ImageRepository::new(repository)?,
            reference,
        })
    }

    /// The registry it comes from.
    #[must_use]
    pub fn registry(&self) -> &RegistryHost {
        &self.registry
    }

    /// Its path inside the registry.
    #[must_use]
    pub fn repository(&self) -> &ImageRepository {
        &self.repository
    }

    /// The tag or digest it is read at.
    #[must_use]
    pub fn reference(&self) -> &ImageReference {
        &self.reference
    }

    /// The same image, pinned to `digest`: what its tag pointed to when
    /// the registry was asked.
    #[must_use]
    pub fn pinned(&self, digest: ImageDigest) -> PinnedImage {
        PinnedImage::of(self.registry.clone(), self.repository.clone(), digest)
    }
}

/// An image named by its content: registry, path and digest, so it is the
/// same image every time, however its tags move.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PinnedImage {
    registry: RegistryHost,
    repository: ImageRepository,
    digest: ImageDigest,
    full: String,
}

impl PinnedImage {
    /// The image `text` names in full, such as
    /// `registry.acme.example/tools/codegen@sha256:…`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it names no registry, or no
    ///   digest, or a part is not one an image name holds.
    pub fn parse(text: &str) -> Result<Self, DomainError> {
        let name = ImageName::parse(text)?;
        let ImageReference::Digest(digest) = name.reference else {
            return Err(DomainError::invalid(message!(
                "workflows-a-kept-image-is-named-by-its-digest",
                "a kept image is named by its digest: registry, path, @sha256: and 64 hex digits"
            )));
        };
        Ok(Self::of(name.registry, name.repository, digest))
    }

    fn of(registry: RegistryHost, repository: ImageRepository, digest: ImageDigest) -> Self {
        let full = format!(
            "{}/{}@{}",
            registry.as_str(),
            repository.as_str(),
            digest.as_str()
        );
        Self {
            registry,
            repository,
            digest,
            full,
        }
    }

    /// The registry it comes from, whose login pulls it.
    #[must_use]
    pub fn registry(&self) -> &RegistryHost {
        &self.registry
    }

    /// Its path inside the registry.
    #[must_use]
    pub fn repository(&self) -> &ImageRepository {
        &self.repository
    }

    /// The digest of its manifest.
    #[must_use]
    pub fn digest(&self) -> &ImageDigest {
        &self.digest
    }

    /// The whole reference a container engine pulls it by.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.full
    }
}

/// A company's image as a version keeps it: pinned to its digest, and how
/// large its registry said it is when the version was saved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnImage {
    image: PinnedImage,
    bytes: u64,
}

impl OwnImage {
    /// `image`, of `bytes` as its registry counts its layers.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it is larger than
    ///   [`MAX_IMAGE_BYTES`].
    pub fn new(image: PinnedImage, bytes: u64) -> Result<Self, DomainError> {
        if bytes > MAX_IMAGE_BYTES {
            return Err(DomainError::invalid(message!(
                "workflows-an-image-may-be-at-most",
                format!("an image may be at most {MAX_IMAGE_BYTES} bytes; this one is {bytes}")
            )));
        }
        Ok(Self { image, bytes })
    }

    /// The image, named by its content.
    #[must_use]
    pub fn image(&self) -> &PinnedImage {
        &self.image
    }

    /// How large it is, in bytes.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

text_value! {
    /// A known vulnerability as a scanner names it, such as
    /// `CVE-2024-3094` or `GHSA-xvch-5gv4-984h`.
    pub struct VulnerabilityId;
}

impl TextValue for VulnerabilityId {
    const FIELD: &'static str = "vulnerability";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.length(1..=64).charset(
            Charset::LOWERCASE
                | Charset::UPPERCASE
                | Charset::DIGIT
                | Charset::HYPHEN
                | Charset::DOT
                | Charset::UNDERSCORE
                | Charset::COLON,
        )
    }
}

impl VulnerabilityId {
    /// A finding whose scanner gave it no name this platform takes; it
    /// still counts, and still refuses the image when it is critical.
    #[must_use]
    pub fn unnamed() -> Self {
        Self("unnamed".to_owned())
    }
}

/// How many findings below critical a scan made, which do not refuse an
/// image but are shown beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LesserFindings {
    /// Findings rated high.
    pub high: u32,
    /// Findings rated medium.
    pub medium: u32,
    /// Findings rated low or not rated.
    pub low: u32,
}

/// What scanning an image for known vulnerabilities found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageFindings {
    critical: Vec<VulnerabilityId>,
    lesser: LesserFindings,
}

impl ImageFindings {
    /// A scan that found `critical`, each named once, and `lesser` below
    /// that. Only the first `MAX_NAMED_FINDINGS` critical ones are kept.
    #[must_use]
    pub fn new(critical: Vec<VulnerabilityId>, lesser: LesserFindings) -> Self {
        let mut named = Vec::new();
        for finding in critical {
            if named.len() < MAX_NAMED_FINDINGS && !named.contains(&finding) {
                named.push(finding);
            }
        }
        Self {
            critical: named,
            lesser,
        }
    }

    /// The critical findings, any of which refuses the image.
    #[must_use]
    pub fn critical(&self) -> &[VulnerabilityId] {
        &self.critical
    }

    /// The findings below critical.
    #[must_use]
    pub fn lesser(&self) -> LesserFindings {
        self.lesser
    }
}

/// The registry before the first `/`, then a path, then a tag after the
/// last `:`, or `latest` when there is none.
fn split_tag(rest: &str) -> Result<(&str, ImageReference), DomainError> {
    let (repository, tag) = match rest.rsplit_once(':') {
        Some((repository, tag)) if !tag.contains('/') => (repository, tag),
        _ => (rest, "latest"),
    };
    Ok((repository, ImageReference::Tag(ImageTag::new(tag)?)))
}

fn no_registry() -> DomainError {
    DomainError::invalid(message!(
        "workflows-an-image-names-its-registry-first",
        "an image names its registry first, such as registry.acme.example/tools/codegen:1.4"
    ))
}

/// A registry is a host name of at least two labels, never numbered, with
/// an optional port from 1 to 65535.
struct RegistryAddress;

impl Rule for RegistryAddress {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let (host, port) = match value.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (value, None),
        };
        let port_fits = port.is_none_or(|port| {
            !port.starts_with('0') && port.parse::<u16>().is_ok_and(|port| port > 0)
        });
        let fits = port_fits && AllowedHost::new(host).is_ok();
        (!fits).then(|| ValidationError::Custom {
            field,
            code: "not_a_registry".to_owned(),
            message: message!(
                "workflows-a-registry-is-a-host-name",
                "a registry is a DNS name of at least two labels, with an optional port"
            ),
        })
    }
}

/// Each part of a path is letters and digits, joined but not begun or
/// ended by `.`, `_` or `-`.
struct PlainParts;

impl Rule for PlainParts {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let plain = value.split('/').all(|part| {
            let edges_plain = part
                .bytes()
                .next()
                .zip(part.bytes().next_back())
                .is_some_and(|(first, last)| {
                    first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric()
                });
            edges_plain && !part.contains("..")
        });
        (!plain).then(|| ValidationError::Custom {
            field,
            code: "not_a_repository".to_owned(),
            message: message!(
                "workflows-an-image-path-is-plain-parts",
                "an image's path is parts of letters and digits, joined by single dots, dashes or underscores"
            ),
        })
    }
}

/// A tag does not begin with `.` or `-`.
struct StartsPlain;

impl Rule for StartsPlain {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let plain = !value.starts_with(['.', '-']);
        (!plain).then(|| ValidationError::Custom {
            field,
            code: "not_a_tag".to_owned(),
            message: message!(
                "workflows-a-tag-begins-with-a-letter-or-digit",
                "an image's tag begins with a letter, digit or underscore"
            ),
        })
    }
}

/// `sha256:` and 64 lowercase hex digits.
struct Sha256Named;

impl Rule for Sha256Named {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let named = value.strip_prefix("sha256:").is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
        (!named).then(|| ValidationError::Custom {
            field,
            code: "not_a_digest".to_owned(),
            message: message!(
                "workflows-an-image-digest-is-sha256",
                "an image's digest is sha256: and 64 lowercase hex digits"
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest() -> String {
        format!("sha256:{}", "ab".repeat(32))
    }

    /// Ann names her image with its registry and a tag. The name reads back
    /// in parts, and pinning it keeps the digest in place of the tag.
    #[test]
    fn a_named_image_is_pinned_to_its_digest() {
        let name = ImageName::parse("registry.acme.example/tools/codegen:1.4").unwrap();

        let pinned = name.pinned(ImageDigest::new(digest()).unwrap());

        assert_eq!(name.registry().as_str(), "registry.acme.example");
        assert_eq!(name.repository().as_str(), "tools/codegen");
        assert_eq!(
            name.reference(),
            &ImageReference::Tag(ImageTag::new("1.4").unwrap())
        );
        assert_eq!(
            pinned.as_str(),
            format!("registry.acme.example/tools/codegen@{}", digest())
        );
        assert_eq!(PinnedImage::parse(pinned.as_str()).unwrap(), pinned);
    }

    /// A name with neither tag nor digest points at `latest`, and a
    /// registry with a port keeps its port.
    #[test]
    fn a_bare_name_points_at_latest() {
        let name = ImageName::parse("registry.acme.example:5000/codegen").unwrap();

        assert_eq!(name.registry().as_str(), "registry.acme.example:5000");
        assert_eq!(
            name.reference(),
            &ImageReference::Tag(ImageTag::new("latest").unwrap())
        );
    }

    /// Names without a registry, with a numbered registry, with an empty
    /// path part or a short digest are refused.
    #[test]
    fn a_name_without_a_plain_registry_is_refused() {
        for refused in [
            "codegen:1.4".to_owned(),
            "acme/codegen:1.4".to_owned(),
            "10.0.0.5/codegen:1.4".to_owned(),
            "registry.acme.example:0/codegen".to_owned(),
            "registry.acme.example/tools//codegen".to_owned(),
            "registry.acme.example/Tools/codegen".to_owned(),
            "registry.acme.example/codegen@sha256:abc".to_owned(),
        ] {
            assert!(ImageName::parse(&refused).is_err(), "{refused} was taken");
        }
    }

    /// A kept image must name its digest; a tag alone is refused.
    #[test]
    fn a_kept_image_names_its_digest() {
        assert!(PinnedImage::parse("registry.acme.example/codegen:1.4").is_err());
    }

    /// An image of 2 GiB is taken; a byte more is refused.
    #[test]
    fn an_image_keeps_to_its_size() {
        let pinned = PinnedImage::parse(&format!("ghcr.io/acme/codegen@{}", digest())).unwrap();

        assert!(OwnImage::new(pinned.clone(), MAX_IMAGE_BYTES).is_ok());
        assert!(OwnImage::new(pinned, MAX_IMAGE_BYTES + 1).is_err());
    }

    /// A scan naming the same critical finding twice keeps it once, and
    /// names at most twenty.
    #[test]
    fn critical_findings_are_named_once_and_bounded() {
        let named: Vec<VulnerabilityId> = (0..30)
            .map(|number| VulnerabilityId::new(format!("CVE-2024-{number:04}")).unwrap())
            .chain([VulnerabilityId::new("CVE-2024-0000").unwrap()])
            .collect();

        let findings = ImageFindings::new(named, LesserFindings::default());

        assert_eq!(findings.critical().len(), MAX_NAMED_FINDINGS);
        assert_eq!(findings.critical()[0].as_str(), "CVE-2024-0000");
    }
}
