//! The languages a sandbox's code is written in, the runtimes a version
//! may run under, and the exact image a version is kept to.

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::{Rule, TextValue, ValidationError, Validator, text_value};

/// The language a sandbox's code is written in. It never changes for a
/// sandbox, so its packages always come from the same registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    /// Python, its packages from PyPI.
    Python,
    /// JavaScript, its packages from npm.
    JavaScript,
}

impl Language {
    /// The language `name` names: `python` or `javascript`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] for any other name.
    pub fn parse(name: &str) -> Result<Self, DomainError> {
        [Self::Python, Self::JavaScript]
            .into_iter()
            .find(|language| language.as_str() == name)
            .ok_or_else(|| {
                DomainError::invalid(message!(
                    "workflows-a-sandbox-language-is-python-or-javascript",
                    "a sandbox's language is python or javascript"
                ))
            })
    }

    /// The stored and shown name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::JavaScript => "javascript",
        }
    }
}

/// The interpreter a version runs under, picked when it is saved.
///
/// A version keeps the runtime it was saved with, and the exact image of
/// it, so nothing the platform changes later moves code already reviewed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Runtime {
    /// CPython 3.11.
    Python311,
    /// CPython 3.12.
    Python312,
    /// CPython 3.13.
    Python313,
    /// Node.js 20.
    Node20,
    /// Node.js 22.
    Node22,
    /// Node.js 24.
    Node24,
}

impl Runtime {
    /// Every runtime a version may name.
    pub const ALL: [Self; 6] = [
        Self::Python311,
        Self::Python312,
        Self::Python313,
        Self::Node20,
        Self::Node22,
        Self::Node24,
    ];

    /// The runtime `name` names, such as `python-3.13` or `node-22`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] for any other name.
    pub fn parse(name: &str) -> Result<Self, DomainError> {
        Self::ALL
            .into_iter()
            .find(|runtime| runtime.as_str() == name)
            .ok_or_else(|| {
                DomainError::invalid(message!(
                    "workflows-no-such-sandbox-runtime",
                    format!("{name} is no sandbox runtime")
                ))
            })
    }

    /// The stored and shown name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Python311 => "python-3.11",
            Self::Python312 => "python-3.12",
            Self::Python313 => "python-3.13",
            Self::Node20 => "node-20",
            Self::Node22 => "node-22",
            Self::Node24 => "node-24",
        }
    }

    /// The language its code is written in.
    #[must_use]
    pub fn language(self) -> Language {
        match self {
            Self::Python311 | Self::Python312 | Self::Python313 => Language::Python,
            Self::Node20 | Self::Node22 | Self::Node24 => Language::JavaScript,
        }
    }

    /// Its interpreter's version as major and minor, such as 3 and 13, or
    /// 22 and 0: what a package's own range of interpreters is read
    /// against.
    #[must_use]
    pub fn release(self) -> (u32, u32) {
        match self {
            Self::Python311 => (3, 11),
            Self::Python312 => (3, 12),
            Self::Python313 => (3, 13),
            Self::Node20 => (20, 0),
            Self::Node22 => (22, 0),
            Self::Node24 => (24, 0),
        }
    }
}

text_value! {
    /// The exact container image a version runs in: a name and the SHA-256
    /// of its content, such as `python:3.13-slim@sha256:…`.
    ///
    /// It is named by its content, never by a tag alone, so the image a
    /// version runs in today is the one it runs in every time after,
    /// however the tag moves.
    pub struct RuntimeImage;
}

impl TextValue for RuntimeImage {
    const FIELD: &'static str = "image";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.length(1..=512).rule(&NamedByContent)
    }
}

/// An image reference ends in `@sha256:` and its 64 hex digits, after a
/// name of letters, digits and the separators image names use.
struct NamedByContent;

impl Rule for NamedByContent {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let named = value.split_once("@sha256:").is_some_and(|(name, digest)| {
            !name.is_empty()
                && name.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'/' | b':' | b'_' | b'-')
                })
                && digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
        (!named).then(|| ValidationError::Custom {
            field,
            code: "not_named_by_content".to_owned(),
            message: message!(
                "workflows-an-image-is-named-by-its-content",
                "an image is named by its content: a name, @sha256: and 64 hex digits"
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every runtime reads back from its stored name and names its own
    /// language.
    #[test]
    fn every_runtime_is_named_by_its_stored_name() {
        for runtime in Runtime::ALL {
            assert_eq!(Runtime::parse(runtime.as_str()).unwrap(), runtime);
        }
        assert_eq!(Runtime::Python313.language(), Language::Python);
        assert_eq!(Runtime::Node24.language(), Language::JavaScript);
        assert!(Runtime::parse("python-2.7").is_err());
    }

    /// `python` and `javascript` name languages; `Python` and `ruby` do
    /// not.
    #[test]
    fn a_language_is_named_by_its_stored_name() {
        assert_eq!(Language::parse("python").unwrap(), Language::Python);
        assert_eq!(Language::parse("javascript").unwrap(), Language::JavaScript);
        assert!(Language::parse("Python").is_err());
        assert!(Language::parse("ruby").is_err());
    }

    /// An image named by its content is taken. A tag alone, which may move,
    /// or a short digest, is refused.
    #[test]
    fn an_image_is_named_by_its_content() {
        let digest = "ab".repeat(32);

        assert!(RuntimeImage::new(format!("python:3.13-slim@sha256:{digest}")).is_ok());
        assert!(RuntimeImage::new("python:3.13-slim").is_err());
        assert!(RuntimeImage::new("python:3.13-slim@sha256:abc").is_err());
        assert!(RuntimeImage::new(format!("@sha256:{digest}")).is_err());
    }
}
