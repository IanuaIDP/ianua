//! The packages a sandbox pins: each named as its registry names it, at
//! one exact version.
//!
//! A range such as `^4.17` would let a later build fetch other code than the
//! version that was reviewed, so only an exact version is taken.

use crate::domains::workflows::sandbox::runtime::Language;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;
use crate::shared::validation::{
    Boundary, Charset, Rule, TextValue, ValidationError, Validator, text_value,
};

/// The most packages one version pins.
pub const MAX_PACKAGES: usize = 50;

text_value! {
    /// An npm package's name: lowercase, at most 214 bytes, maybe under a
    /// scope (`@acme/tools`), no part starting with `.` or `_`.
    pub struct NpmName;
}

impl TextValue for NpmName {
    const FIELD: &'static str = "package_name";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .length(1..=214)
            .charset(
                Charset::LOWERCASE
                    | Charset::DIGIT
                    | Charset::HYPHEN
                    | Charset::DOT
                    | Charset::UNDERSCORE
                    | Charset::TILDE
                    | Charset::AT
                    | Charset::SLASH,
            )
            .rule(&NpmShape)
    }
}

text_value! {
    /// A PyPI package's name, kept in the form PyPI compares names in:
    /// lowercase, with every run of `-`, `_` and `.` written as one `-`. So
    /// `Requests_Toolbelt` and `requests-toolbelt` are the same package.
    pub struct PypiName;
}

impl TextValue for PypiName {
    const FIELD: &'static str = "package_name";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .length(1..=100)
            .charset(Charset::LOWERCASE | Charset::DIGIT | Charset::HYPHEN)
            .boundaries(Boundary::Alphanumeric)
    }

    fn normalized(value: String) -> String {
        pypi_normalized(&value)
    }
}

/// A package's name, as its language's registry knows it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PackageName {
    /// A package on npm.
    Npm(NpmName),
    /// A package on PyPI.
    Pypi(PypiName),
}

impl PackageName {
    /// Checks `value` as a package name of `language`.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] for the first rule the name breaks.
    pub fn new(language: Language, value: impl Into<String>) -> Result<Self, ValidationError> {
        match language {
            Language::JavaScript => NpmName::new(value).map(Self::Npm),
            Language::Python => PypiName::new(value).map(Self::Pypi),
        }
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Npm(name) => name.as_str(),
            Self::Pypi(name) => name.as_str(),
        }
    }

    /// The language whose registry it is found in.
    #[must_use]
    pub fn language(&self) -> Language {
        match self {
            Self::Npm(_) => Language::JavaScript,
            Self::Pypi(_) => Language::Python,
        }
    }
}

impl std::fmt::Display for PackageName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

text_value! {
    /// One exact npm version: three numbers between dots, then maybe a
    /// pre-release after `-` or build data after `+`, such as `4.17.21`.
    pub struct NpmVersion;
}

impl TextValue for NpmVersion {
    const FIELD: &'static str = "package_version";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .length(5..=64)
            .charset(
                Charset::LOWERCASE
                    | Charset::UPPERCASE
                    | Charset::DIGIT
                    | Charset::DOT
                    | Charset::HYPHEN
                    | Charset::PLUS,
            )
            .rule(&ThreeNumbers)
    }
}

text_value! {
    /// One exact PyPI version, starting with its release number, such as
    /// `1.0.0` or `2.0rc1`.
    pub struct PypiVersion;
}

impl TextValue for PypiVersion {
    const FIELD: &'static str = "package_version";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .length(1..=64)
            .charset(Charset::LOWERCASE | Charset::DIGIT | Charset::DOT)
            .rule(&StartsWithADigit)
    }
}

/// One exact version of a package, as its registry writes it. Never a
/// range.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PackageVersion {
    /// A version on npm.
    Npm(NpmVersion),
    /// A version on PyPI.
    Pypi(PypiVersion),
}

impl PackageVersion {
    /// Checks `value` as an exact version of a `language` package.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] for the first rule the version breaks, a range
    ///   or a wildcard among them.
    pub fn new(language: Language, value: impl Into<String>) -> Result<Self, ValidationError> {
        match language {
            Language::JavaScript => NpmVersion::new(value).map(Self::Npm),
            Language::Python => PypiVersion::new(value).map(Self::Pypi),
        }
    }

    /// The version.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Npm(version) => version.as_str(),
            Self::Pypi(version) => version.as_str(),
        }
    }
}

impl std::fmt::Display for PackageVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One package at one exact version.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PinnedPackage {
    name: PackageName,
    version: PackageVersion,
}

impl PinnedPackage {
    /// `name` at `version`.
    #[must_use]
    pub fn new(name: PackageName, version: PackageVersion) -> Self {
        Self { name, version }
    }

    /// The package.
    #[must_use]
    pub fn name(&self) -> &PackageName {
        &self.name
    }

    /// Its exact version.
    #[must_use]
    pub fn version(&self) -> &PackageVersion {
        &self.version
    }
}

/// Every package a version pins, each named once.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Packages(Vec<PinnedPackage>);

impl Packages {
    /// The packages `pinned` names.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when there are more than
    ///   [`MAX_PACKAGES`].
    /// - [`DomainError::Validation`] when a package is pinned twice, even
    ///   at two versions: only one of them could be loaded.
    pub fn new(pinned: Vec<PinnedPackage>) -> Result<Self, DomainError> {
        validate_count("packages", pinned.len(), 0..=MAX_PACKAGES)?;
        if let Some(twice) = first_repeat(pinned.iter().map(PinnedPackage::name)) {
            return Err(DomainError::invalid(message!(
                "workflows-the-package-is-pinned-twice",
                format!("the package {twice} is pinned twice")
            )));
        }
        Ok(Self(pinned))
    }

    /// The packages, in the order they were given.
    #[must_use]
    pub fn as_slice(&self) -> &[PinnedPackage] {
        &self.0
    }

    /// Whether `name` is among them.
    #[must_use]
    pub fn pins(&self, name: &PackageName) -> bool {
        self.0.iter().any(|pinned| pinned.name() == name)
    }

    /// Whether every one of them comes from `language`'s registry.
    #[must_use]
    pub fn all_of(&self, language: Language) -> bool {
        self.0
            .iter()
            .all(|pinned| pinned.name().language() == language)
    }
}

/// A PyPI name in the form PyPI compares names in.
fn pypi_normalized(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        let separator = matches!(character, '-' | '_' | '.');
        if separator && out.ends_with('-') {
            continue;
        }
        out.push(if separator {
            '-'
        } else {
            character.to_ascii_lowercase()
        });
    }
    out
}

/// An npm name is one part, or a scope and one part, `@scope/name`. No
/// part is empty or starts with `.` or `_`.
struct NpmShape;

impl Rule for NpmShape {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let parts: Option<Vec<&str>> = match value.strip_prefix('@') {
            Some(scoped) => scoped
                .split_once('/')
                .map(|(scope, name)| vec![scope, name]),
            None => Some(vec![value]),
        };
        let fits = parts.is_some_and(|parts| {
            parts.iter().all(|part| {
                !part.is_empty() && !part.starts_with(['.', '_']) && !part.contains(['@', '/'])
            })
        });
        (!fits).then(|| ValidationError::Custom {
            field,
            code: "invalid_format".to_owned(),
            message: message!(
                "workflows-is-not-an-npm-package-name",
                format!("{value} is not an npm package name")
            ),
        })
    }
}

/// An npm version is three numbers between dots, then maybe a pre-release
/// after `-` or build data after `+`.
struct ThreeNumbers;

impl Rule for ThreeNumbers {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let core = value.split(['-', '+']).next().unwrap_or_default();
        let numbers: Vec<&str> = core.split('.').collect();
        let fits = numbers.len() == 3
            && numbers
                .iter()
                .all(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()));
        (!fits).then(|| exact_version_needed(field, value))
    }
}

/// A PyPI version starts with its release number.
struct StartsWithADigit;

impl Rule for StartsWithADigit {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let fits = value.bytes().next().is_some_and(|b| b.is_ascii_digit());
        (!fits).then(|| exact_version_needed(field, value))
    }
}

fn exact_version_needed(field: &'static str, value: &str) -> ValidationError {
    ValidationError::Custom {
        field,
        code: "invalid_format".to_owned(),
        message: message!(
            "workflows-is-not-an-exact-package-version",
            format!("{value} is not an exact version; pin one, such as 1.2.3")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn npm(name: &str) -> Result<PackageName, ValidationError> {
        PackageName::new(Language::JavaScript, name)
    }

    fn pypi(name: &str) -> Result<PackageName, ValidationError> {
        PackageName::new(Language::Python, name)
    }

    fn pinned(name: &str, version: &str) -> PinnedPackage {
        PinnedPackage::new(
            pypi(name).unwrap(),
            PackageVersion::new(Language::Python, version).unwrap(),
        )
    }

    /// `lodash` and `@acme/tools` are npm names. `Lodash`, `@acme`,
    /// `_private`, `@acme/` and `a/b` are not.
    #[test]
    fn an_npm_name_is_lowercase_and_maybe_scoped() {
        assert!(npm("lodash").is_ok());
        assert!(npm("@acme/tools").is_ok());
        for refused in ["Lodash", "@acme", "_private", "@acme/", "a/b", ""] {
            assert!(npm(refused).is_err(), "{refused}");
        }
    }

    /// `Requests_Toolbelt` is kept as `requests-toolbelt`, the form PyPI
    /// compares names in. `-requests` and `requests!` are refused.
    #[test]
    fn a_pypi_name_is_kept_as_pypi_compares_it() {
        assert_eq!(
            pypi("Requests_Toolbelt").unwrap().as_str(),
            "requests-toolbelt"
        );
        assert_eq!(pypi("zope..interface").unwrap().as_str(), "zope-interface");
        assert!(pypi("-requests").is_err());
        assert!(pypi("requests!").is_err());
    }

    /// Exact npm and PyPI releases, including prereleases, are accepted.
    /// Ranges, wildcards, incomplete npm versions, `latest` and a prefixed
    /// PyPI version are rejected.
    #[test]
    fn only_an_exact_version_is_taken() {
        assert!(PackageVersion::new(Language::JavaScript, "4.17.21").is_ok());
        assert!(PackageVersion::new(Language::JavaScript, "1.0.0-rc.1").is_ok());
        assert!(PackageVersion::new(Language::Python, "2.0rc1").is_ok());
        for refused in ["^4.17.21", "4.x", "~4.17.0", "4.17", "latest"] {
            assert!(
                PackageVersion::new(Language::JavaScript, refused).is_err(),
                "{refused}"
            );
        }
        for refused in [">=1.0", "1.*", "v1.0"] {
            assert!(
                PackageVersion::new(Language::Python, refused).is_err(),
                "{refused}"
            );
        }
    }

    /// Pinning `requests` twice with different casing and versions is rejected
    /// as a duplicate package.
    #[test]
    fn a_package_pinned_twice_is_refused() {
        let twice = Packages::new(vec![
            pinned("requests", "2.31.0"),
            pinned("Requests", "2.32.0"),
        ]);

        assert!(matches!(twice, Err(DomainError::Validation(_))));
    }
}
