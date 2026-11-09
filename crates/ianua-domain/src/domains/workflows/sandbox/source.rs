//! Where a version's code came from, and where a version is pushed.
//!
//! Code is written in the platform, or imported from a file of a company's
//! repository through a connected account. An imported version records the
//! exact commit it was read at, so the same code always runs and anyone can
//! find it again; a changed file is a new version. Pushing sends a copy of
//! a version to a repository; the version saved in the platform stays the
//! one that runs.

use crate::domains::workflows::integration::IntegrationKey;
use crate::shared::validation::{
    Charset, CharsetUnion, Rule, TextValue, ValidationError, Validator, text_value,
};

text_value! {
    /// A repository as its service names it, such as `acme/web` or a
    /// GitLab group path `acme/platform/web`.
    pub struct RepositoryName;
}

impl TextValue for RepositoryName {
    const FIELD: &'static str = "repository";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .length(3..=200)
            .charset(path_characters())
            .rule(&PlainPath)
    }
}

text_value! {
    /// A file or folder inside a repository, such as `scripts/tidy.py`:
    /// no leading slash, no empty, `.` or `..` part.
    pub struct RepositoryPath;
}

impl TextValue for RepositoryPath {
    const FIELD: &'static str = "path";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .length(1..=400)
            .charset(path_characters())
            .rule(&PlainPath)
    }
}

text_value! {
    /// A branch, tag or commit to read at, or a branch to push to, such as
    /// `main` or `release/2026-11`.
    pub struct GitRef;
}

impl TextValue for GitRef {
    const FIELD: &'static str = "ref";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .length(1..=200)
            .charset(path_characters())
            .rule(&PlainPath)
    }
}

text_value! {
    /// A commit, as the 40 or 64 lowercase hex digits git names it by.
    pub struct CommitSha;
}

impl TextValue for CommitSha {
    const FIELD: &'static str = "commit";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .length(40..=64)
            .charset(Charset::DIGIT | Charset::HEX_LETTER)
            .rule(&GitHashLength)
    }
}

/// The characters a repository, path or ref may hold.
fn path_characters() -> CharsetUnion {
    Charset::LOWERCASE
        | Charset::UPPERCASE
        | Charset::DIGIT
        | Charset::HYPHEN
        | Charset::UNDERSCORE
        | Charset::DOT
        | Charset::SLASH
}

/// Refuses a path with a leading or trailing slash, or an empty, `.` or
/// `..` part, which could point outside the folder meant.
struct PlainPath;

impl Rule for PlainPath {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let plain = value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..");
        if plain {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "crooked_path".to_owned(),
            message: crate::message!(
                "workflows-a-path-names-each-part-plainly",
                "a path names each part plainly, with no empty, . or .. part"
            ),
        })
    }
}

/// Refuses a commit of any length but git's 40 or 64 digits.
struct GitHashLength;

impl Rule for GitHashLength {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        if value.len() == 40 || value.len() == 64 {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "not_a_commit".to_owned(),
            message: crate::message!(
                "workflows-a-commit-is-40-or-64-hex-digits",
                "a commit is 40 or 64 hex digits"
            ),
        })
    }
}

/// A file of a repository at one commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryFile {
    /// The integration of the service keeping the repository.
    pub integration: IntegrationKey,
    /// The project containing the source file at the pinned commit.
    pub repository: RepositoryName,
    /// The file.
    pub path: RepositoryPath,
    /// The commit it was read at.
    pub commit: CommitSha,
}

/// Where a version's code came from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CodeSource {
    /// Written in the platform, by a person or by the tenant's model for
    /// them.
    #[default]
    Written,
    /// Read from this file at this commit.
    Imported(RepositoryFile),
}

/// Where a version is pushed: a folder of a repository's branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushTarget {
    /// The integration of the service keeping the repository.
    pub integration: IntegrationKey,
    /// The project that receives the exported source revision.
    pub repository: RepositoryName,
    /// The target ref advanced by the export commit.
    pub branch: GitRef,
    /// The folder the version's files go in.
    pub folder: RepositoryPath,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Repository names, relative file paths and branch refs are accepted.
    /// File paths reject parent traversal, absolute paths, empty segments and
    /// current-directory segments.
    #[test]
    fn a_path_names_each_part_plainly() {
        assert!(RepositoryName::new("acme/web").is_ok());
        assert!(RepositoryPath::new("scripts/tidy.py").is_ok());
        assert!(GitRef::new("release/2026-11").is_ok());
        for crooked in [
            "../secrets",
            "/etc/passwd",
            "scripts//tidy.py",
            "scripts/./x",
        ] {
            assert!(RepositoryPath::new(crooked).is_err(), "{crooked}");
        }
    }

    /// Full 40- and 64-digit commit hashes are accepted, while a short hash
    /// and branch name are rejected.
    #[test]
    fn a_commit_is_a_full_hash() {
        assert!(CommitSha::new("a".repeat(40)).is_ok());
        assert!(CommitSha::new("b".repeat(64)).is_ok());
        assert!(CommitSha::new("abc1234").is_err());
        assert!(CommitSha::new("main").is_err());
    }
}
