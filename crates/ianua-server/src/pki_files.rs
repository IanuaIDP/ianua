//! Writing a private authority's files: every certificate and key a PKI
//! command issues, into a folder that holds none of them yet, each private
//! key readable by its owner alone.
//!
//! Nothing is written over. Issuing an authority again would leave every
//! certificate already issued under it unaccepted, and whatever trusted it
//! would stop connecting some time after whoever did it stopped watching.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// Why a PKI command's files were not written.
#[derive(Debug, thiserror::Error)]
pub enum PkiFileError {
    /// A file it would write is there already.
    #[error(
        "refusing to write over {path}: issuing the authority again leaves every certificate \
         issued under it unaccepted"
    )]
    Exists {
        /// The file.
        path: PathBuf,
    },
    /// A file could not be written.
    #[error("cannot write {path}")]
    Write {
        /// The file.
        path: PathBuf,
        /// Why.
        #[source]
        cause: std::io::Error,
    },
}

/// Whether a file holds a private key, and so is written for its owner
/// alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Holds {
    Certificate,
    PrivateKey,
}

/// One file to write.
pub struct Planned {
    path: PathBuf,
    contents: String,
    holds: Holds,
}

/// The certificate `contents`, written as `name` under `out`.
#[must_use]
pub fn certificate(out: &Path, name: &str, contents: &str) -> Planned {
    Planned {
        path: out.join(name),
        contents: contents.to_owned(),
        holds: Holds::Certificate,
    }
}

/// The private key `contents`, written as `name` under `out` for its owner
/// alone.
#[must_use]
pub fn key(out: &Path, name: &str, contents: &str) -> Planned {
    Planned {
        path: out.join(name),
        contents: contents.to_owned(),
        holds: Holds::PrivateKey,
    }
}

/// Writes every one of `planned` into `out`, made when missing, once none
/// of them is there already.
///
/// # Errors
///
/// - [`PkiFileError::Exists`] naming the first file there already, before
///   anything is written.
/// - [`PkiFileError::Write`] when the folder or a file cannot be written.
pub fn write_all(out: &Path, planned: &[Planned]) -> Result<(), PkiFileError> {
    ensure_none_exists(planned)?;
    std::fs::create_dir_all(out).map_err(|cause| PkiFileError::Write {
        path: out.to_path_buf(),
        cause,
    })?;
    planned.iter().try_for_each(write_file)
}

/// Refuses when any of `planned` is there already.
fn ensure_none_exists(planned: &[Planned]) -> Result<(), PkiFileError> {
    let Some(existing) = planned.iter().find(|file| file.path.exists()) else {
        return Ok(());
    };
    Err(PkiFileError::Exists {
        path: existing.path.clone(),
    })
}

/// Writes `file`, new, a private key readable by its owner alone.
fn write_file(file: &Planned) -> Result<(), PkiFileError> {
    let failed = |cause| PkiFileError::Write {
        path: file.path.clone(),
        cause,
    };
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    restrict(&mut options, file.holds);
    let mut handle = options.open(&file.path).map_err(failed)?;
    handle.write_all(file.contents.as_bytes()).map_err(failed)
}

/// Files holding a private key are made with mode `0600`.
#[cfg(unix)]
fn restrict(options: &mut OpenOptions, holds: Holds) {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mode = match holds {
        Holds::Certificate => 0o644,
        Holds::PrivateKey => 0o600,
    };
    options.mode(mode);
}

/// Off Unix a file takes its folder's permissions.
#[cfg(not(unix))]
fn restrict(_options: &mut OpenOptions, _holds: Holds) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rewriting an existing certificate returns an exists error and
    /// preserves the original file contents.
    #[test]
    fn nothing_is_written_over() {
        let folder = tempfile::tempdir().unwrap();
        let out = folder.path();
        write_all(out, &[certificate(out, "ca-cert.pem", "first")]).unwrap();

        let again = write_all(out, &[certificate(out, "ca-cert.pem", "second")]);

        assert!(matches!(again, Err(PkiFileError::Exists { .. })));
        assert_eq!(
            std::fs::read_to_string(out.join("ca-cert.pem")).unwrap(),
            "first"
        );
    }

    /// A written private key grants no permissions to group or other users.
    #[cfg(unix)]
    #[test]
    fn a_private_key_is_readable_by_its_owner_alone() {
        use std::os::unix::fs::PermissionsExt as _;
        let folder = tempfile::tempdir().unwrap();
        let out = folder.path();

        write_all(out, &[key(out, "ca-key.pem", "secret")]).unwrap();

        let mode = std::fs::metadata(out.join("ca-key.pem"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
    }
}
