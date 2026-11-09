//! The connector's own folder: its private key, made here once and never
//! sent anywhere, and the certificate and enrollment the API answered.
//!
//! - `key.pem`: the key, made on the first start, readable by the
//!   connector alone, never written over.
//! - `certificate.pem`: the certificate the connector authority signed for
//!   the key, good for a day.
//! - `authority.pem`: the authority's certificate, which the gateway's
//!   listener is checked against.
//! - `connector.json`: which connector this is, and when its certificate
//!   ends and is due for renewal.
//!
//! Each answer replaces its file whole, written beside it first and then
//! moved into place, so a crash mid-write never leaves half a certificate.
//! A folder or key another user on the machine can read is refused.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::path::{Path, PathBuf};

use ianua_domain::shared::security::secret::Secret;
use rcgen::KeyPair;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// The key's file.
const KEY: &str = "key.pem";
/// The certificate's file.
const CERTIFICATE: &str = "certificate.pem";
/// The authority's file.
const AUTHORITY: &str = "authority.pem";
/// The enrollment's file.
const ENROLLMENT: &str = "connector.json";

/// Why the connector's folder could not be used. None of it names a key.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// A file or the folder could not be read or written.
    #[error("{path} cannot be used")]
    Io {
        /// The file or folder.
        path: PathBuf,
        /// Why.
        #[source]
        cause: std::io::Error,
    },
    /// The folder or the key can be read by other users on the machine.
    #[error(
        "{path} can be read by other users; allow its owner alone (chmod 700 for the folder, 600 for the key)"
    )]
    Exposed {
        /// The file or folder.
        path: PathBuf,
    },
    /// A file holds what the connector did not write.
    #[error("{path} does not read")]
    Unreadable {
        /// The file.
        path: PathBuf,
    },
}

/// A certificate the API answered, with which connector it is for.
#[derive(Clone)]
pub struct Issued {
    /// The connector.
    pub id: Uuid,
    /// The connector's certificate, PEM.
    pub certificate_pem: String,
    /// The authority's certificate, PEM.
    pub authority_pem: String,
    /// When the certificate ends.
    pub expires_at: OffsetDateTime,
    /// From when it is due for renewal.
    pub renew_after: OffsetDateTime,
}

impl std::fmt::Debug for Issued {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issued")
            .field("id", &self.id)
            .field("expires_at", &self.expires_at)
            .field("renew_after", &self.renew_after)
            .finish_non_exhaustive()
    }
}

/// `connector.json` as written.
#[derive(Serialize, Deserialize)]
struct Enrollment {
    id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    renew_after: OffsetDateTime,
}

/// The connector's folder.
#[derive(Debug, Clone)]
pub(crate) struct StateDir {
    path: PathBuf,
}

impl StateDir {
    /// The folder at `path`, made for its owner alone when it is missing.
    ///
    /// # Errors
    ///
    /// [`StateError`] when it cannot be made or read, or other users can
    /// read it.
    pub(crate) fn open(path: &Path) -> Result<Self, StateError> {
        create_private_directory(path)?;
        ensure_private(path)?;
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    /// The connector's key, made and written on the first call and read
    /// back on every later one.
    ///
    /// # Errors
    ///
    /// [`StateError`] when it cannot be made, written or read, or other
    /// users can read it.
    pub(crate) fn key(&self) -> Result<Secret, StateError> {
        let path = self.path.join(KEY);
        if !path.exists() {
            let key =
                KeyPair::generate().map_err(|_| StateError::Unreadable { path: path.clone() })?;
            write_new_private(&path, &key.serialize_pem())?;
        }
        ensure_private(&path)?;
        let pem = fs::read_to_string(&path).map_err(io_at(&path))?;
        KeyPair::from_pem(&pem).map_err(|_| StateError::Unreadable { path: path.clone() })?;
        Ok(Secret::new(pem))
    }

    /// The certificate kept from the last answer, or `None` before the
    /// connector enrolled.
    ///
    /// # Errors
    ///
    /// [`StateError`] when a file is there but cannot be read.
    pub(crate) fn issued(&self) -> Result<Option<Issued>, StateError> {
        let enrollment_path = self.path.join(ENROLLMENT);
        let text = match fs::read_to_string(&enrollment_path) {
            Ok(text) => text,
            Err(cause) if cause.kind() == ErrorKind::NotFound => return Ok(None),
            Err(cause) => return Err(io_at(&enrollment_path)(cause)),
        };
        let enrollment: Enrollment =
            serde_json::from_str(&text).map_err(|_| StateError::Unreadable {
                path: enrollment_path.clone(),
            })?;
        Ok(Some(Issued {
            id: enrollment.id,
            certificate_pem: self.read(CERTIFICATE)?,
            authority_pem: self.read(AUTHORITY)?,
            expires_at: enrollment.expires_at,
            renew_after: enrollment.renew_after,
        }))
    }

    /// Keeps `issued`, each file replaced whole. The enrollment goes last,
    /// so a crash before it leaves the old one pointing at files that are
    /// already new or still old, never missing.
    ///
    /// # Errors
    ///
    /// [`StateError`] when a file cannot be written.
    pub(crate) fn keep(&self, issued: &Issued) -> Result<(), StateError> {
        let enrollment = Enrollment {
            id: issued.id,
            expires_at: issued.expires_at,
            renew_after: issued.renew_after,
        };
        let json =
            serde_json::to_string_pretty(&enrollment).map_err(|_| StateError::Unreadable {
                path: self.path.join(ENROLLMENT),
            })?;
        self.replace(CERTIFICATE, &issued.certificate_pem)?;
        self.replace(AUTHORITY, &issued.authority_pem)?;
        self.replace(ENROLLMENT, &json)
    }

    fn read(&self, name: &str) -> Result<String, StateError> {
        let path = self.path.join(name);
        fs::read_to_string(&path).map_err(io_at(&path))
    }

    fn replace(&self, name: &str, contents: &str) -> Result<(), StateError> {
        let path = self.path.join(name);
        let beside = self.path.join(format!(".{name}.new"));
        let _ = fs::remove_file(&beside);
        write_new_private(&beside, contents)?;
        fs::rename(&beside, &path).map_err(io_at(&path))
    }
}

/// A refusal for `path`, for a `map_err`.
fn io_at(path: &Path) -> impl FnOnce(std::io::Error) -> StateError + '_ {
    move |cause| StateError::Io {
        path: path.to_path_buf(),
        cause,
    }
}

/// Writes `contents` to `path`, new, readable by its owner alone, and to
/// the disk before answering.
fn write_new_private(path: &Path, contents: &str) -> Result<(), StateError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    owner_only_file(&mut options);
    let mut file = options.open(path).map_err(io_at(path))?;
    file.write_all(contents.as_bytes()).map_err(io_at(path))?;
    file.sync_all().map_err(io_at(path))
}

/// Makes `path` for its owner alone, when it is missing.
fn create_private_directory(path: &Path) -> Result<(), StateError> {
    if path.is_dir() {
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    owner_only_folder(&mut builder);
    builder.create(path).map_err(io_at(path))
}

#[cfg(unix)]
fn owner_only_file(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn owner_only_file(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn owner_only_folder(builder: &mut fs::DirBuilder) {
    use std::os::unix::fs::DirBuilderExt as _;
    builder.mode(0o700);
}

#[cfg(not(unix))]
fn owner_only_folder(_builder: &mut fs::DirBuilder) {}

/// Refuses `path` when users other than its owner can read or write it.
#[cfg(unix)]
fn ensure_private(path: &Path) -> Result<(), StateError> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = fs::metadata(path)
        .map_err(io_at(path))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(StateError::Exposed {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private(_path: &Path) -> Result<(), StateError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> (tempfile::TempDir, StateDir) {
        let folder = tempfile::tempdir().unwrap();
        let state = StateDir::open(&folder.path().join("state")).unwrap();
        (folder, state)
    }

    fn issued(id: Uuid) -> Issued {
        Issued {
            id,
            certificate_pem: "certificate".to_owned(),
            authority_pem: "authority".to_owned(),
            expires_at: OffsetDateTime::UNIX_EPOCH,
            renew_after: OffsetDateTime::UNIX_EPOCH,
        }
    }

    /// The key is made on the first start and the same key is read on
    /// every later one, so the key the connector enrolled with is never
    /// lost to a restart.
    #[test]
    fn the_key_is_made_once_and_never_written_over() {
        let (_folder, state) = state();

        let first = state.key().unwrap();
        let again = state.key().unwrap();

        assert_eq!(first.expose(), again.expose());
    }

    /// A newly written connector key grants no filesystem permissions to
    /// its owner's group or other users.
    #[cfg(unix)]
    #[test]
    fn the_key_is_readable_by_its_owner_alone() {
        use std::os::unix::fs::PermissionsExt as _;
        let (folder, state) = state();

        state.key().unwrap();

        let mode = fs::metadata(folder.path().join("state").join(KEY))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
    }

    /// Opening a world-readable state directory fails with an exposed-file error.
    #[cfg(unix)]
    #[test]
    fn a_folder_others_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let folder = tempfile::tempdir().unwrap();
        fs::set_permissions(folder.path(), fs::Permissions::from_mode(0o755)).unwrap();

        let opened = StateDir::open(folder.path());

        assert!(matches!(opened, Err(StateError::Exposed { .. })));
    }

    /// Before enrolling nothing is kept; after, the answer reads back.
    #[test]
    fn an_answer_reads_back_once_kept() {
        let (_folder, state) = state();
        let id = Uuid::now_v7();
        assert!(state.issued().unwrap().is_none());

        state.keep(&issued(id)).unwrap();
        state.keep(&issued(id)).unwrap();

        let read = state.issued().unwrap().unwrap();
        assert_eq!(read.id, id);
        assert_eq!(read.certificate_pem, "certificate");
    }
}
