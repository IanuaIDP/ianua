//! The released migrations: each file a version shipped with, by name and
//! the SHA-256 of its text, written when the version is released.
//!
//! Someone running version 1 has applied its files and recorded them. If
//! version 2 changed one of them, their server would refuse to start; if
//! version 2 removed one, a fresh install and an upgrade would differ. So a
//! released file never changes and is never removed: every change is a new
//! file.

use std::path::Path;
use std::{fs, io};

use sha2::{Digest as _, Sha256};

/// The file the released migrations are recorded in.
pub(crate) const LOCK_FILE: &str = "released-migrations.lock";

/// One released migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Released {
    /// Its file name.
    pub(crate) name: String,
    /// The SHA-256 of its text, in hex.
    pub(crate) digest: String,
}

/// The SHA-256 of `text`, in hex.
pub(crate) fn digest_of(text: &[u8]) -> String {
    Sha256::digest(text)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The migrations recorded in the lock at `lock`, none when it does not
/// exist yet.
///
/// # Errors
///
/// Returns the reading error, or `InvalidData` for a line that is not a
/// digest and a name.
pub(crate) fn read(lock: &Path) -> io::Result<Vec<Released>> {
    let text = match fs::read_to_string(lock) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    text.lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| {
            let (digest, name) = line.split_once("  ").ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("not a lock line: {line}"),
                )
            })?;
            Ok(Released {
                name: name.trim().to_owned(),
                digest: digest.trim().to_owned(),
            })
        })
        .collect()
}

/// The lock's text for every `.sql` file in `migrations`, in name order.
///
/// # Errors
///
/// Returns the reading error.
pub(crate) fn written(migrations: &Path) -> io::Result<String> {
    let mut text = String::from(
        "# The migrations released versions shipped with. Never edit or remove one;\n\
         # every change is a new file. Written by `ianua-schema release`.\n",
    );
    for name in sql_files(migrations)? {
        let digest = digest_of(&fs::read(migrations.join(&name))?);
        text.push_str(&format!("{digest}  {name}\n"));
    }
    Ok(text)
}

/// What is wrong with the released files: each one changed or removed
/// since it was released.
///
/// # Errors
///
/// Returns the reading error.
pub(crate) fn broken(released: &[Released], migrations: &Path) -> io::Result<Vec<String>> {
    let mut problems = Vec::new();
    for file in released {
        let path = migrations.join(&file.name);
        let text = match fs::read(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                problems.push(format!("{} was released and is gone", file.name));
                continue;
            }
            Err(error) => return Err(error),
        };
        if digest_of(&text) != file.digest {
            problems.push(format!(
                "{} was released and has changed since; put the change in a new file",
                file.name
            ));
        }
    }
    Ok(problems)
}

/// The `.sql` file names in `folder`, in order.
fn sql_files(folder: &Path) -> io::Result<Vec<String>> {
    let mut names: Vec<String> = fs::read_dir(folder)?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".sql"))
        .collect();
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A released file changed, one removed and one kept are told apart.
    #[test]
    fn a_changed_or_removed_released_file_is_named() {
        let folder = std::env::temp_dir().join(format!("ianua-schema-lock-{}", std::process::id()));
        fs::create_dir_all(&folder).unwrap();
        fs::write(folder.join("0001_kept.sql"), "CREATE TABLE kept ();").unwrap();
        fs::write(
            folder.join("0002_changed.sql"),
            "CREATE TABLE changed (id int);",
        )
        .unwrap();
        let released = vec![
            Released {
                name: "0001_kept.sql".to_owned(),
                digest: digest_of(b"CREATE TABLE kept ();"),
            },
            Released {
                name: "0002_changed.sql".to_owned(),
                digest: digest_of(b"CREATE TABLE changed ();"),
            },
            Released {
                name: "0003_gone.sql".to_owned(),
                digest: digest_of(b"CREATE TABLE gone ();"),
            },
        ];

        let problems = broken(&released, &folder).unwrap();

        fs::remove_dir_all(&folder).unwrap();
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(problems[0].starts_with("0002_changed.sql was released and has changed"));
        assert!(problems[1].starts_with("0003_gone.sql was released and is gone"));
    }

    /// A lock written for a folder reads back as its files and digests.
    #[test]
    fn a_written_lock_reads_back() {
        let folder =
            std::env::temp_dir().join(format!("ianua-schema-written-{}", std::process::id()));
        fs::create_dir_all(&folder).unwrap();
        fs::write(folder.join("0001_notes.sql"), "CREATE TABLE notes ();").unwrap();
        let lock = folder.join(LOCK_FILE);

        fs::write(&lock, written(&folder).unwrap()).unwrap();
        let released = read(&lock).unwrap();

        fs::remove_dir_all(&folder).unwrap();
        assert_eq!(
            released,
            [Released {
                name: "0001_notes.sql".to_owned(),
                digest: digest_of(b"CREATE TABLE notes ();"),
            }]
        );
    }
}
