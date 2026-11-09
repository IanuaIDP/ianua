//! Where the tool reads and writes: the infra crate's `migrations/` and
//! `schema/` folders and the lock of released migrations beside them, and
//! what their files say.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::{fs, io};

use crate::lock::LOCK_FILE;
use crate::plan::Part;

/// The start of the name of a file of the platform's own tables, after its
/// number.
const PLATFORM_FILE: &str = "platform_";

/// The folders and files the tool works on.
pub(crate) struct Sources {
    /// The migrations servers apply.
    pub(crate) migrations: PathBuf,
    /// The schema as it should be.
    pub(crate) schema: PathBuf,
    /// The lock of released migrations.
    pub(crate) lock: PathBuf,
}

impl Sources {
    /// The infra crate's, found from where this crate was built.
    pub(crate) fn of_the_workspace() -> Self {
        let infra = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map_or_else(|| PathBuf::from("crates"), Path::to_path_buf)
            .join("ianua-infra");
        Self {
            migrations: infra.join("migrations"),
            schema: infra.join("schema"),
            lock: infra.join(LOCK_FILE),
        }
    }

    /// The number the next migration takes.
    ///
    /// # Errors
    ///
    /// Returns the reading error.
    pub(crate) fn next_number(&self) -> io::Result<u32> {
        let highest = sql_files(&self.migrations)?
            .iter()
            .filter_map(|(name, _)| name.split('_').next()?.parse::<u32>().ok())
            .max()
            .unwrap_or(0);
        Ok(highest.saturating_add(1))
    }
}

/// The `.sql` files of `folder`, in name order, each with its text.
///
/// # Errors
///
/// Returns the reading error.
pub(crate) fn sql_files(folder: &Path) -> io::Result<Vec<(String, String)>> {
    let mut names: Vec<String> = fs::read_dir(folder)?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".sql"))
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let text = fs::read_to_string(folder.join(&name))?;
            Ok((name, text))
        })
        .collect()
}

/// The database each table lives in, by the file that makes it: a table a
/// platform file makes lives in the platform database alone.
pub(crate) fn parts<'a>(
    files: impl IntoIterator<Item = &'a (String, String)>,
) -> BTreeMap<String, Part> {
    let mut parts = BTreeMap::new();
    for (name, text) in files {
        let part = if is_platform_file(name) {
            Part::Platform
        } else {
            Part::Tenant
        };
        for table in created_tables(text) {
            parts.insert(table, part);
        }
    }
    parts
}

/// Whether the file `name` holds the platform's own tables.
fn is_platform_file(name: &str) -> bool {
    name.split_once('_')
        .is_some_and(|(_, rest)| rest.starts_with(PLATFORM_FILE))
}

/// The tables `text` makes.
fn created_tables(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.trim().strip_prefix("CREATE TABLE "))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(|name| name.trim_end_matches('(').to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A table a platform file makes lives in the platform database alone;
    /// any other table in every database.
    #[test]
    fn a_platform_files_tables_live_in_the_platform_database() {
        let files = vec![
            (
                "0003_platform_tenants.sql".to_owned(),
                "CREATE TABLE tenants (\n    id uuid\n);".to_owned(),
            ),
            (
                "0005_identity.sql".to_owned(),
                "-- People.\nCREATE TABLE users (\n    id uuid\n);".to_owned(),
            ),
        ];

        let parts = parts(&files);

        assert_eq!(parts.get("tenants"), Some(&Part::Platform));
        assert_eq!(parts.get("users"), Some(&Part::Tenant));
    }
}
