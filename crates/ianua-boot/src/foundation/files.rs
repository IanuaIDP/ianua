//! Where the platform keeps files: a directory of the node, or an
//! S3-compatible bucket every node reaches.

use std::path::PathBuf;

use ianua_infra::files::{BucketAddressing, ObjectFileStore, ObjectStoreSettings};

use crate::env::{ConfigError, Env, Read};

/// The object store settings, which only `FILES_STORE=objects` reads.
const OBJECT_SETTINGS: [&str; 7] = [
    "FILES_OBJECTS_ENDPOINT",
    "FILES_OBJECTS_REGION",
    "FILES_OBJECTS_BUCKET",
    "FILES_OBJECTS_ACCESS_KEY_ID",
    "FILES_OBJECTS_SECRET_ACCESS_KEY",
    "FILES_OBJECTS_SECRET_ACCESS_KEY_FILE",
    "FILES_OBJECTS_ADDRESSING",
];

/// Where files are kept: `FILES_STORE`, `disk` by default.
#[derive(Debug, Clone)]
pub enum FilesConfig {
    /// A directory of this node, `FILES_DIR` (`files`).
    Disk {
        /// The directory.
        dir: PathBuf,
    },
    /// An S3-compatible bucket: `FILES_OBJECTS_ENDPOINT`, `_REGION`,
    /// `_BUCKET`, `_ACCESS_KEY_ID`, `_SECRET_ACCESS_KEY` (or `_FILE`) and
    /// `_ADDRESSING` (`virtual_host`, or `path` for MinIO and dotted
    /// bucket names). Give the bucket a lifecycle rule that aborts
    /// unfinished multipart uploads after a day.
    Objects(ObjectStoreSettings),
}

/// Which store `FILES_STORE` names.
#[derive(Debug, Clone, Copy)]
enum Kind {
    Disk,
    Objects,
}

impl FilesConfig {
    /// The file store `vars` names.
    ///
    /// # Errors
    ///
    /// An object store setting missing or refused by the store, or set
    /// beside the disk store.
    pub fn read(vars: &Env) -> Read<Self> {
        let kind = vars.choice(
            "FILES_STORE",
            Kind::Disk,
            &[("disk", Kind::Disk), ("objects", Kind::Objects)],
        )?;
        match kind {
            Kind::Disk => disk(vars),
            Kind::Objects => objects(vars).map(Self::Objects),
        }
    }
}

/// The disk store, refusing object store settings nothing would read.
fn disk(vars: &Env) -> Read<FilesConfig> {
    for name in OBJECT_SETTINGS {
        if vars.optional(name)?.is_some() {
            return Err(ConfigError::contradicts(
                name,
                "is only read with FILES_STORE=objects",
            ));
        }
    }
    Ok(FilesConfig::Disk {
        dir: vars
            .path("FILES_DIR")?
            .unwrap_or_else(|| PathBuf::from("files")),
    })
}

/// The object store, checked as the store checks it.
fn objects(vars: &Env) -> Read<ObjectStoreSettings> {
    if vars.optional("FILES_DIR")?.is_some() {
        return Err(ConfigError::contradicts(
            "FILES_DIR",
            "is only read with FILES_STORE=disk",
        ));
    }
    let endpoint = vars
        .url("FILES_OBJECTS_ENDPOINT")?
        .ok_or_else(|| ConfigError::missing("FILES_OBJECTS_ENDPOINT"))?;
    let settings = ObjectStoreSettings {
        endpoint,
        region: vars.required("FILES_OBJECTS_REGION")?,
        bucket: vars.required("FILES_OBJECTS_BUCKET")?,
        access_key_id: vars.required("FILES_OBJECTS_ACCESS_KEY_ID")?,
        secret_access_key: vars.required_secret("FILES_OBJECTS_SECRET_ACCESS_KEY")?,
        addressing: vars.choice(
            "FILES_OBJECTS_ADDRESSING",
            BucketAddressing::VirtualHost,
            &[
                ("virtual_host", BucketAddressing::VirtualHost),
                ("path", BucketAddressing::Path),
            ],
        )?,
    };
    ObjectFileStore::new(settings.clone())
        .map_err(|cause| ConfigError::rejected("FILES_OBJECTS_*", cause))?;
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn bucket() -> Vec<(&'static str, &'static str)> {
        vec![
            ("FILES_STORE", "objects"),
            (
                "FILES_OBJECTS_ENDPOINT",
                "https://s3.eu-central-1.amazonaws.com",
            ),
            ("FILES_OBJECTS_REGION", "eu-central-1"),
            ("FILES_OBJECTS_BUCKET", "ianua-files"),
            ("FILES_OBJECTS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"),
            ("FILES_OBJECTS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI-secret"),
        ]
    }

    /// With nothing set, files are kept in `files` on this node.
    #[test]
    fn with_nothing_set_files_are_kept_on_disk() {
        let config = FilesConfig::read(&Env::of([])).unwrap();

        assert!(matches!(config, FilesConfig::Disk { dir } if dir == Path::new("files")));
    }

    /// A bucket is read whole, its secret never printed.
    #[test]
    fn a_bucket_is_read_whole_and_never_prints_its_secret() {
        let config = FilesConfig::read(&Env::of(bucket())).unwrap();

        assert!(
            matches!(&config, FilesConfig::Objects(settings) if settings.bucket == "ianua-files")
        );
        assert!(!format!("{config:?}").contains("wJalrXUtnFEMI-secret"));
    }

    /// Omitting the bucket refuses an otherwise configured object store
    /// and names the missing bucket setting.
    #[test]
    fn an_object_store_with_no_bucket_is_refused() {
        let pairs: Vec<_> = bucket()
            .into_iter()
            .filter(|(name, _)| *name != "FILES_OBJECTS_BUCKET")
            .collect();

        let read = FilesConfig::read(&Env::of(pairs));

        assert!(
            matches!(read, Err(ConfigError::Missing { name }) if name == "FILES_OBJECTS_BUCKET")
        );
    }

    /// A bucket setting is refused when the selected file store is disk.
    #[test]
    fn bucket_settings_beside_the_disk_store_are_refused() {
        let read = FilesConfig::read(&Env::of([("FILES_OBJECTS_BUCKET", "ianua-files")]));

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "FILES_OBJECTS_BUCKET")
        );
    }

    /// A plain HTTP object-store endpoint is refused during configuration.
    #[test]
    fn a_plain_http_endpoint_is_refused() {
        let mut pairs = bucket();
        pairs[1] = ("FILES_OBJECTS_ENDPOINT", "http://s3.example.com");

        let read = FilesConfig::read(&Env::of(pairs));

        assert!(matches!(read, Err(ConfigError::Rejected { .. })));
    }
}
