//! The folder a run's container mounts: the version's bundle unpacked, its
//! code, and the entry script that calls it, readable by the container's
//! user and removed with the run.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::{fs, io};

use ianua_domain::domains::workflows::sandbox::build::MAX_BUNDLE_BYTES;
use ianua_domain::domains::workflows::sandbox::version::SandboxVersion;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::TenantId;
use tempfile::TempDir;
use tokio::io::AsyncReadExt as _;

use crate::files::{FileName, FileStore, StoredFile};
use crate::sandbox::entry::{ENTRY_FOLDER, entry_of};

/// What preparing a run's folder came to.
pub(super) enum Prepared {
    /// The folder, ready to mount.
    Ready(TempDir),
    /// The version's bundle is not kept, or it runs a company's image and
    /// has none, so no folder is laid out.
    NoBundle,
}

/// The folder for a run of `version` of `tenant`, made under `under`.
///
/// # Errors
///
/// When the bundle cannot be read or the folder cannot be written.
pub(super) async fn prepared(
    store: &dyn FileStore,
    under: &Path,
    tenant: &TenantId,
    version: &SandboxVersion<ResolvedTenant>,
) -> io::Result<Prepared> {
    let Some(program) = version.recipe().program().code() else {
        return Ok(Prepared::NoBundle);
    };
    let opened = store
        .open(&FileName::sandbox_bundle(tenant, version.id()))
        .await
        .map_err(io::Error::other)?;
    let Some(bundle) = opened else {
        return Ok(Prepared::NoBundle);
    };
    if bundle.length() > MAX_BUNDLE_BYTES {
        return Err(io::Error::other(
            "the bundle is larger than a bundle may be",
        ));
    }
    let folder = tempfile::Builder::new()
        .prefix("ianua-code-")
        .tempdir_in(under)?;
    let archive = folder.path().join(".bundle.tar.gz");
    write_bundle(bundle, &archive).await?;
    let root = folder.path().to_path_buf();
    let code = program.code().as_str().to_owned();
    let runtime = program.runtime();
    tokio::task::spawn_blocking(move || lay_out(&root, &archive, runtime, &code))
        .await
        .map_err(io::Error::other)??;
    Ok(Prepared::Ready(folder))
}

/// Copies at most the bundle limit into the archive and closes it before unpacking.
async fn write_bundle(bundle: StoredFile, archive: &Path) -> io::Result<()> {
    let mut written = tokio::fs::File::create(archive).await?;
    tokio::io::copy(
        &mut bundle.into_reader().take(MAX_BUNDLE_BYTES),
        &mut written,
    )
    .await?;
    drop(written);
    Ok(())
}

/// Unpacks `archive` into `root`, writes `code` and its entry beside it,
/// and leaves every file readable by the container's user.
fn lay_out(
    root: &Path,
    archive: &Path,
    runtime: ianua_domain::domains::workflows::sandbox::runtime::Runtime,
    code: &str,
) -> io::Result<()> {
    let file = fs::File::open(archive)?;
    let mut unpacking = tar::Archive::new(flate2::read::GzDecoder::new(file));
    unpacking.set_preserve_permissions(false);
    unpacking.set_preserve_mtime(false);
    unpacking.unpack(root)?;
    fs::remove_file(archive)?;
    let entry = entry_of(runtime);
    fs::write(root.join(entry.code_file), code)?;
    fs::create_dir(root.join(ENTRY_FOLDER))?;
    fs::write(root.join(ENTRY_FOLDER).join(entry.entry_file), entry.script)?;
    readable(root)
}

/// Makes `path`, and everything under it, readable by anyone and writable
/// by nobody but its owner: the container runs as another user.
fn readable(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
        for child in fs::read_dir(path)? {
            readable(&child?.path())?;
        }
        return Ok(());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o644))
}
