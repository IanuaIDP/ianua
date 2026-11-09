//! The files of a bundle: taken out of a package's archive without trusting
//! it, kept in a folder of their own on disk while the bundle is built, and
//! written out as one gzipped tar that is the same bytes whenever it is
//! built from the same packages.
//!
//! A package's archive is read only for plain files. A path that is
//! absolute, climbs out with `..` or names nothing, an entry that is a link
//! of any kind, and a path given twice are refused, so nothing a package
//! holds can write outside its own folder of the bundle. Every file counts
//! towards the bundle's size and file count as it is read, so an archive
//! that unpacks to far more than it weighs, or to a flood of empty files,
//! stops at the caps. Nothing is held in memory but the list of paths.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use ianua_domain::domains::workflows::sandbox::build::{MAX_BUNDLE_BYTES, MAX_BUNDLE_FILES};
use sha2::{Digest as _, Sha256};

/// Why a package's archive could not go into the bundle.
#[derive(Debug)]
pub(super) enum Unpacked {
    /// The archive could not be read, or holds an entry no bundle takes,
    /// or more files than a bundle may hold.
    Broken,
    /// The bundle would grow past what it may hold, at this many bytes.
    TooLarge(u64),
    /// The folder the files are kept in could not be written.
    Disk(io::Error),
}

/// A packed bundle, kept in a file while it waits to be stored.
#[derive(Debug)]
pub(super) struct Packed {
    /// The file holding it.
    pub(super) path: PathBuf,
    /// How large it is, in bytes.
    pub(super) bytes: u64,
    /// Its SHA-256, in lowercase hex.
    pub(super) digest: String,
}

/// Whether a file in a bundle may be run, as its archive marked it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileMode {
    /// Read only.
    Plain,
    /// Marked runnable, such as a package's command-line script.
    Executable,
}

impl FileMode {
    /// The mode a file marked with the Unix `mode` bits keeps: runnable
    /// when anyone may run it.
    fn of_bits(mode: u32) -> Self {
        if mode & 0o111 != 0 {
            return Self::Executable;
        }
        Self::Plain
    }

    /// The Unix bits the bundle writes it with.
    fn bits(self) -> u32 {
        match self {
            Self::Plain => 0o644,
            Self::Executable => 0o755,
        }
    }
}

/// The files a bundle holds so far, each at its path inside the bundle,
/// in a folder that is removed with it.
#[derive(Debug)]
pub(super) struct Tree {
    folder: tempfile::TempDir,
    files: BTreeMap<String, FileMode>,
    bytes: u64,
}

impl Tree {
    /// An empty bundle in a fresh folder.
    ///
    /// # Errors
    ///
    /// Returns the I/O error when the folder cannot be made.
    pub(super) fn new() -> io::Result<Self> {
        Ok(Self {
            folder: tempfile::tempdir()?,
            files: BTreeMap::new(),
            bytes: 0,
        })
    }

    /// A file in the bundle's own folder, beside its files, for an archive
    /// being fetched or the packed bundle.
    pub(super) fn scratch(&self, name: &str) -> PathBuf {
        self.folder.path().join(format!(".{name}"))
    }

    /// Adds the plain files of the npm tarball at `archive` under
    /// `folder`, each without the tarball's own first folder (`package/`).
    ///
    /// # Errors
    ///
    /// [`Unpacked`] when the tarball cannot be read, holds an entry no
    /// bundle takes, the bundle would grow too large, or a file cannot be
    /// written.
    pub(super) fn add_tarball(&mut self, archive: &Path, folder: &str) -> Result<(), Unpacked> {
        let reader = BufReader::new(File::open(archive).map_err(Unpacked::Disk)?);
        let mut entries = tar::Archive::new(GzDecoder::new(reader));
        for entry in entries.entries().map_err(|_| Unpacked::Broken)? {
            let mut entry = entry.map_err(|_| Unpacked::Broken)?;
            let kind = entry.header().entry_type();
            if kind.is_dir() {
                continue;
            }
            if !kind.is_file() {
                return Err(Unpacked::Broken);
            }
            let path = entry.path().map_err(|_| Unpacked::Broken)?.into_owned();
            let inner = without_first_folder(&path).ok_or(Unpacked::Broken)?;
            let mode = FileMode::of_bits(entry.header().mode().unwrap_or(0));
            self.put(&format!("{folder}/{inner}"), &mut entry, mode)?;
        }
        Ok(())
    }

    /// Adds the plain files of the wheel at `archive` under `folder`, at
    /// the paths the wheel gives them.
    ///
    /// # Errors
    ///
    /// [`Unpacked`] when the wheel cannot be read, holds an entry no
    /// bundle takes, the bundle would grow too large, or a file cannot be
    /// written.
    pub(super) fn add_wheel(&mut self, archive: &Path, folder: &str) -> Result<(), Unpacked> {
        let reader = BufReader::new(File::open(archive).map_err(Unpacked::Disk)?);
        let mut wheel = zip::ZipArchive::new(reader).map_err(|_| Unpacked::Broken)?;
        for index in 0..wheel.len() {
            let mut entry = wheel.by_index(index).map_err(|_| Unpacked::Broken)?;
            if entry.is_dir() {
                continue;
            }
            if entry.is_symlink() {
                return Err(Unpacked::Broken);
            }
            let inner = entry
                .enclosed_name()
                .as_deref()
                .and_then(plain_path)
                .ok_or(Unpacked::Broken)?;
            let mode = FileMode::of_bits(entry.unix_mode().unwrap_or(0));
            self.put(&format!("{folder}/{inner}"), &mut entry, mode)?;
        }
        Ok(())
    }

    /// Writes `entry` to the bundle at `path`, refusing it once the bundle
    /// would pass a cap, or when the path is taken already.
    fn put(&mut self, path: &str, entry: &mut impl Read, mode: FileMode) -> Result<(), Unpacked> {
        if self.files.len() >= MAX_BUNDLE_FILES || self.files.contains_key(path) {
            return Err(Unpacked::Broken);
        }
        let target = self.folder.path().join(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(Unpacked::Disk)?;
        }
        let left = MAX_BUNDLE_BYTES.saturating_sub(self.bytes);
        let mut file = File::create(&target).map_err(Unpacked::Disk)?;
        let written = io::copy(&mut entry.take(left.saturating_add(1)), &mut file)
            .map_err(|_| Unpacked::Broken)?;
        if written > left {
            return Err(Unpacked::TooLarge(self.bytes.saturating_add(written)));
        }
        self.bytes = self.bytes.saturating_add(written);
        self.files.insert(path.to_owned(), mode);
        Ok(())
    }

    /// The bundle, packed into a file of its own: every file in path
    /// order, owned by nobody and dated at the epoch, so the same files
    /// always make the same bytes.
    ///
    /// # Errors
    ///
    /// Returns the I/O error when a file cannot be read or the bundle
    /// cannot be written.
    pub(super) fn packed(&self) -> io::Result<Packed> {
        let path = self.scratch("bundle.tar.gz");
        let hashing = Hashing::new(BufWriter::new(File::create(&path)?));
        let mut builder = tar::Builder::new(GzEncoder::new(hashing, Compression::default()));
        builder.mode(tar::HeaderMode::Deterministic);
        for (inner, mode) in &self.files {
            let source = self.folder.path().join(inner);
            let mut header = tar::Header::new_gnu();
            header.set_size(fs::metadata(&source)?.len());
            header.set_mode(mode.bits());
            header.set_mtime(0);
            header.set_uid(0);
            header.set_gid(0);
            header.set_entry_type(tar::EntryType::Regular);
            builder.append_data(&mut header, inner, BufReader::new(File::open(&source)?))?;
        }
        let hashing = builder.into_inner()?.finish()?;
        let (bytes, digest) = hashing.finish()?;
        Ok(Packed {
            path,
            bytes,
            digest,
        })
    }
}

/// A writer counting and hashing what passes through it.
struct Hashing<W: Write> {
    inner: W,
    hasher: Sha256,
    bytes: u64,
}

impl<W: Write> Hashing<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes: 0,
        }
    }

    /// How many bytes passed, and their SHA-256 in lowercase hex, once
    /// everything is flushed.
    fn finish(mut self) -> io::Result<(u64, String)> {
        self.inner.flush()?;
        let digest = self
            .hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Ok((self.bytes, digest))
    }
}

impl<W: Write> Write for Hashing<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        let passed = buf.get(..written).unwrap_or_default();
        self.hasher.update(passed);
        self.bytes = self
            .bytes
            .saturating_add(u64::try_from(written).unwrap_or(u64::MAX));
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// `path` without its first folder, as plain relative parts.
fn without_first_folder(path: &Path) -> Option<String> {
    let mut parts = path.components();
    parts.next()?;
    plain_path(parts.as_path())
}

/// `path` as plain relative parts joined by `/`: no root, no `..`, no
/// `.`, and something to name. Every bundle file sits under a package
/// folder, so none meets a scratch file at the top.
fn plain_path(path: &Path) -> Option<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        let Component::Normal(part) = component else {
            return None;
        };
        parts.push(part.to_str()?.to_owned());
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tarball(dir: &Path, entries: &[(&str, &[u8])]) -> PathBuf {
        let path = dir.join("pkg.tgz");
        let file = File::create(&path).unwrap();
        let mut builder = tar::Builder::new(GzEncoder::new(file, Compression::default()));
        for (name, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_path(name).unwrap();
            header.set_cksum();
            builder.append(&header, *bytes).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();
        path
    }

    /// An npm tarball's files land under the package's folder, without the
    /// tarball's own `package/`.
    #[test]
    fn a_tarball_lands_under_its_package_folder() {
        let dir = tempfile::tempdir().unwrap();
        let mut tree = Tree::new().unwrap();

        tree.add_tarball(
            &tarball(dir.path(), &[("package/index.js", b"module.exports = 1")]),
            "node_modules/lodash",
        )
        .unwrap();

        assert!(tree.files.contains_key("node_modules/lodash/index.js"));
        assert_eq!(tree.bytes, 18);
    }

    /// A tarball entry containing parent-directory traversal is rejected as a broken archive.
    #[test]
    fn a_path_climbing_out_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evil.tgz");
        let mut header = tar::Header::new_gnu();
        header.set_size(1);
        header.set_entry_type(tar::EntryType::Regular);
        let name = b"package/../../etc/passwd";
        header.as_old_mut().name[..name.len()].copy_from_slice(name);
        header.set_cksum();
        let mut builder = tar::Builder::new(GzEncoder::new(
            File::create(&path).unwrap(),
            Compression::default(),
        ));
        builder.append(&header, &b"x"[..]).unwrap();
        builder.into_inner().unwrap().finish().unwrap();
        let mut tree = Tree::new().unwrap();

        assert!(matches!(
            tree.add_tarball(&path, "node_modules/evil"),
            Err(Unpacked::Broken)
        ));
    }

    /// The same files make the same bundle, byte for byte, whatever order
    /// they were added in.
    #[test]
    fn the_same_files_make_the_same_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let mut first = Tree::new().unwrap();
        let mut second = Tree::new().unwrap();
        first
            .add_tarball(
                &tarball(
                    dir.path(),
                    &[("package/a.js", b"a"), ("package/b.js", b"b")],
                ),
                "m",
            )
            .unwrap();
        second
            .add_tarball(
                &tarball(
                    dir.path(),
                    &[("package/b.js", b"b"), ("package/a.js", b"a")],
                ),
                "m",
            )
            .unwrap();

        let (one, two) = (first.packed().unwrap(), second.packed().unwrap());

        assert_eq!(one.digest, two.digest);
        assert_eq!(fs::read(one.path).unwrap(), fs::read(two.path).unwrap());
    }

    /// Once the bundle holds its maximum file count, even another empty file is refused.
    #[test]
    fn a_flood_of_files_is_refused_at_the_cap() {
        let mut tree = Tree::new().unwrap();
        for index in 0..MAX_BUNDLE_FILES {
            tree.put(&format!("m/{index}"), &mut io::empty(), FileMode::Plain)
                .unwrap();
        }

        let one_more = tree.put("m/last", &mut io::empty(), FileMode::Plain);

        assert!(matches!(one_more, Err(Unpacked::Broken)));
    }
}
