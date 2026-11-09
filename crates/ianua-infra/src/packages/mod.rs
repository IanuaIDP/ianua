//! Package bundles of sandbox versions: each pinned package fetched from
//! its runtime's registry, or the mirror the operator names, checked
//! against the fingerprint the registry published, and every one kept as
//! one gzipped tar in the file store, named by the tenant and the version.
//!
//! npm packages land under `node_modules/<name>/`, Python wheels under
//! `python/`. Packages are fetched one at a time, outside any unit of work,
//! each streamed to a file and unpacked into a folder on disk that goes
//! with the build, so a bundle of 200 MB never sits in memory.
//! A registry that cannot be reached is reported as such, so the build is
//! tried again; a package that cannot go into a bundle, or says it does
//! not run under the version's runtime, is reported with why, so the
//! version fails naming it.

mod archive;
mod download;
mod npm;
mod pypi;
mod ranges;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::workflows::{BundleRequest, Bundling, PackageBundler};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::workflows::sandbox::build::{
    BuildFailure, Bundle, BundleDigest, MAX_BUNDLE_BYTES,
};
use ianua_domain::domains::workflows::sandbox::package::{PackageName, PinnedPackage};
use ianua_domain::domains::workflows::sandbox::runtime::{Language, Runtime};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::UntrustedText;
use tokio::io::AsyncReadExt as _;

use crate::files::{FileName, FileStore};
use crate::packages::archive::{Tree, Unpacked};

/// Where packages are fetched from.
#[derive(Debug, Clone)]
pub struct PackageRegistries {
    /// The npm registry, such as `https://registry.npmjs.org`.
    pub npm: String,
    /// The Python package index, such as `https://pypi.org`.
    pub pypi: String,
    /// The hosts the Python index's files may be fetched from, such as
    /// `files.pythonhosted.org`.
    pub pypi_file_hosts: Vec<String>,
    /// The longest one fetch may take.
    pub timeout: Duration,
}

/// What fetching one package came to.
#[derive(Debug)]
pub(crate) enum Fetched {
    /// Its archive is on disk and matches its published fingerprint.
    Got(Downloaded),
    /// It cannot go into a bundle, for this reason.
    Refused(BuildFailure),
    /// The registry could not be reached or failed, as this says.
    Down(String),
}

/// A package's archive, fetched and checked, waiting to be unpacked.
#[derive(Debug)]
pub(crate) struct Downloaded {
    /// How it is unpacked into the bundle.
    pub(crate) layout: Layout,
    /// The packages it says it needs, as its registry names them.
    pub(crate) needs: Vec<String>,
    /// The interpreters it says it runs under.
    pub(crate) runs_under: RunsUnder,
}

/// The interpreters a package says it runs under.
#[derive(Debug, Clone)]
pub(crate) enum RunsUnder {
    /// It says nothing.
    Any,
    /// Its `requires_python`, such as `>=3.9`.
    Python(String),
    /// Its `engines.node`, such as `^18 || >=20`.
    Node(String),
}

impl RunsUnder {
    /// Whether it says it does not run under `runtime`. A range not read
    /// says nothing, and refuses nothing.
    fn refuses(&self, runtime: Runtime) -> bool {
        let (major, minor) = runtime.release();
        let allows = match self {
            Self::Any => None,
            Self::Python(range) => ranges::python_allows(range, (major, minor)),
            Self::Node(range) => ranges::node_allows(range, major),
        };
        allows == Some(false)
    }
}

/// How a package's archive is unpacked into a bundle.
#[derive(Debug, Clone)]
pub(crate) enum Layout {
    /// An npm tarball, into this folder under `node_modules`.
    NodeModule(String),
    /// A wheel, into `python/`.
    Wheel,
}

impl Layout {
    /// Unpacks the archive at `archive` into `tree` as this layout says.
    fn unpack(&self, tree: &mut Tree, archive: &Path) -> Result<(), Unpacked> {
        match self {
            Self::NodeModule(folder) => tree.add_tarball(archive, folder),
            Self::Wheel => tree.add_wheel(archive, "python"),
        }
    }
}

/// The name a package's archive is fetched to, beside the bundle's files.
const ARCHIVE: &str = "archive";

/// How many bytes of a packed bundle are stored at a time.
const UPLOAD_CHUNK: usize = 1024 * 1024;

/// Bundles fetched from public registries, or the operator's mirrors, kept
/// in a file store.
pub struct RegistryPackageBundler {
    client: reqwest::Client,
    registries: PackageRegistries,
    store: Arc<dyn FileStore>,
}

/// Unpacked packages and their dependency names, ready to pack and store together.
struct PreparedBundle {
    tree: Tree,
    needs: Vec<String>,
}

impl TenantScoped for RegistryPackageBundler {}

impl RegistryPackageBundler {
    /// A bundler fetching from `registries` and keeping bundles in `store`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the HTTP client cannot be
    /// built.
    pub fn new(
        registries: PackageRegistries,
        store: Arc<dyn FileStore>,
    ) -> Result<Self, DomainError> {
        let client = reqwest::Client::builder()
            .timeout(registries.timeout)
            .connect_timeout(registries.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(DomainError::infra)?;
        Ok(Self {
            client,
            registries,
            store,
        })
    }

    /// Fetches the archive of `pinned`, from its runtime's registry, into
    /// the file `into`.
    async fn fetched(&self, runtime: Runtime, pinned: &PinnedPackage, into: &Path) -> Fetched {
        match runtime.language() {
            Language::JavaScript => {
                npm::fetch(&self.client, base(&self.registries.npm), pinned, into).await
            }
            Language::Python => {
                let index = pypi::Index {
                    base: base(&self.registries.pypi),
                    file_hosts: &self.registries.pypi_file_hosts,
                };
                pypi::fetch(&self.client, &index, pinned, into).await
            }
        }
    }

    /// Stores the bundle packed at `packed` as the bundle of `request`'s
    /// version, a chunk at a time.
    async fn store_bundle(
        &self,
        tenant: &ScopedTenant,
        request: BundleRequest<'_>,
        packed: &Path,
    ) -> Result<(), DomainError> {
        let mut file = tokio::fs::File::open(packed)
            .await
            .map_err(DomainError::infra)?;
        let mut upload = self
            .store
            .create(&FileName::sandbox_bundle(tenant, request.version))
            .await?;
        let mut chunk = vec![0_u8; UPLOAD_CHUNK];
        loop {
            let read = file.read(&mut chunk).await.map_err(DomainError::infra)?;
            let Some(part) = chunk.get(..read).filter(|part| !part.is_empty()) else {
                break;
            };
            upload.write(part).await?;
        }
        upload.finish().await
    }

    /// Packs the prepared tree, checks its final size and stores it before returning its digest.
    async fn finish_bundle(
        &self,
        tenant: &ScopedTenant,
        request: BundleRequest<'_>,
        prepared: PreparedBundle,
    ) -> Result<Bundling, DomainError> {
        let PreparedBundle { tree, needs } = prepared;
        let unlisted = unlisted(request, needs);
        let (tree, packed) = blocking(move || {
            let packed = tree.packed();
            (tree, packed)
        })
        .await?;
        let packed = packed.map_err(DomainError::infra)?;
        if packed.bytes > MAX_BUNDLE_BYTES {
            return Ok(Bundling::Refused(BuildFailure::TooLarge {
                bytes: packed.bytes,
            }));
        }
        let digest = BundleDigest::new(packed.digest).map_err(DomainError::infra)?;
        self.store_bundle(tenant, request, &packed.path).await?;
        drop(tree);
        Bundle::new(digest, packed.bytes, unlisted).map(Bundling::Built)
    }
}

#[async_trait]
impl PackageBundler for RegistryPackageBundler {
    async fn bundle(
        &self,
        tenant_id: &ScopedTenant,
        request: BundleRequest<'_>,
    ) -> Result<Bundling, DomainError> {
        let mut tree = Tree::new().map_err(DomainError::infra)?;
        let mut needs: Vec<String> = Vec::new();
        for pinned in request.packages.as_slice() {
            let archive = tree.scratch(ARCHIVE);
            let downloaded = match self.fetched(request.runtime, pinned, &archive).await {
                Fetched::Got(downloaded) => downloaded,
                Fetched::Refused(failure) => return Ok(Bundling::Refused(failure)),
                Fetched::Down(why) => {
                    return Ok(Bundling::Unavailable(UntrustedText::record(&why)));
                }
            };
            if downloaded.runs_under.refuses(request.runtime) {
                return Ok(Bundling::Refused(BuildFailure::WrongRuntime(
                    pinned.name().clone(),
                )));
            }
            let layout = downloaded.layout.clone();
            let (back, unpacked) = blocking(move || unpack_into(tree, &layout, &archive)).await?;
            tree = back;
            if let Err(unpacked) = unpacked {
                return refusal(pinned.name(), unpacked);
            }
            needs.extend(downloaded.needs);
        }
        self.finish_bundle(tenant_id, request, PreparedBundle { tree, needs })
            .await
    }
}

/// `tree` with the archive at `archive` unpacked into it as `layout` says,
/// handed back with what unpacking came to.
fn unpack_into(mut tree: Tree, layout: &Layout, archive: &Path) -> (Tree, Result<(), Unpacked>) {
    let unpacked = layout.unpack(&mut tree, archive);
    let removed = std::fs::remove_file(archive).map_err(Unpacked::Disk);
    (tree, unpacked.and(removed))
}

/// What `work` gives back, run on a thread that may block, as reading and
/// writing files does.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, DomainError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(DomainError::infra)
}

/// The packages `needs` names that `request` does not pin, each once, in
/// name order. A name its registry would not take is left out.
fn unlisted(request: BundleRequest<'_>, needs: Vec<String>) -> Vec<PackageName> {
    let language = request.runtime.language();
    let mut names: Vec<PackageName> = needs
        .into_iter()
        .filter_map(|need| PackageName::new(language, need).ok())
        .filter(|name| !request.packages.pins(name))
        .collect();
    names.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    names.dedup();
    names
}

/// What a package's archive that could not be unpacked means for the
/// build: refused naming the package, or a disk that failed.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the bundle's folder could
/// not be written.
fn refusal(name: &PackageName, unpacked: Unpacked) -> Result<Bundling, DomainError> {
    match unpacked {
        Unpacked::Broken => Ok(Bundling::Refused(BuildFailure::BadArchive(name.clone()))),
        Unpacked::TooLarge(bytes) => Ok(Bundling::Refused(BuildFailure::TooLarge { bytes })),
        Unpacked::Disk(error) => Err(DomainError::infra(error)),
    }
}

/// The failure of a file larger than any bundle may be.
pub(crate) fn too_large() -> BuildFailure {
    BuildFailure::TooLarge {
        bytes: MAX_BUNDLE_BYTES.saturating_add(1),
    }
}

/// `url` without a slash at its end, so paths are joined with one.
fn base(url: &str) -> &str {
    url.trim_end_matches('/')
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use ianua_domain::domains::workflows::sandbox::package::{PackageVersion, Packages};
    use ianua_domain::types::{SandboxVersionId, TenantId};
    use serde_json::json;
    use sha2::{Digest as _, Sha512};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::files::DiskFileStore;

    /// An npm tarball holding `index.js`.
    fn tarball() -> Vec<u8> {
        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        let body = b"module.exports = (s) => s.trim()";
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_path("package/index.js").unwrap();
        header.set_cksum();
        builder.append(&header, &body[..]).unwrap();
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn integrity_of(bytes: &[u8]) -> String {
        format!("sha512-{}", STANDARD.encode(Sha512::digest(bytes)))
    }

    /// A stand-in npm registry serving `trim` 1.0.0 with `metadata`, and
    /// its tarball.
    async fn registry(metadata: serde_json::Value) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/trim/1.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/trim/-/trim-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball()))
            .mount(&server)
            .await;
        server
    }

    /// A bundler on a stand-in registry, keeping bundles in a folder of its
    /// own.
    struct OnRegistry {
        _dir: tempfile::TempDir,
        bundler: RegistryPackageBundler,
    }

    fn bundler_on(server: &MockServer) -> OnRegistry {
        let dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn FileStore> = Arc::new(DiskFileStore::new(dir.path()));
        let registries = PackageRegistries {
            npm: server.uri(),
            pypi: server.uri(),
            pypi_file_hosts: Vec::new(),
            timeout: Duration::from_secs(5),
        };
        OnRegistry {
            bundler: RegistryPackageBundler::new(registries, store).unwrap(),
            _dir: dir,
        }
    }

    async fn bundled(bundling: &OnRegistry) -> Bundling {
        let trim = PinnedPackage::new(
            PackageName::new(Language::JavaScript, "trim").unwrap(),
            PackageVersion::new(Language::JavaScript, "1.0.0").unwrap(),
        );
        let packages = Packages::new(vec![trim]).unwrap();
        let tenant = ScopedTenant::for_background(TenantId::new());
        let version = SandboxVersionId::new();
        let request = BundleRequest {
            version: &version,
            runtime: Runtime::Node22,
            packages: &packages,
        };
        bundling.bundler.bundle(&tenant, request).await.unwrap()
    }

    /// Ann pins `trim` 1.0.0, which needs `left-pad`. The registry's
    /// tarball matches its fingerprint, so the bundle is built and names
    /// `left-pad` as needed but not pinned.
    #[tokio::test]
    async fn a_package_matching_its_fingerprint_is_bundled() {
        let server = registry(json!({
            "dist": {"integrity": integrity_of(&tarball())},
            "dependencies": {"left-pad": "^1.3.0"}
        }))
        .await;
        let bundling = bundler_on(&server);

        let answer = bundled(&bundling).await;

        let Bundling::Built(bundle) = answer else {
            panic!("the bundle was not built: {answer:?}");
        };
        let unlisted: Vec<&str> = bundle.unlisted().iter().map(PackageName::as_str).collect();
        assert_eq!(unlisted, ["left-pad"]);
        assert!(bundle.bytes() > 0);
    }

    /// Bundling trim for Node 22 fails with its package name when it requires Node 24.
    #[tokio::test]
    async fn a_package_that_needs_another_node_is_refused() {
        let server = registry(json!({
            "dist": {"integrity": integrity_of(&tarball())},
            "engines": {"node": ">=24"}
        }))
        .await;
        let bundling = bundler_on(&server);

        let answer = bundled(&bundling).await;

        assert!(
            matches!(&answer, Bundling::Refused(BuildFailure::WrongRuntime(name)) if name.as_str() == "trim"),
            "{answer:?}"
        );
    }

    /// A tarball differing from its published fingerprint fails the bundle build.
    #[tokio::test]
    async fn a_package_not_matching_its_fingerprint_is_refused() {
        let server = registry(json!({"dist": {"integrity": integrity_of(b"other bytes")}})).await;
        let bundling = bundler_on(&server);

        let answer = bundled(&bundling).await;

        assert!(matches!(
            answer,
            Bundling::Refused(BuildFailure::FingerprintMismatch(_))
        ));
    }

    /// A package declaring a postinstall script receives an install-script refusal.
    #[tokio::test]
    async fn a_package_running_an_install_script_is_refused() {
        let server = registry(json!({
            "dist": {"integrity": integrity_of(&tarball())},
            "scripts": {"postinstall": "node setup.js"}
        }))
        .await;
        let bundling = bundler_on(&server);

        let answer = bundled(&bundling).await;

        assert!(matches!(
            answer,
            Bundling::Refused(BuildFailure::InstallScript(_))
        ));
    }

    /// The registry answers 503. The build is told the registry is
    /// unavailable, so it is tried again rather than failed.
    #[tokio::test]
    async fn a_registry_that_is_down_is_reported_as_unavailable() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let bundling = bundler_on(&server);

        let answer = bundled(&bundling).await;

        assert!(matches!(answer, Bundling::Unavailable(_)));
    }
}
