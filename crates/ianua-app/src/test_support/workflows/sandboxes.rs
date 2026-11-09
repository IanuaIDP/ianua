//! Sandboxes and their versions kept in memory, read back the way storage
//! reads them, a bundler answering as a test says, the builds queued, and
//! the sandboxes the tests start from.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::workflows::sandbox::build::{Bundle, BundleDigest};
use ianua_domain::domains::workflows::sandbox::network::NetworkAccess;
use ianua_domain::domains::workflows::sandbox::package::{
    PackageName, PackageVersion, Packages, PinnedPackage,
};
use ianua_domain::domains::workflows::sandbox::recipe::{
    CodeParams, CodeProgram, Program, RunBudget, SandboxCode,
};
use ianua_domain::domains::workflows::sandbox::runtime::{Language, Runtime, RuntimeImage};
use ianua_domain::domains::workflows::sandbox::source::CodeSource;
use ianua_domain::domains::workflows::sandbox::version::{SandboxVersion, SandboxVersionRow};
use ianua_domain::domains::workflows::sandbox::{
    CreateSandboxParams, Sandbox, SandboxKind, SandboxRow, VersionDraft,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::types::{Label, SandboxId, SandboxVersionId, TenantId};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::workflows::{
    BundleRequest, Bundling, NewestFirstField, OfferedRuntime, PackageBundler, SandboxRuntimes,
    SandboxSortField, SandboxStore, SandboxVersionStore,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::listing::page;
use crate::test_support::scheduling::FakeJobQueue;
use crate::test_support::workflows::graphs::{managing, person};
use crate::test_support::{Fake, test_ctx};
use crate::use_cases::scheduling::jobs::payload_of;
use crate::use_cases::workflows::sandboxes::build::BuildJob;
use crate::use_cases::workflows::sandboxes::{BUILD_SANDBOX_JOB, SandboxBuilds};

/// `sandbox` read back from its row, as storage reads it.
fn sandbox_copy(sandbox: &Sandbox<ResolvedTenant>) -> Sandbox<ResolvedTenant> {
    Sandbox::reconstitute(SandboxRow {
        id: *sandbox.id(),
        name: sandbox.name().clone(),
        kind: sandbox.kind(),
        status: sandbox.status(),
        latest_version: sandbox.latest_version(),
        created_by: sandbox.created_by().clone(),
        created_at: Aggregate::created_at(sandbox),
        updated_at: Aggregate::updated_at(sandbox),
    })
    .expect("a kept sandbox reads back as itself")
}

/// `version` read back from its row, as storage reads it.
fn version_copy(version: &SandboxVersion<ResolvedTenant>) -> SandboxVersion<ResolvedTenant> {
    SandboxVersion::reconstitute(SandboxVersionRow {
        id: *version.id(),
        sandbox_id: *version.sandbox_id(),
        number: version.number(),
        recipe: version.recipe().clone(),
        source: version.source().clone(),
        build: version.build().clone(),
        holds: version.holds().clone(),
        saved_by: version.saved_by().clone(),
        created_at: Aggregate::created_at(version),
        updated_at: Aggregate::updated_at(version),
    })
    .expect("a kept version reads back as itself")
}

/// In-memory sandbox store: sandboxes kept under their tenant.
#[derive(Default)]
pub struct FakeSandboxStore {
    sandboxes: Mutex<Vec<(TenantId, Sandbox<ResolvedTenant>)>>,
}

impl TenantScoped for FakeSandboxStore {}

impl FakeSandboxStore {
    /// A store holding no sandbox.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `sandbox` in the test tenant.
    #[must_use]
    pub fn holding(sandbox: &Sandbox<ResolvedTenant>) -> Self {
        Self {
            sandboxes: Mutex::new(vec![(test_ctx().tenant_id(), sandbox_copy(sandbox))]),
        }
    }

    /// The sandbox `id`, as the test tenant keeps it now.
    #[must_use]
    pub fn stored(&self, id: &SandboxId) -> Option<Sandbox<ResolvedTenant>> {
        let tenant = test_ctx().tenant_id();
        self.sandboxes
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, kept)| *owner == tenant && kept.id() == id)
            .map(|(_, kept)| sandbox_copy(kept))
    }

    /// Every sandbox kept, in every tenant.
    #[must_use]
    pub fn all(&self) -> Vec<Sandbox<ResolvedTenant>> {
        self.sandboxes
            .lock()
            .unwrap()
            .iter()
            .map(|(_, kept)| sandbox_copy(kept))
            .collect()
    }
}

#[async_trait]
impl SandboxStore for FakeSandboxStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &SandboxId,
    ) -> Result<Option<Sandbox<ResolvedTenant>>, DomainError> {
        Ok(self
            .sandboxes
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, kept)| owner == &**tenant_id && kept.id() == id)
            .map(|(_, kept)| sandbox_copy(kept)))
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<SandboxSortField>,
        request: &PageRequest,
    ) -> Result<Page<Sandbox<ResolvedTenant>>, DomainError> {
        let found: Vec<_> = self
            .sandboxes
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, _)| owner == &**tenant_id)
            .map(|(_, kept)| sandbox_copy(kept))
            .collect();
        page(found, sort, request)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        sandbox: &Sandbox<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut sandboxes = self.sandboxes.lock().unwrap();
        sandboxes.retain(|(owner, kept)| owner != &**tenant_id || kept.id() != sandbox.id());
        sandboxes.push((**tenant_id, sandbox_copy(sandbox)));
        Ok(())
    }
}

impl Fake for Arc<dyn SandboxStore> {
    fn fake() -> Self {
        Arc::new(FakeSandboxStore::empty())
    }
}

/// In-memory version store: versions kept under their tenant, a number
/// taken once per sandbox, and a build written only while building.
#[derive(Default)]
pub struct FakeSandboxVersionStore {
    versions: Mutex<Vec<(TenantId, SandboxVersion<ResolvedTenant>)>>,
}

impl TenantScoped for FakeSandboxVersionStore {}

impl FakeSandboxVersionStore {
    /// A store holding no version.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `version` in the test tenant.
    #[must_use]
    pub fn holding(version: &SandboxVersion<ResolvedTenant>) -> Self {
        Self {
            versions: Mutex::new(vec![(test_ctx().tenant_id(), version_copy(version))]),
        }
    }

    /// The version `id`, as the test tenant keeps it now.
    #[must_use]
    pub fn stored(&self, id: &SandboxVersionId) -> Option<SandboxVersion<ResolvedTenant>> {
        let tenant = test_ctx().tenant_id();
        self.versions
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, kept)| *owner == tenant && kept.id() == id)
            .map(|(_, kept)| version_copy(kept))
    }
}

#[async_trait]
impl SandboxVersionStore for FakeSandboxVersionStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &SandboxVersionId,
    ) -> Result<Option<SandboxVersion<ResolvedTenant>>, DomainError> {
        Ok(self
            .versions
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, kept)| owner == &**tenant_id && kept.id() == id)
            .map(|(_, kept)| version_copy(kept)))
    }

    async fn list_of(
        &self,
        tenant_id: &ScopedTenant,
        sandbox_id: &SandboxId,
        request: &PageRequest,
    ) -> Result<Page<SandboxVersion<ResolvedTenant>>, DomainError> {
        let found: Vec<_> = self
            .versions
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, kept)| owner == &**tenant_id && kept.sandbox_id() == sandbox_id)
            .map(|(_, kept)| version_copy(kept))
            .collect();
        page(found, &SortOrder::<NewestFirstField>::default(), request)
    }

    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        version: &SandboxVersion<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut versions = self.versions.lock().unwrap();
        let taken = versions.iter().any(|(owner, kept)| {
            owner == &**tenant_id
                && kept.sandbox_id() == version.sandbox_id()
                && kept.number() == version.number()
        });
        if taken {
            return Err(DomainError::conflict(
                "the sandbox already has a version of that number",
            ));
        }
        versions.push((**tenant_id, version_copy(version)));
        Ok(())
    }

    async fn save_build(
        &self,
        tenant_id: &ScopedTenant,
        version: &SandboxVersion<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut versions = self.versions.lock().unwrap();
        let building = versions.iter().position(|(owner, kept)| {
            owner == &**tenant_id
                && kept.id() == version.id()
                && kept.build().as_str() == "building"
        });
        let Some(index) = building else {
            return Err(DomainError::conflict(
                "the version was built or failed already",
            ));
        };
        versions[index] = (**tenant_id, version_copy(version));
        Ok(())
    }
}

impl Fake for Arc<dyn SandboxVersionStore> {
    fn fake() -> Self {
        Arc::new(FakeSandboxVersionStore::empty())
    }
}

/// A bundler giving every request the same answer.
pub struct FakePackageBundler {
    answer: Bundling,
}

impl TenantScoped for FakePackageBundler {}

impl FakePackageBundler {
    /// A bundler answering `answer`.
    #[must_use]
    pub fn answering(answer: Bundling) -> Self {
        Self { answer }
    }
}

#[async_trait]
impl PackageBundler for FakePackageBundler {
    async fn bundle(
        &self,
        _tenant_id: &ScopedTenant,
        _request: BundleRequest<'_>,
    ) -> Result<Bundling, DomainError> {
        Ok(self.answer.clone())
    }
}

impl Fake for Arc<dyn PackageBundler> {
    fn fake() -> Self {
        Arc::new(FakePackageBundler::answering(Bundling::Unavailable(
            ianua_domain::types::UntrustedText::record("no registry in this test"),
        )))
    }
}

/// The builds a use case queues, held in a fake queue.
#[derive(Default)]
pub struct QueuedBuilds {
    queue: Arc<FakeJobQueue>,
}

impl QueuedBuilds {
    /// No build queued yet.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// The builds the use case under test queues, kept here.
    #[must_use]
    pub fn builds(&self) -> SandboxBuilds {
        SandboxBuilds::new(self.queue.clone())
    }

    /// The versions whose builds were queued, in order.
    ///
    /// # Panics
    ///
    /// When a queued build job does not name a version.
    #[must_use]
    pub fn queued(&self) -> Vec<SandboxVersionId> {
        self.queue
            .jobs_of(BUILD_SANDBOX_JOB)
            .iter()
            .map(|job| payload_of::<BuildJob>(job).unwrap().version_id)
            .collect()
    }
}

impl Fake for SandboxBuilds {
    fn fake() -> Self {
        QueuedBuilds::none().builds()
    }
}

/// Ann's Python sandbox "Clean issue text", with no version yet.
///
/// # Panics
///
/// Never: Ann holds every workflow right.
#[must_use]
pub fn python_sandbox() -> Sandbox<ResolvedTenant> {
    Sandbox::create(
        CreateSandboxParams {
            name: Label::new("name", "Clean issue text").expect("a name"),
            kind: SandboxKind::Code(Language::Python),
        },
        &managing(&person("ann@corp.test")),
    )
    .expect("Ann makes a sandbox")
}

/// The image these tests say `runtime` is offered in: named by a digest
/// made from the runtime's name.
///
/// # Panics
///
/// Never: the digest is 64 hex digits.
#[must_use]
pub fn test_image(runtime: Runtime) -> RuntimeImage {
    let digest = format!("{:0>64}", runtime.as_str().len());
    RuntimeImage::new(format!("{}-slim@sha256:{digest}", runtime.as_str())).expect("an image")
}

/// Runtimes offered as a test says: every one in its [`test_image`], but
/// those it retired.
pub struct FakeSandboxRuntimes {
    retired: Vec<Runtime>,
}

impl FakeSandboxRuntimes {
    /// Every runtime offered.
    #[must_use]
    pub fn offering_all() -> Self {
        Self {
            retired: Vec::new(),
        }
    }

    /// Every runtime offered but `retired`.
    #[must_use]
    pub fn retiring(retired: Runtime) -> Self {
        Self {
            retired: vec![retired],
        }
    }
}

impl SandboxRuntimes for FakeSandboxRuntimes {
    fn offered(&self) -> Vec<OfferedRuntime> {
        Runtime::ALL
            .into_iter()
            .filter(|runtime| !self.retired.contains(runtime))
            .map(|runtime| OfferedRuntime {
                runtime,
                image: test_image(runtime),
            })
            .collect()
    }

    fn image_of(&self, runtime: Runtime) -> Option<RuntimeImage> {
        (!self.retired.contains(&runtime)).then(|| test_image(runtime))
    }
}

impl Fake for Arc<dyn SandboxRuntimes> {
    fn fake() -> Self {
        Arc::new(FakeSandboxRuntimes::offering_all())
    }
}

/// The next version of `sandbox`, under Python 3.13 and pinning
/// `requests` 2.31.0, its bundle still to build.
///
/// # Panics
///
/// Never: the sandbox is active and Ann holds every workflow right.
#[must_use]
pub fn version_of(sandbox: &mut Sandbox<ResolvedTenant>) -> SandboxVersion<ResolvedTenant> {
    let requests = PinnedPackage::new(
        PackageName::new(Language::Python, "requests").expect("a name"),
        PackageVersion::new(Language::Python, "2.31.0").expect("a version"),
    );
    let code = CodeProgram::new(CodeParams {
        runtime: Runtime::Python313,
        image: test_image(Runtime::Python313),
        code: SandboxCode::new("def main(item):\n\treturn item\n").expect("code"),
        packages: Packages::new(vec![requests]).expect("one package"),
    })
    .expect("Python code pinning a Python package");
    let draft = VersionDraft {
        program: Program::Code(code),
        budget: RunBudget::new(30, 256).expect("a budget"),
        network: NetworkAccess::closed(),
        source: CodeSource::Written,
    };
    sandbox
        .save_version(&managing(&person("ann@corp.test")), draft)
        .expect("Ann saves a version")
}

/// Version 1 of a fresh [`python_sandbox`], its bundle still to build.
#[must_use]
pub fn building_version() -> SandboxVersion<ResolvedTenant> {
    version_of(&mut python_sandbox())
}

/// The next version of `sandbox`, its bundle built.
///
/// # Panics
///
/// Never: the version is being built and its bundle fits it.
#[must_use]
pub fn built_version_of(sandbox: &mut Sandbox<ResolvedTenant>) -> SandboxVersion<ResolvedTenant> {
    let mut version = version_of(sandbox);
    let bundle = Bundle::new(
        BundleDigest::new("b".repeat(64)).expect("a digest"),
        4096,
        Vec::new(),
    )
    .expect("a bundle");
    version.finish_build(bundle).expect("the bundle fits");
    version
}
