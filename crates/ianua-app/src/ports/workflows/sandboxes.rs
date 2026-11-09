//! Sandboxes ports: where sandboxes and their versions are kept, what
//! fetches a version's packages, checks them and keeps them as one bundle,
//! what runs a version's code; and for a company's own image, where the
//! allowed registries are kept, what pins a named image to its digest and
//! what scans it for known vulnerabilities.

use async_trait::async_trait;
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::execution::step::CodeOutcome;
use ianua_domain::domains::workflows::sandbox::Sandbox;
use ianua_domain::domains::workflows::sandbox::build::{BuildFailure, Bundle};
use ianua_domain::domains::workflows::sandbox::image::{
    ImageDigest, ImageFindings, ImageName, PinnedImage, RegistryHost,
};
use ianua_domain::domains::workflows::sandbox::package::Packages;
use ianua_domain::domains::workflows::sandbox::registry::{ImageRegistry, RegistryUsername};
use ianua_domain::domains::workflows::sandbox::runtime::{Runtime, RuntimeImage};
use ianua_domain::domains::workflows::sandbox::trial::SandboxTrial;
use ianua_domain::domains::workflows::sandbox::version::SandboxVersion;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    CodeRunId, ImageRegistryId, SandboxId, SandboxTrialId, SandboxVersionId, UntrustedText,
};
use time::OffsetDateTime;

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::workflows::NewestFirstField;
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// Field a listing of sandboxes can be ordered by.
    pub enum SandboxSortField {
        /// Order by when it last changed.
        UpdatedAt => "updated_at",
        /// Order by name.
        Name => "name",
    }
    default = UpdatedAt;
    default direction = Desc;
}

impl SortKeys<SandboxSortField> for Sandbox<ResolvedTenant> {
    fn sort_key(&self, field: SandboxSortField) -> SortKey {
        match field {
            SandboxSortField::UpdatedAt => Aggregate::updated_at(self).into(),
            SandboxSortField::Name => self.name().as_str().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

impl SortKeys<NewestFirstField> for SandboxVersion<ResolvedTenant> {
    fn sort_key(&self, field: NewestFirstField) -> SortKey {
        match field {
            NewestFirstField::CreatedAt => Aggregate::created_at(self).into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// Where a tenant's sandboxes are kept.
#[async_trait]
pub trait SandboxStore: Send + Sync + TenantScoped {
    /// One sandbox.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &SandboxId,
    ) -> Result<Option<Sandbox<ResolvedTenant>>, DomainError>;

    /// The tenant's sandboxes, ordered and paged, archived ones among them.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn list(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<SandboxSortField>,
        page: &PageRequest,
    ) -> Result<Page<Sandbox<ResolvedTenant>>, DomainError>;

    /// Keeps a sandbox: a new one is added, a known one takes its name,
    /// status and latest version number.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be
    /// written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        sandbox: &Sandbox<ResolvedTenant>,
    ) -> Result<(), DomainError>;
}

/// Where the versions of a tenant's sandboxes are kept.
#[async_trait]
pub trait SandboxVersionStore: Send + Sync + TenantScoped {
    /// One version.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &SandboxVersionId,
    ) -> Result<Option<SandboxVersion<ResolvedTenant>>, DomainError>;

    /// The versions of `sandbox_id`, newest first and paged.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn list_of(
        &self,
        tenant_id: &ScopedTenant,
        sandbox_id: &SandboxId,
        page: &PageRequest,
    ) -> Result<Page<SandboxVersion<ResolvedTenant>>, DomainError>;

    /// Adds a version just saved.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` when the sandbox already has a
    /// version of that number, saved by someone else meanwhile, and
    /// `DomainError::Infrastructure` when the store cannot be written.
    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        version: &SandboxVersion<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Writes what building a version's bundle came to, only while the
    /// stored version is still being built.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` when it was built or failed already,
    /// or is gone, and `DomainError::Infrastructure` when the store cannot
    /// be written.
    async fn save_build(
        &self,
        tenant_id: &ScopedTenant,
        version: &SandboxVersion<ResolvedTenant>,
    ) -> Result<(), DomainError>;
}

/// Where the trials of a tenant's sandbox versions are kept.
#[async_trait]
pub trait SandboxTrialStore: Send + Sync + TenantScoped {
    /// One trial.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &SandboxTrialId,
    ) -> Result<Option<SandboxTrial<ResolvedTenant>>, DomainError>;

    /// Adds a trial just started.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be
    /// written.
    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        trial: &SandboxTrial<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Writes how a trial went, only while the stored trial still runs.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` when it ended already or is gone,
    /// and `DomainError::Infrastructure` when the store cannot be written.
    async fn save_end(
        &self,
        tenant_id: &ScopedTenant,
        trial: &SandboxTrial<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Removes the tenant's trials that ended before `cutoff`, and says how
    /// many went. Trials still running are kept, however old.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be
    /// written.
    async fn purge_ended_before(
        &self,
        tenant_id: &ScopedTenant,
        cutoff: OffsetDateTime,
    ) -> Result<u64, DomainError>;
}

/// The packages of one version, to fetch and bundle.
#[derive(Debug, Clone, Copy)]
pub struct BundleRequest<'a> {
    /// The version the bundle is kept for.
    pub version: &'a SandboxVersionId,
    /// The runtime it runs under, which picks the registry and what of a
    /// package runs there.
    pub runtime: Runtime,
    /// The exact packages to fetch.
    pub packages: &'a Packages,
}

/// What fetching a version's packages came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bundling {
    /// Every package was fetched, matched its published fingerprint and is
    /// kept in the bundle.
    Built(Bundle),
    /// A package cannot go in a bundle, for this reason. Trying again
    /// changes nothing.
    Refused(BuildFailure),
    /// The registry could not be reached or answered with an error, as
    /// this says; it may answer a later try.
    Unavailable(UntrustedText),
}

/// Fetches a version's exact packages from its runtime's registry, or the
/// mirror the operator names, checks each against the fingerprint the
/// registry published, and keeps them as one bundle for the version.
///
/// Nothing a package holds is run while it is fetched: one that runs a
/// script when it is installed is refused.
#[async_trait]
pub trait PackageBundler: Send + Sync + TenantScoped {
    /// The bundle of `request`'s packages, kept for its version.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the bundle cannot be
    /// kept.
    async fn bundle(
        &self,
        tenant_id: &ScopedTenant,
        request: BundleRequest<'_>,
    ) -> Result<Bundling, DomainError>;
}

/// One runtime the platform offers new versions, and the exact image it
/// offers it in now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferedRuntime {
    /// The language environment available for new code versions.
    pub runtime: Runtime,
    /// The image a version saved now keeps.
    pub image: RuntimeImage,
}

/// The runtimes the platform offers new versions, as its operator set them.
///
/// A runtime the operator retired is offered no more, but the versions
/// saved under it keep their image and still run. Moving a runtime to a
/// newer image changes only the versions saved after.
pub trait SandboxRuntimes: Send + Sync {
    /// Every runtime offered now, oldest first within each language.
    fn offered(&self) -> Vec<OfferedRuntime>;

    /// The image `runtime` is offered in now. `None` when it is not
    /// offered: retired, or never set up.
    fn image_of(&self, runtime: Runtime) -> Option<RuntimeImage>;
}

/// One run of a version's code, to make.
#[derive(Debug, Clone, Copy)]
pub struct CodeRequest<'a> {
    /// The run, which the runner may name its work after.
    pub run_id: CodeRunId,
    /// The version whose code runs, with its runtime, limits and bundle,
    /// or its company's image.
    pub version: &'a SandboxVersion<ResolvedTenant>,
    /// What the code is given.
    pub input: &'a FlowData,
    /// How a company's image is pulled; anonymous for code, whose
    /// runtime's image the platform offers.
    pub login: &'a PullLogin,
}

/// What asking for a run came to.
#[derive(Debug, Clone, PartialEq)]
pub enum CodeRan {
    /// The code ran, and this is how it went.
    Ran(CodeOutcome),
    /// No sandbox could take the run, as this says; a later try may find
    /// one. The code did not run.
    Unavailable(UntrustedText),
}

/// Runs a version's code in a sandbox of its own: its runtime, its bundle
/// of packages, and nothing else; or its company's image, pulled with the
/// request's login within a bounded time.
///
/// The sandbox reaches no network, writes nowhere that outlives it, and is
/// stopped at the version's time and memory limits. The code is handed its
/// input and gives back one JSON value. An image that cannot be pulled
/// fails the run as not run.
#[async_trait]
pub trait CodeRunner: Send + Sync + TenantScoped {
    /// Runs `request`'s code for `tenant_id`.
    async fn run(&self, tenant_id: &ScopedTenant, request: CodeRequest<'_>) -> CodeRan;
}

/// Where a tenant's allowed image registries are kept, once per host.
#[async_trait]
pub trait ImageRegistryStore: Send + Sync + TenantScoped {
    /// One registry.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ImageRegistryId,
    ) -> Result<Option<ImageRegistry<ResolvedTenant>>, DomainError>;

    /// The registry kept for `host`, which an image names first.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn find_by_host(
        &self,
        tenant_id: &ScopedTenant,
        host: &RegistryHost,
    ) -> Result<Option<ImageRegistry<ResolvedTenant>>, DomainError>;

    /// Every registry the tenant allowed, by host. A tenant allows a few,
    /// so they are read whole.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<ImageRegistry<ResolvedTenant>>, DomainError>;

    /// Adds a registry just allowed.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` when the tenant allowed its host
    /// already, and `DomainError::Infrastructure` when the store cannot be
    /// written.
    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        registry: &ImageRegistry<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Drops a registry taken off the list.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be
    /// written.
    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &ImageRegistryId,
    ) -> Result<(), DomainError>;
}

/// How an image is pulled from its registry, opened only to pull it.
#[derive(Debug, Clone)]
pub enum PullLogin {
    /// With no login.
    Anonymous,
    /// As a user, with a password or token.
    Password {
        /// The user it is pulled as.
        username: RegistryUsername,
        /// The password or token, in the clear and redacted when printed.
        password: Secret,
    },
}

/// What asking a registry about a named image came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolving {
    /// The name points to the image of this digest, of this many bytes as
    /// the registry counts its layers.
    Resolved {
        /// The digest of its manifest.
        digest: ImageDigest,
        /// Its size, in bytes.
        bytes: u64,
    },
    /// The registry has no such image, or refused the login, as this says.
    Refused(UntrustedText),
    /// The registry could not be reached or answered with an error, as
    /// this says; a later try may reach it.
    Unavailable(UntrustedText),
}

/// Asks a registry what a named image points to now, so a version keeps
/// that digest whatever later happens to the tag.
///
/// Only the image's manifest is read, within a bounded time; the registry's
/// host is looked up and refused when it leads anywhere private.
#[async_trait]
pub trait ImageResolver: Send + Sync {
    /// What `name` points to now, asked with `login`.
    async fn resolve(&self, name: &ImageName, login: &PullLogin) -> Resolving;
}

/// What scanning an image came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scanning {
    /// The image was scanned, and this is what was found.
    Scanned(ImageFindings),
    /// No scanner is set up, so no image is cleared.
    NotSetUp,
    /// The scanner could not scan the image, as this says; a later try may.
    Unavailable(UntrustedText),
}

/// Scans a company's image for known vulnerabilities before it first runs.
#[async_trait]
pub trait ImageScanner: Send + Sync {
    /// What scanning `image`, pulled with `login`, found.
    async fn scan(&self, image: &PinnedImage, login: &PullLogin) -> Scanning;
}

/// Whether this installation runs companies' own images, as its operator
/// set it; off unless turned on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OwnImages {
    /// No company image is saved, scanned or run.
    #[default]
    Off,
    /// Images from registries a tenant allowed are saved, scanned and run.
    On,
}
