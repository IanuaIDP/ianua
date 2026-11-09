//! Build version: a saved sandbox version's packages are fetched, checked
//! against the fingerprints their registry published and kept as one
//! bundle, and the version is marked ready, or failed with why. A version
//! of a company's image is scanned for known vulnerabilities instead, with
//! its registry's login: nothing critical clears it to run, one critical
//! finding refuses it, and no scanner set up refuses it too.
//!
//! It runs as a `sandbox.build` job, queued in the unit of work that saved
//! the version. Fetching is slow, so it happens outside any unit of work;
//! only the result is kept, with its record, and only while the version is
//! still being built, so a second try that raced the first changes
//! nothing. A registry or scanner that cannot be reached is tried again;
//! on the last try the version fails, so no version waits for ever.

use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_key::KeyHold;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::domains::workflows::sandbox::build::{Build, BuildFailure};
use ianua_domain::domains::workflows::sandbox::recipe::{CodeProgram, Program};
use ianua_domain::domains::workflows::sandbox::version::SandboxVersion;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{SandboxVersionId, TenantId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::runtime::UnitOfWork;
use crate::ports::scheduling::JobQueue;
use crate::ports::workflows::{
    BundleRequest, Bundling, ImageScanner, PackageBundler, SandboxVersionStore, Scanning,
};
use crate::services::kept_together::kept_together;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::scheduling::{
    Handled, JobHandler, NewJob, RetryWhen, key_of, payload_of, unless_gone,
};
use crate::use_cases::workflows::sandboxes::images::pulls::{ImagePulls, Pull};

/// The job type that builds a sandbox version's bundle.
pub const BUILD_SANDBOX_JOB: &str = "sandbox.build";

/// Tries a build gets. A registry down for longer than the backoff over
/// these tries fails the version, which a person saves again.
const BUILD_TRIES: NonZeroU32 = match NonZeroU32::new(5) {
    Some(tries) => tries,
    None => NonZeroU32::MIN,
};

/// What a build job carries: which version of which tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct BuildJob {
    /// The scope owning the source revision to build.
    pub(crate) tenant_id: TenantId,
    /// The saved code revision whose runnable bundle is needed.
    pub(crate) version_id: SandboxVersionId,
}

/// Where saved versions ask for their bundle to be built.
#[derive(Clone)]
pub struct SandboxBuilds {
    queue: Arc<dyn JobQueue>,
}

impl SandboxBuilds {
    /// Builds queued on `queue`.
    #[must_use]
    pub fn new(queue: Arc<dyn JobQueue>) -> Self {
        Self { queue }
    }

    /// Builds the bundle of `version` of `tenant` as soon as a worker is
    /// free. Asking twice queues one job.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the job cannot be built or queued.
    pub(crate) async fn queue(
        &self,
        tenant: &ScopedTenant,
        version: &SandboxVersionId,
    ) -> Result<(), AppError> {
        NewJob {
            job_type: BUILD_SANDBOX_JOB,
            payload: &BuildJob {
                tenant_id: **tenant,
                version_id: *version,
            },
            tenant_id: **tenant,
            key: key_of(version, BUILD_SANDBOX_JOB)?,
            hold: KeyHold::WhileLive,
            run_at: clock::now(),
            attempts: BUILD_TRIES,
        }
        .queue(self.queue.as_ref())
        .await?;
        Ok(())
    }
}

/// Whether a try is the build's last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildTry {
    /// Another follows if this one cannot reach the registry.
    NotLast,
    /// None follows: a registry that cannot be reached fails the version.
    Last,
}

/// One try at building a version's bundle.
#[derive(Debug, Clone, Copy)]
pub struct BuildRequest {
    /// The saved code revision whose runnable bundle is needed.
    pub version_id: SandboxVersionId,
    /// Whether this try is the last.
    pub attempt: BuildTry,
}

/// What a try at a build came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildTurn {
    /// The version is ready or failed, or was gone or built already.
    Settled,
    /// The registry or the scanner could not be reached; the build is
    /// tried again.
    TryAgain,
}

/// The ports [`BuildVersionUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct BuildVersionPorts {
    /// Keeps the versions.
    pub versions: Arc<dyn SandboxVersionStore>,
    /// Fetches, checks and keeps a version's packages.
    pub bundler: Arc<dyn PackageBundler>,
    /// Opens the login a company's image is scanned with.
    pub pulls: ImagePulls,
    /// Scans a company's image for known vulnerabilities.
    pub scanner: Arc<dyn ImageScanner>,
    /// Keeps the result and its record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Builds the bundles of saved sandbox versions.
pub struct BuildVersionUseCase {
    ports: BuildVersionPorts,
}

impl BuildVersionUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: BuildVersionPorts) -> Self {
        Self { ports }
    }

    /// Builds the bundle of `version`'s code. `None` when the registry could
    /// not be reached and another try follows.
    async fn bundled(
        &self,
        tenant: &ScopedTenant,
        version: &mut SandboxVersion<ResolvedTenant>,
        attempt: BuildTry,
    ) -> Result<Option<()>, AppError> {
        let Program::Code(code) = version.recipe().program() else {
            return Ok(Some(()));
        };
        let request = bundle_request(version.id(), code);
        let bundling = self
            .ports
            .bundler
            .bundle(tenant, request)
            .await
            .or_internal()?;
        let built = match (bundling, attempt) {
            (Bundling::Built(bundle), _) => version.finish_build(bundle),
            (Bundling::Refused(failure), _) => version.fail_build(failure),
            (Bundling::Unavailable(_), BuildTry::NotLast) => return Ok(None),
            (Bundling::Unavailable(_), BuildTry::Last) => {
                version.fail_build(BuildFailure::RegistryUnavailable)
            }
        };
        built.map(Some).map_err(AppError::from_domain)
    }

    /// Scans the company's image of `version` with its registry's login.
    /// `None` when the scanner could not scan it and another try follows.
    async fn scanned(
        &self,
        tenant: &ScopedTenant,
        version: &mut SandboxVersion<ResolvedTenant>,
        attempt: BuildTry,
    ) -> Result<Option<()>, AppError> {
        let Program::Image(own) = version.recipe().program() else {
            return Ok(Some(()));
        };
        let image = own.image().clone();
        let login = match self
            .ports
            .pulls
            .for_registry(tenant, image.registry())
            .await?
        {
            Pull::Allowed(login) => login,
            Pull::Refused(refusal) => {
                return version
                    .fail_build(refusal.build_failure())
                    .map(Some)
                    .map_err(AppError::from_domain);
            }
        };
        let scanned = match (self.ports.scanner.scan(&image, &login).await, attempt) {
            (Scanning::Scanned(findings), _) => version.finish_scan(&findings),
            (Scanning::NotSetUp, _) => version.fail_build(BuildFailure::NotScanned),
            (Scanning::Unavailable(_), BuildTry::NotLast) => return Ok(None),
            (Scanning::Unavailable(_), BuildTry::Last) => {
                version.fail_build(BuildFailure::ScannerUnavailable)
            }
        };
        scanned.map(Some).map_err(AppError::from_domain)
    }

    /// Keeps `version`, its build settled, with its record, unless another
    /// try settled it first.
    async fn settled(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        mut version: SandboxVersion<ResolvedTenant>,
    ) -> Result<BuildTurn, AppError> {
        let kept = kept_together(self.ports.unit_of_work.as_ref(), async {
            self.ports
                .versions
                .save_build(tenant, &version)
                .await
                .map_err(AppError::from_domain)?;
            auditor
                .dispatch(&version.take_events(tenant))
                .await
                .or_internal()
        })
        .await;
        match kept {
            Ok(()) | Err(AppError::Conflict(_)) => Ok(BuildTurn::Settled),
            Err(error) => Err(error),
        }
    }
}

impl Command for BuildVersionUseCase {
    type Caller = ScopedTenant;
    type Input = BuildRequest;
    type Output = Result<BuildTurn, AppError>;

    /// Builds the bundle of `request.version_id`, or scans its image,
    /// unless it is gone or built already.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the bundle the bundler kept does not fit
    ///   the version.
    /// - `AppError::Internal` when a store, the bundle's storage, a login or
    ///   the audit trail fails.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: BuildRequest,
    ) -> Result<BuildTurn, AppError> {
        let Some(mut version) = self
            .ports
            .versions
            .find_by_id(tenant, &request.version_id)
            .await
            .or_internal()?
        else {
            return Ok(BuildTurn::Settled);
        };
        if version.build() != &Build::Building {
            return Ok(BuildTurn::Settled);
        }
        let settled = match version.recipe().program() {
            Program::Code(_) => self.bundled(tenant, &mut version, request.attempt).await?,
            Program::Image(_) => self.scanned(tenant, &mut version, request.attempt).await?,
        };
        if settled.is_none() {
            return Ok(BuildTurn::TryAgain);
        }
        self.settled(tenant, auditor, version).await
    }
}

/// The packages of `code`, the program of `version`, to fetch for it.
fn bundle_request<'a>(version: &'a SandboxVersionId, code: &'a CodeProgram) -> BundleRequest<'a> {
    BundleRequest {
        version,
        runtime: code.runtime(),
        packages: code.packages(),
    }
}

/// Runs build jobs through [`BuildVersionUseCase`].
pub struct BuildHandler {
    job_type: JobType,
    build: Arc<BuildVersionUseCase>,
}

impl BuildHandler {
    /// A handler building bundles through `build`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when the job type is not one,
    /// which it always is.
    pub fn new(build: Arc<BuildVersionUseCase>) -> Result<Self, DomainError> {
        let job_type = JobType::new(BUILD_SANDBOX_JOB)?;
        Ok(Self { job_type, build })
    }
}

#[async_trait]
impl JobHandler for BuildHandler {
    fn job_type(&self) -> &JobType {
        &self.job_type
    }

    /// Builds the version's bundle. One gone or built already is left
    /// alone; a registry that cannot be reached is tried again on the
    /// queue's backoff, until the last try fails the version.
    async fn handle(
        &self,
        job: &ScheduledJob,
        auditor: &RequestAuditor,
    ) -> Result<Handled, AppError> {
        let payload: BuildJob = payload_of(job)?;
        let tenant = ScopedTenant::for_background(payload.tenant_id);
        let auditor = auditor.with_tenant(payload.tenant_id);
        let attempt = if job.can_retry() {
            BuildTry::NotLast
        } else {
            BuildTry::Last
        };
        let request = BuildRequest {
            version_id: payload.version_id,
            attempt,
        };
        let turn = unless_gone(self.build.execute(&tenant, &auditor, request).await)?;
        match turn {
            Some(BuildTurn::TryAgain) => Ok(Handled::Retry {
                reason: "the package registry or the image scanner could not be reached",
                when: RetryWhen::OnBackoff,
            }),
            Some(BuildTurn::Settled) | None => Ok(Handled::Done),
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::sandbox::build::{Bundle, BundleDigest};
    use ianua_domain::domains::workflows::sandbox::image::{
        ImageFindings, LesserFindings, VulnerabilityId,
    };
    use ianua_domain::types::UntrustedText;

    use super::*;
    use crate::ports::workflows::OwnImages;
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::workflows::{
        FakeImageRegistryStore, FakeImageScanner, FakePackageBundler, FakeSandboxVersionStore,
        acme_registry_with_login, building_image_version, building_version,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// What a build wrote, and what it recorded.
    struct Building {
        versions: Arc<FakeSandboxVersionStore>,
        sink: Arc<FakeEventDispatcher>,
        id: SandboxVersionId,
    }

    impl Building {
        fn new() -> Self {
            let version = building_version();
            Self {
                id: *version.id(),
                versions: Arc::new(FakeSandboxVersionStore::holding(&version)),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn build(&self, answer: Bundling, attempt: BuildTry) -> BuildTurn {
            let use_case = BuildVersionUseCase::new(BuildVersionPorts {
                versions: self.versions.clone(),
                bundler: Arc::new(FakePackageBundler::answering(answer)),
                ..BuildVersionPorts::fakes()
            });
            let request = BuildRequest {
                version_id: self.id,
                attempt,
            };
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.sink.clone()),
                request,
            ))
            .unwrap()
        }

        fn build_state(&self) -> Build {
            self.versions.stored(&self.id).unwrap().build().clone()
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    fn bundle() -> Bundle {
        Bundle::new(BundleDigest::new("c".repeat(64)).unwrap(), 8192, Vec::new()).unwrap()
    }

    fn down() -> Bundling {
        Bundling::Unavailable(UntrustedText::record("connection refused"))
    }

    /// Ann's version's packages are fetched and match their fingerprints.
    /// The version is ready with its bundle, and the trail records it.
    #[test]
    fn a_fetched_and_checked_bundle_makes_the_version_ready() {
        let building = Building::new();

        let turn = building.build(Bundling::Built(bundle()), BuildTry::NotLast);

        assert_eq!(turn, BuildTurn::Settled);
        assert_eq!(building.build_state(), Build::Ready(bundle()));
        assert_eq!(building.records(), ["workflows.sandbox_version_built"]);
    }

    /// A bundler refusal settles the build as failed with its supplied reason
    /// and records the version's failure.
    #[test]
    fn a_refused_package_fails_the_version() {
        let building = Building::new();
        let failure = BuildFailure::RegistryUnavailable;

        let turn = building.build(Bundling::Refused(failure.clone()), BuildTry::NotLast);

        assert_eq!(turn, BuildTurn::Settled);
        assert_eq!(building.build_state(), Build::Failed(failure));
        assert_eq!(building.records(), ["workflows.sandbox_version_failed"]);
    }

    /// The registry is down. An early try changes nothing and asks to be
    /// tried again; the last try fails the version, so it does not wait
    /// for ever.
    #[test]
    fn a_registry_that_stays_down_fails_the_version_on_the_last_try() {
        let building = Building::new();

        let early = building.build(down(), BuildTry::NotLast);
        let still_building = building.build_state();
        let last = building.build(down(), BuildTry::Last);

        assert_eq!(early, BuildTurn::TryAgain);
        assert_eq!(still_building, Build::Building);
        assert_eq!(last, BuildTurn::Settled);
        assert_eq!(
            building.build_state(),
            Build::Failed(BuildFailure::RegistryUnavailable)
        );
    }

    /// A second try finds the version ready already, and changes nothing.
    #[test]
    fn a_version_built_already_is_left_alone() {
        let building = Building::new();
        building.build(Bundling::Built(bundle()), BuildTry::NotLast);

        let again = building.build(down(), BuildTry::Last);

        assert_eq!(again, BuildTurn::Settled);
        assert_eq!(building.build_state(), Build::Ready(bundle()));
        assert_eq!(building.records().len(), 1);
    }

    /// What a scan of a company's image wrote, and what it recorded.
    struct ImageBuilding {
        versions: Arc<FakeSandboxVersionStore>,
        sink: Arc<FakeEventDispatcher>,
        id: SandboxVersionId,
        own_images: OwnImages,
        allowed: bool,
    }

    impl ImageBuilding {
        fn new() -> Self {
            let version = building_image_version();
            Self {
                id: *version.id(),
                versions: Arc::new(FakeSandboxVersionStore::holding(&version)),
                sink: Arc::new(FakeEventDispatcher::new()),
                own_images: OwnImages::On,
                allowed: true,
            }
        }

        fn scan(&self, answer: Scanning, attempt: BuildTry) -> BuildTurn {
            let tenant = test_ctx().tenant();
            let registries = match self.allowed {
                true => FakeImageRegistryStore::holding(&acme_registry_with_login(
                    &tenant,
                    "robot$acme",
                    "s3cret token",
                )),
                false => FakeImageRegistryStore::empty(),
            };
            let use_case = BuildVersionUseCase::new(BuildVersionPorts {
                versions: self.versions.clone(),
                pulls: ImagePulls::new(
                    Arc::new(registries),
                    Arc::new(FakeEncryptor),
                    self.own_images,
                ),
                scanner: Arc::new(FakeImageScanner::answering(answer)),
                ..BuildVersionPorts::fakes()
            });
            let request = BuildRequest {
                version_id: self.id,
                attempt,
            };
            block_on(use_case.execute(&tenant, &test_auditor(self.sink.clone()), request)).unwrap()
        }

        fn build_state(&self) -> Build {
            self.versions.stored(&self.id).unwrap().build().clone()
        }
    }

    /// Ann's image is scanned and found one high finding and nothing
    /// critical. It is cleared to run, and the trail records it as built.
    #[test]
    fn an_image_with_nothing_critical_is_cleared() {
        let building = ImageBuilding::new();
        let high = LesserFindings {
            high: 1,
            ..LesserFindings::default()
        };

        let turn = building.scan(
            Scanning::Scanned(ImageFindings::new(Vec::new(), high)),
            BuildTry::NotLast,
        );

        assert_eq!(turn, BuildTurn::Settled);
        assert_eq!(building.build_state(), Build::Cleared(high));
        assert_eq!(
            building.sink.records.lock().unwrap().as_slice(),
            ["workflows.sandbox_version_built"]
        );
    }

    /// One critical finding refuses the image, naming it.
    #[test]
    fn a_critical_finding_refuses_the_image() {
        let building = ImageBuilding::new();
        let xz = VulnerabilityId::new("CVE-2024-3094").unwrap();

        building.scan(
            Scanning::Scanned(ImageFindings::new(
                vec![xz.clone()],
                LesserFindings::default(),
            )),
            BuildTry::NotLast,
        );

        assert_eq!(
            building.build_state(),
            Build::Failed(BuildFailure::CriticalVulnerabilities(vec![xz]))
        );
    }

    /// With no scanner set up, the image is refused: nothing unscanned runs.
    #[test]
    fn no_scanner_refuses_the_image() {
        let building = ImageBuilding::new();

        building.scan(Scanning::NotSetUp, BuildTry::NotLast);

        assert_eq!(
            building.build_state(),
            Build::Failed(BuildFailure::NotScanned)
        );
    }

    /// A scanner that stays down is tried again, and fails the version on
    /// the last try.
    #[test]
    fn a_scanner_that_stays_down_fails_the_image_on_the_last_try() {
        let building = ImageBuilding::new();
        let down = || Scanning::Unavailable(UntrustedText::record("connection refused"));

        let early = building.scan(down(), BuildTry::NotLast);
        let last = building.scan(down(), BuildTry::Last);

        assert_eq!(early, BuildTurn::TryAgain);
        assert_eq!(last, BuildTurn::Settled);
        assert_eq!(
            building.build_state(),
            Build::Failed(BuildFailure::ScannerUnavailable)
        );
    }

    /// An image whose registry was removed before its scan, or scanned
    /// while the operator turned companies' images off, is refused.
    #[test]
    fn an_image_that_may_not_be_pulled_is_refused() {
        let removed = ImageBuilding {
            allowed: false,
            ..ImageBuilding::new()
        };
        let off = ImageBuilding {
            own_images: OwnImages::Off,
            ..ImageBuilding::new()
        };
        let clean = || Scanning::Scanned(ImageFindings::new(Vec::new(), LesserFindings::default()));

        removed.scan(clean(), BuildTry::NotLast);
        off.scan(clean(), BuildTry::NotLast);

        assert_eq!(
            removed.build_state(),
            Build::Failed(BuildFailure::RegistryNotAllowed)
        );
        assert_eq!(off.build_state(), Build::Failed(BuildFailure::OwnImagesOff));
    }
}
