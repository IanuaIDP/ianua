//! Save image version: a person saves the company's own image as the next
//! version of an image sandbox, and its scan is queued.
//!
//! The image must come from a registry an administrator allowed. Its
//! registry is asked, with that registry's login, what the named tag points
//! to now, and the version keeps that digest and the image's size, so a
//! later push to the same tag never changes it. The registry is asked
//! before any unit of work opens; the version, the sandbox, the scan's job
//! and the record are then kept all or nothing, as for code.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::sandbox::VersionDraft;
use ianua_domain::domains::workflows::sandbox::image::{ImageName, OwnImage};
use ianua_domain::domains::workflows::sandbox::network::NetworkAccess;
use ianua_domain::domains::workflows::sandbox::recipe::{Program, RunBudget};
use ianua_domain::domains::workflows::sandbox::source::CodeSource;
use ianua_domain::domains::workflows::sandbox::version::SandboxVersion;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::SandboxId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::runtime::UnitOfWork;
use crate::ports::workflows::{
    ImageResolver, PullLogin, Resolving, SandboxStore, SandboxVersionStore,
};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::workflows::sandboxes::build::SandboxBuilds;
use crate::use_cases::workflows::sandboxes::images::pulls::{ImagePulls, Pull};
use crate::use_cases::workflows::sandboxes::lookup::existing_sandbox;
use crate::use_cases::workflows::sandboxes::save_version::VersionKeeping;

/// What a person saves as an image sandbox's next version.
pub struct SaveRequest {
    /// The image sandbox receiving a new version.
    pub sandbox_id: SandboxId,
    /// The image, by its registry, path and tag or digest.
    pub image: ImageName,
    /// What one run may use.
    pub budget: RunBudget,
    /// The hosts the image may reach; none for one that reaches no network.
    pub network: NetworkAccess,
}

/// Why a registry could not be asked about an image.
#[derive(Debug, thiserror::Error)]
#[error("the image registry could not be reached")]
struct RegistryUnreachable;

/// The ports [`SaveUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SavePorts {
    /// Keeps the sandboxes.
    pub sandboxes: Arc<dyn SandboxStore>,
    /// Keeps their versions.
    pub versions: Arc<dyn SandboxVersionStore>,
    /// Queues the job that scans a version's image.
    pub builds: SandboxBuilds,
    /// Opens the login the image's registry is asked with.
    pub pulls: ImagePulls,
    /// Asks the registry what the image points to now.
    pub resolver: Arc<dyn ImageResolver>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Keeps the version, the sandbox, the scan's job and the record all or
    /// nothing.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Saves versions of companies' images.
pub struct SaveUseCase {
    ports: SavePorts,
}

impl SaveUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SavePorts) -> Self {
        Self { ports }
    }

    /// `name`, pinned to what its registry says it points to now.
    async fn pinned(&self, tenant: &ScopedTenant, name: &ImageName) -> Result<OwnImage, AppError> {
        let login = match self
            .ports
            .pulls
            .for_registry(tenant, name.registry())
            .await?
        {
            Pull::Allowed(login) => login,
            Pull::Refused(refusal) => return Err(refusal.refusal()),
        };
        resolved(self.ports.resolver.as_ref(), name, &login).await
    }
}

impl Command for SaveUseCase {
    type Caller = CallerContext;
    type Input = SaveRequest;
    type Output = Result<SandboxVersion<ResolvedTenant>, AppError>;

    /// Saves `request.image`, pinned to its digest, as the next version of
    /// its sandbox, saved by the person `ctx` names, and queues its scan.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `NotFound` for a missing tenant sandbox; `Forbidden` without workflow-change rights or while companies' images are off.
    /// - `AppError::Domain` for a registry not on the list, an image the registry refuses or one too large, or a code sandbox; `Upstream` when the registry cannot be reached.
    /// - `AppError::Conflict` for an archived sandbox or concurrent version save; `Internal` on persistence, queue or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: SaveRequest,
    ) -> Result<SandboxVersion<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        control
            .ensure_may(WorkflowAction::Update)
            .map_err(AppError::from_domain)?;
        self.ports.pulls.ensure_on()?;
        let tenant = ctx.tenant();
        let mut sandbox =
            existing_sandbox(self.ports.sandboxes.as_ref(), &tenant, &request.sandbox_id).await?;
        let image = self.pinned(&tenant, &request.image).await?;
        let draft = VersionDraft {
            program: Program::Image(image),
            budget: request.budget,
            network: request.network,
            source: CodeSource::Written,
        };
        let mut version = sandbox
            .save_version(&control, draft)
            .map_err(AppError::from_domain)?;
        let keeping = VersionKeeping {
            sandboxes: self.ports.sandboxes.as_ref(),
            versions: self.ports.versions.as_ref(),
            builds: &self.ports.builds,
            unit_of_work: self.ports.unit_of_work.as_ref(),
        };
        keeping.keep(ctx, auditor, &sandbox, &mut version).await?;
        Ok(version)
    }
}

/// `name` as `resolver` pins it, asked with `login`.
///
/// # Errors
///
/// - `AppError::Domain` when the registry has no such image or refuses the
///   login, or the image is larger than a version may run.
/// - `AppError::Upstream` when the registry cannot be reached.
async fn resolved(
    resolver: &dyn ImageResolver,
    name: &ImageName,
    login: &PullLogin,
) -> Result<OwnImage, AppError> {
    match resolver.resolve(name, login).await {
        Resolving::Resolved { digest, bytes } => {
            OwnImage::new(name.pinned(digest), bytes).map_err(AppError::from_domain)
        }
        Resolving::Refused(_) => Err(AppError::from_domain(DomainError::invalid(message!(
            "workflows-the-registry-refused-the-image",
            "the registry has no such image, or refused the login it was asked with"
        )))),
        Resolving::Unavailable(_) => Err(AppError::upstream(RegistryUnreachable)),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::workflows::sandbox::Sandbox;
    use ianua_domain::domains::workflows::sandbox::build::Build;
    use ianua_domain::domains::workflows::sandbox::image::{ImageDigest, MAX_IMAGE_BYTES};
    use ianua_domain::types::UntrustedText;

    use super::*;
    use crate::ports::workflows::OwnImages;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::workflows::{
        FakeImageRegistryStore, FakeImageResolver, FakeSandboxStore, FakeSandboxVersionStore,
        QueuedBuilds, acme_registry_with_login, image_sandbox, python_sandbox,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const CHANGES: [SystemPermission; 1] = [SystemPermission::Workflows(WorkflowAction::Update)];

    fn digest() -> ImageDigest {
        ImageDigest::new(format!("sha256:{}", "ef".repeat(32))).unwrap()
    }

    fn found(bytes: u64) -> Resolving {
        Resolving::Resolved {
            digest: digest(),
            bytes,
        }
    }

    /// What a save wrote, queued and recorded.
    struct Saving {
        sandboxes: Arc<FakeSandboxStore>,
        versions: Arc<FakeSandboxVersionStore>,
        builds: QueuedBuilds,
        resolver: Arc<FakeImageResolver>,
        sink: Arc<FakeEventDispatcher>,
        own_images: OwnImages,
        sandbox_id: SandboxId,
    }

    impl Saving {
        fn of(sandbox: &Sandbox<ResolvedTenant>, answer: Resolving) -> Self {
            Self {
                sandbox_id: *sandbox.id(),
                sandboxes: Arc::new(FakeSandboxStore::holding(sandbox)),
                versions: Arc::new(FakeSandboxVersionStore::empty()),
                builds: QueuedBuilds::none(),
                resolver: Arc::new(FakeImageResolver::answering(answer)),
                sink: Arc::new(FakeEventDispatcher::new()),
                own_images: OwnImages::On,
            }
        }

        fn new(answer: Resolving) -> Self {
            Self::of(&image_sandbox(), answer)
        }

        fn save(&self, image: &str) -> Result<SandboxVersion<ResolvedTenant>, AppError> {
            let registry =
                acme_registry_with_login(&test_ctx().tenant(), "robot$acme", "s3cret token");
            let use_case = SaveUseCase::new(SavePorts {
                sandboxes: self.sandboxes.clone(),
                versions: self.versions.clone(),
                builds: self.builds.builds(),
                pulls: ImagePulls::new(
                    Arc::new(FakeImageRegistryStore::holding(&registry)),
                    Arc::new(FakeEncryptor),
                    self.own_images,
                ),
                resolver: self.resolver.clone(),
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&CHANGES)),
                ..SavePorts::fakes()
            });
            let request = SaveRequest {
                sandbox_id: self.sandbox_id,
                image: ImageName::parse(image).unwrap(),
                budget: RunBudget::new(60, 512).unwrap(),
                network: NetworkAccess::closed(),
            };
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.sink.clone()), request))
        }
    }

    /// Ann saves `registry.acme.example/tools/codegen:1.4`. The registry is
    /// asked with Acme's robot login, the version keeps the digest the tag
    /// points to now, and its scan is queued.
    #[test]
    fn a_saved_image_is_pinned_to_its_digest() {
        let saving = Saving::new(found(80 * 1024 * 1024));

        let version = saving
            .save("registry.acme.example/tools/codegen:1.4")
            .unwrap();

        let Program::Image(own) = version.recipe().program() else {
            panic!("the version keeps no image");
        };
        assert_eq!(
            own.image().as_str(),
            format!("registry.acme.example/tools/codegen@{}", digest().as_str())
        );
        assert_eq!(version.build(), &Build::Building);
        assert_eq!(saving.builds.queued(), [*version.id()]);
        assert_eq!(saving.resolver.asked_as(), Some("robot$acme".to_owned()));
        assert_eq!(
            saving.sink.records.lock().unwrap().as_slice(),
            ["workflows.sandbox_version_saved"]
        );
    }

    /// An image from a registry nobody allowed is refused before the
    /// registry is asked.
    #[test]
    fn an_image_from_a_registry_not_allowed_is_refused() {
        let saving = Saving::new(found(1024));

        let refused = saving.save("ghcr.io/acme/codegen:1.4");

        assert!(matches!(refused, Err(AppError::Domain(_))));
        assert_eq!(saving.resolver.asked_as(), None);
        assert!(saving.builds.queued().is_empty());
    }

    /// An image larger than a version may run is refused, and so is one the
    /// registry does not have; a registry that cannot be reached is an
    /// upstream failure.
    #[test]
    fn an_image_the_registry_cannot_offer_is_refused() {
        let large = Saving::new(found(MAX_IMAGE_BYTES + 1));
        let missing = Saving::new(Resolving::Refused(UntrustedText::record(
            "unknown manifest",
        )));
        let down = Saving::new(Resolving::Unavailable(UntrustedText::record("timed out")));

        let image = "registry.acme.example/tools/codegen:1.4";

        assert!(matches!(large.save(image), Err(AppError::Domain(_))));
        assert!(matches!(missing.save(image), Err(AppError::Domain(_))));
        assert!(matches!(down.save(image), Err(AppError::Upstream(_))));
        assert!(down.builds.queued().is_empty());
    }

    /// While the operator has companies' images off, nothing is saved.
    #[test]
    fn no_image_is_saved_while_images_are_off() {
        let saving = Saving {
            own_images: OwnImages::Off,
            ..Saving::new(found(1024))
        };

        let refused = saving.save("registry.acme.example/tools/codegen:1.4");

        assert!(matches!(refused, Err(AppError::Forbidden(_))));
        assert_eq!(saving.resolver.asked_as(), None);
    }

    /// An image cannot be saved in a sandbox of Python code.
    #[test]
    fn an_image_in_a_code_sandbox_is_refused() {
        let saving = Saving::of(&python_sandbox(), found(1024));

        let refused = saving.save("registry.acme.example/tools/codegen:1.4");

        assert!(matches!(refused, Err(AppError::Domain(_))));
        assert!(saving.builds.queued().is_empty());
    }
}
