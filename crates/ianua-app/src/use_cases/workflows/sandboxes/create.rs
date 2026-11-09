//! Create sandbox: a person makes a named sandbox for one language, or for
//! the company's own image, with no version yet.
//!
//! Only someone who may create workflows makes one, and the tenant's plan
//! caps how many it holds. A sandbox of the company's image is made only
//! while the installation runs companies' images, and the plan caps those
//! apart as well.

use std::sync::Arc;

use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::sandbox::{CreateSandboxParams, Sandbox, SandboxKind};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::Label;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::workflows::SandboxStore;
use crate::use_case::Command;
use crate::use_cases::workflows::sandboxes::images::ImagePulls;

/// A new sandbox, as a person names it.
pub struct CreateSandboxRequest {
    /// The label people use to recognize this code project.
    pub name: Label,
    /// What its versions run: code of a language, or the company's image.
    pub kind: SandboxKind,
}

/// The ports [`CreateSandboxUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreateSandboxPorts {
    /// Keeps the sandboxes.
    pub sandboxes: Arc<dyn SandboxStore>,
    /// Checks the plan's sandbox limits.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// Whether the installation runs companies' images.
    pub pulls: ImagePulls,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Makes sandboxes.
pub struct CreateSandboxUseCase {
    ports: CreateSandboxPorts,
}

impl CreateSandboxUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CreateSandboxPorts) -> Self {
        Self { ports }
    }

    /// Refuses a sandbox of `kind` past the plan's limits, or of the
    /// company's image while the installation runs none.
    async fn ensure_room(&self, ctx: &CallerContext, kind: SandboxKind) -> Result<(), AppError> {
        if kind == SandboxKind::OwnImage {
            self.ports.pulls.ensure_on()?;
            self.ensure_below(ctx, ResourceKind::OwnImages).await?;
        }
        self.ensure_below(ctx, ResourceKind::Sandboxes).await
    }

    async fn ensure_below(&self, ctx: &CallerContext, kind: ResourceKind) -> Result<(), AppError> {
        self.ports
            .limit_enforcer
            .check_tenant_limit(ctx.plan_limits(), &ctx.tenant(), kind)
            .await
            .map_err(AppError::from_domain)
    }
}

impl Command for CreateSandboxUseCase {
    type Caller = CallerContext;
    type Input = CreateSandboxRequest;
    type Output = Result<Sandbox<ResolvedTenant>, AppError>;

    /// Makes a sandbox for the person `ctx` names.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the plan's sandbox limit, or its limit of
    ///   companies' images, is reached, companies' images are off, or the
    ///   caller may not create workflows.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: CreateSandboxRequest,
    ) -> Result<Sandbox<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        self.ensure_room(ctx, request.kind).await?;
        let params = CreateSandboxParams {
            name: request.name,
            kind: request.kind,
        };
        let mut sandbox = Sandbox::create(params, &WorkflowControl::new(&authority))
            .map_err(AppError::from_domain)?;
        self.ports
            .sandboxes
            .save(&ctx.tenant(), &sandbox)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&ctx.actor(), sandbox.take_events(&ctx.tenant()))
            .await
            .or_internal()?;
        Ok(sandbox)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::sandbox::runtime::Language;

    use super::*;
    use crate::ports::workflows::OwnImages;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::workflows::{FakeImageRegistryStore, FakeSandboxStore};
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };

    fn request() -> CreateSandboxRequest {
        CreateSandboxRequest {
            name: Label::new("name", "Clean issue text").unwrap(),
            kind: SandboxKind::Code(Language::Python),
        }
    }

    fn creating(
        sandboxes: &Arc<FakeSandboxStore>,
        sink: &Arc<FakeEventDispatcher>,
        ports: CreateSandboxPorts,
    ) -> Result<Sandbox<ResolvedTenant>, AppError> {
        creating_kind(sandboxes, sink, ports, request())
    }

    fn creating_kind(
        sandboxes: &Arc<FakeSandboxStore>,
        sink: &Arc<FakeEventDispatcher>,
        ports: CreateSandboxPorts,
        request: CreateSandboxRequest,
    ) -> Result<Sandbox<ResolvedTenant>, AppError> {
        let use_case = CreateSandboxUseCase::new(CreateSandboxPorts {
            sandboxes: sandboxes.clone(),
            ..ports
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(sink.clone()), request))
    }

    fn image_request() -> CreateSandboxRequest {
        CreateSandboxRequest {
            name: Label::new("name", "Code generator").unwrap(),
            kind: SandboxKind::OwnImage,
        }
    }

    fn images(own_images: OwnImages) -> ImagePulls {
        ImagePulls::new(
            Arc::new(FakeImageRegistryStore::empty()),
            Arc::new(FakeEncryptor),
            own_images,
        )
    }

    fn creator() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::Create)])
    }

    /// Ann may create workflows and makes a Python sandbox. It is kept,
    /// and the trail records it.
    #[test]
    fn a_creator_makes_a_sandbox() {
        let sandboxes = Arc::new(FakeSandboxStore::empty());
        let sink = Arc::new(FakeEventDispatcher::new());

        let made = creating(
            &sandboxes,
            &sink,
            CreateSandboxPorts {
                tenant_authorities: Arc::new(creator()),
                ..CreateSandboxPorts::fakes()
            },
        )
        .unwrap();

        assert!(sandboxes.stored(made.id()).is_some());
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["workflows.sandbox_created"]
        );
    }

    /// A plan-limit refusal prevents sandbox creation and leaves the store empty.
    #[test]
    fn a_sandbox_past_the_plan_limit_is_refused() {
        let sandboxes = Arc::new(FakeSandboxStore::empty());
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = creating(
            &sandboxes,
            &sink,
            CreateSandboxPorts {
                tenant_authorities: Arc::new(creator()),
                limit_enforcer: Arc::new(RejectingLimitEnforcer),
                ..CreateSandboxPorts::fakes()
            },
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(sandboxes.all().is_empty());
    }

    /// Workflow view rights do not permit creating a sandbox.
    #[test]
    fn a_viewer_makes_no_sandbox() {
        let sandboxes = Arc::new(FakeSandboxStore::empty());
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = creating(
            &sandboxes,
            &sink,
            CreateSandboxPorts {
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                    SystemPermission::Workflows(WorkflowAction::View),
                ])),
                ..CreateSandboxPorts::fakes()
            },
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann makes a sandbox for her company's code generator image. It is
    /// kept as an image sandbox.
    #[test]
    fn a_creator_makes_an_image_sandbox() {
        let sandboxes = Arc::new(FakeSandboxStore::empty());
        let sink = Arc::new(FakeEventDispatcher::new());

        let made = creating_kind(
            &sandboxes,
            &sink,
            CreateSandboxPorts {
                tenant_authorities: Arc::new(creator()),
                pulls: images(OwnImages::On),
                ..CreateSandboxPorts::fakes()
            },
            image_request(),
        )
        .unwrap();

        assert_eq!(
            sandboxes.stored(made.id()).map(|kept| kept.kind()),
            Some(SandboxKind::OwnImage)
        );
    }

    /// The plan's limit of companies' images refuses another image sandbox,
    /// before the sandbox limit is asked, and nothing is kept.
    #[test]
    fn an_image_sandbox_past_the_plan_limit_is_refused() {
        let sandboxes = Arc::new(FakeSandboxStore::empty());
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = creating_kind(
            &sandboxes,
            &sink,
            CreateSandboxPorts {
                tenant_authorities: Arc::new(creator()),
                limit_enforcer: Arc::new(RejectingLimitEnforcer),
                pulls: images(OwnImages::On),
                ..CreateSandboxPorts::fakes()
            },
            image_request(),
        );

        let Err(AppError::Forbidden(refusal)) = result else {
            panic!("the image sandbox was not refused");
        };
        assert!(refusal.as_str().contains("OwnImages"));
        assert!(sandboxes.all().is_empty());
    }

    /// While the operator has companies' images off, no image sandbox is
    /// made, though a code sandbox still is.
    #[test]
    fn no_image_sandbox_is_made_while_images_are_off() {
        let sandboxes = Arc::new(FakeSandboxStore::empty());
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = || CreateSandboxPorts {
            tenant_authorities: Arc::new(creator()),
            pulls: images(OwnImages::Off),
            ..CreateSandboxPorts::fakes()
        };

        let image = creating_kind(&sandboxes, &sink, ports(), image_request());
        let code = creating(&sandboxes, &sink, ports());

        assert!(matches!(image, Err(AppError::Forbidden(_))));
        assert!(code.is_ok());
    }
}
