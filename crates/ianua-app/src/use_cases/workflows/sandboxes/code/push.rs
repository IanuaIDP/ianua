//! Push a version: a person sends a copy of a sandbox version, its code and
//! its pinned packages, to a folder of a branch of a company's repository,
//! through an account they own or may manage. The version saved in the
//! platform stays the one that runs; the push is recorded with where it
//! went and the commit it became.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::account::IntegrationAccount;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::sandbox::Sandbox;
use ianua_domain::domains::workflows::sandbox::source::{
    CommitSha, GitRef, PushTarget, RepositoryName, RepositoryPath,
};
use ianua_domain::domains::workflows::sandbox::version::SandboxVersion;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{IntegrationAccountId, SandboxId, SandboxVersionId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::runtime::UnitOfWork;
use crate::ports::workflows::{
    CodeRepositories, IntegrationAccountStore, Push, SandboxStore, SandboxVersionStore,
};
use crate::services::account_grants::AccountGrants;
use crate::services::renewals::Renewing;
use crate::use_case::Command;
use crate::use_cases::workflows::lookup::owned_account;
use crate::use_cases::workflows::sandboxes::code::files::{refused, version_files};
use crate::use_cases::workflows::sandboxes::code::through::Through;
use crate::use_cases::workflows::sandboxes::lookup::{existing_sandbox, existing_version};

/// Which version goes where, through which account.
pub struct PushVersionRequest {
    /// The code project that must own the selected revision.
    pub sandbox_id: SandboxId,
    /// The saved source revision to copy into the repository.
    pub version_id: SandboxVersionId,
    /// The account the push goes through; its integration names the
    /// service keeping the repository.
    pub account: IntegrationAccountId,
    /// The destination repository receiving the saved source files.
    pub repository: RepositoryName,
    /// The branch it goes to.
    pub branch: GitRef,
    /// The folder of the branch its files go in.
    pub folder: RepositoryPath,
}

/// The ports [`PushVersionUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PushVersionPorts {
    /// Keeps the sandboxes.
    pub sandboxes: Arc<dyn SandboxStore>,
    /// Keeps their versions.
    pub versions: Arc<dyn SandboxVersionStore>,
    /// The tenant's integration accounts.
    pub accounts: Arc<dyn IntegrationAccountStore>,
    /// Pushes the files.
    pub repositories: Arc<dyn CodeRepositories>,
    /// Keeps the account's short-lived token good just before the push.
    pub grants: Arc<AccountGrants>,
    /// Keeps a renewed credential with its record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Pushes sandbox versions to repositories.
pub struct PushVersionUseCase {
    ports: PushVersionPorts,
}

impl PushVersionUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: PushVersionPorts) -> Self {
        Self { ports }
    }

    /// The version `request` names, refused unless it is of its sandbox.
    async fn version_of(
        &self,
        ctx: &CallerContext,
        request: &PushVersionRequest,
    ) -> Result<SandboxVersion<ResolvedTenant>, AppError> {
        let version = existing_version(
            self.ports.versions.as_ref(),
            &ctx.tenant(),
            &request.version_id,
        )
        .await?;
        if version.sandbox_id() != &request.sandbox_id {
            return Err(AppError::NotFound(message!(
                "workflows-sandbox-version",
                "sandbox version"
            )));
        }
        Ok(version)
    }

    /// Pushes `push` through `through`'s account, keeping a credential the
    /// service renewed; the commit it became.
    async fn pushed(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        through: Through,
        push: &Push,
    ) -> Result<CommitSha, AppError> {
        let through = through
            .with_current_grant(&self.ports.grants, &ctx.tenant(), auditor)
            .await
            .map_err(refused)?;
        let pushed = self
            .ports
            .repositories
            .push(&ctx.tenant(), &through.account, push)
            .await
            .map_err(refused)?;
        let renewing = Renewing {
            accounts: self.ports.accounts.as_ref(),
            unit_of_work: self.ports.unit_of_work.as_ref(),
        };
        through
            .keep_renewal(&renewing, ctx, auditor, pushed.renewal)
            .await?;
        Ok(pushed.commit)
    }
}

impl Command for PushVersionUseCase {
    type Caller = CallerContext;
    type Input = PushVersionRequest;
    type Output = Result<SandboxVersion<ResolvedTenant>, AppError>;

    /// Pushes the version `request` names to its target, for the person
    /// `ctx` names, and records it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without workflow-change rights.
    /// - `AppError::NotFound` for a missing tenant sandbox/version, inaccessible account, repository or branch.
    /// - `AppError::Domain` for an integration without code storage; `Upstream` for a refused/unreachable service.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: PushVersionRequest,
    ) -> Result<SandboxVersion<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        control
            .ensure_may(WorkflowAction::Update)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let sandbox =
            existing_sandbox(self.ports.sandboxes.as_ref(), &tenant, &request.sandbox_id).await?;
        let mut version = self.version_of(ctx, &request).await?;
        let account = owned_account(
            self.ports.accounts.as_ref(),
            &tenant,
            &request.account,
            &control,
        )
        .await?;
        let push = push_of(&sandbox, &version, target_of(&account, request))?;
        let commit = self
            .pushed(ctx, auditor, Through::of(&tenant, &account), &push)
            .await?;
        version
            .record_push(&control, push.target, commit)
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&ctx.actor(), version.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(version)
    }
}

/// Where `request` pushes to, at the service `account` keeps code at.
fn target_of(
    account: &IntegrationAccount<ResolvedTenant>,
    request: PushVersionRequest,
) -> PushTarget {
    PushTarget {
        integration: account.integration().clone(),
        repository: request.repository,
        branch: request.branch,
        folder: request.folder,
    }
}

/// The push of `version` of `sandbox` to `target`: its files and a message
/// naming it.
fn push_of(
    sandbox: &Sandbox<ResolvedTenant>,
    version: &SandboxVersion<ResolvedTenant>,
    target: PushTarget,
) -> Result<Push, AppError> {
    Ok(Push {
        target,
        files: version_files(version.recipe().program())?,
        message: format!(
            "{} version {} from Ianua",
            sandbox.name().as_str(),
            version.number()
        ),
    })
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::workflows::account::AccountSharing;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::workflows::{
        FakeCodeRepositories, FakeIntegrationAccountStore, FakeSandboxStore,
        FakeSandboxVersionStore, person, python_sandbox, sheets_account, version_of,
    };
    use crate::test_support::{
        Fake, FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor, test_ctx,
    };

    const MANAGES: [SystemPermission; 2] = [
        SystemPermission::Workflows(WorkflowAction::Update),
        SystemPermission::Workflows(WorkflowAction::ConnectAccounts),
    ];

    /// Ann's sandbox with version 1, Bob's account, and what a push sent
    /// and recorded.
    struct Pushing {
        sandbox: SandboxId,
        version: SandboxVersionId,
        account: IntegrationAccountId,
        repositories: Arc<FakeCodeRepositories>,
        sink: Arc<FakeEventDispatcher>,
        use_case: PushVersionUseCase,
    }

    impl Pushing {
        fn new(holds: &[SystemPermission]) -> Self {
            let mut sandbox = python_sandbox();
            let version = version_of(&mut sandbox);
            let account = sheets_account(&person("bob@corp.test"), AccountSharing::Tenant);
            let repositories = Arc::new(FakeCodeRepositories::default());
            Self {
                sandbox: *sandbox.id(),
                version: *version.id(),
                account: *account.id(),
                repositories: repositories.clone(),
                sink: Arc::new(FakeEventDispatcher::new()),
                use_case: PushVersionUseCase::new(PushVersionPorts {
                    sandboxes: Arc::new(FakeSandboxStore::holding(&sandbox)),
                    versions: Arc::new(FakeSandboxVersionStore::holding(&version)),
                    accounts: Arc::new(FakeIntegrationAccountStore::holding(&account)),
                    repositories,
                    grants: Fake::fake(),
                    unit_of_work: Arc::new(RecordingUnitOfWork::default()),
                    tenant_authorities: Arc::new(FakeTenantAuthorities::holding(holds)),
                }),
            }
        }

        fn request(&self) -> PushVersionRequest {
            PushVersionRequest {
                sandbox_id: self.sandbox,
                version_id: self.version,
                account: self.account,
                repository: RepositoryName::new("acme/web").unwrap(),
                branch: GitRef::new("ianua/tidy").unwrap(),
                folder: RepositoryPath::new("scripts/tidy").unwrap(),
            }
        }

        fn push(
            &self,
            request: PushVersionRequest,
        ) -> Result<SandboxVersion<ResolvedTenant>, AppError> {
            block_on(
                self.use_case
                    .execute(&test_ctx(), &test_auditor(self.sink.clone()), request),
            )
        }
    }

    /// Ann pushes version 1 of her Python sandbox to `scripts/tidy` on
    /// branch `ianua/tidy` through Bob's account. The code goes as
    /// `main.py` and its pin as `requirements.txt`, and the trail records
    /// the push.
    #[test]
    fn a_pushed_version_sends_its_code_and_pins() {
        let pushing = Pushing::new(&MANAGES);

        let result = pushing.push(pushing.request());

        assert!(result.is_ok());
        let pushes = pushing.repositories.pushes();
        let names: Vec<&str> = pushes[0].files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["main.py", "requirements.txt"]);
        assert_eq!(
            pushes[0].files[1].content,
            "# Packages pinned by the sandbox version.\nrequests==2.31.0\n"
        );
        assert_eq!(
            pushing.sink.records.lock().unwrap().as_slice(),
            ["workflows.sandbox_version_pushed"]
        );
    }

    /// A workflow editor without account management rights cannot push through
    /// another person's account. It appears missing and no repository push occurs.
    #[test]
    fn a_push_through_someone_elses_account_is_refused() {
        let pushing = Pushing::new(&[SystemPermission::Workflows(WorkflowAction::Update)]);

        let result = pushing.push(pushing.request());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(pushing.repositories.pushes().is_empty());
    }

    /// Naming a version under an unknown sandbox returns not found without
    /// pushing to the repository.
    #[test]
    fn a_version_named_under_another_sandbox_is_not_pushed() {
        let pushing = Pushing::new(&MANAGES);
        let request = PushVersionRequest {
            sandbox_id: SandboxId::new(),
            ..pushing.request()
        };

        let result = pushing.push(request);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(pushing.repositories.pushes().is_empty());
    }
}
