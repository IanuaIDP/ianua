//! Save version: a person saves a sandbox's runtime, code, packages and
//! limits as its next version, and the version's bundle is queued to be
//! built. The version keeps the exact image the platform offers its runtime
//! in now, so a newer image later never changes it.
//!
//! The packages are named as the runtime's language's registry names them,
//! so they are read here; the sandbox then refuses a runtime of another
//! language than its own, and any code at all in a sandbox of a company's
//! image.
//! The version and its build job are kept in one unit of work, so no
//! version waits for a build nobody queued.
//!
//! A version may hold an agent with the rules it works under; its code is
//! then the check every answer of that agent must pass, and the rules are
//! pinned with the version as its image is.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::account::IntegrationAccount;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::sandbox::agent::HeldAgent;
use ianua_domain::domains::workflows::sandbox::network::NetworkAccess;
use ianua_domain::domains::workflows::sandbox::package::{
    PackageName, PackageVersion, Packages, PinnedPackage,
};
use ianua_domain::domains::workflows::sandbox::recipe::{
    CodeParams, CodeProgram, Program, RunBudget, SandboxCode,
};
use ianua_domain::domains::workflows::sandbox::runtime::{Language, Runtime, RuntimeImage};
use ianua_domain::domains::workflows::sandbox::source::{
    CodeSource, CommitSha, GitRef, RepositoryFile, RepositoryName, RepositoryPath,
};
use ianua_domain::domains::workflows::sandbox::version::SandboxVersion;
use ianua_domain::domains::workflows::sandbox::{Sandbox, VersionDraft};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{IntegrationAccountId, SandboxId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::runtime::UnitOfWork;
use crate::ports::workflows::{
    CodeRepositories, FileAt, FileRead, IntegrationAccountStore, SandboxRuntimes, SandboxStore,
    SandboxVersionStore,
};
use crate::services::account_grants::AccountGrants;
use crate::services::kept_together::kept_together;
use crate::services::renewals::Renewing;
use crate::use_case::Command;
use crate::use_cases::workflows::lookup::owned_account;
use crate::use_cases::workflows::sandboxes::build::SandboxBuilds;
use crate::use_cases::workflows::sandboxes::code::{Through, refused};
use crate::use_cases::workflows::sandboxes::lookup::existing_sandbox;

/// One package as a person writes it, before the sandbox's language says
/// how its name and version are read.
pub struct WrittenPackage {
    /// Its name, such as `requests-toolbelt` or `@acme/tools`.
    pub name: String,
    /// Its exact version, such as `1.0.0`.
    pub version: String,
}

/// What a person saves as a sandbox's next version.
pub struct SaveVersionRequest {
    /// The code project receiving a new immutable revision.
    pub sandbox_id: SandboxId,
    /// The runtime it runs under, of the sandbox's language.
    pub runtime: Runtime,
    /// The code, written or imported from a repository.
    pub code: VersionCode,
    /// The packages it pins.
    pub packages: Vec<WrittenPackage>,
    /// What one run may use.
    pub budget: RunBudget,
    /// The hosts its code may reach; none for code that reaches no
    /// network.
    pub network: NetworkAccess,
    /// The agent the version holds, under its rules, whose every answer
    /// the code checks; `None` when the code is the step's work.
    pub agent: Option<HeldAgent>,
}

/// Where a version's code comes from.
pub enum VersionCode {
    /// Written here.
    Written(SandboxCode),
    /// Read from a repository's file through an account the person owns or
    /// may manage, at the commit its ref points to now. The account's
    /// integration names the service keeping the repository.
    Imported {
        /// The account the file is read through.
        account: IntegrationAccountId,
        /// The source repository containing the file to import.
        repository: RepositoryName,
        /// The file.
        path: RepositoryPath,
        /// The branch, tag or commit it is read at.
        at: GitRef,
    },
}

/// The ports [`SaveVersionUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SaveVersionPorts {
    /// Keeps the sandboxes.
    pub sandboxes: Arc<dyn SandboxStore>,
    /// Keeps their versions.
    pub versions: Arc<dyn SandboxVersionStore>,
    /// Queues the job that builds a version's bundle.
    pub builds: SandboxBuilds,
    /// The runtimes offered now, and their images.
    pub runtimes: Arc<dyn SandboxRuntimes>,
    /// The tenant's integration accounts, for code imported through one.
    pub accounts: Arc<dyn IntegrationAccountStore>,
    /// Reads imported code.
    pub repositories: Arc<dyn CodeRepositories>,
    /// Keeps the account's short-lived token good just before the read.
    pub grants: Arc<AccountGrants>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Keeps the version, the sandbox, the build job and the record all or
    /// nothing.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Saves sandbox versions.
pub struct SaveVersionUseCase {
    ports: SaveVersionPorts,
}

impl SaveVersionUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SaveVersionPorts) -> Self {
        Self { ports }
    }

    /// Where a version saved here is kept.
    fn keeping(&self) -> VersionKeeping<'_> {
        VersionKeeping {
            sandboxes: self.ports.sandboxes.as_ref(),
            versions: self.ports.versions.as_ref(),
            builds: &self.ports.builds,
            unit_of_work: self.ports.unit_of_work.as_ref(),
        }
    }

    /// The code `code` names and where it came from, reading an imported
    /// file through its account and keeping a credential renewed on the
    /// way.
    async fn code_of(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        control: &WorkflowControl<'_>,
        code: VersionCode,
    ) -> Result<(SandboxCode, CodeSource), AppError> {
        let (account, repository, path, at) = match code {
            VersionCode::Written(code) => return Ok((code, CodeSource::Written)),
            VersionCode::Imported {
                account,
                repository,
                path,
                at,
            } => (account, repository, path, at),
        };
        let tenant = ctx.tenant();
        let account =
            owned_account(self.ports.accounts.as_ref(), &tenant, &account, control).await?;
        let file = FileAt {
            integration: account.integration().clone(),
            repository,
            path,
            at,
        };
        let read = self.read_through(ctx, auditor, &account, &file).await?;
        imported_code(file, read)
    }

    /// `file`, read through `account`, keeping a credential its service
    /// renewed on the way.
    async fn read_through(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        account: &IntegrationAccount<ResolvedTenant>,
        file: &FileAt,
    ) -> Result<ReadFile, AppError> {
        let through = Through::of(&ctx.tenant(), account)
            .with_current_grant(&self.ports.grants, &ctx.tenant(), auditor)
            .await
            .map_err(refused)?;
        let FileRead {
            content,
            commit,
            renewal,
        } = self
            .ports
            .repositories
            .read(&ctx.tenant(), &through.account, file)
            .await
            .map_err(refused)?;
        let renewing = Renewing {
            accounts: self.ports.accounts.as_ref(),
            unit_of_work: self.ports.unit_of_work.as_ref(),
        };
        through
            .keep_renewal(&renewing, ctx, auditor, renewal)
            .await?;
        Ok(ReadFile { content, commit })
    }
}

/// Where a saved version is kept with its sandbox, its build job and its
/// record, all or nothing: shared by code and by companies' images.
pub(super) struct VersionKeeping<'a> {
    /// Keeps the sandbox, counting the version as its latest.
    pub(super) sandboxes: &'a dyn SandboxStore,
    /// Keeps the version.
    pub(super) versions: &'a dyn SandboxVersionStore,
    /// Queues its bundle's build, or its image's scan.
    pub(super) builds: &'a SandboxBuilds,
    /// Keeps it all together.
    pub(super) unit_of_work: &'a dyn UnitOfWork,
}

impl VersionKeeping<'_> {
    /// Keeps `version`, `sandbox` counting it as its latest, its build job
    /// and its record, for the person `ctx` names, in one unit of work.
    ///
    /// # Errors
    ///
    /// - `AppError::Conflict` when the sandbox gained that version number
    ///   meanwhile; `Internal` on persistence, queue or audit failure.
    pub(super) async fn keep(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        sandbox: &Sandbox<ResolvedTenant>,
        version: &mut SandboxVersion<ResolvedTenant>,
    ) -> Result<(), AppError> {
        kept_together(self.unit_of_work, async {
            let tenant = ctx.tenant();
            self.versions
                .insert(&tenant, version)
                .await
                .map_err(AppError::from_domain)?;
            self.sandboxes
                .save(&tenant, sandbox)
                .await
                .map_err(AppError::from_domain)?;
            self.builds.queue(&tenant, version.id()).await?;
            auditor
                .dispatch_by(&ctx.actor(), version.take_events(&tenant))
                .await
                .or_internal()
        })
        .await
    }
}

/// A repository's file as it was read: its text, at the commit it was read
/// at.
struct ReadFile {
    content: String,
    commit: CommitSha,
}

impl Command for SaveVersionUseCase {
    type Caller = CallerContext;
    type Input = SaveVersionRequest;
    type Output = Result<SandboxVersion<ResolvedTenant>, AppError>;

    /// Saves `request` as the next version of its sandbox, saved by the
    /// person `ctx` names, and queues its bundle to be built.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `NotFound` for a missing tenant sandbox; `Forbidden` without workflow-change rights.
    /// - `AppError::Domain` for an unoffered/wrong-language runtime, invalid package names/versions or duplicate/excess packages.
    /// - `AppError::Conflict` for an archived sandbox or concurrent version save; `Internal` on persistence, queue or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: SaveVersionRequest,
    ) -> Result<SandboxVersion<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        control
            .ensure_may(WorkflowAction::Update)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let mut sandbox =
            existing_sandbox(self.ports.sandboxes.as_ref(), &tenant, &request.sandbox_id).await?;
        let language = request.runtime.language();
        let (code, source) = self.code_of(ctx, auditor, &control, request.code).await?;
        let program = CodeProgram::new(CodeParams {
            runtime: request.runtime,
            image: offered_image(self.ports.runtimes.as_ref(), request.runtime)?,
            code,
            packages: packages_of(language, request.packages).map_err(AppError::from_domain)?,
        })
        .map_err(AppError::from_domain)?;
        let draft = VersionDraft {
            program: Program::Code(program),
            budget: request.budget,
            network: request.network,
            source,
        };
        let mut version = saved_version(&mut sandbox, &control, draft, request.agent)?;
        self.keeping()
            .keep(ctx, auditor, &sandbox, &mut version)
            .await?;
        Ok(version)
    }
}

/// `draft` saved as the next version of `sandbox` by `control`, holding
/// `agent` when one is given.
///
/// # Errors
///
/// - `AppError::Domain` when the sandbox refuses the version.
fn saved_version(
    sandbox: &mut Sandbox<ResolvedTenant>,
    control: &WorkflowControl<'_>,
    draft: VersionDraft,
    agent: Option<HeldAgent>,
) -> Result<SandboxVersion<ResolvedTenant>, AppError> {
    match agent {
        None => sandbox.save_version(control, draft),
        Some(agent) => sandbox.save_agent_version(control, draft, agent),
    }
    .map_err(AppError::from_domain)
}

/// The code `read` holds of `file`, and that it was imported from there at
/// the commit it was read at.
///
/// # Errors
///
/// - `AppError::Domain` when the file is not text a version keeps.
fn imported_code(file: FileAt, read: ReadFile) -> Result<(SandboxCode, CodeSource), AppError> {
    let imported = SandboxCode::new(read.content).map_err(|_| {
        AppError::from_domain(DomainError::invalid(message!(
            "workflows-the-imported-file-is-not-code",
            "the imported file is not code a version keeps: text of at most 256 KiB"
        )))
    })?;
    Ok((
        imported,
        CodeSource::Imported(RepositoryFile {
            integration: file.integration,
            repository: file.repository,
            path: file.path,
            commit: read.commit,
        }),
    ))
}

/// The image `runtime` is offered in now, which the version keeps.
///
/// # Errors
///
/// - `AppError::Domain` when the platform does not offer `runtime`: it was
///   retired, or never set up.
fn offered_image(
    runtimes: &dyn SandboxRuntimes,
    runtime: Runtime,
) -> Result<RuntimeImage, AppError> {
    runtimes.image_of(runtime).ok_or_else(|| {
        AppError::from_domain(DomainError::invalid(message!(
            "workflows-the-runtime-is-not-offered",
            format!(
                "{} is not offered for new versions; pick another runtime",
                runtime.as_str()
            )
        )))
    })
}

/// The packages `written` names, read as `language`'s registry names them.
///
/// # Errors
///
/// - [`DomainError::Validation`] when a name or version is not one the
///   registry takes, a package is pinned twice or there are too many.
fn packages_of(language: Language, written: Vec<WrittenPackage>) -> Result<Packages, DomainError> {
    let pinned = written
        .into_iter()
        .map(|package| {
            Ok(PinnedPackage::new(
                PackageName::new(language, package.name)?,
                PackageVersion::new(language, package.version)?,
            ))
        })
        .collect::<Result<Vec<_>, DomainError>>()?;
    Packages::new(pinned)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::account::AccountSharing;
    use ianua_domain::domains::workflows::sandbox::build::Build;
    use ianua_domain::types::AgentId;

    use super::*;
    use crate::ports::runtime::Settlement;
    use crate::ports::shared::EventDispatcher;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::workflows::{
        FakeCodeRepositories, FakeIntegrationAccountStore, FakeSandboxRuntimes, FakeSandboxStore,
        FakeSandboxVersionStore, QueuedBuilds, person, python_sandbox, sheets_account,
        summarising_rules,
    };
    use crate::test_support::{
        FailingEventDispatcher, Fake, FakeEventDispatcher, RecordingUnitOfWork, block_on,
        test_auditor, test_ctx,
    };

    /// What a save wrote, queued and recorded.
    struct Saving {
        sandboxes: Arc<FakeSandboxStore>,
        versions: Arc<FakeSandboxVersionStore>,
        builds: QueuedBuilds,
        runtimes: Arc<FakeSandboxRuntimes>,
        accounts: Arc<FakeIntegrationAccountStore>,
        repositories: Arc<FakeCodeRepositories>,
        sink: Arc<FakeEventDispatcher>,
        unit: Arc<RecordingUnitOfWork>,
    }

    impl Saving {
        fn new() -> (Self, SandboxId) {
            let sandbox = python_sandbox();
            let id = *sandbox.id();
            let saving = Self {
                sandboxes: Arc::new(FakeSandboxStore::holding(&sandbox)),
                versions: Arc::new(FakeSandboxVersionStore::empty()),
                builds: QueuedBuilds::none(),
                runtimes: Arc::new(FakeSandboxRuntimes::offering_all()),
                accounts: Arc::new(FakeIntegrationAccountStore::empty()),
                repositories: Arc::new(FakeCodeRepositories::default()),
                sink: Arc::new(FakeEventDispatcher::new()),
                unit: Arc::new(RecordingUnitOfWork::default()),
            };
            (saving, id)
        }

        fn save(
            &self,
            request: SaveVersionRequest,
            holds: &[SystemPermission],
        ) -> Result<SandboxVersion<ResolvedTenant>, AppError> {
            self.save_recorded_by(request, holds, self.sink.clone())
        }

        fn save_recorded_by(
            &self,
            request: SaveVersionRequest,
            holds: &[SystemPermission],
            sink: Arc<dyn EventDispatcher>,
        ) -> Result<SandboxVersion<ResolvedTenant>, AppError> {
            let use_case = SaveVersionUseCase::new(SaveVersionPorts {
                sandboxes: self.sandboxes.clone(),
                versions: self.versions.clone(),
                builds: self.builds.builds(),
                runtimes: self.runtimes.clone(),
                accounts: self.accounts.clone(),
                repositories: self.repositories.clone(),
                grants: Fake::fake(),
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(holds)),
                unit_of_work: self.unit.clone(),
            });
            block_on(use_case.execute(&test_ctx(), &test_auditor(sink), request))
        }
    }

    const CHANGES: [SystemPermission; 1] = [SystemPermission::Workflows(WorkflowAction::Update)];

    fn request(sandbox_id: SandboxId, packages: &[(&str, &str)]) -> SaveVersionRequest {
        SaveVersionRequest {
            sandbox_id,
            runtime: Runtime::Python313,
            code: VersionCode::Written(
                SandboxCode::new("def main(item):\n\treturn item\n").unwrap(),
            ),
            packages: packages
                .iter()
                .map(|(name, version)| WrittenPackage {
                    name: (*name).to_owned(),
                    version: (*version).to_owned(),
                })
                .collect(),
            budget: RunBudget::new(30, 256).unwrap(),
            network: NetworkAccess::closed(),
            agent: None,
        }
    }

    /// Ann saves her Python sandbox with `Requests_Toolbelt` pinned. Version
    /// 1 is kept waiting for its bundle, its build is queued, the sandbox
    /// counts it as its latest, and the trail records the save.
    #[test]
    fn a_saved_version_waits_for_the_build_it_queued() {
        let (saving, id) = Saving::new();

        let version = saving
            .save(request(id, &[("Requests_Toolbelt", "1.0.0")]), &CHANGES)
            .unwrap();

        assert_eq!(version.number(), 1);
        assert_eq!(version.build(), &Build::Building);
        assert_eq!(
            version
                .recipe()
                .program()
                .code()
                .unwrap()
                .packages()
                .as_slice()[0]
                .name()
                .as_str(),
            "requests-toolbelt"
        );
        assert!(saving.versions.stored(version.id()).is_some());
        assert_eq!(saving.sandboxes.stored(&id).unwrap().latest_version(), 1);
        assert_eq!(saving.builds.queued(), [*version.id()]);
        assert_eq!(
            saving.sink.records.lock().unwrap().as_slice(),
            ["workflows.sandbox_version_saved"]
        );
        assert_eq!(saving.unit.settlements(), [Settlement::Commit]);
    }

    /// Ann saves a version holding an agent summarising orders, its code the
    /// check of every summary. The version keeps the agent's rules, and its
    /// build is queued as any version's.
    #[test]
    fn a_version_holding_an_agent_keeps_its_rules() {
        let (saving, id) = Saving::new();
        let drafter = summarising_rules(AgentId::new());

        let version = saving
            .save(
                SaveVersionRequest {
                    agent: Some(drafter.clone()),
                    ..request(id, &[])
                },
                &CHANGES,
            )
            .unwrap();

        assert_eq!(version.held_agent(), Some(&drafter));
        assert_eq!(
            saving.versions.stored(version.id()).unwrap().held_agent(),
            Some(&drafter)
        );
        assert_eq!(saving.builds.queued(), [*version.id()]);
    }

    /// An audit failure makes saving a version fail internally and asks the
    /// unit of work to roll back.
    #[test]
    fn a_save_the_trail_cannot_record_is_rolled_back() {
        let (saving, id) = Saving::new();

        let result = saving.save_recorded_by(
            request(id, &[("requests", "2.31.0")]),
            &CHANGES,
            Arc::new(FailingEventDispatcher),
        );

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert_eq!(saving.unit.settlements(), [Settlement::Rollback]);
    }

    /// A package version range is refused without queueing a build.
    #[test]
    fn a_range_instead_of_a_version_is_refused() {
        let (saving, id) = Saving::new();

        let result = saving.save(request(id, &[("requests", ">=2.0")]), &CHANGES);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(saving.builds.queued().is_empty());
    }

    /// Ann saves under Python 3.13. The version keeps the exact image the
    /// platform offers 3.13 in now.
    #[test]
    fn a_version_keeps_the_image_its_runtime_is_offered_in() {
        let (saving, id) = Saving::new();

        let version = saving.save(request(id, &[]), &CHANGES).unwrap();

        assert_eq!(
            version.recipe().program().code().unwrap().runtime(),
            Runtime::Python313
        );
        assert_eq!(
            Some(version.recipe().program().code().unwrap().image().clone()),
            saving.runtimes.image_of(Runtime::Python313)
        );
    }

    /// Saving with a retired runtime is refused without queueing a build.
    #[test]
    fn a_retired_runtime_takes_no_new_version() {
        let (mut saving, id) = Saving::new();
        saving.runtimes = Arc::new(FakeSandboxRuntimes::retiring(Runtime::Python313));

        let result = saving.save(request(id, &[]), &CHANGES);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(saving.builds.queued().is_empty());
    }

    /// Workflow view rights do not permit saving a sandbox version.
    #[test]
    fn a_viewer_saves_no_version() {
        let (saving, id) = Saving::new();

        let result = saving.save(
            request(id, &[]),
            &[SystemPermission::Workflows(WorkflowAction::View)],
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    const MANAGES: [SystemPermission; 2] = [
        SystemPermission::Workflows(WorkflowAction::Update),
        SystemPermission::Workflows(WorkflowAction::ConnectAccounts),
    ];

    fn imported(sandbox_id: SandboxId, account: IntegrationAccountId) -> SaveVersionRequest {
        SaveVersionRequest {
            code: VersionCode::Imported {
                account,
                repository: RepositoryName::new("acme/web").unwrap(),
                path: RepositoryPath::new("scripts/tidy.py").unwrap(),
                at: GitRef::new("main").unwrap(),
            },
            ..request(sandbox_id, &[])
        }
    }

    /// Ann, who manages accounts, imports `scripts/tidy.py` from `main`
    /// through Bob's account. The file is read from the account's own
    /// service, and the version keeps its text and the exact commit `main`
    /// pointed to, not the branch.
    #[test]
    fn an_imported_version_keeps_the_file_at_its_commit() {
        let (mut saving, id) = Saving::new();
        let account = sheets_account(&person("bob@corp.test"), AccountSharing::Tenant);
        saving.accounts = Arc::new(FakeIntegrationAccountStore::holding(&account));
        saving.repositories = Arc::new(FakeCodeRepositories::holding(
            "def main(input):\n\treturn input\n",
        ));

        let version = saving.save(imported(id, *account.id()), &MANAGES).unwrap();

        assert!(
            version
                .recipe()
                .program()
                .code()
                .unwrap()
                .code()
                .as_str()
                .starts_with("def main")
        );
        let CodeSource::Imported(file) = version.source() else {
            panic!("an imported version names its file");
        };
        assert_eq!(file.commit, FakeCodeRepositories::commit());
        assert_eq!(file.path.as_str(), "scripts/tidy.py");
        assert_eq!(&file.integration, account.integration());
        let reads = saving.repositories.reads();
        assert_eq!(&reads[0].integration, account.integration());
        assert_eq!(reads[0].at.as_str(), "main");
    }

    /// A workflow editor without account management rights cannot import through
    /// another person's account. It appears missing, no repository read occurs
    /// and no build is queued.
    #[test]
    fn an_import_through_someone_elses_account_is_refused() {
        let (mut saving, id) = Saving::new();
        let account = sheets_account(&person("bob@corp.test"), AccountSharing::Tenant);
        saving.accounts = Arc::new(FakeIntegrationAccountStore::holding(&account));
        saving.repositories = Arc::new(FakeCodeRepositories::holding("print(1)\n"));

        let result = saving.save(imported(id, *account.id()), &CHANGES);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(saving.repositories.reads().is_empty());
        assert!(saving.builds.queued().is_empty());
    }

    /// Importing a missing repository file returns not found without queueing
    /// a build.
    #[test]
    fn an_import_of_a_missing_file_is_refused() {
        let (mut saving, id) = Saving::new();
        let account = sheets_account(&person("bob@corp.test"), AccountSharing::Tenant);
        saving.accounts = Arc::new(FakeIntegrationAccountStore::holding(&account));

        let result = saving.save(imported(id, *account.id()), &MANAGES);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(saving.builds.queued().is_empty());
    }
}
