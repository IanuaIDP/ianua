//! Start an import: an admin brings accounts over from another system's
//! export, such as the identity provider the tenant is leaving, with the
//! password hashes that system kept.
//!
//! Up to ten thousand records do not fit in one request: opening each
//! account, keeping its hash, granting its roles and mailing its link takes
//! longer than a request may run, and a request cut off halfway would roll
//! the accounts back after their mails had left. So the request only checks
//! the batch, keeps it and queues the job that works it through; the answer
//! is the import's id, to follow its progress by.

use std::sync::Arc;

use ianua_domain::domains::identity::account::import::ImportBatch;
use ianua_domain::domains::identity::account::import::run::UserImport;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::UserImportId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserImportStore;
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::scheduling::JobQueue;
use crate::use_case::Command;
use crate::use_cases::identity::imports::job::ImportJob;

/// The accounts to bring over, and where their confirmation links land.
pub struct StartRequest {
    /// The records, checked as a whole.
    pub batch: ImportBatch,
    /// Where each confirmation link lands.
    pub scope: LinkScope,
}

/// The ports [`StartUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct StartPorts {
    /// Keeps the import.
    pub import_store: Arc<dyn UserImportStore>,
    /// Holds the tenant to its plan's user limit.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// Queues the job that works the import through.
    pub job_queue: Arc<dyn JobQueue>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Keeps an import of accounts and queues the work of opening them.
pub struct StartUseCase {
    ports: StartPorts,
}

impl StartUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: StartPorts) -> Self {
        Self { ports }
    }

    /// Refuses the batch when the plan has no room for all of it.
    async fn ensure_room(&self, ctx: &CallerContext, batch: &ImportBatch) -> Result<(), AppError> {
        let wanted = u64::try_from(batch.records().len()).unwrap_or(u64::MAX);
        self.ports
            .limit_enforcer
            .check_tenant_room(
                ctx.plan_limits(),
                &ctx.tenant(),
                ResourceKind::Users,
                wanted,
            )
            .await
            .map_err(AppError::from_domain)
    }

    /// Keeps `import` and queues the job that works it through, its links
    /// landing on `scope`.
    async fn keep_and_queue(
        &self,
        ctx: &CallerContext,
        import: &UserImport<ResolvedTenant>,
        scope: LinkScope,
    ) -> Result<(), AppError> {
        self.ports
            .import_store
            .save(&ctx.tenant(), import)
            .await
            .or_internal()?;
        let job = ImportJob {
            tenant_id: ctx.tenant_id(),
            import_id: *import.id(),
            scope,
        }
        .scheduled()?;
        self.ports.job_queue.enqueue(&job).await.or_internal()?;
        Ok(())
    }
}

impl Command for StartUseCase {
    type Caller = CallerContext;
    type Input = StartRequest;
    type Output = Result<UserImportId, AppError>;

    /// Keeps `request.batch` as an import pending for the worker, queues
    /// the `identity.import` job that opens its accounts in chunks, and
    /// records `identity.user_import_started`. Nothing is opened or mailed
    /// yet: the worker records each account as it opens it, and
    /// `identity.users_imported` once the import ends.
    ///
    /// Sam may only view users. Without the domain's check, he imports an
    /// account for a mailbox of his own, with a password hash he made, and
    /// signs in once its default roles fill it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not create users, or the
    ///   plan has no room for every record.
    /// - `AppError::Internal` on persistence or queue failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: StartRequest,
    ) -> Result<UserImportId, AppError> {
        let StartRequest { batch, scope } = request;
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        self.ensure_room(ctx, &batch).await?;
        let mut import = UserImport::start(batch, ctx.actor(), &authority.standing())
            .map_err(AppError::from_domain)?;

        self.keep_and_queue(ctx, &import, scope).await?;
        auditor
            .dispatch_by(&ctx.actor(), import.take_events(&ctx.tenant()))
            .await
            .or_internal()?;
        Ok(*import.id())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::identity::account::import::state::ImportStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::{FakeUserImportStore, import_batch};
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
        test_link_scope,
    };
    use crate::use_cases::identity::imports::job::IMPORT_JOB;

    struct Fixture {
        imports: Arc<FakeUserImportStore>,
        queue: Arc<FakeJobQueue>,
        audit: Arc<FakeEventDispatcher>,
        ports: StartPorts,
    }

    impl Fixture {
        fn new() -> Self {
            let imports = Arc::new(FakeUserImportStore::empty());
            let queue = Arc::new(FakeJobQueue::new());
            Self {
                ports: StartPorts {
                    import_store: imports.clone(),
                    job_queue: queue.clone(),
                    ..StartPorts::fakes()
                },
                imports,
                queue,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }

        fn start(self, records: usize) -> (Result<UserImportId, AppError>, Self) {
            let use_case = StartUseCase::new(self.ports);
            let request = StartRequest {
                batch: import_batch(records),
                scope: test_link_scope(),
            };
            let auditor = test_auditor(self.audit.clone());
            let result = block_on(use_case.execute(&test_ctx(), &auditor, request));
            let fixture = Self {
                ports: use_case.ports,
                ..self
            };
            (result, fixture)
        }
    }

    /// Ann sends two thousand accounts. The import is kept pending with
    /// every record, the job that works it through is queued, and the start
    /// is recorded; nothing is opened in the request.
    #[test]
    fn a_batch_is_kept_and_its_job_queued() {
        let (result, fixture) = Fixture::new().start(2_000);

        let kept = fixture.imports.stored(&result.unwrap()).unwrap();
        assert_eq!(kept.status(), ImportStatus::Pending);
        assert_eq!(kept.counts().total, 2_000);
        assert!(fixture.queue.holds(IMPORT_JOB));
        assert_eq!(fixture.recorded(), ["identity.user_import_started"]);
    }

    /// Acme's plan has no room for the batch. It is refused before anything
    /// is kept or queued.
    #[test]
    fn a_batch_past_the_plan_limit_is_refused() {
        let mut fixture = Fixture::new();
        fixture.ports.limit_enforcer = Arc::new(RejectingLimitEnforcer);

        let (result, fixture) = fixture.start(1);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.imports.count(), 0);
        assert_eq!(fixture.queue.count(), 0);
    }

    /// User-viewing rights do not permit importing accounts. No import,
    /// job or audit event is created.
    #[test]
    fn a_caller_who_may_not_create_users_is_refused() {
        let mut fixture = Fixture::new();
        fixture.ports.tenant_authorities =
            Arc::new(FakeTenantAuthorities::holding(&[SystemPermission::Users(
                UserAction::View,
            )]));

        let (result, fixture) = fixture.start(1);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.imports.count(), 0);
        assert_eq!(fixture.queue.count(), 0);
        assert!(fixture.recorded().is_empty());
    }

    /// A signed-out caller cannot start an account import.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let mut fixture = Fixture::new();
        fixture.ports.tenant_authorities =
            Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let (result, _) = fixture.start(1);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
