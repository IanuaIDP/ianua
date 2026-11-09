//! Run an import: the worker opens the accounts an import holds, a chunk at
//! a time.
//!
//! Each chunk is one unit of work: its accounts, their password hashes and
//! starting roles, the record of each, and the import's progress are kept
//! together or not at all. So a worker that stops halfway, or a chunk the
//! database refuses, leaves the import exactly as far as its last kept
//! chunk, and the next try goes on from there; nobody is imported twice.
//! The links that confirm each address are mailed only once their chunk is
//! kept, so no mail goes to an account that was rolled back.
//!
//! The account's address is checked again here: someone may have signed up
//! with it since the import was sent. That record is set aside with its
//! line, and the rest of the import goes on.
//!
//! The plan's room for users is checked again for each chunk too. Starting
//! the import checked it once, but two imports started together both pass
//! that check, and people sign up meanwhile. So each chunk opens only as
//! many accounts as the plan has room for when it runs; the records past
//! that are set aside as past the limit, each with its line.
//!
//! The tenant's default roles are read once per chunk and given to every
//! account it opens, not read again for each account.

use std::sync::Arc;

use ianua_domain::domains::authorization::role::Role;
use ianua_domain::domains::identity::account::import::ImportedPassword;
use ianua_domain::domains::identity::account::import::refusal::{
    FailedRecord, RecordLine, RecordRefusal,
};
use ianua_domain::domains::identity::account::import::run::{
    ChunkEntry, ChunkOutcome, ImportChunk, Opening, UserImport,
};
use ianua_domain::domains::identity::account::import::state::ImportStatus;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, UserImportId};

use crate::auditor::RequestAuditor;
use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::CredentialStore;
use crate::ports::authorization::{RoleAssignmentStore, RoleStore};
use crate::ports::identity::{UserImportStore, UserStore};
use crate::ports::limits::{LimitEnforcer, PlanLimitsSource, ResourceKind};
use crate::ports::runtime::UnitOfWork;
use crate::services::authorization::starting_roles::{self, Starting};
use crate::services::kept_together::kept_together;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::email::VerificationLinks;
use crate::use_cases::identity::imports::job::{ImportRun, Tries};

/// The ports [`RunUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RunPorts {
    /// Keeps the import and its progress.
    pub import_store: Arc<dyn UserImportStore>,
    /// Saves the accounts and finds addresses already taken.
    pub user_store: Arc<dyn UserStore>,
    /// Keeps the password hashes the records bring.
    pub credential_store: Arc<dyn CredentialStore>,
    /// Reads the tenant's default roles, once per chunk.
    pub role_store: Arc<dyn RoleStore>,
    /// Grants them.
    pub assignment_store: Arc<dyn RoleAssignmentStore>,
    /// The tenant's plan, read again for each chunk.
    pub plan_limits: Arc<dyn PlanLimitsSource>,
    /// How much room the plan has left for users when a chunk runs.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// Mails the link that confirms each address.
    pub verification_links: Arc<VerificationLinks>,
    /// Keeps each chunk whole.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Works an import through, chunk by chunk.
pub struct RunUseCase {
    ports: RunPorts,
}

/// Where a run works: the tenant, its record, and where links land.
struct Work<'a> {
    /// The import's tenant.
    tenant: &'a ScopedTenant,
    /// Records against the tenant.
    auditor: &'a RequestAuditor,
    /// Where each confirmation link lands.
    scope: &'a LinkScope,
}

/// An account a chunk opens, with the password it brought.
struct Opened {
    /// The account.
    user: User<ResolvedTenant>,
    /// Its password, when the record carried one.
    password: ImportedPassword,
}

/// What a chunk made of its records, before it is kept.
struct Worked {
    /// The accounts it opens.
    opened: Vec<Opened>,
    /// What it did, for the import's progress.
    outcome: ChunkOutcome,
}

/// How many more users the plan has room for while a chunk runs.
struct Room(u64);

impl Room {
    /// `opening`, unless it opens an account the plan has no place left
    /// for: then the record on `line` is set aside as past the limit. An
    /// account let in takes a place.
    fn admit(
        &mut self,
        opening: Opening<ResolvedTenant>,
        line: RecordLine,
    ) -> Opening<ResolvedTenant> {
        let Opening::Opened { .. } = opening else {
            return opening;
        };
        let Some(left) = self.0.checked_sub(1) else {
            let failed = FailedRecord::new(line, RecordRefusal::UserLimitReached);
            return Opening::Refused(failed);
        };
        self.0 = left;
        opening
    }
}

impl RunUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RunPorts) -> Self {
        Self { ports }
    }

    /// The import with `id`, as last kept.
    async fn kept_import(
        &self,
        tenant: &ScopedTenant,
        id: &UserImportId,
    ) -> Result<UserImport<ResolvedTenant>, AppError> {
        self.ports
            .import_store
            .find_by_id(tenant, id)
            .await
            .or_internal()?
            .ok_or_else(|| AppError::NotFound(message!("identity-user-import", "user import")))
    }

    /// Takes the import up and keeps it running, so its progress shows
    /// before the first chunk is in.
    async fn take_up(
        &self,
        tenant: &ScopedTenant,
        import: &mut UserImport<ResolvedTenant>,
    ) -> Result<(), AppError> {
        import.take_up().map_err(AppError::from_domain)?;
        self.ports
            .import_store
            .save(tenant, import)
            .await
            .or_internal()
    }

    /// One try at the import: taken up, then worked through.
    async fn attempt(
        &self,
        work: &Work<'_>,
        import: &mut UserImport<ResolvedTenant>,
    ) -> Result<(), AppError> {
        self.take_up(work.tenant, import).await?;
        self.work_through(work, import).await
    }

    /// Works through every chunk still to go, each kept before the next.
    async fn work_through(
        &self,
        work: &Work<'_>,
        import: &mut UserImport<ResolvedTenant>,
    ) -> Result<(), AppError> {
        while let Some(chunk) = import.next_chunk() {
            let Worked { opened, outcome } = self.worked(work.tenant, import, chunk).await?;
            import
                .record_chunk(outcome, clock::now())
                .map_err(AppError::from_domain)?;
            let unit = self.ports.unit_of_work.as_ref();
            let users = kept_together(unit, self.kept(work, import, opened)).await?;
            self.mail_links(work, import.started_by(), users).await?;
        }
        Ok(())
    }

    /// How many more users the tenant's plan has room for now.
    async fn room(&self, tenant: &ScopedTenant) -> Result<Room, AppError> {
        let plan = self
            .ports
            .plan_limits
            .for_tenant(tenant)
            .await
            .map_err(AppError::from_domain)?;
        let left = self
            .ports
            .limit_enforcer
            .tenant_room(&plan, tenant, ResourceKind::Users)
            .await
            .map_err(AppError::from_domain)?;
        Ok(Room(left))
    }

    /// What `chunk` makes of each of its records, opening no more accounts
    /// than the plan has room for when it runs.
    async fn worked(
        &self,
        tenant: &ScopedTenant,
        import: &UserImport<ResolvedTenant>,
        chunk: ImportChunk<'_>,
    ) -> Result<Worked, AppError> {
        let end = chunk.end();
        let mut room = self.room(tenant).await?;
        let mut opened = Vec::new();
        let mut refused = Vec::new();
        for entry in chunk.entries() {
            let line = entry.line;
            let opening = self.opening(tenant, import, entry).await?;
            match room.admit(opening, line) {
                Opening::Opened { user, password } => opened.push(Opened {
                    user: *user,
                    password,
                }),
                Opening::Refused(failed) => refused.push(failed),
            }
        }
        let imported = u32::try_from(opened.len()).unwrap_or(u32::MAX);
        Ok(Worked {
            opened,
            outcome: ChunkOutcome {
                end,
                imported,
                refused,
            },
        })
    }

    /// What the record of `entry` becomes: refused when its address has an
    /// account by now, else whatever the import makes of it.
    async fn opening(
        &self,
        tenant: &ScopedTenant,
        import: &UserImport<ResolvedTenant>,
        entry: ChunkEntry<'_>,
    ) -> Result<Opening<ResolvedTenant>, AppError> {
        let email = &entry.record.account.email;
        let taken = self
            .ports
            .user_store
            .email_exists(tenant, email)
            .await
            .or_internal()?;
        if taken {
            let failed = FailedRecord::new(entry.line, RecordRefusal::AddressTaken);
            return Ok(Opening::Refused(failed));
        }
        import.open(entry).map_err(AppError::from_domain)
    }

    /// Keeps the import's progress first, then each opened account, and
    /// records them all against whoever sent the import. Returns the
    /// accounts, to mail once kept.
    async fn kept(
        &self,
        work: &Work<'_>,
        import: &mut UserImport<ResolvedTenant>,
        opened: Vec<Opened>,
    ) -> Result<Vec<User<ResolvedTenant>>, AppError> {
        self.ports
            .import_store
            .save(work.tenant, import)
            .await
            .or_internal()?;
        let defaults =
            starting_roles::defaults(self.ports.role_store.as_ref(), work.tenant).await?;
        let mut events = Vec::new();
        let mut users = Vec::with_capacity(opened.len());
        for mut account in opened {
            self.store(work.tenant, &account, &defaults).await?;
            events.extend(account.user.take_events(work.tenant));
            users.push(account.user);
        }
        events.extend(import.take_events(work.tenant));
        work.auditor
            .dispatch_by(import.started_by(), events)
            .await
            .or_internal()?;
        Ok(users)
    }

    /// Saves one account, its password and its starting roles: `defaults`,
    /// read once for the chunk.
    async fn store(
        &self,
        tenant: &ScopedTenant,
        account: &Opened,
        defaults: &[Role<ResolvedTenant>],
    ) -> Result<(), AppError> {
        self.ports
            .user_store
            .save(tenant, &account.user)
            .await
            .or_internal()?;
        if let ImportedPassword::Hash(hash) = &account.password {
            self.ports
                .credential_store
                .import_password_hash(tenant, account.user.id(), hash)
                .await
                .or_internal()?;
        }
        let starting = Starting {
            user_id: *account.user.id(),
            defaults,
            extra: Vec::new(),
        };
        starting_roles::grant_from(self.ports.assignment_store.as_ref(), tenant, starting).await
    }

    /// Mails each kept account the link that confirms its address, and
    /// records the links that went out.
    ///
    /// A link that cannot be made is logged and left: the account is kept
    /// and its holder asks for another link, where failing the job would
    /// only skip the chunk on the next try.
    async fn mail_links(
        &self,
        work: &Work<'_>,
        actor: &ActorRef,
        users: Vec<User<ResolvedTenant>>,
    ) -> Result<(), AppError> {
        let links = &self.ports.verification_links;
        let mut events = Vec::new();
        for mut user in users {
            match links.send(work.tenant, &user, work.scope).await {
                Ok(mailed) => mailed.note_on(&mut user),
                Err(error) => tracing::warn!(
                    user_id = %user.id(),
                    %error,
                    "could not make an imported account's confirmation link; its holder can ask for another"
                ),
            }
            events.extend(user.take_events(work.tenant));
        }
        work.auditor.dispatch_by(actor, events).await.or_internal()
    }

    /// Gives up on the import with `id`, as last kept, and records it. An
    /// import that ended meanwhile is left as it is.
    async fn give_up(&self, work: &Work<'_>, id: &UserImportId) -> Result<(), AppError> {
        let mut import = self.kept_import(work.tenant, id).await?;
        if has_ended(&import) {
            return Ok(());
        }
        import
            .give_up(clock::now())
            .map_err(AppError::from_domain)?;
        kept_together(self.ports.unit_of_work.as_ref(), async {
            self.ports
                .import_store
                .save(work.tenant, &import)
                .await
                .or_internal()?;
            let events = import.take_events(work.tenant);
            work.auditor
                .dispatch_by(import.started_by(), events)
                .await
                .or_internal()
        })
        .await
    }
}

impl Command for RunUseCase {
    type Caller = ();
    type Input = ImportRun;
    type Output = Result<(), AppError>;

    /// Opens the accounts of the import `run` names that no kept chunk has
    /// opened yet, in chunks of five hundred. Each account is recorded as
    /// `identity.user_imported` against whoever sent the import, which
    /// colleagues are not told of one by one; `identity.users_imported`
    /// tells them once the import ends. An import that has ended is left as
    /// it is.
    ///
    /// When the last try fails, the import is given up on: the chunks kept
    /// so far stay, and it is recorded as failed.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the tenant has no such import.
    /// - `AppError::Domain` when a record cannot be opened for a reason no
    ///   refusal names.
    /// - `AppError::Internal` on persistence or audit failure. The chunk
    ///   that failed was kept whole or not at all.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        run: ImportRun,
    ) -> Result<(), AppError> {
        let ImportRun { job, tries } = run;
        let tenant = ScopedTenant::for_background(job.tenant_id);
        let auditor = auditor.with_tenant(job.tenant_id);
        let work = Work {
            tenant: &tenant,
            auditor: &auditor,
            scope: &job.scope,
        };
        let mut import = self.kept_import(&tenant, &job.import_id).await?;
        if has_ended(&import) {
            return Ok(());
        }
        let worked = self.attempt(&work, &mut import).await;
        let Err(error) = worked else {
            return Ok(());
        };
        match tries {
            Tries::MoreLeft => Err(error),
            Tries::Last => {
                self.give_up(&work, &job.import_id).await?;
                Err(error)
            }
        }
    }
}

/// Whether `import` has finished or been given up on.
fn has_ended(import: &UserImport<ResolvedTenant>) -> bool {
    matches!(
        import.status(),
        ImportStatus::Finished | ImportStatus::Failed
    )
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use async_trait::async_trait;
    use ianua_domain::domains::organization::billing::plan::{OrganizationPlan, PlanLimits};
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{OrganizationId, UserId};

    use super::*;
    use crate::ports::TenantScoped;
    use crate::ports::limits::{OrgResourceCounter, ResourceCounter};
    use crate::ports::runtime::Settlement;
    use crate::services::limits::enforcer::PlanLimitEnforcer;
    use crate::test_support::authorization::FakeRoleStore;
    use crate::test_support::identity::{
        FakeTokenStore, FakeUserImportStore, FakeUserStore, import_batch_of,
        verification_links_over,
    };
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::{
        FakeEventDispatcher, FakeLimitEnforcer, FakeMailer, FixedPlanLimits, RecordingUnitOfWork,
        RejectingLimitEnforcer, block_on, test_auditor, test_ctx, test_link_scope,
    };
    use crate::use_cases::identity::imports::job::IMPORT_JOB;
    use crate::use_cases::identity::imports::start::{StartPorts, StartRequest, StartUseCase};

    /// Counts the tenant's users as the fake user store holds them now.
    struct CountingUsers(Arc<FakeUserStore>);

    impl TenantScoped for CountingUsers {}

    #[async_trait]
    impl ResourceCounter for CountingUsers {
        async fn count_for_tenant(
            &self,
            _: &ScopedTenant,
            _: ResourceKind,
        ) -> Result<u64, DomainError> {
            Ok(u64::try_from(self.0.count()).unwrap_or(u64::MAX))
        }
    }

    #[async_trait]
    impl OrgResourceCounter for CountingUsers {
        async fn count_for_org(
            &self,
            _: &OrganizationId,
            _: ResourceKind,
        ) -> Result<u64, DomainError> {
            Ok(0)
        }
    }

    /// The Free plan, holding a tenant to `users` users.
    fn plan_of(users: u64) -> PlanLimits {
        PlanLimits {
            max_users: users,
            ..OrganizationPlan::Free.default_limits()
        }
    }

    struct Fixture {
        imports: Arc<FakeUserImportStore>,
        users: Arc<FakeUserStore>,
        roles: Arc<FakeRoleStore>,
        mailer: Arc<FakeMailer>,
        audit: Arc<FakeEventDispatcher>,
        unit: Arc<RecordingUnitOfWork>,
        use_case: RunUseCase,
    }

    impl Fixture {
        fn over(users: FakeUserStore) -> Self {
            Self::limited(
                Arc::new(users),
                Arc::new(FakeLimitEnforcer),
                plan_of(u64::MAX),
            )
        }

        /// A worker over `users`, asking `limits` how much room `plan`
        /// leaves.
        fn limited(
            users: Arc<FakeUserStore>,
            limits: Arc<dyn LimitEnforcer>,
            plan: PlanLimits,
        ) -> Self {
            let imports = Arc::new(FakeUserImportStore::empty());
            let roles = Arc::new(FakeRoleStore::empty());
            let mailer = Arc::new(FakeMailer::new());
            let unit = Arc::new(RecordingUnitOfWork::default());
            let tokens = Arc::new(FakeTokenStore::empty());
            let use_case = RunUseCase::new(RunPorts {
                import_store: imports.clone(),
                user_store: users.clone(),
                role_store: roles.clone(),
                plan_limits: Arc::new(FixedPlanLimits(plan)),
                limit_enforcer: limits,
                verification_links: verification_links_over(&tokens, &mailer),
                unit_of_work: unit.clone(),
                ..RunPorts::fakes()
            });
            Self {
                imports,
                users,
                roles,
                mailer,
                audit: Arc::new(FakeEventDispatcher::new()),
                unit,
                use_case,
            }
        }

        /// A worker over `users`, where the plan holds the tenant to
        /// `ceiling` users, counted as the store holds them when each chunk
        /// runs.
        fn capped_at(users: FakeUserStore, ceiling: u64) -> Self {
            let users = Arc::new(users);
            let counted = Arc::new(CountingUsers(users.clone()));
            let limits = Arc::new(PlanLimitEnforcer::new(counted.clone(), counted));
            Self::limited(users, limits, plan_of(ceiling))
        }

        /// Ann starts an import of `records`, and the worker claims its job.
        fn started(&self, records: usize) -> ImportRun {
            self.started_of(0..records)
        }

        /// Ann starts an import of the records numbered `numbers`, and the
        /// worker claims its job.
        fn started_of(&self, numbers: Range<usize>) -> ImportRun {
            let queue = Arc::new(FakeJobQueue::new());
            let start = StartUseCase::new(StartPorts {
                import_store: self.imports.clone(),
                job_queue: queue.clone(),
                ..StartPorts::fakes()
            });
            let request = StartRequest {
                batch: import_batch_of(numbers),
                scope: test_link_scope(),
            };
            block_on(start.execute(&test_ctx(), &test_auditor(self.audit.clone()), request))
                .unwrap();
            let mut claimed = queue.jobs_of(IMPORT_JOB).remove(0);
            claimed.mark_running().unwrap();
            ImportRun::read(&claimed).unwrap()
        }

        fn run(&self, run: &ImportRun) -> Result<(), AppError> {
            block_on(
                self.use_case
                    .execute(&(), &test_auditor(self.audit.clone()), run.clone()),
            )
        }

        fn import(&self, run: &ImportRun) -> UserImport<ResolvedTenant> {
            self.imports.stored(&run.job.import_id).unwrap()
        }

        fn recorded(&self, event_type: &str) -> usize {
            self.audit
                .records
                .lock()
                .unwrap()
                .iter()
                .filter(|name| *name == event_type)
                .count()
        }
    }

    /// Ann's import of 1,200 accounts is worked through as three chunks,
    /// each kept as one unit. Every account is opened and mailed, each is
    /// recorded once, and colleagues hear of the import once.
    #[test]
    fn an_import_is_worked_through_in_chunks_each_kept_whole() {
        let fixture = Fixture::over(FakeUserStore::empty());
        let run = fixture.started(1_200);

        fixture.run(&run).unwrap();

        assert_eq!(
            fixture.unit.settlements(),
            [Settlement::Commit, Settlement::Commit, Settlement::Commit]
        );
        assert_eq!(fixture.users.count(), 1_200);
        assert_eq!(fixture.mailer.count(), 1_200);
        assert_eq!(fixture.recorded("identity.user_imported"), 1_200);
        assert_eq!(fixture.recorded("identity.users_imported"), 1);
        assert_eq!(fixture.import(&run).status(), ImportStatus::Finished);
    }

    /// The database goes away while the second chunk is kept. That chunk
    /// opens nobody and mails nobody; only the first chunk's 500 are mailed.
    /// The next try goes on from record 501, and nobody is imported twice.
    #[test]
    fn a_failed_chunk_mails_nobody_and_the_next_try_goes_on_from_it() {
        let fixture = Fixture::over(FakeUserStore::empty());
        let run = fixture.started(1_200);
        fixture.imports.fail_once_after(2);

        let failed = fixture.run(&run);

        assert!(matches!(failed, Err(AppError::Internal(_))));
        assert_eq!(fixture.users.count(), 500);
        assert_eq!(fixture.mailer.count(), 500);
        assert_eq!(fixture.import(&run).done(), 500);

        fixture.run(&run).unwrap();

        let finished = fixture.import(&run);
        assert_eq!(finished.status(), ImportStatus::Finished);
        assert_eq!(finished.counts().imported, 1_200);
        assert_eq!(finished.counts().failed, 0);
        assert_eq!(fixture.users.count(), 1_200);
        assert_eq!(fixture.mailer.count(), 1_200);
        assert_eq!(fixture.recorded("identity.user_imported"), 1_200);
    }

    /// Bob signed up with person1@acme.test after Ann sent her import. That
    /// record, on line two, is set aside as taken, and the others are
    /// opened.
    #[test]
    fn an_address_taken_since_the_import_was_sent_is_set_aside() {
        let fixture = Fixture::over(FakeUserStore::with_user(UserId::new(), "person1@acme.test"));
        let run = fixture.started(3);

        fixture.run(&run).unwrap();

        let finished = fixture.import(&run);
        assert_eq!(finished.counts().imported, 2);
        assert_eq!(
            finished.refused(),
            [FailedRecord::new(
                RecordLine::new(2).unwrap(),
                RecordRefusal::AddressTaken
            )]
        );
        assert_eq!(fixture.users.count(), 3);
        assert_eq!(fixture.mailer.count(), 2);
    }

    /// Ann and Bob each start an import of four accounts while Acme's plan
    /// has room for five users. Both pass the check at the start. Ann's
    /// runs first and opens all four; Bob's opens the one that still fits
    /// and sets the other three aside as past the limit, each with its
    /// line, so the plan is never passed.
    #[test]
    fn two_imports_racing_to_the_limit_never_pass_it() {
        let fixture = Fixture::capped_at(FakeUserStore::empty(), 5);
        let ann = fixture.started_of(0..4);
        let bob = fixture.started_of(10..14);

        fixture.run(&ann).unwrap();
        fixture.run(&bob).unwrap();

        assert_eq!(fixture.users.count(), 5);
        let bobs = fixture.import(&bob);
        assert_eq!(bobs.status(), ImportStatus::Finished);
        assert_eq!(bobs.counts().imported, 1);
        let past: Vec<FailedRecord> = (2..=4)
            .map(|line| {
                FailedRecord::new(
                    RecordLine::new(line).unwrap(),
                    RecordRefusal::UserLimitReached,
                )
            })
            .collect();
        assert_eq!(bobs.refused(), past.as_slice());
        assert_eq!(fixture.mailer.count(), 5);
    }

    /// When the worker finds no room under the plan, all three imported
    /// records fail with the user-limit reason. No accounts or mail are created.
    #[test]
    fn a_full_plan_opens_nobody() {
        let fixture = Fixture::limited(
            Arc::new(FakeUserStore::empty()),
            Arc::new(RejectingLimitEnforcer),
            plan_of(u64::MAX),
        );
        let run = fixture.started(3);

        fixture.run(&run).unwrap();

        let finished = fixture.import(&run);
        assert_eq!(finished.counts().imported, 0);
        assert_eq!(finished.counts().failed, 3);
        assert!(
            finished
                .refused()
                .iter()
                .all(|failed| failed.reason() == RecordRefusal::UserLimitReached)
        );
        assert_eq!(fixture.users.count(), 0);
        assert_eq!(fixture.mailer.count(), 0);
    }

    /// Ann's import of 1,200 accounts runs as three chunks. Acme's default
    /// roles are read once per chunk, three times in all, not once for each
    /// of the 1,200 accounts.
    #[test]
    fn the_default_roles_are_read_once_per_chunk() {
        let fixture = Fixture::over(FakeUserStore::empty());
        let run = fixture.started(1_200);

        fixture.run(&run).unwrap();

        assert_eq!(fixture.users.count(), 1_200);
        assert_eq!(fixture.roles.default_reads(), 3);
    }

    /// The last try fails too. The import is given up on, keeps the chunk it
    /// finished, and colleagues hear it failed.
    #[test]
    fn a_failed_last_try_gives_the_import_up() {
        let fixture = Fixture::over(FakeUserStore::empty());
        let mut run = fixture.started(1_200);
        run.tries = Tries::Last;
        fixture.imports.fail_once_after(2);

        let failed = fixture.run(&run);

        assert!(failed.is_err());
        let given_up = fixture.import(&run);
        assert_eq!(given_up.status(), ImportStatus::Failed);
        assert_eq!(given_up.counts().imported, 500);
        assert_eq!(fixture.users.count(), 500);
        assert_eq!(fixture.recorded("identity.users_imported"), 1);
    }

    /// The queue hands a finished import's job over again. Nothing more is
    /// opened or mailed.
    #[test]
    fn a_finished_import_is_left_as_it_is() {
        let fixture = Fixture::over(FakeUserStore::empty());
        let run = fixture.started(2);
        fixture.run(&run).unwrap();

        fixture.run(&run).unwrap();

        assert_eq!(fixture.users.count(), 2);
        assert_eq!(fixture.mailer.count(), 2);
    }

    /// The job names an import Acme does not have. It is not found.
    #[test]
    fn an_unknown_import_is_not_found() {
        let fixture = Fixture::over(FakeUserStore::empty());
        let mut run = fixture.started(1);
        run.job.import_id = UserImportId::new();

        assert!(matches!(fixture.run(&run), Err(AppError::NotFound(_))));
    }
}
