//! Build exports: gather the file of every export still waiting for one,
//! in every tenant, mark it ready for its download window, and tell the
//! person.
//!
//! An export whose file cannot be gathered stays waiting and is built
//! again on the next run; it does not stop the others.

use std::sync::Arc;

use ianua_domain::domains::identity::privacy::export::DataExportRequest;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ActorRef;
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::listing::{Limit, PageRequest};
use crate::ports::identity::{DataExportBuilder, DataExportNotifier, DataExportStore, UserStore};
use crate::ports::shared::MailRecipient;
use crate::ports::tenant::TenantStore;
use crate::services::tenant_batches::TenantBatches;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// What one run built.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BuildReport {
    /// Exports made ready.
    pub built: u64,
    /// Exports whose file could not be gathered; each is tried again next
    /// run.
    pub failed: u64,
}

impl BuildReport {
    /// This report and `other` added together.
    fn plus(self, other: Self) -> Self {
        Self {
            built: self.built.saturating_add(other.built),
            failed: self.failed.saturating_add(other.failed),
        }
    }
}

/// The ports [`BuildExportsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct BuildExportsPorts {
    /// Lists the tenants to look in.
    pub tenant_store: Arc<dyn TenantStore>,
    /// The requests.
    pub export_store: Arc<dyn DataExportStore>,
    /// Gathers each file.
    pub builder: Arc<dyn DataExportBuilder>,
    /// The accounts, for the address the person is told at.
    pub user_store: Arc<dyn UserStore>,
    /// Tells the person their export is ready.
    pub notifier: Arc<dyn DataExportNotifier>,
}

/// Gathers the file of every waiting export.
pub struct BuildExportsUseCase {
    ports: BuildExportsPorts,
}

/// One tenant a run works in, with the auditor its records go through.
struct InTenant<'a> {
    /// The scope whose personal-data requests this worker exports.
    tenant: ScopedTenant,
    /// Its records go through this.
    auditor: &'a RequestAuditor,
    /// The moment the run works for.
    now: OffsetDateTime,
}

impl BuildExportsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: BuildExportsPorts) -> Self {
        Self { ports }
    }

    /// What building every waiting export of one tenant came to.
    async fn build_tenant(&self, within: &InTenant<'_>) -> Result<BuildReport, AppError> {
        let mut report = BuildReport::default();
        let limit = Limit::internal(500);
        let mut page = PageRequest::first(limit);
        loop {
            let waiting = self
                .ports
                .export_store
                .waiting(&within.tenant, within.now, &page)
                .await
                .or_internal()?;
            for export in waiting.items {
                report = report.plus(self.build_one(within, export).await?);
            }
            let Some(next) = waiting.next else {
                return Ok(report);
            };
            page = PageRequest::new(Some(next), limit);
        }
    }

    /// Gathers one export's file and makes it ready, or leaves it waiting
    /// when the file cannot be gathered.
    async fn build_one(
        &self,
        within: &InTenant<'_>,
        mut export: DataExportRequest<ResolvedTenant>,
    ) -> Result<BuildReport, AppError> {
        let tenant = &within.tenant;
        if let Err(error) = self.ports.builder.build(tenant, &export).await {
            tracing::warn!(%error, export_id = %export.id(), "data export not built; retried next run");
            return Ok(BuildReport {
                built: 0,
                failed: 1,
            });
        }
        export
            .mark_ready(within.now)
            .map_err(AppError::from_domain)?;
        self.ports
            .export_store
            .save(tenant, &export)
            .await
            .or_internal()?;
        self.tell(tenant, &export).await;
        within
            .auditor
            .dispatch_by(&ActorRef::System, export.take_events(tenant))
            .await
            .or_internal()?;
        Ok(BuildReport {
            built: 1,
            failed: 0,
        })
    }

    /// Tells the person their export is ready. Telling is best effort: the
    /// export waits for them whether or not the mail went out.
    async fn tell(&self, tenant: &ScopedTenant, export: &DataExportRequest<ResolvedTenant>) {
        let Some(until) = export.state().available_until() else {
            return;
        };
        let Ok(Some(account)) = self
            .ports
            .user_store
            .find_by_id(tenant, export.user_id())
            .await
        else {
            return;
        };
        let to = MailRecipient {
            email: account.email(),
            locale: account.locale(),
        };
        let told = self.ports.notifier.ready(tenant, to, until).await;
        if let Err(error) = told {
            tracing::warn!(%error, "the person was not told their data export is ready");
        }
    }
}

impl Command for BuildExportsUseCase {
    type Caller = ();
    type Input = OffsetDateTime;
    type Output = Result<BuildReport, AppError>;

    /// Gathers the file of every waiting export in every tenant as of
    /// `now`, marks each ready for its download window, records
    /// `identity.data_export_ready`, and tells the person by mail. Each
    /// tenant's records go through `auditor` scoped to that tenant,
    /// attributed to the system.
    ///
    /// # Errors
    ///
    /// - `AppError::Conflict` if a waiting export refuses to be made ready.
    /// - `AppError::Internal` when the tenants or their exports cannot be
    ///   read or written, or what was done cannot be recorded.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        now: OffsetDateTime,
    ) -> Result<BuildReport, AppError> {
        let mut report = BuildReport::default();
        let mut tenants = TenantBatches::over(self.ports.tenant_store.as_ref());
        while let Some(batch) = tenants.next().await? {
            for tenant in &batch {
                let tenant_auditor = auditor.with_tenant(*tenant.id());
                let within = InTenant {
                    tenant: ScopedTenant::for_background(*tenant.id()),
                    auditor: &tenant_auditor,
                    now,
                };
                report = report.plus(self.build_tenant(&within).await?);
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::privacy::export_state::ExportStatus;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{Locale, Preference, UserId};

    use super::*;
    use crate::test_support::identity::{
        FakeDataExportBuilder, FakeDataExportStore, FakeUserStore, RecordingExportNotifier,
        asked_export_of, user_reading,
    };
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    struct Fixture {
        exports: Arc<FakeDataExportStore>,
        notifier: Arc<RecordingExportNotifier>,
        audit: Arc<FakeEventDispatcher>,
        ports: BuildExportsPorts,
    }

    fn with_waiting_export_of(ann: UserId) -> (Fixture, ianua_domain::types::DataExportId) {
        let export = asked_export_of(ann);
        let id = *export.id();
        let exports = Arc::new(FakeDataExportStore::holding(&export));
        let notifier = Arc::new(RecordingExportNotifier::default());
        let fixture = Fixture {
            ports: BuildExportsPorts {
                tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                export_store: exports.clone(),
                user_store: Arc::new(FakeUserStore::with_user(ann, "ann@acme.test")),
                notifier: notifier.clone(),
                ..BuildExportsPorts::fakes()
            },
            exports,
            notifier,
            audit: Arc::new(FakeEventDispatcher::new()),
        };
        (fixture, id)
    }

    fn run(fixture: Fixture) -> (Result<BuildReport, AppError>, Fixture) {
        let use_case = BuildExportsUseCase::new(fixture.ports);
        let result =
            block_on(use_case.execute(&(), &test_auditor(fixture.audit.clone()), clock::now()));
        let fixture = Fixture {
            ports: use_case.ports,
            ..fixture
        };
        (result, fixture)
    }

    /// Ann's export waits for its file. The run gathers it, makes it ready,
    /// tells Ann and records it.
    #[test]
    fn a_waiting_export_is_built_and_the_person_told() {
        let ann = UserId::new();
        let (fixture, id) = with_waiting_export_of(ann);

        let (result, fixture) = run(fixture);

        assert_eq!(
            result.unwrap(),
            BuildReport {
                built: 1,
                failed: 0
            }
        );
        assert_eq!(
            fixture.exports.stored(&id).unwrap().status(),
            ExportStatus::Ready
        );
        assert_eq!(fixture.notifier.told(), ["ann@acme.test"]);
        assert_eq!(
            fixture.audit.records.lock().unwrap().as_slice(),
            ["identity.data_export_ready"]
        );
    }

    /// A section could not be read in time. Ann's export stays waiting,
    /// nobody is told, and the run goes on to report it.
    #[test]
    fn an_export_that_cannot_be_built_waits_for_the_next_run() {
        let (mut fixture, id) = with_waiting_export_of(UserId::new());
        fixture.ports.builder = Arc::new(FakeDataExportBuilder::failing());

        let (result, fixture) = run(fixture);

        assert_eq!(
            result.unwrap(),
            BuildReport {
                built: 0,
                failed: 1
            }
        );
        assert_eq!(
            fixture.exports.stored(&id).unwrap().status(),
            ExportStatus::Requested
        );
        assert!(fixture.notifier.told().is_empty());
        assert!(fixture.audit.records.lock().unwrap().is_empty());
    }

    /// A backlog larger than one batch cannot be built. Every request is
    /// attempted once per run, left waiting, and retried by the next run.
    #[test]
    fn export_build_batches_advance_past_failed_builders() {
        let (mut fixture, _) = with_waiting_export_of(UserId::new());
        add_waiting_exports(&fixture, 500);
        fixture.ports.builder = Arc::new(FakeDataExportBuilder::failing());

        let (result, fixture) = run(fixture);

        assert_eq!(
            result.unwrap(),
            BuildReport {
                built: 0,
                failed: 501
            }
        );
        assert_eq!(fixture.exports.count(), 501);
        assert!(fixture.audit.records.lock().unwrap().is_empty());
        assert_eq!(fixture.exports.waiting_batch_sizes(), [500, 1]);

        let (retried, fixture) = run(fixture);

        assert_eq!(
            retried.unwrap(),
            BuildReport {
                built: 0,
                failed: 501
            }
        );
        assert_eq!(fixture.exports.waiting_batch_sizes(), [500, 1, 500, 1]);
    }

    /// Adds separate requested exports to the tenant backlog without attempting builds.
    fn add_waiting_exports(fixture: &Fixture, count: usize) {
        let tenant = ScopedTenant::for_background(*test_tenant_for_ctx().id());
        for _ in 0..count {
            block_on(
                fixture
                    .exports
                    .save(&tenant, &asked_export_of(UserId::new())),
            )
            .unwrap();
        }
    }

    /// Ann reads mail in German. Her export is ready, and she is told in
    /// German.
    #[test]
    fn the_person_is_told_in_their_language() {
        let ann = UserId::new();
        let (mut fixture, _) = with_waiting_export_of(ann);
        let users = FakeUserStore::empty();
        users.add(user_reading(ann, "ann@acme.test", "de-DE"));
        fixture.ports.user_store = Arc::new(users);

        let (_, fixture) = run(fixture);

        assert_eq!(
            fixture.notifier.locales(),
            [Preference::Own(Locale::new("de-DE").unwrap())]
        );
    }
}
