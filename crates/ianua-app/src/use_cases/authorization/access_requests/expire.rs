//! Expire access requests: the background sweep that closes the requests
//! nobody answered within the answer window.
//!
//! A request past its window can no longer be approved anyway; closing it
//! says so on the record and takes it off every approver's list.

use std::sync::Arc;

use ianua_domain::domains::authorization::access_request::AccessRequest;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ActorRef;
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::listing::{Limit, PageRequest};
use crate::ports::authorization::AccessRequestStore;
use crate::ports::runtime::UnitOfWork;
use crate::ports::tenant::TenantStore;
use crate::services::tenant_batches::TenantBatches;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authorization::sweeps::swept;

/// The ports [`ExpireUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ExpirePorts {
    /// Lists the tenants to look in.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Finds and saves the requests that ran out.
    pub request_store: Arc<dyn AccessRequestStore>,
    /// Keeps each closing and the record of it together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Closes every access request nobody answered in time.
pub struct ExpireUseCase {
    ports: ExpirePorts,
}

impl ExpireUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ExpirePorts) -> Self {
        Self { ports }
    }

    /// How many of `tenant`'s requests were closed.
    async fn expire_in(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        now: OffsetDateTime,
    ) -> Result<u64, AppError> {
        let store = self.ports.request_store.as_ref();
        let unit = self.ports.unit_of_work.as_ref();
        let mut closed: u64 = 0;
        let limit = Limit::internal(500);
        let mut page = PageRequest::first(limit);
        loop {
            let lapsed = store.find_lapsed(tenant, now, &page).await.or_internal()?;
            for request in lapsed.items {
                let work = self.close(tenant, auditor, request, now);
                closed = closed.saturating_add(swept(unit, "access request", work).await);
            }
            let Some(next) = lapsed.next else {
                return Ok(closed);
            };
            page = PageRequest::new(Some(next), limit);
        }
    }

    /// Closes `request` as run out, and records it, by the platform.
    async fn close(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        mut request: AccessRequest<ResolvedTenant>,
        now: OffsetDateTime,
    ) -> Result<(), AppError> {
        request.expire(now).map_err(AppError::from_domain)?;
        self.ports
            .request_store
            .save(tenant, &request)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ActorRef::System, request.take_events(tenant))
            .await
            .or_internal()
    }
}

impl Command for ExpireUseCase {
    type Caller = ();
    type Input = OffsetDateTime;
    type Output = Result<u64, AppError>;

    /// Closes every request in every tenant still pending once its answer
    /// window closed by `now`, and returns how many were closed.
    ///
    /// Each is kept together with its record as one unit. One that cannot
    /// be closed is logged and tried again on the next run. Each tenant's
    /// records go through `auditor` scoped to that tenant, attributed to
    /// the system.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the tenants, or a tenant's lapsed
    ///   requests, cannot be read.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        now: OffsetDateTime,
    ) -> Result<u64, AppError> {
        let mut closed: u64 = 0;
        let mut tenants = TenantBatches::over(self.ports.tenant_store.as_ref());
        while let Some(batch) = tenants.next_ids().await? {
            for tenant_id in batch {
                let tenant = ScopedTenant::for_background(tenant_id);
                let tenant_auditor = auditor.with_tenant(tenant_id);
                closed =
                    closed.saturating_add(self.expire_in(&tenant, &tenant_auditor, now).await?);
            }
        }
        Ok(closed)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::access_request::{AccessRequestStatus, AskedAccess};
    use ianua_domain::shared::clock;
    use ianua_domain::types::RoleId;
    use time::Duration;

    use super::*;
    use crate::ports::runtime::Settlement;
    use crate::test_support::authorization::{FakeAccessRequestStore, pending_request_by};
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{
        FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor, test_ctx,
    };

    /// Runs the sweep over `requests`, watched by `sink` and `unit`.
    fn sweep(
        requests: &Arc<FakeAccessRequestStore>,
        sink: &Arc<FakeEventDispatcher>,
        unit: &Arc<RecordingUnitOfWork>,
    ) -> u64 {
        let use_case = ExpireUseCase::new(ExpirePorts {
            tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
            request_store: requests.clone(),
            unit_of_work: unit.clone(),
        });
        block_on(use_case.execute(&(), &test_auditor(sink.clone()), clock::now())).unwrap()
    }

    /// Bob asked eight days ago and Carol an hour ago. The sweep closes
    /// Bob's, which nobody answered in a week, records it, and leaves
    /// Carol's open.
    #[test]
    fn unanswered_requests_past_their_window_are_closed() {
        let asked = AskedAccess::Role(RoleId::new());
        let old = pending_request_by(asked, "bob@acme.test", clock::now() - Duration::days(8));
        let new = pending_request_by(asked, "carol@acme.test", clock::now() - Duration::hours(1));
        let (old_id, new_id) = (*old.id(), *new.id());
        let tenant = test_ctx().tenant_id();
        let requests = Arc::new(FakeAccessRequestStore::holding(tenant, [old, new]));
        let sink = Arc::new(FakeEventDispatcher::new());
        let unit = Arc::new(RecordingUnitOfWork::default());

        let closed = sweep(&requests, &sink, &unit);

        assert_eq!(closed, 1);
        assert_eq!(
            requests.status_of(tenant, &old_id),
            Some(AccessRequestStatus::Expired)
        );
        assert_eq!(
            requests.status_of(tenant, &new_id),
            Some(AccessRequestStatus::Pending)
        );
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.access_request_expired"]
        );
        assert_eq!(unit.settlements(), [Settlement::Commit]);
    }

    /// A backlog larger than one page is closed once per request with its
    /// audit record, while each read stays within one batch.
    #[test]
    fn lapsed_access_requests_are_read_in_bounded_batches() {
        let asked = AskedAccess::Role(RoleId::new());
        let at = clock::now() - Duration::days(8);
        let rows = (0..501)
            .map(|index| pending_request_by(asked, &format!("person-{index}@acme.test"), at));
        let requests = Arc::new(FakeAccessRequestStore::holding(
            test_ctx().tenant_id(),
            rows,
        ));
        let sink = Arc::new(FakeEventDispatcher::new());
        let unit = Arc::new(RecordingUnitOfWork::default());

        let closed = sweep(&requests, &sink, &unit);

        assert_eq!(closed, 501);
        assert_eq!(sink.records.lock().unwrap().len(), 501);
        assert_eq!(unit.settlements(), vec![Settlement::Commit; 501]);
        assert_eq!(requests.lapsed_batch_sizes(), [500, 1]);
    }

    /// Nobody asked for anything. The sweep closes nothing.
    #[test]
    fn nothing_is_closed_when_nothing_ran_out() {
        let requests = Arc::new(FakeAccessRequestStore::empty());

        let closed = sweep(
            &requests,
            &Arc::new(FakeEventDispatcher::new()),
            &Arc::new(RecordingUnitOfWork::default()),
        );

        assert_eq!(closed, 0);
    }
}
