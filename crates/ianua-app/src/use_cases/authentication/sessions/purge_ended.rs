//! Purge ended sessions: remove every tenant's and every organization's
//! sessions once they are over and past the domain's keeping, so the rows
//! of sessions long ended do not pile up.
//!
//! A session over is one that expired, or one that was ended and that no
//! later session replaced by a refresh; the domain keeps it for
//! [`ENDED_KEPT_FOR`] after. What happened stays in the audit trail, which
//! keeps sign-ins as long as each tenant's compliance asks, so a removed
//! session leaves no record of its own.
//!
//! It runs on a schedule, outside any request, for nobody, so no one's
//! rights are asked. Running it late or twice removes nothing that should
//! stay: it looks at what is over now, and a session in force is never
//! over.
//!
//! [`ENDED_KEPT_FOR`]: ianua_domain::domains::authentication::sessions::retention::ENDED_KEPT_FOR

use std::sync::Arc;

use ianua_domain::domains::authentication::sessions::retention::{
    ENDED_KEPT_FOR, ended_kept_since,
};
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::shared::clock;
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrgSessionStore;
use crate::ports::shared::SessionStore;
use crate::ports::tenant::TenantStore;
use crate::services::tenant_batches::{PurgeReport, TenantBatches};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The ports [`PurgeEndedUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PurgeEndedPorts {
    /// Tenant users' sessions.
    pub session_store: Arc<dyn SessionStore>,
    /// Organization members' sessions.
    pub org_session_store: Arc<dyn OrgSessionStore>,
    /// Lists the tenants whose sessions are purged.
    pub tenants: Arc<dyn TenantStore>,
}

/// Removes every plane's sessions over and past their keeping.
pub struct PurgeEndedUseCase {
    ports: PurgeEndedPorts,
}

impl PurgeEndedUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: PurgeEndedPorts) -> Self {
        Self { ports }
    }

    /// Removes the organization members' sessions past the keeping, and
    /// returns how many went.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the store cannot remove them.
    async fn purged_members(&self) -> Result<u64, AppError> {
        let days = u32::try_from(ENDED_KEPT_FOR.whole_days()).unwrap_or(u32::MAX);
        self.ports
            .org_session_store
            .purge_expired(days)
            .await
            .or_internal()
    }

    /// Removes `tenant`'s sessions over by `cutoff` and returns how many
    /// went. A failure is logged and answered with `None`: the tenant is
    /// purged again next time, and the others still are now.
    async fn purged_tenant(&self, tenant: &Tenant, cutoff: OffsetDateTime) -> Option<u64> {
        let scoped = ScopedTenant::for_background(*tenant.id());
        match self.ports.session_store.purge_ended(&scoped, cutoff).await {
            Ok(removed) => Some(removed),
            Err(error) => {
                tracing::warn!(tenant_id = %tenant.id(), %error, "sessions not purged");
                None
            }
        }
    }
}

impl Command for PurgeEndedUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<PurgeReport, AppError>;

    /// Removes the sessions over before the domain's cutoff now, the
    /// organization members' and every tenant's, and returns how many went.
    ///
    /// One tenant whose sessions cannot be removed does not stop the
    /// others; it is counted as unpurged and tried again next time. Records
    /// nothing: removing sessions long over is housekeeping, not a change
    /// anyone made.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the members' sessions cannot be purged or
    /// the tenant list cannot be read.
    async fn execute(
        &self,
        (): &(),
        _auditor: &RequestAuditor,
        (): (),
    ) -> Result<PurgeReport, AppError> {
        let cutoff = ended_kept_since(clock::now());
        let mut report = PurgeReport {
            removed: self.purged_members().await?,
            unpurged: 0,
        };
        let mut tenants = TenantBatches::over(self.ports.tenants.as_ref());
        while let Some(batch) = tenants.next().await? {
            for tenant in &batch {
                report = report.counting(self.purged_tenant(tenant, cutoff).await);
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::sessions::session::{Session, SessionRow};
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::UserId;
    use time::Duration;

    use super::*;
    use crate::test_support::authentication::{FakeSessionStore, session_row_for};
    use crate::test_support::tenant::{FakeTenantStore, test_tenant, test_tenant_for_ctx};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    /// A session of a new account, last used and run out `ago`, `revoked`
    /// or not.
    fn over_since(ago: Duration, status: SessionStatus) -> Session<ResolvedTenant> {
        let then = clock::now() - ago;
        Session::reconstitute(SessionRow {
            status,
            signed_in_at: then - Duration::hours(1),
            created_at: then - Duration::hours(1),
            last_active_at: then,
            expires_at: then,
            ..session_row_for(UserId::new())
        })
        .unwrap()
    }

    fn purge(store: &Arc<FakeSessionStore>, tenants: Vec<Tenant>) -> PurgeReport {
        let use_case = PurgeEndedUseCase::new(PurgeEndedPorts {
            session_store: store.clone(),
            tenants: Arc::new(FakeTenantStore::holding_all(tenants)),
            ..PurgeEndedPorts::fakes()
        });
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        block_on(use_case.execute(&(), &auditor, ())).unwrap()
    }

    /// Purging removes an old ended session from each tenant while retaining
    /// the recently expired session and reporting both removals.
    #[test]
    fn a_session_long_over_goes_and_a_recent_one_stays() {
        let store = Arc::new(FakeSessionStore::empty());
        let (acme, globex) = (
            test_tenant_for_ctx(),
            test_tenant("globex", "globex.example.com"),
        );
        let recent = over_since(Duration::days(1), SessionStatus::Active);
        for tenant in [&acme, &globex] {
            let scoped = ScopedTenant::for_background(*tenant.id());
            let old = over_since(ENDED_KEPT_FOR + Duration::days(1), SessionStatus::Revoked);
            block_on(store.save(&scoped, &old)).unwrap();
        }
        let scoped = ScopedTenant::for_background(*acme.id());
        block_on(store.save(&scoped, &recent)).unwrap();

        let report = purge(&store, vec![acme, globex]);

        assert_eq!(report.removed, 2);
        assert_eq!(report.unpurged, 0);
        assert_eq!(store.session_count(), 1);
        assert!(store.get_session(recent.id()).is_some());
    }

    /// A session created before the retention cutoff remains stored while
    /// its expiry is still in the future.
    #[test]
    fn a_session_in_force_is_kept_however_old() {
        let store = Arc::new(FakeSessionStore::empty());
        let acme = test_tenant_for_ctx();
        let long_ago = clock::now() - ENDED_KEPT_FOR - Duration::days(30);
        let running = Session::reconstitute(SessionRow {
            signed_in_at: long_ago,
            created_at: long_ago,
            last_active_at: long_ago,
            expires_at: clock::now() + Duration::days(1),
            ..session_row_for(UserId::new())
        })
        .unwrap();
        block_on(store.save(&ScopedTenant::for_background(*acme.id()), &running)).unwrap();

        let report = purge(&store, vec![acme]);

        assert_eq!(report.removed, 0);
        assert!(store.get_session(running.id()).is_some());
    }
}
