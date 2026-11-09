//! Purge old notifications: remove every inbox's notifications once they
//! are older than the domain keeps them for, read or not.
//!
//! Notifications are an activity feed. What happened stays in the audit
//! trail, which keeps it as long as each tenant's compliance asks, so a
//! notice past [`KEPT_FOR`] is removed without a record of its own.
//!
//! It runs on a schedule, outside any request, for nobody, so no one's
//! rights are asked. Running it late or twice removes nothing that should
//! stay: it looks at what is old now.
//!
//! [`KEPT_FOR`]: ianua_domain::domains::notifications::notification::KEPT_FOR

use std::sync::Arc;

use ianua_domain::domains::notifications::notification::kept_since;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::shared::clock;
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::notifications::{
    OrgNotificationStore, PlatformNotificationStore, TenantNotificationStore,
};
use crate::ports::tenant::TenantStore;
use crate::services::tenant_batches::{PurgeReport, TenantBatches};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The ports [`PurgeOldUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PurgeOldPorts {
    /// Operators' notifications.
    pub platform_store: Arc<dyn PlatformNotificationStore>,
    /// Organization members' notifications.
    pub org_store: Arc<dyn OrgNotificationStore>,
    /// Tenant users' notifications.
    pub tenant_store: Arc<dyn TenantNotificationStore>,
    /// Lists the tenants whose inboxes are purged.
    pub tenants: Arc<dyn TenantStore>,
}

/// Removes every inbox's notifications past their keeping.
pub struct PurgeOldUseCase {
    ports: PurgeOldPorts,
}

impl PurgeOldUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: PurgeOldPorts) -> Self {
        Self { ports }
    }

    /// Removes the operators' and organization members' notifications
    /// from before `cutoff`, and returns how many went.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when either store cannot remove them.
    async fn purged_platform(&self, cutoff: OffsetDateTime) -> Result<u64, AppError> {
        let operators = self
            .ports
            .platform_store
            .purge_before(cutoff)
            .await
            .or_internal()?;
        let members = self
            .ports
            .org_store
            .purge_before(cutoff)
            .await
            .or_internal()?;
        Ok(operators.saturating_add(members))
    }

    /// Removes `tenant`'s notifications from before `cutoff` and returns
    /// how many went. A failure is logged and answered with `None`: the
    /// tenant is purged again next time, and the others still are now.
    async fn purged_tenant(&self, tenant: &Tenant, cutoff: OffsetDateTime) -> Option<u64> {
        let scoped = ScopedTenant::for_background(*tenant.id());
        match self.ports.tenant_store.purge_before(&scoped, cutoff).await {
            Ok(removed) => Some(removed),
            Err(error) => {
                tracing::warn!(tenant_id = %tenant.id(), %error, "notifications not purged");
                None
            }
        }
    }
}

impl Command for PurgeOldUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<PurgeReport, AppError>;

    /// Removes the notifications made before the domain's cutoff now from
    /// the operators', the organization members' and every tenant's
    /// inboxes, and returns how many went.
    ///
    /// One tenant whose notifications cannot be removed does not stop the
    /// others; it is counted as unpurged and tried again next time. Records
    /// nothing: removing old notices is housekeeping, not a change anyone
    /// made.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the platform's inboxes cannot be purged or
    /// the tenant list cannot be read.
    async fn execute(
        &self,
        (): &(),
        _auditor: &RequestAuditor,
        (): (),
    ) -> Result<PurgeReport, AppError> {
        let cutoff = kept_since(clock::now());
        let mut report = PurgeReport {
            removed: self.purged_platform(cutoff).await?,
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
    use ianua_domain::domains::notifications::notification::{
        KEPT_FOR, Notification, NotificationRow, ReadState,
    };
    use ianua_domain::domains::notifications::severity::NotificationSeverity;
    use ianua_domain::types::{OperatorId, UserId};
    use time::Duration;

    use super::*;
    use crate::test_support::notifications::{
        FakeOrgNotificationStore, FakePlatformNotificationStore, FakeTenantNotificationStore,
        user_registered,
    };
    use crate::test_support::tenant::{FakeTenantStore, test_tenant, test_tenant_for_ctx};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    /// A notification like `user_registered`, made `age` ago and read.
    fn made_ago(age: Duration) -> Notification {
        let fresh = user_registered(NotificationSeverity::Info);
        Notification::reconstitute(NotificationRow {
            id: fresh.id(),
            event_type: *fresh.event_type(),
            severity: fresh.severity(),
            title: fresh.title().clone(),
            body: fresh.body().cloned(),
            resource_id: fresh.resource_id(),
            reach: fresh.reach(),
            read: ReadState::Read,
            created_at: clock::now() - age,
        })
        .unwrap()
    }

    struct Inboxes {
        platform: Arc<FakePlatformNotificationStore>,
        tenant: Arc<FakeTenantNotificationStore>,
    }

    fn purge(inboxes: &Inboxes, tenants: Vec<Tenant>) -> PurgeReport {
        let use_case = PurgeOldUseCase::new(PurgeOldPorts {
            platform_store: inboxes.platform.clone(),
            org_store: Arc::new(FakeOrgNotificationStore::empty()),
            tenant_store: inboxes.tenant.clone(),
            tenants: Arc::new(FakeTenantStore::holding_all(tenants)),
        });
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        block_on(use_case.execute(&(), &auditor, ())).unwrap()
    }

    /// Purging an operator's inbox removes the notice past retention,
    /// reports one removal and preserves yesterday's notice.
    #[test]
    fn an_old_notice_goes_and_a_recent_one_stays() {
        let inboxes = Inboxes {
            platform: Arc::new(FakePlatformNotificationStore::empty()),
            tenant: Arc::new(FakeTenantNotificationStore::empty()),
        };
        let ann = OperatorId::new();
        let (old, recent) = (
            made_ago(KEPT_FOR + Duration::days(1)),
            made_ago(Duration::days(1)),
        );
        for notice in [&old, &recent] {
            block_on(inboxes.platform.save(&ann, notice)).unwrap();
        }

        let report = purge(&inboxes, Vec::new());

        let held = inboxes.platform.notifications.lock().unwrap();
        assert_eq!(report.removed, 1);
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].1.id(), recent.id());
    }

    /// Every tenant's inbox is purged, not only the first: an old notice in
    /// each of two tenants goes.
    #[test]
    fn every_tenants_inbox_is_purged() {
        let inboxes = Inboxes {
            platform: Arc::new(FakePlatformNotificationStore::empty()),
            tenant: Arc::new(FakeTenantNotificationStore::empty()),
        };
        let (acme, globex) = (
            test_tenant_for_ctx(),
            test_tenant("globex", "globex.example.com"),
        );
        for tenant in [&acme, &globex] {
            let scoped = ScopedTenant::for_background(*tenant.id());
            let old = made_ago(KEPT_FOR + Duration::days(1));
            block_on(inboxes.tenant.save(&scoped, &UserId::new(), &old)).unwrap();
        }

        let report = purge(&inboxes, vec![acme, globex]);

        assert_eq!(report.removed, 2);
        assert_eq!(report.unpurged, 0);
        assert!(inboxes.tenant.notifications.lock().unwrap().is_empty());
    }
}
