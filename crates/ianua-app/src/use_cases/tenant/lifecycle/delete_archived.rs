//! Delete archived tenants: the sweep that wipes each archived tenant once
//! its grace has passed, for the platform, and takes it off its
//! organization.
//!
//! Nobody asks for it: an archived tenant whose owner did not restore it in
//! time is deleted as the archive said it would be. The domain checks the
//! grace again, so a tenant restored or held meanwhile is left alone. Each
//! tenant is kept with its records in a unit of its own, so one that fails
//! is tried on the next round without stopping the others.

use std::num::NonZeroU32;
use std::sync::Arc;

use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActedBy, ActorRef};
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::organization::OrganizationStore;
use crate::ports::runtime::UnitOfWork;
use crate::ports::tenant::TenantStore;
use crate::services::kept_together::kept_together;
use crate::use_case::Command;

/// The ports [`DeleteArchivedUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeleteArchivedPorts {
    /// Finds archived workspaces eligible for deletion and persists the change.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Organizations, which lose the tenant.
    pub org_store: Arc<dyn OrganizationStore>,
    /// Keeps each deletion and its records together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Deletes the archived tenants whose grace has passed.
///
/// It runs as a sweep: no one calls it, so it takes no caller.
pub struct DeleteArchivedUseCase {
    ports: DeleteArchivedPorts,
    batch: NonZeroU32,
}

impl DeleteArchivedUseCase {
    /// A sweep over `ports`, deleting at most `batch` tenants a round.
    #[must_use]
    pub fn new(ports: DeleteArchivedPorts, batch: NonZeroU32) -> Self {
        Self { ports, batch }
    }

    /// Deletes `tenant`, takes it off its organization, and records both.
    async fn delete(&self, mut tenant: Tenant, auditor: &RequestAuditor) -> Result<(), AppError> {
        tenant
            .delete(ActedBy::Platform)
            .map_err(AppError::from_domain)?;
        let mut organization = self
            .ports
            .org_store
            .find_by_id(tenant.organization_id())
            .await
            .or_internal()?
            .or_not_found(message!(
                "authentication-organization-not-found",
                "organization not found"
            ))?;
        organization
            .remove_tenant(tenant.id(), ActedBy::Platform)
            .map_err(AppError::from_domain)?;
        self.ports.tenant_store.save(&tenant).await.or_internal()?;
        self.ports
            .org_store
            .save(&organization)
            .await
            .or_internal()?;
        auditor
            .with_tenant(*tenant.id())
            .dispatch_by(&ActorRef::System, tenant.take_events())
            .await
            .or_internal()
    }

    /// Deletes `tenant` in a unit of its own, and lets its organization's
    /// cached view go. A failure is logged, and the next round tries again.
    async fn delete_one(&self, tenant: Tenant, auditor: &RequestAuditor) -> u32 {
        let (id, organization) = (*tenant.id(), *tenant.organization_id());
        let unit = self.ports.unit_of_work.as_ref();
        if let Err(error) = kept_together(unit, self.delete(tenant, auditor)).await {
            tracing::warn!(tenant_id = %id, %error, "archived tenant not deleted");
            return 0;
        }
        if let Err(error) = self.ports.org_store.invalidate(&organization).await {
            tracing::warn!(%organization, %error, "organization view not refreshed");
        }
        1
    }
}

impl Command for DeleteArchivedUseCase {
    type Caller = ();
    type Input = OffsetDateTime;
    type Output = Result<u32, AppError>;

    /// Deletes, as of `now`, up to a batch of archived tenants whose grace
    /// has passed, each recorded by the system as `tenant.status_changed`
    /// and `tenant.deleted`, and returns how many it deleted.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the tenants due cannot be read. A tenant
    ///   that fails on its own is logged and left for the next round.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        now: OffsetDateTime,
    ) -> Result<u32, AppError> {
        let due = self
            .ports
            .tenant_store
            .list_past_grace(now, self.batch)
            .await
            .or_internal()?;
        let mut deleted = 0u32;
        for tenant in due {
            deleted = deleted.saturating_add(self.delete_one(tenant, auditor).await);
        }
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::status::{PlatformHold, TenantStatus};

    use super::*;
    use crate::test_support::organization::{org_store_with, test_org};
    use crate::test_support::tenant::{FakeTenantStore, archived_tenant_for_ctx};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Setup {
        uc: DeleteArchivedUseCase,
        tenants: Arc<FakeTenantStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    fn setup(tenant: Tenant) -> Setup {
        let tenants = Arc::new(FakeTenantStore::holding(tenant));
        let uc = DeleteArchivedUseCase::new(
            DeleteArchivedPorts {
                tenant_store: tenants.clone(),
                org_store: org_store_with([test_org(test_ctx().organization_id(), "acme")]),
                ..DeleteArchivedPorts::fakes()
            },
            NonZeroU32::new(10).unwrap(),
        );
        Setup {
            uc,
            tenants,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn sweep(setup: &Setup) -> u32 {
        block_on(setup.uc.execute(
            &(),
            &test_auditor(setup.audit.clone()),
            ianua_domain::shared::clock::now(),
        ))
        .unwrap()
    }

    /// Acme archived its tenant forty days ago and never restored it. The
    /// sweep deletes it, by the system, and says so.
    #[test]
    fn an_archived_tenant_past_its_grace_is_deleted() {
        let setup = setup(archived_tenant_for_ctx(40, PlatformHold::Free));

        let deleted = sweep(&setup);

        assert_eq!(deleted, 1);
        let stored = setup.tenants.tenants.lock().unwrap()[0].clone();
        assert_eq!(stored.status(), TenantStatus::Deleted);
        assert!(
            setup
                .audit
                .records
                .lock()
                .unwrap()
                .contains(&"tenant.deleted".to_owned())
        );
    }

    /// Acme archived its tenant yesterday. Its grace still runs, so the
    /// sweep leaves it archived.
    #[test]
    fn an_archived_tenant_within_its_grace_is_kept() {
        let setup = setup(archived_tenant_for_ctx(1, PlatformHold::Free));

        assert_eq!(sweep(&setup), 0);
        let stored = setup.tenants.tenants.lock().unwrap()[0].clone();
        assert_eq!(stored.status(), TenantStatus::Archived);
    }
}
