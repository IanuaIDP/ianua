//! A fake store for tenant admins' support impersonations.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::identity::impersonation::state::{
    ImpersonationConsent, ImpersonationState, ImpersonationWindow,
};
use ianua_domain::domains::identity::impersonation::{
    SupportImpersonation, SupportImpersonationRow,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{SupportImpersonationId, Text, UserId};

use crate::acting::TenantAuthorities;
use crate::acting::tenant::{
    OperatorPorts, TenantActing, TenantActingPorts, TenantCredentialPorts,
};
use crate::ports::TenantScoped;
use crate::ports::identity::SupportImpersonationStore;
use crate::tenancy::ScopedTenant;
use crate::test_support::authentication::{FakeSessionStore, Plane, test_caller_id};
use crate::test_support::identity::FakeUserStore;
use crate::test_support::oauth::signed_in_session;
use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
use crate::test_support::{Fake, test_session_id};

/// In-memory support impersonations, kept as rows in their tenant.
#[derive(Default)]
pub struct FakeSupportImpersonationStore {
    rows: Mutex<Vec<(Plane, SupportImpersonationRow)>>,
}

impl FakeSupportImpersonationStore {
    /// None held.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Holds `impersonation` in the test tenant.
    #[must_use]
    pub fn holding(impersonation: &SupportImpersonation<ResolvedTenant>) -> Self {
        let store = Self::default();
        store.put(Plane::test_tenant(), impersonation);
        store
    }

    /// The impersonation with `id` in the test tenant, as last saved.
    #[must_use]
    pub fn stored(
        &self,
        id: &SupportImpersonationId,
    ) -> Option<SupportImpersonation<ResolvedTenant>> {
        self.found(Plane::test_tenant(), id)
    }

    /// The impersonation with `id` held on `plane`.
    fn found(
        &self,
        plane: Plane,
        id: &SupportImpersonationId,
    ) -> Option<SupportImpersonation<ResolvedTenant>> {
        self.matching(plane, |row| row.id == *id).into_iter().next()
    }

    /// How many are held, across tenants.
    #[must_use]
    pub fn count(&self) -> usize {
        self.rows.lock().unwrap().len()
    }

    fn put(&self, plane: Plane, impersonation: &SupportImpersonation<ResolvedTenant>) {
        let mut rows = self.rows.lock().unwrap();
        rows.retain(|(held_on, row)| !(*held_on == plane && row.id == *impersonation.id()));
        rows.push((plane, row_of(impersonation)));
    }

    fn matching(
        &self,
        plane: Plane,
        keep: impl Fn(&SupportImpersonationRow) -> bool,
    ) -> Vec<SupportImpersonation<ResolvedTenant>> {
        let mut found: Vec<_> = self
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|(held_on, row)| *held_on == plane && keep(row))
            .map(|(_, row)| {
                SupportImpersonation::reconstitute(copy_row(row)).expect("a kept row rebuilds")
            })
            .collect();
        found.reverse();
        found
    }
}

/// `admin`'s request, made just now, to act as `user_id` for half an hour,
/// waiting for them to approve.
#[must_use]
pub fn impersonation_asked(admin: UserId, user_id: UserId) -> SupportImpersonation<ResolvedTenant> {
    impersonation_in(admin, user_id, ImpersonationState::AwaitingConsent)
}

/// `admin`'s request to act as `user_id` for half an hour, approved just
/// now, so its window is open.
#[must_use]
pub fn impersonation_active(
    admin: UserId,
    user_id: UserId,
) -> SupportImpersonation<ResolvedTenant> {
    let since = clock::now();
    impersonation_in(admin, user_id, ImpersonationState::Active { since })
}

/// `admin`'s request to act as `user_id`, standing at `state`.
///
/// # Panics
///
/// Panics if `admin` is `user_id`, which no test passes.
fn impersonation_in(
    admin: UserId,
    user_id: UserId,
    state: ImpersonationState,
) -> SupportImpersonation<ResolvedTenant> {
    SupportImpersonation::reconstitute(SupportImpersonationRow {
        id: SupportImpersonationId::new(),
        admin,
        user_id,
        reason: Text::new("reason", "the billing page is blank").expect("a valid reason"),
        window: ImpersonationWindow::minutes(30).expect("half an hour is a window"),
        consent: ImpersonationConsent::HolderApproves,
        state,
        requested_at: clock::now() - time::Duration::minutes(1),
    })
    .expect("a consistent impersonation row")
}

/// The row storage would keep for `impersonation`.
fn row_of(impersonation: &SupportImpersonation<ResolvedTenant>) -> SupportImpersonationRow {
    SupportImpersonationRow {
        id: *impersonation.id(),
        admin: *impersonation.admin(),
        user_id: *impersonation.user_id(),
        reason: impersonation.reason().clone(),
        window: impersonation.window(),
        consent: impersonation.consent(),
        state: impersonation.state(),
        requested_at: impersonation.requested_at(),
    }
}

/// A copy of `row`, which does not implement `Clone`.
fn copy_row(row: &SupportImpersonationRow) -> SupportImpersonationRow {
    SupportImpersonationRow {
        id: row.id,
        admin: row.admin,
        user_id: row.user_id,
        reason: row.reason.clone(),
        window: row.window,
        consent: row.consent,
        state: row.state,
        requested_at: row.requested_at,
    }
}

impl TenantScoped for FakeSupportImpersonationStore {}

#[async_trait]
impl SupportImpersonationStore for FakeSupportImpersonationStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        impersonation: &SupportImpersonation<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.put(Plane::of(tenant_id), impersonation);
        Ok(())
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &SupportImpersonationId,
    ) -> Result<Option<SupportImpersonation<ResolvedTenant>>, DomainError> {
        Ok(self.found(Plane::of(tenant_id), id))
    }

    async fn list_involving(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<SupportImpersonation<ResolvedTenant>>, DomainError> {
        Ok(self.matching(Plane::of(tenant_id), |row| {
            row.admin == *user_id || row.user_id == *user_id
        }))
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<SupportImpersonation<ResolvedTenant>>, DomainError> {
        Ok(self.matching(Plane::of(tenant_id), |_| true))
    }
}

impl Fake for Arc<dyn SupportImpersonationStore> {
    fn fake() -> Self {
        Arc::new(FakeSupportImpersonationStore::empty())
    }
}

/// The real `acting` over the test tenant, where the test caller is signed
/// in with the test session and `other` is an active user too, reading
/// support impersonations from `store`.
#[must_use]
pub fn support_acting_over(
    store: Arc<FakeSupportImpersonationStore>,
    other: UserId,
) -> Arc<dyn TenantAuthorities> {
    let users = FakeUserStore::with_user(test_caller_id(), "caller@acme.test");
    users.add_active_user(other, "other@acme.test");
    let session = signed_in_session(test_session_id(), test_caller_id());
    Arc::new(TenantActing::new(TenantActingPorts {
        tenants: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
        tenant: TenantCredentialPorts {
            users: Arc::new(users),
            sessions: Arc::new(FakeSessionStore::with_session(session)),
            ..TenantCredentialPorts::fakes()
        },
        operators: OperatorPorts {
            support_impersonations: store,
            ..OperatorPorts::fakes()
        },
        ..TenantActingPorts::fakes()
    }))
}
