//! The background sweep that marks device requests nobody answered in time
//! expired.

use std::sync::Arc;

use ianua_domain::domains::oauth::grants::device_authorization::DeviceAuthorization;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::oauth::DeviceAuthStore;
use crate::ports::tenant::TenantStore;
use crate::services::tenant_batches::TenantBatches;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The ports [`ExpireDeviceAuthorizationsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ExpireDeviceAuthorizationsPorts {
    /// Where device requests are kept, in each tenant.
    pub device_auth_store: Arc<dyn DeviceAuthStore>,
    /// Walks every tenant in bounded pages before reading its routed requests.
    pub tenant_store: Arc<dyn TenantStore>,
}

/// Marks every device request that ran out unanswered expired.
///
/// It runs as a periodic job of the platform, with nobody asking. A poll
/// already reads a lapsed request as expired; the sweep makes the stored
/// state say so too, so nobody can answer it later and storage can let it
/// go. Nothing happened to anyone, so nothing is recorded.
pub struct ExpireDeviceAuthorizationsUseCase {
    ports: ExpireDeviceAuthorizationsPorts,
}

impl ExpireDeviceAuthorizationsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ExpireDeviceAuthorizationsPorts) -> Self {
        Self { ports }
    }

    /// Drains one tenant through its current route, stopping on the first
    /// read or save failure so the rest wait for the next sweep.
    async fn expire_in(
        &self,
        tenant: &ScopedTenant,
        now: OffsetDateTime,
    ) -> Result<usize, AppError> {
        let mut count = 0usize;
        loop {
            let lapsed = self
                .ports
                .device_auth_store
                .list_lapsed(tenant, now)
                .await
                .or_internal()?;
            if lapsed.is_empty() {
                return Ok(count);
            }
            for auth in lapsed {
                self.expire(tenant, auth).await.or_internal()?;
                count = count.saturating_add(1);
            }
        }
    }

    /// Marks `auth` expired and saves it through the tenant's current route.
    async fn expire(
        &self,
        tenant: &ScopedTenant,
        mut auth: DeviceAuthorization<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        auth.expire()?;
        self.ports.device_auth_store.save(tenant, &auth).await
    }
}

impl Command for ExpireDeviceAuthorizationsUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<usize, AppError>;

    /// Marks every pending request past its expiry expired, each in its own
    /// tenant. Returns how many it marked.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the lapsed requests cannot be listed or
    ///   one cannot be saved. The rest wait for the next sweep.
    async fn execute(&self, (): &(), _: &RequestAuditor, (): ()) -> Result<usize, AppError> {
        let now = clock::now();
        let mut count = 0usize;
        let mut tenants = TenantBatches::over(self.ports.tenant_store.as_ref());
        while let Some(ids) = tenants.next_ids().await? {
            for id in ids {
                let tenant = ScopedTenant::for_background(id);
                count = count.saturating_add(self.expire_in(&tenant, now).await?);
            }
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::client::GrantType;
    use ianua_domain::domains::oauth::grants::device_auth_status::DeviceAuthStatus;
    use ianua_domain::domains::oauth::grants::device_authorization::{
        DeviceAuthRow, DeviceAuthState,
    };
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::types::{DeviceUserCode, TokenHash};
    use time::Duration;

    use super::*;
    use crate::test_support::oauth::{
        FakeDeviceAuthStore, TEST_USER_CODE, device_row, stored_client,
    };
    use crate::test_support::tenant::{FakeTenantStore, test_tenant, test_tenant_for_ctx};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A pending request in the registered test tenant, adjusted for the
    /// expiry or answer state the test exercises.
    fn store_with(edit: impl FnOnce(&mut DeviceAuthRow)) -> Arc<FakeDeviceAuthStore> {
        let tv = stored_client("TV", &[GrantType::DeviceCode]);
        let mut row = device_row(&tv, DeviceAuthState::Pending);
        edit(&mut row);
        let store = Arc::new(FakeDeviceAuthStore::empty());
        let auth = DeviceAuthorization::reconstitute(row).unwrap();
        block_on(store.save(&test_ctx().tenant(), &auth)).unwrap();
        store
    }

    /// Places the request entirely before the current clock so expiry is due.
    fn lapsed(row: &mut DeviceAuthRow) {
        row.created_at = clock::now() - Duration::minutes(20);
        row.expires_at = clock::now() - Duration::minutes(10);
    }

    /// Runs the complete tenant traversal over the test tenant's requests.
    fn sweep(store: Arc<FakeDeviceAuthStore>) -> usize {
        let use_case = ExpireDeviceAuthorizationsUseCase::new(ExpireDeviceAuthorizationsPorts {
            device_auth_store: store,
            tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
        });
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        block_on(use_case.execute(&(), &auditor, ())).unwrap()
    }

    /// Reads the original request after expiry to verify its persisted state.
    fn status(store: &FakeDeviceAuthStore) -> DeviceAuthStatus {
        let code = DeviceUserCode::new(TEST_USER_CODE).unwrap();
        block_on(store.find_by_user_code(&test_ctx().tenant(), &code))
            .unwrap()
            .unwrap()
            .status()
    }

    /// Ann's TV asked to sign in ten minutes past its window and nobody
    /// answered. The sweep marks the request expired.
    #[test]
    fn an_unanswered_request_past_its_window_is_expired() {
        let store = store_with(lapsed);

        let expired = sweep(store.clone());

        assert_eq!(expired, 1);
        assert_eq!(status(&store), DeviceAuthStatus::Expired);
    }

    /// The sweep reads each tenant through its route, so an unrelated tenant's
    /// stored requests never become a prefix scanned before this tenant's work.
    #[test]
    fn device_expiry_reads_through_the_tenants_scope() {
        let store = store_with(lapsed);

        assert_eq!(sweep(store.clone()), 1);

        assert_eq!(
            store.lapsed_scopes(),
            [Some(test_ctx().tenant_id()), Some(test_ctx().tenant_id())]
        );
    }

    /// More tenants than one registry page are visited once, including empty
    /// tenants, and expiry consumes each routed request without audit events.
    #[test]
    fn device_expiry_walks_every_tenant_page_and_keeps_empty_tenants() {
        let store = Arc::new(FakeDeviceAuthStore::empty());
        let tenants: Vec<_> = (0..503)
            .map(|n| test_tenant(&format!("tenant-{n}"), &format!("tenant-{n}.example.test")))
            .collect();
        let mut expected: Vec<_> = tenants.iter().map(|tenant| *tenant.id()).collect();
        expected.sort_by_key(|id| *id.as_uuid());
        seed_lapsed_requests(&store, &tenants[..501]);
        let use_case = ExpireDeviceAuthorizationsUseCase::new(ExpireDeviceAuthorizationsPorts {
            device_auth_store: store.clone(),
            tenant_store: Arc::new(FakeTenantStore::holding_all(tenants)),
        });
        let events = Arc::new(FakeEventDispatcher::new());
        let auditor = test_auditor(events.clone());

        assert_eq!(block_on(use_case.execute(&(), &auditor, ())).unwrap(), 501);

        let mut seen: Vec<_> = store
            .lapsed_scopes()
            .into_iter()
            .map(Option::unwrap)
            .collect();
        assert_eq!(seen.len(), 1004);
        seen.dedup();
        assert_eq!(seen, expected);
        assert!(store.lapsed_batch_sizes().into_iter().all(|size| size <= 1));
        assert!(events.records.lock().unwrap().is_empty());
        assert_eq!(block_on(use_case.execute(&(), &auditor, ())).unwrap(), 0);
    }

    /// Each supplied tenant has one pending request whose expiry is already due.
    fn seed_lapsed_requests(store: &FakeDeviceAuthStore, tenants: &[Tenant]) {
        let tv = stored_client("TV", &[GrantType::DeviceCode]);
        for tenant in tenants {
            let mut row = device_row(&tv, DeviceAuthState::Pending);
            lapsed(&mut row);
            let request = DeviceAuthorization::reconstitute(row).unwrap();
            block_on(store.save(&ScopedTenant::for_background(*tenant.id()), &request)).unwrap();
        }
    }

    /// An expiry save failure returns an internal error after one batch,
    /// preserving the pending request and recording no activity.
    #[test]
    fn a_device_expiry_save_failure_stops_the_sweep_without_recording_activity() {
        let store = store_with(lapsed);
        store.refuse_saves();
        let use_case = ExpireDeviceAuthorizationsUseCase::new(ExpireDeviceAuthorizationsPorts {
            device_auth_store: store.clone(),
            tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
        });
        let events = Arc::new(FakeEventDispatcher::new());
        let auditor = test_auditor(events.clone());

        let result = block_on(use_case.execute(&(), &auditor, ()));

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert_eq!(store.lapsed_batch_sizes(), [1]);
        assert_eq!(status(&store), DeviceAuthStatus::Pending);
        assert!(events.records.lock().unwrap().is_empty());
    }

    /// More than one batch of device requests expired. Every request closes,
    /// while each read stays bounded and the next sweep has nothing to repeat.
    #[test]
    fn device_expiry_reads_bounded_batches_until_all_requests_are_closed() {
        let store = Arc::new(FakeDeviceAuthStore::empty());
        let tv = stored_client("TV", &[GrantType::DeviceCode]);
        for number in 0..501 {
            let mut row = device_row(&tv, DeviceAuthState::Pending);
            row.device_code_hash = TokenHash::from_stored(format!("device-{number}"));
            row.user_code = DeviceUserCode::new(format!("CODE-{number:04}")).unwrap();
            lapsed(&mut row);
            let auth = DeviceAuthorization::reconstitute(row).unwrap();
            block_on(store.save(&test_ctx().tenant(), &auth)).unwrap();
        }

        assert_eq!(sweep(store.clone()), 501);
        let first = block_on(store.find_by_user_code(
            &test_ctx().tenant(),
            &DeviceUserCode::new("CODE-0000").unwrap(),
        ))
        .unwrap()
        .unwrap();
        assert_eq!(first.status(), DeviceAuthStatus::Expired);
        assert_eq!(store.lapsed_batch_sizes(), [500, 1, 0]);
        assert_eq!(sweep(store.clone()), 0);
    }

    /// Ann's TV asked a minute ago. The sweep leaves the request waiting
    /// for her.
    #[test]
    fn a_request_still_in_its_window_keeps_waiting() {
        let store = store_with(|_| {});

        let expired = sweep(store.clone());

        assert_eq!(expired, 0);
        assert_eq!(status(&store), DeviceAuthStatus::Pending);
    }

    /// Ann denied her TV's request before it ran out. The sweep leaves her
    /// answer as it is.
    #[test]
    fn an_answered_request_is_left_as_answered() {
        let store = store_with(|row| {
            lapsed(row);
            row.state = DeviceAuthState::Denied;
        });

        let expired = sweep(store.clone());

        assert_eq!(expired, 0);
        assert_eq!(status(&store), DeviceAuthStatus::Denied);
    }
}
