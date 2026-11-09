//! Delete connection: remove a federation connection for good.

use std::sync::Arc;

use ianua_domain::domains::federation::control::{FederationControl, FederationRight};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ConnectionId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::federation::ConnectionStore;
use crate::use_case::Command;
use crate::use_cases::federation::lookup::existing_connection;

/// The ports [`DeleteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeletePorts {
    /// Loads and deletes connections.
    pub connection_store: Arc<dyn ConnectionStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Deletes a federation connection for good.
pub struct DeleteUseCase {
    ports: DeletePorts,
}

impl DeleteUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DeletePorts) -> Self {
        Self { ports }
    }
}

impl Command for DeleteUseCase {
    type Caller = CallerContext;
    type Input = ConnectionId;
    type Output = Result<(), AppError>;

    /// Deletes a disabled connection, with every link to it, and records
    /// `federation.connection_deleted`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not delete connections, or
    ///   the connection is still active and must be disabled first.
    /// - `AppError::NotFound` if the connection doesn't exist.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        connection_id: ConnectionId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = FederationControl::new(&authority);
        control
            .ensure_may(FederationRight::DeleteConnection)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let mut conn = existing_connection(
            self.ports.connection_store.as_ref(),
            &tenant,
            &connection_id,
        )
        .await?;
        conn.delete(&control).map_err(AppError::from_domain)?;

        self.ports
            .connection_store
            .delete(&tenant, &connection_id)
            .await
            .or_internal()?;

        auditor
            .dispatch_by(&ctx.actor(), conn.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{FederationAction, SystemPermission};
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::federation::{FakeConnectionStore, test_connection};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn store_holding(status: ConnectionStatus) -> (Arc<FakeConnectionStore>, ConnectionId) {
        let id = ConnectionId::new();
        let store =
            FakeConnectionStore::holding(&test_ctx().tenant(), [test_connection(id, status)]);
        (Arc::new(store), id)
    }

    fn use_case(
        store: Arc<FakeConnectionStore>,
        authorities: FakeTenantAuthorities,
    ) -> DeleteUseCase {
        DeleteUseCase::new(DeletePorts {
            connection_store: store,
            tenant_authorities: Arc::new(authorities),
        })
    }

    fn delete(
        use_case: &DeleteUseCase,
        audit: Arc<FakeEventDispatcher>,
        id: ConnectionId,
    ) -> Result<(), AppError> {
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit), id))
    }

    /// Fay deletes the Okta connection she switched off. It is gone and the
    /// deletion is recorded.
    #[test]
    fn a_disabled_connection_is_deleted_and_recorded() {
        let (store, id) = store_holding(ConnectionStatus::Disabled);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding_everything());

        delete(&use_case, audit.clone(), id).unwrap();

        assert_eq!(store.count(), 0);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["federation.connection_deleted"]
        );
    }

    /// Deleting an active connection is forbidden and leaves it stored.
    #[test]
    fn an_active_connection_is_not_deleted() {
        let (store, id) = store_holding(ConnectionStatus::Active);
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding_everything());

        let result = delete(&use_case, Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 1);
    }

    /// Fay names a connection her tenant does not have. It is not found and
    /// nothing is recorded.
    #[test]
    fn an_unknown_connection_is_not_found() {
        let store = Arc::new(FakeConnectionStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store, FakeTenantAuthorities::holding_everything());

        let result = delete(&use_case, audit.clone(), ConnectionId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// The update right does not permit deleting a disabled connection.
    /// The refusal leaves the connection stored.
    #[test]
    fn the_update_right_does_not_delete() {
        let (store, id) = store_holding(ConnectionStatus::Disabled);
        let update = [SystemPermission::Federation(FederationAction::Update)];
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding(&update));

        let result = delete(&use_case, Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 1);
    }

    /// Deleting a connection without tenant rights is forbidden and leaves
    /// the connection stored.
    #[test]
    fn a_caller_without_the_right_is_refused() {
        let (store, id) = store_holding(ConnectionStatus::Disabled);
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding(&[]));

        let result = delete(&use_case, Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 1);
    }

    /// A caller without the deletion right receives a permission refusal
    /// even when the requested connection does not exist.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_connection() {
        let store = Arc::new(FakeConnectionStore::empty());
        let use_case = use_case(store, FakeTenantAuthorities::holding(&[]));

        let result = delete(
            &use_case,
            Arc::new(FakeEventDispatcher::new()),
            ConnectionId::new(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot delete the stored connection.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = store_holding(ConnectionStatus::Disabled);
        let use_case = use_case(
            store.clone(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = delete(&use_case, Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(store.count(), 1);
    }
}
