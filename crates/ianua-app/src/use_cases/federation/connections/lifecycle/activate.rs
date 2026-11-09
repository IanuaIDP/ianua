//! Activate connection: turn a disabled federation connection back on.

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

/// The ports [`ActivateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ActivatePorts {
    /// Loads and saves connections.
    pub connection_store: Arc<dyn ConnectionStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Turns a disabled federation connection back on.
pub struct ActivateUseCase {
    ports: ActivatePorts,
}

impl ActivateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ActivatePorts) -> Self {
        Self { ports }
    }
}

impl Command for ActivateUseCase {
    type Caller = CallerContext;
    type Input = ConnectionId;
    type Output = Result<(), AppError>;

    /// Turns the connection back on and records
    /// `federation.connection_activated`. It was off for a reason, so this
    /// needs the full federation right.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not manage federation.
    /// - `AppError::NotFound` if the connection doesn't exist.
    /// - `AppError::Domain` if the connection is already active.
    /// - `AppError::Internal` on audit or persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        connection_id: ConnectionId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = FederationControl::new(&authority);
        control
            .ensure_may(FederationRight::TrustConnection)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let mut conn = existing_connection(
            self.ports.connection_store.as_ref(),
            &tenant,
            &connection_id,
        )
        .await?;
        conn.activate(&control).map_err(AppError::from_domain)?;

        self.ports
            .connection_store
            .save(&tenant, &conn)
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
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, block_on, test_auditor, test_ctx,
    };

    fn store_holding(status: ConnectionStatus) -> (Arc<FakeConnectionStore>, ConnectionId) {
        let id = ConnectionId::new();
        let store =
            FakeConnectionStore::holding(&test_ctx().tenant(), [test_connection(id, status)]);
        (Arc::new(store), id)
    }

    fn use_case(
        store: Arc<FakeConnectionStore>,
        authorities: FakeTenantAuthorities,
    ) -> ActivateUseCase {
        ActivateUseCase::new(ActivatePorts {
            connection_store: store,
            tenant_authorities: Arc::new(authorities),
        })
    }

    fn activate(
        use_case: &ActivateUseCase,
        audit: Arc<FakeEventDispatcher>,
        id: ConnectionId,
    ) -> Result<(), AppError> {
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit), id))
    }

    fn saved_status(store: &FakeConnectionStore, id: ConnectionId) -> ConnectionStatus {
        block_on(store.find_by_id(&test_ctx().tenant(), &id))
            .unwrap()
            .unwrap()
            .status()
    }

    /// Fay manages federation. She turns Acme's Okta back on after an
    /// incident, and the change is recorded.
    #[test]
    fn a_disabled_connection_is_turned_back_on_and_recorded() {
        let (store, id) = store_holding(ConnectionStatus::Disabled);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding_everything());

        activate(&use_case, audit.clone(), id).unwrap();

        assert_eq!(saved_status(&store, id), ConnectionStatus::Active);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["federation.connection_activated"]
        );
    }

    /// The record of turning it back on cannot be written. The change fails
    /// rather than go unrecorded.
    #[test]
    fn activating_fails_when_its_record_cannot_be_written() {
        let (store, id) = store_holding(ConnectionStatus::Disabled);
        let use_case = use_case(store, FakeTenantAuthorities::holding_everything());

        let result = block_on(use_case.execute(
            &test_ctx(),
            &test_auditor(Arc::new(FailingEventDispatcher)),
            id,
        ));

        assert!(matches!(result, Err(AppError::Internal(_))));
    }

    /// Fay turns on a connection that is already on. She is told it is in
    /// the wrong state.
    #[test]
    fn an_active_connection_cannot_be_activated() {
        let (store, id) = store_holding(ConnectionStatus::Active);
        let use_case = use_case(store, FakeTenantAuthorities::holding_everything());

        let result = activate(&use_case, Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Fay names a connection her tenant does not have. It is not found and
    /// nothing is recorded.
    #[test]
    fn an_unknown_connection_is_not_found() {
        let store = Arc::new(FakeConnectionStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store, FakeTenantAuthorities::holding_everything());

        let result = activate(&use_case, audit.clone(), ConnectionId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// The update right does not permit activating a connection. The
    /// permission refusal leaves the connection disabled.
    #[test]
    fn the_update_right_does_not_turn_a_connection_back_on() {
        let (store, id) = store_holding(ConnectionStatus::Disabled);
        let update = [SystemPermission::Federation(FederationAction::Update)];
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding(&update));

        let result = activate(&use_case, Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(saved_status(&store, id), ConnectionStatus::Disabled);
    }

    /// A caller without tenant rights cannot activate a disabled connection.
    #[test]
    fn a_caller_without_the_right_is_refused() {
        let (store, id) = store_holding(ConnectionStatus::Disabled);
        let use_case = use_case(store, FakeTenantAuthorities::holding(&[]));

        let result = activate(&use_case, Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A caller without federation management rights receives a permission
    /// refusal even when the connection to activate does not exist.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_connection() {
        let store = Arc::new(FakeConnectionStore::empty());
        let use_case = use_case(store, FakeTenantAuthorities::holding(&[]));

        let result = activate(
            &use_case,
            Arc::new(FakeEventDispatcher::new()),
            ConnectionId::new(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot activate a federation connection.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = store_holding(ConnectionStatus::Disabled);
        let use_case = use_case(store, FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = activate(&use_case, Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
