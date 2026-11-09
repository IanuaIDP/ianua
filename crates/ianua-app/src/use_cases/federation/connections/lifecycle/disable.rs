//! Disable connection: stop people signing in through a federation
//! connection.

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

/// The ports [`DisableUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DisablePorts {
    /// Loads and saves connections.
    pub connection_store: Arc<dyn ConnectionStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Switches a federation connection off.
pub struct DisableUseCase {
    ports: DisablePorts,
}

impl DisableUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DisablePorts) -> Self {
        Self { ports }
    }
}

impl Command for DisableUseCase {
    type Caller = CallerContext;
    type Input = ConnectionId;
    type Output = Result<(), AppError>;

    /// Switches the connection off and records
    /// `federation.connection_disabled`. It only stops the provider, so the
    /// update right is enough, and anyone who may edit a connection can stop
    /// it in an incident.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not update connections.
    /// - `AppError::NotFound` if the connection doesn't exist.
    /// - `AppError::Domain` if the connection is already disabled.
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
            .ensure_may(FederationRight::EditConnection)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let mut conn = existing_connection(
            self.ports.connection_store.as_ref(),
            &tenant,
            &connection_id,
        )
        .await?;
        conn.disable(&control).map_err(AppError::from_domain)?;

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
    ) -> DisableUseCase {
        DisableUseCase::new(DisablePorts {
            connection_store: store,
            tenant_authorities: Arc::new(authorities),
        })
    }

    fn disable(
        use_case: &DisableUseCase,
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

    /// Fay switches Acme's Okta off. It is saved disabled and the change is
    /// recorded.
    #[test]
    fn a_connection_is_switched_off_and_recorded() {
        let (store, id) = store_holding(ConnectionStatus::Active);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding_everything());

        disable(&use_case, audit.clone(), id).unwrap();

        assert_eq!(saved_status(&store, id), ConnectionStatus::Disabled);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["federation.connection_disabled"]
        );
    }

    /// Sam may update connections but not manage federation. In an incident
    /// he may still switch one off.
    #[test]
    fn the_update_right_switches_a_connection_off() {
        let (store, id) = store_holding(ConnectionStatus::Active);
        let update = [SystemPermission::Federation(FederationAction::Update)];
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding(&update));

        disable(&use_case, Arc::new(FakeEventDispatcher::new()), id).unwrap();

        assert_eq!(saved_status(&store, id), ConnectionStatus::Disabled);
    }

    /// The record of switching it off cannot be written. The change fails
    /// rather than go unrecorded.
    #[test]
    fn disabling_fails_when_its_record_cannot_be_written() {
        let (store, id) = store_holding(ConnectionStatus::Active);
        let use_case = use_case(store, FakeTenantAuthorities::holding_everything());

        let result = block_on(use_case.execute(
            &test_ctx(),
            &test_auditor(Arc::new(FailingEventDispatcher)),
            id,
        ));

        assert!(matches!(result, Err(AppError::Internal(_))));
    }

    /// Fay switches off a connection that is already off. She is told it is
    /// in the wrong state.
    #[test]
    fn a_disabled_connection_cannot_be_disabled_again() {
        let (store, id) = store_holding(ConnectionStatus::Disabled);
        let use_case = use_case(store, FakeTenantAuthorities::holding_everything());

        let result = disable(&use_case, Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Fay names a connection her tenant does not have. It is not found and
    /// nothing is recorded.
    #[test]
    fn an_unknown_connection_is_not_found() {
        let store = Arc::new(FakeConnectionStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store, FakeTenantAuthorities::holding_everything());

        let result = disable(&use_case, audit.clone(), ConnectionId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Disabling a connection without tenant rights is forbidden and leaves
    /// the connection active.
    #[test]
    fn a_caller_without_the_right_is_refused() {
        let (store, id) = store_holding(ConnectionStatus::Active);
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding(&[]));

        let result = disable(&use_case, Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(saved_status(&store, id), ConnectionStatus::Active);
    }

    /// A caller without the update right receives a permission refusal even
    /// when the connection to disable does not exist.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_connection() {
        let store = Arc::new(FakeConnectionStore::empty());
        let use_case = use_case(store, FakeTenantAuthorities::holding(&[]));

        let result = disable(
            &use_case,
            Arc::new(FakeEventDispatcher::new()),
            ConnectionId::new(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot disable a federation connection.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = store_holding(ConnectionStatus::Active);
        let use_case = use_case(store, FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = disable(&use_case, Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
