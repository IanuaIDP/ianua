//! Delete connector: remove a revoked connector no service is reached
//! through any more.

use std::sync::Arc;

use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ConnectorId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::routing::{ConnectorStore, ServiceStore};
use crate::use_case::Command;
use crate::use_cases::routing::connectors::lookup::{existing_connector, services_through};

/// The ports [`DeleteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeletePorts {
    /// Keeps the tenant's connectors.
    pub connector_store: Arc<dyn ConnectorStore>,
    /// The tenant's services, none of which may still be reached through
    /// the connector.
    pub service_store: Arc<dyn ServiceStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Deletes a connector.
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
    type Input = ConnectorId;
    type Output = Result<(), AppError>;

    /// Deletes the connector once the domain agrees it may go, and records
    /// `routing.connector_deleted`.
    ///
    /// A connector is revoked first, so its tunnel is closed before its
    /// record goes. A service still reached through it would point at
    /// nothing, so each is moved off first.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without routing-deletion rights.
    /// - `AppError::NotFound` for a missing connector; `Domain` for one not revoked; `Conflict` for one still serving a service.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        connector_id: ConnectorId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let by = RoutingControl::new(&authority);
        by.ensure_may(RoutingRight::Delete)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let store = self.ports.connector_store.as_ref();
        let mut connector = existing_connector(store, &tenant, &connector_id).await?;
        let reaching =
            services_through(self.ports.service_store.as_ref(), &tenant, &connector_id).await?;
        connector
            .delete(reaching.len(), &by)
            .map_err(AppError::from_domain)?;
        store.delete(&tenant, &connector_id).await.or_internal()?;
        auditor
            .dispatch_by(&caller.actor(), connector.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};
    use ianua_domain::domains::routing::connector::PrivateConnector;
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::routing::{
        FakeConnectorStore, FakeServiceStore, awaiting_connector, routing_admin, service_named,
        unpinned_upstream,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The stores, the audit record, the use case a test runs, and the
    /// payroll connector it holds.
    struct Fixture {
        connectors: Arc<FakeConnectorStore>,
        services: Arc<FakeServiceStore>,
        audit: Arc<FakeEventDispatcher>,
        use_case: DeleteUseCase,
        connector: ConnectorId,
    }

    /// A fixture holding `connector`, the caller holding what `authorities`
    /// says.
    fn fixture_holding(
        connector: &PrivateConnector<ResolvedTenant>,
        authorities: FakeTenantAuthorities,
    ) -> Fixture {
        let connectors = Arc::new(FakeConnectorStore::holding(
            test_ctx().tenant_id(),
            connector,
        ));
        let services = Arc::new(FakeServiceStore::empty());
        Fixture {
            use_case: DeleteUseCase::new(DeletePorts {
                connector_store: connectors.clone(),
                service_store: services.clone(),
                tenant_authorities: Arc::new(authorities),
            }),
            connectors,
            services,
            audit: Arc::new(FakeEventDispatcher::new()),
            connector: *connector.id(),
        }
    }

    /// The payroll connector, revoked.
    fn revoked() -> PrivateConnector<ResolvedTenant> {
        let mut connector =
            awaiting_connector("payroll", "enroll-code-a", &["payroll.corp.internal"]);
        connector.revoke(&routing_admin()).unwrap();
        connector
    }

    /// Deletes `id`.
    fn delete(f: &Fixture, id: ConnectorId) -> Result<(), AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), id),
        )
    }

    /// A service reached through the fixture's connector is saved.
    fn with_service_through(f: &Fixture) {
        let upstream =
            unpinned_upstream("https://payroll.corp.internal").through_connector(f.connector);
        let service = service_named("payroll-app", upstream);
        block_on(f.services.save(&test_ctx().tenant(), &service)).unwrap();
    }

    /// Ann deletes a revoked connector nothing uses. It is gone and the
    /// deletion recorded.
    #[test]
    fn a_revoked_unused_connector_is_deleted() {
        let f = fixture_holding(&revoked(), FakeTenantAuthorities::holding_everything());

        delete(&f, f.connector).unwrap();

        assert_eq!(f.connectors.count(), 0);
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["routing.connector_deleted"]
        );
    }

    /// An active connector awaiting enrollment cannot be deleted. It remains
    /// stored and no deletion event is recorded.
    #[test]
    fn an_active_connector_is_not_deleted() {
        let active = awaiting_connector("payroll", "enroll-code-a", &["payroll.corp.internal"]);
        let f = fixture_holding(&active, FakeTenantAuthorities::holding_everything());

        let result = delete(&f, f.connector);

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert_eq!(f.connectors.count(), 1);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Deleting a revoked connector still referenced by a service returns a
    /// conflict, preserves the connector and records no deletion event.
    #[test]
    fn a_connector_a_service_is_reached_through_is_not_deleted() {
        let f = fixture_holding(&revoked(), FakeTenantAuthorities::holding_everything());
        with_service_through(&f);

        let result = delete(&f, f.connector);

        assert!(matches!(result, Err(AppError::Conflict(_))), "{result:?}");
        assert_eq!(f.connectors.count(), 1);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Ann names a connector the tenant does not have. It is not found.
    #[test]
    fn an_unknown_connector_is_not_found() {
        let f = fixture_holding(&revoked(), FakeTenantAuthorities::holding_everything());

        let result = delete(&f, ConnectorId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// The routing update right does not permit deleting a revoked connector.
    /// The refusal preserves it and records no deletion event.
    #[test]
    fn a_caller_without_the_delete_right_is_refused() {
        let f = fixture_holding(
            &revoked(),
            FakeTenantAuthorities::holding(&[SystemPermission::Routing(RoutingAction::Update)]),
        );

        let result = delete(&f, f.connector);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.connectors.count(), 1);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot delete the stored connector.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture_holding(
            &revoked(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = delete(&f, f.connector);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(f.connectors.count(), 1);
    }
}
