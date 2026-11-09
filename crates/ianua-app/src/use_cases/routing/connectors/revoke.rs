//! Revoke connector: refuse a connector's tunnel for good, say when its
//! certificate may have leaked.

use std::sync::Arc;

use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ConnectorId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::routing::ConnectorStore;
use crate::use_case::Command;
use crate::use_cases::routing::connectors::lookup::existing_connector;

/// The ports [`RevokeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokePorts {
    /// Keeps the tenant's connectors.
    pub connector_store: Arc<dyn ConnectorStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Revokes a connector.
pub struct RevokeUseCase {
    ports: RevokePorts,
}

impl RevokeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RevokePorts) -> Self {
        Self { ports }
    }
}

impl Command for RevokeUseCase {
    type Caller = CallerContext;
    type Input = ConnectorId;
    type Output = Result<(), AppError>;

    /// Revokes the connector and records `routing.connector_revoked`. The
    /// gateway closes its tunnel and every service reached through it is
    /// unreachable until moved to another connector.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update routing.
    /// - `AppError::NotFound` if the connector doesn't exist.
    /// - `AppError::Domain` if it is already revoked.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        connector_id: ConnectorId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let by = RoutingControl::new(&authority);
        by.ensure_may(RoutingRight::Update)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let store = self.ports.connector_store.as_ref();
        let mut connector = existing_connector(store, &tenant, &connector_id).await?;
        connector.revoke(&by).map_err(AppError::from_domain)?;
        store.save(&tenant, &connector).await.or_internal()?;
        auditor
            .dispatch_by(&caller.actor(), connector.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};
    use ianua_domain::domains::routing::connector::{ConnectorStatus, PrivateConnector};
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::routing::{FakeConnectorStore, awaiting_connector};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The store, the audit record, the use case a test runs, and the
    /// payroll connector it holds.
    struct Fixture {
        connectors: Arc<FakeConnectorStore>,
        audit: Arc<FakeEventDispatcher>,
        use_case: RevokeUseCase,
        connector: ConnectorId,
    }

    /// A fixture holding the payroll connector, the caller holding what
    /// `authorities` says.
    fn fixture(authorities: FakeTenantAuthorities) -> Fixture {
        let connector = payroll();
        let connectors = Arc::new(FakeConnectorStore::holding(
            test_ctx().tenant_id(),
            &connector,
        ));
        Fixture {
            use_case: RevokeUseCase::new(RevokePorts {
                connector_store: connectors.clone(),
                tenant_authorities: Arc::new(authorities),
            }),
            connectors,
            audit: Arc::new(FakeEventDispatcher::new()),
            connector: *connector.id(),
        }
    }

    /// The payroll connector, awaiting its code.
    fn payroll() -> PrivateConnector<ResolvedTenant> {
        awaiting_connector("payroll", "enroll-code-a", &["payroll.corp.internal"])
    }

    /// Revokes `id`.
    fn revoke(f: &Fixture, id: ConnectorId) -> Result<(), AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), id),
        )
    }

    /// The stored connector's status.
    fn status(f: &Fixture) -> ConnectorStatus {
        f.connectors
            .stored(test_ctx().tenant_id(), &f.connector)
            .unwrap()
            .status()
    }

    /// Ann fears the payroll agent's certificate leaked and revokes the
    /// connector. It is revoked and the revocation recorded.
    #[test]
    fn a_connector_is_revoked_and_recorded() {
        let f = fixture(FakeTenantAuthorities::holding_everything());

        revoke(&f, f.connector).unwrap();

        assert_eq!(status(&f), ConnectorStatus::Revoked);
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["routing.connector_revoked"]
        );
    }

    /// Ann revokes it a second time. It is refused, and recorded once.
    #[test]
    fn a_revoked_connector_is_not_revoked_again() {
        let f = fixture(FakeTenantAuthorities::holding_everything());
        revoke(&f, f.connector).unwrap();

        let again = revoke(&f, f.connector);

        assert!(again.is_err());
        assert_eq!(f.audit.records.lock().unwrap().len(), 1);
    }

    /// Ann names a connector the tenant does not have. It is not found.
    #[test]
    fn an_unknown_connector_is_not_found() {
        let f = fixture(FakeTenantAuthorities::holding_everything());

        let result = revoke(&f, ConnectorId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A routing viewer cannot revoke a connector. The refusal leaves it
    /// active and records no revocation event.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let f = fixture(FakeTenantAuthorities::holding(&[
            SystemPermission::Routing(RoutingAction::View),
        ]));

        let result = revoke(&f, f.connector);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(status(&f), ConnectorStatus::Active);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot revoke a connector, which remains active.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = revoke(&f, f.connector);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(status(&f), ConnectorStatus::Active);
    }
}
