//! Change connector scope: replace the networks and domains a connector may
//! be asked to dial.

use std::sync::Arc;

use ianua_domain::domains::routing::connector::scope::ConnectorScope;
use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::domains::routing::service::Service;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ConnectorId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::routing::{ConnectorStore, ServiceStore};
use crate::use_case::Command;
use crate::use_cases::routing::connectors::lookup::{
    ensure_scope_permits, existing_connector, services_through,
};

/// A connector's new scope.
pub struct ChangeScopeRequest {
    /// The connector to change.
    pub connector_id: ConnectorId,
    /// The networks and domains it may be asked to dial from now on.
    pub scope: ConnectorScope,
}

/// The ports [`ChangeScopeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeScopePorts {
    /// Keeps the tenant's connectors.
    pub connector_store: Arc<dyn ConnectorStore>,
    /// The tenant's services, each reached through the connector staying
    /// inside its new scope.
    pub service_store: Arc<dyn ServiceStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes what a connector may dial.
pub struct ChangeScopeUseCase {
    ports: ChangeScopePorts,
}

impl ChangeScopeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ChangeScopePorts) -> Self {
        Self { ports }
    }
}

impl Command for ChangeScopeUseCase {
    type Caller = CallerContext;
    type Input = ChangeScopeRequest;
    type Output = Result<(), AppError>;

    /// Replaces the connector's scope and records
    /// `routing.connector_updated`.
    ///
    /// A narrower scope that leaves out a service still reached through the
    /// connector would cut that service off without a word, so it is
    /// refused until the service moves.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update routing.
    /// - `AppError::NotFound` if the connector doesn't exist.
    /// - `AppError::Domain` if the connector is revoked, or a service
    ///   reached through it falls outside the new scope.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: ChangeScopeRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let by = RoutingControl::new(&authority);
        by.ensure_may(RoutingRight::Update)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let store = self.ports.connector_store.as_ref();
        let mut connector = existing_connector(store, &tenant, &request.connector_id).await?;
        let reached =
            services_through(self.ports.service_store.as_ref(), &tenant, connector.id()).await?;
        ensure_all_permitted(&request.scope, &reached)?;
        connector
            .change_scope(request.scope, &by)
            .map_err(AppError::from_domain)?;
        store.save(&tenant, &connector).await.or_internal()?;
        auditor
            .dispatch_by(&caller.actor(), connector.take_events(&tenant))
            .await
            .or_internal()
    }
}

/// Refuses `scope` unless every service in `reached` stays inside it.
///
/// # Errors
///
/// `AppError::Domain` naming the first address left outside.
fn ensure_all_permitted(
    scope: &ConnectorScope,
    reached: &[Service<ResolvedTenant>],
) -> Result<(), AppError> {
    reached
        .iter()
        .try_for_each(|service| ensure_scope_permits(scope, service.upstream()))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};
    use ianua_domain::domains::routing::connector::PrivateConnector;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::routing::{
        FakeConnectorStore, FakeServiceStore, awaiting_connector, connector_scope, routing_admin,
        service_named, unpinned_upstream,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The stores, the audit record, the use case a test runs, and the
    /// payroll connector it holds.
    struct Fixture {
        connectors: Arc<FakeConnectorStore>,
        services: Arc<FakeServiceStore>,
        audit: Arc<FakeEventDispatcher>,
        use_case: ChangeScopeUseCase,
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
            use_case: ChangeScopeUseCase::new(ChangeScopePorts {
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

    /// The domains the connector may dial when a test starts.
    const START: [&str; 2] = ["*.payroll.corp.internal", "*.billing.corp.internal"];

    /// The payroll connector, allowed to dial the payroll and billing
    /// hosts.
    fn payroll() -> PrivateConnector<ResolvedTenant> {
        awaiting_connector("payroll", "enroll-code-a", &START)
    }

    /// A fixture holding the payroll connector, run by a routing admin.
    fn fixture() -> Fixture {
        fixture_holding(&payroll(), FakeTenantAuthorities::holding_everything())
    }

    /// Changes the connector's scope to `domains`.
    fn change(f: &Fixture, domains: &[&str]) -> Result<(), AppError> {
        block_on(f.use_case.execute(
            &test_ctx(),
            &test_auditor(f.audit.clone()),
            ChangeScopeRequest {
                connector_id: f.connector,
                scope: connector_scope(domains),
            },
        ))
    }

    /// The domains the stored connector may dial.
    fn stored_domains(f: &Fixture) -> Vec<String> {
        f.connectors
            .stored(test_ctx().tenant_id(), &f.connector)
            .unwrap()
            .scope()
            .domains()
            .iter()
            .map(|domain| domain.as_str().to_owned())
            .collect()
    }

    /// The payroll app at `app.payroll.corp.internal` is reached through
    /// the connector.
    fn with_payroll_app(f: &Fixture) {
        let upstream =
            unpinned_upstream("https://app.payroll.corp.internal").through_connector(f.connector);
        let service = service_named("payroll-app", upstream);
        block_on(f.services.save(&test_ctx().tenant(), &service)).unwrap();
    }

    /// Ann narrows the connector to the payroll domain, where the payroll
    /// app lives. It is saved and the change recorded.
    #[test]
    fn a_narrower_scope_that_keeps_every_service_is_saved() {
        let f = fixture();
        with_payroll_app(&f);

        change(&f, &["*.payroll.corp.internal"]).unwrap();

        assert_eq!(stored_domains(&f), ["*.payroll.corp.internal"]);
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["routing.connector_updated"]
        );
    }

    /// Narrowing a connector's scope to exclude a service using it is
    /// refused, preserving the saved scope and recording no update event.
    #[test]
    fn a_scope_leaving_out_a_reached_service_is_refused() {
        let f = fixture();
        with_payroll_app(&f);

        let result = change(&f, &["*.billing.corp.internal"]);

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert_eq!(stored_domains(&f), START);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Ann changes the scope of a revoked connector. It is refused.
    #[test]
    fn a_revoked_connectors_scope_is_not_changed() {
        let mut connector = payroll();
        connector.revoke(&routing_admin()).unwrap();
        let f = fixture_holding(&connector, FakeTenantAuthorities::holding_everything());

        let result = change(&f, &["*.payroll.corp.internal"]);

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Ann names a connector the tenant does not have. It is not found.
    #[test]
    fn an_unknown_connector_is_not_found() {
        let f = fixture();

        let result = block_on(f.use_case.execute(
            &test_ctx(),
            &test_auditor(f.audit.clone()),
            ChangeScopeRequest {
                connector_id: ConnectorId::new(),
                scope: connector_scope(&START),
            },
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A routing viewer cannot widen the connector's scope. The refusal
    /// preserves the saved domains and records no update event.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let f = fixture_holding(
            &payroll(),
            FakeTenantAuthorities::holding(&[SystemPermission::Routing(RoutingAction::View)]),
        );

        let result = change(&f, &["*.payroll.corp.internal", "dc.ad.internal"]);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(stored_domains(&f), START);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot change a connector's saved scope.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture_holding(
            &payroll(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = change(&f, &["dc.ad.internal"]);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(stored_domains(&f), START);
    }
}
