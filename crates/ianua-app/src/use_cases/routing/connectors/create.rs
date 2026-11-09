//! Create connector: add an agent inside the tenant's network, and hand out
//! the one-time code it enrolls with.

use std::sync::Arc;

use ianua_domain::domains::routing::connector::scope::ConnectorScope;
use ianua_domain::domains::routing::connector::{
    ConnectorEnrollment, CreateConnectorParams, PrivateConnector,
};
use ianua_domain::domains::routing::control::RoutingControl;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ConnectorId, Label, TokenHash};
use time::OffsetDateTime;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::routing::{ConnectorCodeGenerator, ConnectorStore};
use crate::services::limits::room::ensure_room_in_tenant;
use crate::use_case::Command;

/// What a new connector is made of.
pub struct CreateRequest {
    /// Name, unique within the tenant.
    pub name: Label,
    /// The networks and domains it may be asked to dial.
    pub scope: ConnectorScope,
}

/// A connector just created, with the code its agent enrolls with.
pub struct CreatedConnector {
    /// The new connector.
    pub connector_id: ConnectorId,
    /// The one-time enrollment code. Shown this once and never kept: only
    /// its hash is stored.
    pub enrollment_code: Secret,
    /// When the code stops being good.
    pub expires_at: OffsetDateTime,
}

/// The ports [`CreateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreatePorts {
    /// Keeps the tenant's connectors.
    pub connector_store: Arc<dyn ConnectorStore>,
    /// Makes enrollment codes and their hashes.
    pub code_generator: Arc<dyn ConnectorCodeGenerator>,
    /// The tenant's plan limits.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Adds a private-network connector to the tenant.
pub struct CreateUseCase {
    ports: CreatePorts,
}

impl CreateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CreatePorts) -> Self {
        Self { ports }
    }
}

impl Command for CreateUseCase {
    type Caller = CallerContext;
    type Input = CreateRequest;
    type Output = Result<CreatedConnector, AppError>;

    /// Creates the connector awaiting enrollment and records
    /// `routing.connector_created`. The enrollment code comes back once;
    /// only its hash is stored, and it is good for an hour.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not create routing, or
    ///   the plan's connector limit is reached.
    /// - `AppError::Conflict` if another connector of the tenant has the
    ///   name.
    /// - `AppError::Internal` on code, storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: CreateRequest,
    ) -> Result<CreatedConnector, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        ensure_room_in_tenant(
            self.ports.limit_enforcer.as_ref(),
            caller,
            ResourceKind::Connectors,
        )
        .await?;
        let by = RoutingControl::new(&authority);
        let (code, code_hash) = self.ports.code_generator.generate().await.or_internal()?;
        let mut connector = new_connector(request, code_hash, &by)?;
        let expires_at = code_expiry(&connector)?;
        let tenant = caller.tenant();
        self.ports
            .connector_store
            .save(&tenant, &connector)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&caller.actor(), connector.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(CreatedConnector {
            connector_id: *connector.id(),
            enrollment_code: code,
            expires_at,
        })
    }
}

/// The connector `request` describes, awaiting the code hashed to
/// `code_hash`, made by `by`.
///
/// # Errors
///
/// `AppError::Forbidden` when `by` may not create routing.
fn new_connector(
    request: CreateRequest,
    code_hash: TokenHash,
    by: &RoutingControl<'_>,
) -> Result<PrivateConnector<ResolvedTenant>, AppError> {
    PrivateConnector::create(
        CreateConnectorParams {
            name: request.name,
            scope: request.scope,
            code_hash,
        },
        by,
    )
    .map_err(AppError::from_domain)
}

/// When the code of a connector just created stops being good.
///
/// # Errors
///
/// `AppError::Internal` if the new connector does not await enrollment,
/// which the domain never allows.
fn code_expiry(connector: &PrivateConnector<ResolvedTenant>) -> Result<OffsetDateTime, AppError> {
    let ConnectorEnrollment::Awaiting { expires_at, .. } = connector.enrollment() else {
        return Err(AppError::internal_msg(
            "a connector just created awaits enrollment",
        ));
    };
    Ok(*expires_at)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::routing::{
        FakeConnectorStore, awaiting_connector, connector_code_hash, connector_scope, routing_label,
    };
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };

    /// The store, the audit record and the use case a test runs.
    struct Fixture {
        connectors: Arc<FakeConnectorStore>,
        audit: Arc<FakeEventDispatcher>,
        use_case: CreateUseCase,
    }

    /// A fixture over `connectors`, with the caller holding what
    /// `authorities` says.
    fn fixture_with(connectors: FakeConnectorStore, authorities: FakeTenantAuthorities) -> Fixture {
        let connectors = Arc::new(connectors);
        Fixture {
            use_case: CreateUseCase::new(CreatePorts {
                connector_store: connectors.clone(),
                tenant_authorities: Arc::new(authorities),
                ..CreatePorts::fakes()
            }),
            connectors,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    /// A fixture with no connector yet, run by a routing admin.
    fn fixture() -> Fixture {
        fixture_with(
            FakeConnectorStore::empty(),
            FakeTenantAuthorities::holding_everything(),
        )
    }

    /// A connector named `name` in the payroll network.
    fn request(name: &str) -> CreateRequest {
        CreateRequest {
            name: routing_label(name),
            scope: connector_scope(&["*.payroll.corp.internal"]),
        }
    }

    /// Runs the use case for `request`.
    fn run(f: &Fixture, request: CreateRequest) -> Result<CreatedConnector, AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), request),
        )
    }

    /// Ann adds a connector for the payroll network. She is shown its code
    /// once, the connector keeps only the code's hash, and the creation is
    /// recorded.
    #[test]
    fn a_connector_is_saved_with_its_code_hashed_and_shown_once() {
        let f = fixture();

        let created = run(&f, request("payroll")).unwrap();

        assert_eq!(created.enrollment_code.expose(), "enroll-code-1");
        let stored = f
            .connectors
            .stored(test_ctx().tenant_id(), &created.connector_id)
            .unwrap();
        assert!(matches!(
            stored.enrollment(),
            ConnectorEnrollment::Awaiting { code_hash, .. }
                if *code_hash == connector_code_hash("enroll-code-1")
        ));
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["routing.connector_created"]
        );
    }

    /// Ann names a new connector as the one she already has. It is refused
    /// as a conflict and nothing more is saved or recorded.
    #[test]
    fn a_name_already_taken_is_a_conflict() {
        let taken = awaiting_connector("payroll", "old-code", &["payroll.corp.internal"]);
        let f = fixture_with(
            FakeConnectorStore::holding(test_ctx().tenant_id(), &taken),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = run(&f, request("payroll"));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(f.connectors.count(), 1);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A routing viewer cannot create a connector. The refusal saves no
    /// connector and records no creation event.
    #[test]
    fn a_caller_without_the_create_right_is_refused() {
        let f = fixture_with(
            FakeConnectorStore::empty(),
            FakeTenantAuthorities::holding(&[SystemPermission::Routing(RoutingAction::View)]),
        );

        let result = run(&f, request("payroll"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.connectors.count(), 0);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot create a connector and leaves the store empty.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture_with(
            FakeConnectorStore::empty(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = run(&f, request("payroll"));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(f.connectors.count(), 0);
    }

    /// Ann's tenant already has as many connectors as its plan allows. Her
    /// new one is refused, and nothing is saved or recorded.
    #[test]
    fn a_connector_past_the_plan_limit_is_refused() {
        let connectors = Arc::new(FakeConnectorStore::empty());
        let f = Fixture {
            use_case: CreateUseCase::new(CreatePorts {
                connector_store: connectors.clone(),
                limit_enforcer: Arc::new(RejectingLimitEnforcer),
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
                ..CreatePorts::fakes()
            }),
            connectors,
            audit: Arc::new(FakeEventDispatcher::new()),
        };

        let result = run(&f, request("payroll"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.connectors.count(), 0);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }
}
