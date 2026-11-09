//! Roll over certificate: a SAML connection takes its provider's next
//! certificate as its only one, once the provider switched to it.

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

/// The ports [`RollOverCertificateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RollOverCertificatePorts {
    /// Loads and saves connections.
    pub connection_store: Arc<dyn ConnectionStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Retires a SAML connection's current certificate for its next one.
pub struct RollOverCertificateUseCase {
    ports: RollOverCertificatePorts,
}

impl RollOverCertificateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RollOverCertificatePorts) -> Self {
        Self { ports }
    }
}

impl Command for RollOverCertificateUseCase {
    type Caller = CallerContext;
    type Input = ConnectionId;
    type Output = Result<(), AppError>;

    /// Makes the connection's next certificate its only one and records
    /// `federation.connection_updated`. The old certificate signs nothing
    /// in any more. Nobody new may sign answers, so the update right is
    /// enough.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not update connections.
    /// - `AppError::NotFound` if the connection doesn't exist.
    /// - `AppError::Conflict` if it is not a SAML connection, or has no next
    ///   certificate.
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
        let store = self.ports.connection_store.as_ref();
        let mut conn = existing_connection(store, &tenant, &connection_id).await?;
        conn.roll_over_certificate(&control)
            .map_err(AppError::from_domain)?;

        store.save(&tenant, &conn).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), conn.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{FederationAction, SystemPermission};
    use ianua_domain::domains::federation::connection::{
        ConnectionConfig, FederatedIdpConnection, GroupMapping, IdpCertificates, SamlConfig,
    };
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::CertificatePem;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::federation::{
        FakeConnectionStore, TEST_IDP_CERTIFICATE, test_connection, test_saml_connection,
        test_saml_settings,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const NEXT: &str = "-----BEGIN CERTIFICATE-----\nTkVYVA==\n-----END CERTIFICATE-----";

    /// Acme's Okta, taking its current certificate and, while it rolls
    /// over, its next one.
    fn rolling_over(id: ConnectionId) -> FederatedIdpConnection<ResolvedTenant> {
        let certificates = IdpCertificates::rolling_over(
            CertificatePem::new(TEST_IDP_CERTIFICATE).unwrap(),
            CertificatePem::new(NEXT).unwrap(),
        )
        .unwrap();
        let saml = SamlConfig {
            certificates,
            ..test_saml_settings()
        };
        test_saml_connection(id, saml, GroupMapping::Off)
    }

    fn store_holding(conn: FederatedIdpConnection<ResolvedTenant>) -> Arc<FakeConnectionStore> {
        Arc::new(FakeConnectionStore::holding(&test_ctx().tenant(), [conn]))
    }

    fn roll_over(
        store: Arc<FakeConnectionStore>,
        authorities: FakeTenantAuthorities,
        audit: &Arc<FakeEventDispatcher>,
        id: ConnectionId,
    ) -> Result<(), AppError> {
        let use_case = RollOverCertificateUseCase::new(RollOverCertificatePorts {
            connection_store: store,
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), id))
    }

    fn certificates(store: &FakeConnectionStore, id: &ConnectionId) -> IdpCertificates {
        let conn = block_on(store.find_by_id(&test_ctx().tenant(), id))
            .unwrap()
            .unwrap();
        let ConnectionConfig::Saml(saml) = conn.config() else {
            panic!("expected a SAML connection");
        };
        saml.certificates.clone()
    }

    /// Okta switched to its new key. Sam, who may update connections,
    /// retires the old certificate: only the new one is taken, and the
    /// change is recorded.
    #[test]
    fn the_next_certificate_becomes_the_only_one() {
        let id = ConnectionId::new();
        let store = store_holding(rolling_over(id));
        let audit = Arc::new(FakeEventDispatcher::new());
        let update = [SystemPermission::Federation(FederationAction::Update)];

        roll_over(
            store.clone(),
            FakeTenantAuthorities::holding(&update),
            &audit,
            id,
        )
        .unwrap();

        let kept = certificates(&store, &id);
        assert_eq!(kept.current().as_str(), NEXT);
        assert!(kept.upcoming().is_none());
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["federation.connection_updated"]
        );
    }

    /// Okta has no next certificate. There is nothing to roll over to, and
    /// nothing is recorded.
    #[test]
    fn a_connection_with_no_next_certificate_conflicts() {
        let id = ConnectionId::new();
        let store = store_holding(test_connection(id, ConnectionStatus::Active));
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = roll_over(
            store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            id,
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Sam names a connection his tenant does not have. It is not found.
    #[test]
    fn an_unknown_connection_is_not_found() {
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = roll_over(
            Arc::new(FakeConnectionStore::empty()),
            FakeTenantAuthorities::holding_everything(),
            &audit,
            ConnectionId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A federation viewer cannot roll over the provider certificate. The
    /// refusal retains the upcoming certificate and records no update event.
    #[test]
    fn a_viewer_cannot_roll_over() {
        let id = ConnectionId::new();
        let store = store_holding(rolling_over(id));
        let audit = Arc::new(FakeEventDispatcher::new());
        let view = [SystemPermission::Federation(FederationAction::View)];

        let result = roll_over(
            store.clone(),
            FakeTenantAuthorities::holding(&view),
            &audit,
            id,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(certificates(&store, &id).upcoming().is_some());
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot roll over a provider certificate.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let id = ConnectionId::new();
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = roll_over(
            store_holding(rolling_over(id)),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &audit,
            id,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
