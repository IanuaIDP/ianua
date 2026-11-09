//! Accept readable assertions: a SAML connection stops requiring sealed
//! assertions and forgets the key it opened them with.

use std::sync::Arc;

use ianua_domain::domains::federation::connection::AssertionDecryption;
use ianua_domain::domains::federation::control::{FederationControl, FederationRight};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ConnectionId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::federation::ConnectionStore;
use crate::use_case::Command;
use crate::use_cases::federation::connections::saml::require_encrypted_assertions::{
    saml_of, with_decryption,
};
use crate::use_cases::federation::lookup::existing_connection;

/// The ports [`AcceptReadableAssertionsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AcceptReadableAssertionsPorts {
    /// Loads and saves connections.
    pub connection_store: Arc<dyn ConnectionStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lets a SAML connection take readable assertions again.
pub struct AcceptReadableAssertionsUseCase {
    ports: AcceptReadableAssertionsPorts,
}

impl AcceptReadableAssertionsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AcceptReadableAssertionsPorts) -> Self {
        Self { ports }
    }
}

impl Command for AcceptReadableAssertionsUseCase {
    type Caller = CallerContext;
    type Input = ConnectionId;
    type Output = Result<(), AppError>;

    /// Makes the connection take readable assertions, drops its key, and
    /// records `federation.connection_updated`. Assertions then pass through
    /// the browser readable, so this checks less and needs the full
    /// federation right.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not manage federation.
    /// - `AppError::NotFound` if the connection doesn't exist.
    /// - `AppError::Conflict` if it is not a SAML connection.
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
        let store = self.ports.connection_store.as_ref();
        let mut conn = existing_connection(store, &tenant, &connection_id).await?;
        let saml = saml_of(&conn)?;
        let readable = with_decryption(saml, AssertionDecryption::NotExpected);
        conn.update_config(readable, &control)
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
        GroupMapping, SamlConfig, SpEncryptionKey,
    };
    use ianua_domain::types::{CertificatePem, SealedSecret};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::domain::TEST_CERTIFICATE_PEM;
    use crate::test_support::federation::{
        FakeConnectionStore, test_saml_connection, test_saml_settings,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Acme's Okta, taking only sealed assertions.
    fn sealing() -> (Arc<FakeConnectionStore>, ConnectionId) {
        let id = ConnectionId::new();
        let key = SpEncryptionKey::new(
            CertificatePem::new(TEST_CERTIFICATE_PEM).unwrap(),
            SealedSecret::new("sealed-key").unwrap(),
        );
        let saml = SamlConfig {
            assertion_decryption: AssertionDecryption::Required(key),
            ..test_saml_settings()
        };
        let conn = test_saml_connection(id, saml, GroupMapping::Off);
        let store = FakeConnectionStore::holding(&test_ctx().tenant(), [conn]);
        (Arc::new(store), id)
    }

    fn accept(
        store: Arc<FakeConnectionStore>,
        authorities: FakeTenantAuthorities,
        audit: &Arc<FakeEventDispatcher>,
        id: ConnectionId,
    ) -> Result<(), AppError> {
        let use_case = AcceptReadableAssertionsUseCase::new(AcceptReadableAssertionsPorts {
            connection_store: store,
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), id))
    }

    fn decryption(store: &FakeConnectionStore, id: &ConnectionId) -> AssertionDecryption {
        let conn = block_on(store.find_by_id(&test_ctx().tenant(), id))
            .unwrap()
            .unwrap();
        saml_of(&conn).unwrap().assertion_decryption
    }

    /// Okta cannot encrypt for a while. Fay lets the connection take
    /// readable assertions again; its key is dropped and the change is
    /// recorded.
    #[test]
    fn the_connection_takes_readable_assertions_again() {
        let (store, id) = sealing();
        let audit = Arc::new(FakeEventDispatcher::new());

        accept(
            store.clone(),
            FakeTenantAuthorities::holding_everything(),
            &audit,
            id,
        )
        .unwrap();

        assert_eq!(decryption(&store, &id), AssertionDecryption::NotExpected);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["federation.connection_updated"]
        );
    }

    /// Fay names a connection her tenant does not have. It is not found.
    #[test]
    fn an_unknown_connection_is_not_found() {
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = accept(
            Arc::new(FakeConnectionStore::empty()),
            FakeTenantAuthorities::holding_everything(),
            &audit,
            ConnectionId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// The update right does not permit accepting readable assertions. The
    /// refusal preserves required decryption and records no update event.
    #[test]
    fn the_update_right_does_not_turn_sealing_off() {
        let (store, id) = sealing();
        let audit = Arc::new(FakeEventDispatcher::new());
        let update = [SystemPermission::Federation(FederationAction::Update)];

        let result = accept(
            store.clone(),
            FakeTenantAuthorities::holding(&update),
            &audit,
            id,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(matches!(
            decryption(&store, &id),
            AssertionDecryption::Required(_)
        ));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot stop requiring encrypted assertions.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = sealing();
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = accept(
            store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &audit,
            id,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
