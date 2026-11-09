//! Require encrypted assertions: a SAML connection takes only assertions
//! its provider sealed to a key of this platform's, so the browser they
//! pass through cannot read them.
//!
//! The key pair is made here, or the tenant brings its own. Either way the
//! private key is sealed before the connection keeps it, and only the
//! certificate comes back, to publish in the metadata.

use std::sync::Arc;

use ianua_domain::domains::federation::connection::{
    AssertionDecryption, ConnectionConfig, FederatedIdpConnection, SamlConfig, SpEncryptionKey,
};
use ianua_domain::domains::federation::control::{FederationControl, FederationRight};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificatePem, ConnectionId, SamlEntityId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{SealOwner, SecretEncryptor};
use crate::ports::federation::{
    ConnectionStore, GeneratedSpKey, SamlConnection, SamlEncryptionKeys,
};
use crate::use_case::Command;
use crate::use_cases::federation::lookup::existing_connection;

/// Where the key assertions are sealed to comes from. An uploaded key holds
/// the private key, so it has no `Debug`.
pub enum SpKeySource {
    /// This platform makes a new pair.
    Generated,
    /// The tenant brings its own pair.
    Uploaded {
        /// The certificate the provider encrypts to.
        certificate: CertificatePem,
        /// Its private key, as PEM.
        private_key: Secret,
    },
}

/// Which connection to seal assertions for, and with which key.
pub struct RequireEncryptedAssertionsRequest {
    /// The SAML connection.
    pub connection_id: ConnectionId,
    /// This platform's entity id as the connection's service provider, the
    /// subject of a certificate made here.
    pub service_provider: SamlEntityId,
    /// Where the key comes from.
    pub key: SpKeySource,
}

/// The ports [`RequireEncryptedAssertionsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RequireEncryptedAssertionsPorts {
    /// Loads and saves connections.
    pub connection_store: Arc<dyn ConnectionStore>,
    /// Makes key pairs and checks uploaded ones.
    pub encryption_keys: Arc<dyn SamlEncryptionKeys>,
    /// Seals the private key before it is stored.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Makes a SAML connection take only sealed assertions.
pub struct RequireEncryptedAssertionsUseCase {
    ports: RequireEncryptedAssertionsPorts,
}

impl RequireEncryptedAssertionsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RequireEncryptedAssertionsPorts) -> Self {
        Self { ports }
    }

    /// The pair `request` names: made now, or the uploaded one once its
    /// private key matches its certificate.
    async fn key_pair(
        &self,
        request: RequireEncryptedAssertionsRequest,
    ) -> Result<GeneratedSpKey, AppError> {
        let keys = self.ports.encryption_keys.as_ref();
        match request.key {
            SpKeySource::Generated => keys.generate(&request.service_provider).await.or_internal(),
            SpKeySource::Uploaded {
                certificate,
                private_key,
            } => {
                keys.ensure_pair(&certificate, &private_key)
                    .map_err(AppError::from_domain)?;
                Ok(GeneratedSpKey {
                    certificate,
                    private_key,
                })
            }
        }
    }

    /// `pair` with its private key sealed for storage on `connection`.
    async fn sealed(
        &self,
        pair: GeneratedSpKey,
        connection: &SamlConnection,
    ) -> Result<SpEncryptionKey, AppError> {
        let sealed = self
            .ports
            .encryptor
            .encrypt(
                pair.private_key.expose().as_bytes(),
                &connection.decryption_key_place(),
            )
            .await
            .or_internal()?;
        Ok(SpEncryptionKey::new(pair.certificate, sealed))
    }
}

impl Command for RequireEncryptedAssertionsUseCase {
    type Caller = CallerContext;
    type Input = RequireEncryptedAssertionsRequest;
    type Output = Result<CertificatePem, AppError>;

    /// Makes the connection refuse readable assertions, and take sealed ones
    /// with the new key, and records `federation.connection_updated`.
    /// Returns the certificate the provider encrypts to; the private key is
    /// only ever stored sealed. It replaces any key the connection held.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without federation-management rights.
    /// - `AppError::NotFound` for a missing connection; `Conflict` for a non-SAML connection.
    /// - `AppError::Domain` for a key not matching its certificate; `Internal` on key, sealing, audit or persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: RequireEncryptedAssertionsRequest,
    ) -> Result<CertificatePem, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = FederationControl::new(&authority);
        control
            .ensure_may(FederationRight::TrustConnection)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let store = self.ports.connection_store.as_ref();
        let mut conn = existing_connection(store, &tenant, &request.connection_id).await?;
        let saml = saml_of(&conn)?;
        let through = SamlConnection {
            owner: SealOwner::from(&tenant),
            id: *conn.id(),
        };
        let key = self.sealed(self.key_pair(request).await?, &through).await?;
        let certificate = key.certificate().clone();
        let decryption = AssertionDecryption::Required(key);
        conn.update_config(with_decryption(saml, decryption), &control)
            .map_err(AppError::from_domain)?;

        store.save(&tenant, &conn).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), conn.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(certificate)
    }
}

/// The SAML settings of `conn`.
///
/// # Errors
///
/// - `AppError::Conflict` if `conn` is an OIDC connection, whose tokens
///   are never sealed to this platform.
pub(in crate::use_cases::federation::connections) fn saml_of(
    conn: &FederatedIdpConnection<ResolvedTenant>,
) -> Result<SamlConfig, AppError> {
    let ConnectionConfig::Saml(saml) = conn.config() else {
        return Err(AppError::Conflict(message!(
            "federation-only-a-saml-connection-takes-sealed",
            "only a SAML connection takes sealed assertions"
        )));
    };
    Ok((**saml).clone())
}

/// `saml` taking assertions as `decryption` says.
pub(in crate::use_cases::federation::connections) fn with_decryption(
    saml: SamlConfig,
    decryption: AssertionDecryption,
) -> ConnectionConfig {
    ConnectionConfig::Saml(Box::new(SamlConfig {
        assertion_decryption: decryption,
        ..saml
    }))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{FederationAction, SystemPermission};
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::domain::TEST_CERTIFICATE_PEM;
    use crate::test_support::federation::{
        FakeConnectionStore, FakeSamlEncryptionKeys, test_connection,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn seeded() -> (Arc<FakeConnectionStore>, ConnectionId) {
        let id = ConnectionId::new();
        let conn = test_connection(id, ConnectionStatus::Active);
        let store = FakeConnectionStore::holding(&test_ctx().tenant(), [conn]);
        (Arc::new(store), id)
    }

    fn request(id: ConnectionId, key: SpKeySource) -> RequireEncryptedAssertionsRequest {
        RequireEncryptedAssertionsRequest {
            connection_id: id,
            service_provider: SamlEntityId::new("https://acme.ianua.test/saml").unwrap(),
            key,
        }
    }

    fn require(
        store: Arc<FakeConnectionStore>,
        authorities: FakeTenantAuthorities,
        audit: &Arc<FakeEventDispatcher>,
        request: RequireEncryptedAssertionsRequest,
    ) -> Result<CertificatePem, AppError> {
        let use_case = RequireEncryptedAssertionsUseCase::new(RequireEncryptedAssertionsPorts {
            connection_store: store,
            tenant_authorities: Arc::new(authorities),
            ..RequireEncryptedAssertionsPorts::fakes()
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request))
    }

    fn decryption(store: &FakeConnectionStore, id: &ConnectionId) -> AssertionDecryption {
        let conn = block_on(store.find_by_id(&test_ctx().tenant(), id))
            .unwrap()
            .unwrap();
        saml_of(&conn).unwrap().assertion_decryption
    }

    /// Fay wants Okta's assertions sealed. A key pair is made, she gets its
    /// certificate to give Okta, the private key is kept only sealed, and
    /// the change is recorded.
    #[test]
    fn a_made_key_seals_assertions_and_is_kept_sealed() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());

        let certificate = require(
            store.clone(),
            FakeTenantAuthorities::holding_everything(),
            &audit,
            request(id, SpKeySource::Generated),
        )
        .unwrap();

        assert_eq!(certificate.as_str(), TEST_CERTIFICATE_PEM);
        let AssertionDecryption::Required(key) = decryption(&store, &id) else {
            panic!("the connection takes readable assertions");
        };
        assert_eq!(
            *key.sealed_private_key(),
            FakeEncryptor::sealed_for(
                FakeSamlEncryptionKeys::PRIVATE_KEY,
                &SamlConnection {
                    owner: SealOwner::from(&test_ctx().tenant()),
                    id,
                }
                .decryption_key_place()
            )
        );
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["federation.connection_updated"]
        );
    }

    /// Fay uploads a certificate with a private key that is not its pair.
    /// Okta's assertions could never be opened, so it is refused and the
    /// connection keeps taking readable ones.
    #[test]
    fn an_uploaded_key_that_is_not_the_pair_is_refused() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let key = SpKeySource::Uploaded {
            certificate: CertificatePem::new(TEST_CERTIFICATE_PEM).unwrap(),
            private_key: Secret::new("another-key"),
        };

        let result = require(
            store.clone(),
            FakeTenantAuthorities::holding_everything(),
            &audit,
            request(id, key),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(decryption(&store, &id), AssertionDecryption::NotExpected);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Fay names a connection her tenant does not have. It is not found.
    #[test]
    fn an_unknown_connection_is_not_found() {
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = require(
            Arc::new(FakeConnectionStore::empty()),
            FakeTenantAuthorities::holding_everything(),
            &audit,
            request(ConnectionId::new(), SpKeySource::Generated),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// The update right does not permit generating an assertion encryption
    /// key. The refusal leaves decryption unconfigured and records no update.
    #[test]
    fn the_update_right_does_not_set_the_key() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let update = [SystemPermission::Federation(FederationAction::Update)];

        let result = require(
            store.clone(),
            FakeTenantAuthorities::holding(&update),
            &audit,
            request(id, SpKeySource::Generated),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(decryption(&store, &id), AssertionDecryption::NotExpected);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot require encrypted assertions.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = require(
            store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &audit,
            request(id, SpKeySource::Generated),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
