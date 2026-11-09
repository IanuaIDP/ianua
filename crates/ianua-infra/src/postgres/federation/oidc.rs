//! A tenant's OIDC sign-ins between the redirect to the provider and its
//! callback.
//!
//! A sign-in is kept under a digest of its state, taken by the same digest,
//! and removed as it is taken, so a state answers once and a reader of the
//! table holds no state that would answer one. The PKCE verifier is sealed
//! before it is written and opened as it is taken. A sign-in not answered
//! within [`LAPSE`] is never handed out, and the tenant's lapsed ones are
//! cleared when the next one is kept.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use data_encoding::HEXLOWER;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authentication::{SealOwner, SealedField, SealedFor, SecretEncryptor};
use ianua_app::ports::federation::{OidcFlowStore, OidcLoginFlow};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::SealedSecret;
use sha2::{Digest as _, Sha256};
use sqlx::PgConnection;
use time::{Duration, OffsetDateTime};

use self::record::{FlowColumns, FlowRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// How long a sign-in waits for the provider's answer before it lapses: as
/// long as a person takes to sign in at their provider, and no longer.
const LAPSE: Duration = Duration::minutes(10);

/// Where the PKCE verifier of `tenant`'s sign-in kept under `state` is
/// sealed for: the row the state's digest names, so a verifier moved to
/// another sign-in, or another tenant's, does not open there. The digest
/// is no secret, as the row keeps it.
fn verifier_place(tenant: &ScopedTenant, state: &Secret) -> SealedFor {
    let digest = HEXLOWER.encode(&Sha256::digest(state.expose().as_bytes()));
    SealedFor::new(
        SealOwner::from(tenant),
        SealedField::OidcFlowVerifier,
        digest,
    )
}

/// The Postgres store of OIDC sign-ins in flight.
pub struct PgOidcFlowStore {
    databases: Arc<Databases>,
    encryptor: Arc<dyn SecretEncryptor>,
}

impl PgOidcFlowStore {
    /// A store keeping sign-ins in `databases`, their PKCE verifiers sealed
    /// by `encryptor`.
    #[must_use]
    pub fn new(databases: Arc<Databases>, encryptor: Arc<dyn SecretEncryptor>) -> Self {
        Self {
            databases,
            encryptor,
        }
    }

    /// The PKCE verifier of `flow`, sealed for storage at `place`.
    async fn sealed(
        &self,
        flow: &OidcLoginFlow,
        place: &SealedFor,
    ) -> Result<SealedSecret, DomainError> {
        self.encryptor
            .encrypt(flow.pkce_verifier.expose().as_bytes(), place)
            .await
    }

    /// The verifier `record` keeps at `place`, opened.
    async fn opened(&self, record: &FlowRecord, place: &SealedFor) -> Result<Secret, DomainError> {
        let sealed = record.sealed_verifier()?;
        let opened = self.encryptor.decrypt(&sealed, place).await?;
        String::from_utf8(opened)
            .map(Secret::new)
            .map_err(DomainError::infra)
    }
}

impl TenantScoped for PgOidcFlowStore {}

/// Clears this tenant's expired callback state before saving another sign-in.
async fn clear_lapsed(
    connection: &mut PgConnection,
    tenant: &ScopedTenant,
    now: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query_file!("queries/oidc_flows/clear_lapsed.sql", tenant.as_uuid(), now)
        .execute(connection)
        .await
        .map(|_| ())
}

#[async_trait]
impl OidcFlowStore for PgOidcFlowStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        state: &Secret,
        flow: &OidcLoginFlow,
    ) -> Result<(), DomainError> {
        let place = verifier_place(tenant_id, state);
        let columns = FlowColumns::of(flow, self.sealed(flow, &place).await?);
        let now = clock::now();
        let lapses_at = now.saturating_add(LAPSE);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                clear_lapsed(connection, tenant_id, now).await?;
                sqlx::query_file!(
                    "queries/oidc_flows/keep.sql",
                    tenant_id.as_uuid(),
                    state.expose(),
                    columns.connection_id,
                    columns.nonce,
                    columns.sealed_pkce_verifier.as_str(),
                    columns.redirect_uri,
                    columns.binding_hash,
                    columns.dashboard_hash,
                    lapses_at,
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn consume(
        &self,
        tenant_id: &ScopedTenant,
        state: &Secret,
    ) -> Result<Option<OidcLoginFlow>, DomainError> {
        let now = clock::now();
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    FlowRecord,
                    "queries/oidc_flows/take.sql",
                    tenant_id.as_uuid(),
                    state.expose(),
                    now
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        let Some(record) = record else {
            return Ok(None);
        };
        let verifier = self
            .opened(&record, &verifier_place(tenant_id, state))
            .await?;
        record.into_flow(verifier).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::federation::ConnectionStore;
    use ianua_app::test_support::authentication::FakeEncryptor;
    use ianua_domain::domains::federation::connection::FederatedIdpConnection;
    use ianua_domain::types::ConnectionId;

    use super::*;
    use crate::postgres::federation::PgConnectionStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::federation::{connection_row, oidc_config, oidc_flow};

    struct Fixture {
        db: TestDb,
        store: PgOidcFlowStore,
        tenant: ScopedTenant,
        okta: ConnectionId,
    }

    /// A fresh database holding a tenant with Okta over OIDC, and the store
    /// on it, sealing with the app's test sealer.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = tenant();
        let okta =
            FederatedIdpConnection::reconstitute(connection_row("Okta", oidc_config())).unwrap();
        PgConnectionStore::new(Arc::clone(&db.databases))
            .save(&tenant, &okta)
            .await
            .unwrap();
        Fixture {
            store: PgOidcFlowStore::new(Arc::clone(&db.databases), Arc::new(FakeEncryptor)),
            okta: *okta.id(),
            tenant,
            db,
        }
    }

    fn state(text: &str) -> Secret {
        Secret::new(text)
    }

    /// A sign-in kept under its state is handed out once, with what its
    /// callback is checked with, its verifier opened again.
    #[tokio::test]
    async fn a_sign_in_is_taken_once_under_its_state() {
        let fx = fixture().await;
        let kept = oidc_flow(fx.okta);
        let state = state("oidc-state-0123456789abcdef");
        fx.store.save(&fx.tenant, &state, &kept).await.unwrap();

        let first = fx.store.consume(&fx.tenant, &state).await.unwrap().unwrap();
        let again = fx.store.consume(&fx.tenant, &state).await.unwrap();

        assert_eq!(first.connection_id, fx.okta);
        assert_eq!(first.nonce, kept.nonce);
        assert_eq!(first.pkce_verifier.expose(), kept.pkce_verifier.expose());
        assert_eq!(first.redirect_uri, kept.redirect_uri);
        assert_eq!(first.binding_hash, kept.binding_hash);
        assert_eq!(first.dashboard_hash, kept.dashboard_hash);
        assert!(again.is_none());
    }

    /// Sealing a PKCE verifier for storage produces text that neither
    /// equals nor contains the verifier.
    #[tokio::test]
    async fn the_verifier_is_kept_sealed() {
        let fx = fixture().await;
        let flow = oidc_flow(fx.okta);

        let place = verifier_place(&fx.tenant, &state("oidc-state-0123456789abcdef"));
        let written = fx.store.sealed(&flow, &place).await.unwrap();

        assert_ne!(written.as_str(), flow.pkce_verifier.expose());
        assert!(!written.as_str().contains(flow.pkce_verifier.expose()));
    }

    /// A state never issued takes nothing, rather than failing.
    #[tokio::test]
    async fn a_state_never_issued_takes_nothing() {
        let fx = fixture().await;

        let taken = fx
            .store
            .consume(&fx.tenant, &state("never-issued-0123456789"))
            .await
            .unwrap();

        assert!(taken.is_none());
    }

    /// An OIDC sign-in past its stored lapse time cannot be consumed.
    #[tokio::test]
    async fn a_lapsed_sign_in_is_not_taken() {
        let fx = fixture().await;
        let state = state("lapsing-state-0123456789");
        fx.store
            .save(&fx.tenant, &state, &oidc_flow(fx.okta))
            .await
            .unwrap();
        fx.db
            .tamper("UPDATE oidc_flows SET lapses_at = now() - interval '1 minute'")
            .await;

        let taken = fx.store.consume(&fx.tenant, &state).await.unwrap();

        assert!(taken.is_none());
    }

    /// Consuming Acme's OIDC state in another tenant returns none and
    /// leaves the sign-in available to Acme.
    #[tokio::test]
    async fn another_tenants_state_takes_nothing() {
        let fx = fixture().await;
        let state = state("acme-state-0123456789");
        fx.store
            .save(&fx.tenant, &state, &oidc_flow(fx.okta))
            .await
            .unwrap();

        let globex = fx.store.consume(&tenant(), &state).await.unwrap();
        let acme = fx.store.consume(&fx.tenant, &state).await.unwrap();

        assert!(globex.is_none());
        assert!(acme.is_some());
    }

    /// A stored verifier that cannot be opened makes OIDC consumption
    /// fail as corrupt storage.
    #[tokio::test]
    async fn a_verifier_that_does_not_open_is_refused() {
        let fx = fixture().await;
        let state = state("corrupt-state-0123456789");
        fx.store
            .save(&fx.tenant, &state, &oidc_flow(fx.okta))
            .await
            .unwrap();
        fx.db
            .tamper("UPDATE oidc_flows SET sealed_pkce_verifier = 'v9.someoneelses'")
            .await;

        let taken = fx.store.consume(&fx.tenant, &state).await;

        assert!(matches!(taken, Err(DomainError::Infrastructure(_))));
    }
}
