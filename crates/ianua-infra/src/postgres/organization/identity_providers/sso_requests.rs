//! The dashboard sign-ins sent to an organization's provider and waiting on
//! its answer, kept in the platform database.
//!
//! A request is kept under a digest of its key, taken by the same digest,
//! and removed as it is taken, so an answer is used once and a reader of
//! the table holds no key that would answer one. The kind of key keeps an
//! OIDC state and a SAML request id apart. The PKCE verifier is sealed for
//! the organization and the row it is kept in before it is written, and
//! opened as it is taken. A request not answered within [`LAPSE`] is never
//! handed out, and is cleared when the next one is kept.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use data_encoding::HEXLOWER;
use ianua_app::ports::authentication::{SealOwner, SealedField, SealedFor, SecretEncryptor};
use ianua_app::ports::organization::{OrgSsoKey, OrgSsoRequest, OrgSsoRequestStore};
use ianua_domain::shared::clock;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{OrganizationId, SealedSecret};
use sha2::{Digest as _, Sha256};
use time::Duration;

use self::record::{RequestColumns, RequestRecord, verifier_of};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// How long a sign-in waits for the provider's answer before it lapses: as
/// long as a person takes to sign in at their provider, and no longer.
const LAPSE: Duration = Duration::minutes(10);

/// The Postgres store of dashboard sign-ins in flight.
pub struct PgOrgSsoRequestStore {
    databases: Arc<Databases>,
    limits: DomainLimits,
    encryptor: Arc<dyn SecretEncryptor>,
}

impl PgOrgSsoRequestStore {
    /// A store keeping sign-ins in `databases`, their PKCE verifiers sealed
    /// by `encryptor`, checking each stored tenant slug against `limits` as
    /// it is read back.
    #[must_use]
    pub fn new(
        databases: Arc<Databases>,
        limits: DomainLimits,
        encryptor: Arc<dyn SecretEncryptor>,
    ) -> Self {
        Self {
            databases,
            limits,
            encryptor,
        }
    }

    /// `verifier`, sealed for storage at `place`.
    async fn sealed(
        &self,
        verifier: Option<&Secret>,
        place: &SealedFor,
    ) -> Result<Option<SealedSecret>, DomainError> {
        let Some(verifier) = verifier else {
            return Ok(None);
        };
        self.encryptor
            .encrypt(verifier.expose().as_bytes(), place)
            .await
            .map(Some)
    }

    /// The request `record` holds, its verifier opened from `place`.
    async fn opened(
        &self,
        record: RequestRecord,
        place: &SealedFor,
    ) -> Result<OrgSsoRequest, DomainError> {
        let verifier = match record.sealed_verifier()? {
            None => None,
            Some(sealed) => Some(self.opened_verifier(&sealed, place).await?),
        };
        record.into_request(verifier, &self.limits)
    }

    /// The verifier `sealed`, kept at `place`, opened.
    async fn opened_verifier(
        &self,
        sealed: &SealedSecret,
        place: &SealedFor,
    ) -> Result<Secret, DomainError> {
        let bytes = self.encryptor.decrypt(sealed, place).await?;
        String::from_utf8(bytes)
            .map(Secret::new)
            .map_err(|_| DomainError::infra_msg("a sealed PKCE verifier does not open to text"))
    }
}

/// The kind `key` is kept under, and its text, which is only ever bound to
/// be digested.
fn kind_and_text(key: OrgSsoKey<'_>) -> (&'static str, &str) {
    match key {
        OrgSsoKey::OidcState(state) => ("oidc_state", state.expose()),
        OrgSsoKey::SamlRequest(request_id) => ("saml_request", request_id.as_str()),
    }
}

/// Where the PKCE verifier of `organization`'s sign-in kept under the key
/// of `kind` with `text` is sealed for: the row the key's digest names, so
/// a verifier moved to another sign-in does not open there. The digest is
/// no secret, as the row keeps it.
fn verifier_place(organization: OrganizationId, kind: &str, text: &str) -> SealedFor {
    let digest = HEXLOWER.encode(&Sha256::digest(text.as_bytes()));
    SealedFor::new(
        SealOwner::Organization(organization),
        SealedField::OrgSsoVerifier,
        format!("{kind}:{digest}"),
    )
}

#[async_trait]
impl OrgSsoRequestStore for PgOrgSsoRequestStore {
    async fn save(&self, key: OrgSsoKey<'_>, request: &OrgSsoRequest) -> Result<(), DomainError> {
        let (kind, text) = kind_and_text(key);
        let columns = RequestColumns::of(request);
        let place = verifier_place(request.organization_id, kind, text);
        let pkce_verifier = self.sealed(verifier_of(request), &place).await?;
        let now = clock::now();
        let lapses_at = now.saturating_add(LAPSE);
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!("queries/org_sso_requests/clear_lapsed.sql", now)
                .execute(&mut *connection)
                .await?;
            sqlx::query_file!(
                "queries/org_sso_requests/keep.sql",
                kind,
                text,
                columns.organization_id,
                columns.connection_id,
                columns.binding_hash,
                columns.tenant_slug,
                columns.nonce,
                pkce_verifier.as_ref().map(SealedSecret::as_str),
                columns.redirect_uri,
                lapses_at,
            )
            .execute(connection)
            .await?;
            Ok(())
        })
        .await
    }

    async fn take(&self, key: OrgSsoKey<'_>) -> Result<Option<OrgSsoRequest>, DomainError> {
        let (kind, text) = kind_and_text(key);
        let now = clock::now();
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                RequestRecord,
                "queries/org_sso_requests/take.sql",
                kind,
                text,
                now
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        let Some(record) = record else {
            return Ok(None);
        };
        let place = verifier_place(record.organization(), kind, text);
        self.opened(record, &place).await.map(Some)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::organization::{
        OrgIdentityProviderStore, OrgSsoAwaiting, OrganizationStore,
    };
    use ianua_domain::domains::organization::access::identity_provider::OrgIdentityProvider;
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{ConnectionId, OrganizationId, SamlRequestId};

    use super::*;
    use crate::crypto::{AesGcmSecretEncryptor, SealingKey};
    use crate::postgres::organization::{PgOrgIdentityProviderStore, PgOrganizationStore};
    use crate::test_support::TestDb;
    use crate::test_support::rows::organization::{
        org_identity_provider_row, org_oidc_sso_request, org_saml_config, org_saml_sso_request,
        organization_row,
    };

    struct Fixture {
        db: TestDb,
        store: PgOrgSsoRequestStore,
        acme: OrganizationId,
        okta: ConnectionId,
    }

    /// A fresh database holding Acme and its provider, and the store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let organization = Organization::reconstitute(organization_row("acme", "Acme")).unwrap();
        PgOrganizationStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&organization)
            .await
            .unwrap();
        let acme = *organization.id();
        let provider =
            OrgIdentityProvider::reconstitute(org_identity_provider_row(acme, org_saml_config()))
                .unwrap();
        PgOrgIdentityProviderStore::new(Arc::clone(&db.databases))
            .save(&provider)
            .await
            .unwrap();
        let sealer =
            AesGcmSecretEncryptor::new(SealingKey::new("k1", [7; 32]).unwrap(), Vec::new());
        let store = PgOrgSsoRequestStore::new(
            Arc::clone(&db.databases),
            DomainLimits::default(),
            Arc::new(sealer),
        );
        Fixture {
            db,
            store,
            acme,
            okta: *provider.id(),
        }
    }

    fn state(text: &str) -> Secret {
        Secret::new(text)
    }

    fn request_id(text: &str) -> SamlRequestId {
        SamlRequestId::new(text).unwrap()
    }

    /// An OIDC sign-in kept under its state is handed out once, with what
    /// its answer is checked with.
    #[tokio::test]
    async fn an_oidc_sign_in_is_taken_once_under_its_state() {
        let fx = fixture().await;
        let kept = org_oidc_sso_request(fx.acme, fx.okta);
        let state = state("oidc-state-0123456789abcdef");
        fx.store
            .save(OrgSsoKey::OidcState(&state), &kept)
            .await
            .unwrap();

        let first = fx.store.take(OrgSsoKey::OidcState(&state)).await.unwrap();
        let again = fx.store.take(OrgSsoKey::OidcState(&state)).await.unwrap();

        let first = first.unwrap();
        assert_eq!(first.organization_id, fx.acme);
        assert_eq!(first.connection_id, fx.okta);
        assert_eq!(first.binding_hash, kept.binding_hash);
        assert_eq!(first.tenant_slug, kept.tenant_slug);
        assert_oidc_payload(&first.awaiting, &kept.awaiting);
        assert!(again.is_none());
    }

    /// An OIDC round trip preserves the nonce, verifier and redirect URI exactly.
    fn assert_oidc_payload(found: &OrgSsoAwaiting, kept: &OrgSsoAwaiting) {
        let (
            OrgSsoAwaiting::Oidc {
                nonce,
                pkce_verifier,
                redirect_uri,
            },
            OrgSsoAwaiting::Oidc {
                nonce: kept_nonce,
                pkce_verifier: kept_verifier,
                redirect_uri: kept_uri,
            },
        ) = (found, kept)
        else {
            panic!("an OIDC sign-in reads back as one");
        };
        assert_eq!(nonce, kept_nonce);
        assert_eq!(pkce_verifier.expose(), kept_verifier.expose());
        assert_eq!(redirect_uri, kept_uri);
    }

    /// Sealing an OIDC verifier for its storage location produces text
    /// that does not contain the plaintext verifier.
    #[tokio::test]
    async fn the_verifier_is_kept_sealed() {
        let fx = fixture().await;
        let kept = org_oidc_sso_request(fx.acme, fx.okta);
        let verifier = verifier_of(&kept).unwrap();
        let place = verifier_place(fx.acme, "oidc_state", "oidc-state-0123456789abcdef");

        let written = fx
            .store
            .sealed(Some(verifier), &place)
            .await
            .unwrap()
            .unwrap();

        assert!(!written.as_str().contains(verifier.expose()));
    }

    /// Taking a sign-in whose sealed verifier was copied from another
    /// sign-in's row returns an infrastructure error.
    #[tokio::test]
    async fn a_verifier_moved_to_another_sign_in_is_refused() {
        let fx = fixture().await;
        let (first, second) = (
            state("first-state-0123456789"),
            state("second-state-0123456789"),
        );
        for key in [&first, &second] {
            fx.store
                .save(
                    OrgSsoKey::OidcState(key),
                    &org_oidc_sso_request(fx.acme, fx.okta),
                )
                .await
                .unwrap();
        }
        fx.db
            .tamper(
                "UPDATE org_sso_requests SET pkce_verifier = source.pkce_verifier \
                 FROM org_sso_requests source \
                 WHERE source.key_hash = sha256(convert_to('first-state-0123456789', 'UTF8')) \
                 AND org_sso_requests.key_hash = sha256(convert_to('second-state-0123456789', 'UTF8'))",
            )
            .await;

        let moved = fx.store.take(OrgSsoKey::OidcState(&second)).await;

        assert!(matches!(moved, Err(DomainError::Infrastructure(_))));
    }

    /// A SAML sign-in kept under its request id is handed out once.
    #[tokio::test]
    async fn a_saml_sign_in_is_taken_once_under_its_request_id() {
        let fx = fixture().await;
        let id = request_id("_a1b2c3d4e5f6");
        fx.store
            .save(
                OrgSsoKey::SamlRequest(&id),
                &org_saml_sso_request(fx.acme, fx.okta),
            )
            .await
            .unwrap();

        let first = fx.store.take(OrgSsoKey::SamlRequest(&id)).await.unwrap();
        let again = fx.store.take(OrgSsoKey::SamlRequest(&id)).await.unwrap();

        assert!(matches!(
            first.map(|request| request.awaiting),
            Some(OrgSsoAwaiting::Saml)
        ));
        assert!(again.is_none());
    }

    /// Taking an OIDC request through a SAML key with the same text returns
    /// no request.
    #[tokio::test]
    async fn a_key_of_the_other_kind_takes_nothing() {
        let fx = fixture().await;
        let text = "shared-key-0123456789";
        fx.store
            .save(
                OrgSsoKey::OidcState(&state(text)),
                &org_oidc_sso_request(fx.acme, fx.okta),
            )
            .await
            .unwrap();

        let taken = fx
            .store
            .take(OrgSsoKey::SamlRequest(&request_id(text)))
            .await
            .unwrap();

        assert!(taken.is_none());
    }

    /// A key never issued takes nothing, rather than failing.
    #[tokio::test]
    async fn a_key_never_issued_takes_nothing() {
        let fx = fixture().await;

        let taken = fx
            .store
            .take(OrgSsoKey::OidcState(&state("never-issued-0123456789")))
            .await
            .unwrap();

        assert!(taken.is_none());
    }

    /// Taking a sign-in whose stored lapse time is in the past returns none.
    #[tokio::test]
    async fn a_lapsed_sign_in_is_not_taken() {
        let fx = fixture().await;
        let state = state("lapsing-state-0123456789");
        fx.store
            .save(
                OrgSsoKey::OidcState(&state),
                &org_oidc_sso_request(fx.acme, fx.okta),
            )
            .await
            .unwrap();
        fx.db
            .tamper("UPDATE org_sso_requests SET lapses_at = now() - interval '1 minute'")
            .await;

        let taken = fx.store.take(OrgSsoKey::OidcState(&state)).await.unwrap();

        assert!(taken.is_none());
    }

    /// Taking a sign-in whose stored tenant slug is malformed returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_row_holding_a_broken_value_is_refused() {
        let fx = fixture().await;
        let state = state("corrupt-state-0123456789");
        fx.store
            .save(
                OrgSsoKey::OidcState(&state),
                &org_oidc_sso_request(fx.acme, fx.okta),
            )
            .await
            .unwrap();
        fx.db
            .tamper("UPDATE org_sso_requests SET tenant_slug = 'Not A Slug!'")
            .await;

        let taken = fx.store.take(OrgSsoKey::OidcState(&state)).await;

        assert!(matches!(taken, Err(DomainError::Infrastructure(_))));
    }
}
