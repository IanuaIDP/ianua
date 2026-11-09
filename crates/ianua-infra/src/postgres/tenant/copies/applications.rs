//! The OAuth applications part of a clone: every active client, without
//! its secret.
//!
//! A client keeps its public client id in the target, and is matched there
//! by it, so a copy made again writes over the one it made before. A
//! client that signs in with a secret gets a fresh one nobody is shown: it
//! stays a confidential client, and works once someone in the target
//! rotates its secret. A secret the target already gave the client is kept.
//! Keys and certificate subjects are public, so they come as they are. A
//! client that registered itself comes managed by the target's admins, as
//! its registration token stays behind with the source. A client the target
//! revoked stays revoked, and the source's revoked ones are not copied.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_app::listing::SortOrder;
use ianua_app::ports::oauth::{ClientSecretGenerator, OAuthClientStore as _};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::oauth::clients::client::{OAuthClient, OAuthClientRow};
use ianua_domain::domains::oauth::clients::credential::{ClientCredential, ClientSecret};
use ianua_domain::domains::oauth::clients::registration::ClientManagement;
use ianua_domain::domains::oauth::clients::status::OAuthClientStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::OAuthClientId;
use time::OffsetDateTime;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::oauth::PgOAuthClientStore;
use crate::postgres::tenant::copies::{Pair, all_of, whole_part};

/// Copies a tenant's OAuth applications.
pub(crate) struct ApplicationCopy {
    clients: PgOAuthClientStore,
    secrets: Arc<dyn ClientSecretGenerator>,
}

impl ApplicationCopy {
    /// A copy reading and writing the tenants of `databases`, with fresh
    /// secrets from `secrets`.
    pub(crate) fn new(databases: &Arc<Databases>, secrets: Arc<dyn ClientSecretGenerator>) -> Self {
        Self {
            clients: PgOAuthClientStore::new(Arc::clone(databases)),
            secrets,
        }
    }

    /// Gives `pair`'s target the source's active clients.
    pub(crate) async fn copy(&self, pair: &Pair) -> Result<(), DomainError> {
        let source = self
            .clients_of(&pair.source, Some(OAuthClientStatus::Active))
            .await?;
        let target = self.clients_of(&pair.target, None).await?;
        let held: HashMap<&str, &OAuthClient<ResolvedTenant>> = target
            .iter()
            .map(|client| (client.client_id_value().as_str(), client))
            .collect();
        let now = clock::now();
        for client in &source {
            let kept = held.get(client.client_id_value().as_str()).copied();
            if kept.is_some_and(|held| held.status() == OAuthClientStatus::Revoked) {
                continue;
            }
            let credential = self.credential_for(client, kept).await?;
            let copy = client_for_target(client, kept, credential, now)?;
            self.clients.save(&pair.target, &copy).await?;
        }
        Ok(())
    }

    /// The clients of `tenant`, of `status` or of any.
    async fn clients_of(
        &self,
        tenant: &ScopedTenant,
        status: Option<OAuthClientStatus>,
    ) -> Result<Vec<OAuthClient<ResolvedTenant>>, DomainError> {
        let page = self
            .clients
            .list_all(tenant, status, &SortOrder::default(), &whole_part())
            .await?;
        all_of(page, "OAuth applications")
    }

    /// How the copy of `client` proves itself: the secret the target's
    /// `kept` copy already has, a fresh one nobody holds, or the same keys,
    /// certificate or nothing as the source's.
    async fn credential_for(
        &self,
        client: &OAuthClient<ResolvedTenant>,
        kept: Option<&OAuthClient<ResolvedTenant>>,
    ) -> Result<ClientCredential, DomainError> {
        let ClientCredential::Secret(secret) = client.credential() else {
            return Ok(client.credential().clone());
        };
        if let Some(ClientCredential::Secret(own)) = kept.map(OAuthClient::credential) {
            return Ok(ClientCredential::Secret(own.clone()));
        }
        let fresh = self.secrets.generate_secret().await?;
        Ok(ClientCredential::Secret(ClientSecret::new(
            fresh.secret_hash,
            secret.sent_by(),
        )))
    }
}

/// `client` as the target keeps it, proving itself with `credential`,
/// managed by the target's admins, under the id of `kept` when the target
/// has it.
fn client_for_target(
    client: &OAuthClient<ResolvedTenant>,
    kept: Option<&OAuthClient<ResolvedTenant>>,
    credential: ClientCredential,
    now: OffsetDateTime,
) -> Result<OAuthClient<ResolvedTenant>, DomainError> {
    OAuthClient::reconstitute(OAuthClientRow {
        id: kept.map_or_else(OAuthClientId::new, |held| *held.id()),
        client_id_value: client.client_id_value().clone(),
        credential,
        name: client.name().clone(),
        redirect_uris: client.redirect_uris().to_vec(),
        post_logout_redirect_uris: client.post_logout_redirect_uris().to_vec(),
        grant_types: client.grant_types().to_vec(),
        scopes: client.scopes().to_vec(),
        settings: client.settings().clone(),
        management: ClientManagement::ByAdmins,
        status: OAuthClientStatus::Active,
        created_at: kept.map_or(now, OAuthClient::created_at),
    })
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::oauth::InitialAccessTokenStore as _;
    use ianua_app::ports::tenant::ClonePartCopier as _;
    use ianua_domain::domains::oauth::clients::client::GrantType;
    use ianua_domain::domains::oauth::clients::registration::InitialAccessToken;
    use ianua_domain::domains::tenant::clone::{ClonePart, TenantClone};
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::postgres::oauth::PgInitialAccessTokenStore;
    use crate::postgres::tenant::copies::tests::{clone_between, copier};
    use crate::test_support::TestDb;
    use crate::test_support::rows::oauth::{hash, initial_access_token_row, oauth_client_row};

    /// Two tenants of one clone, and the copy's store over them.
    struct Tenants {
        db: TestDb,
        clients: PgOAuthClientStore,
        clone: TenantClone,
        source: ScopedTenant,
        target: ScopedTenant,
    }

    async fn tenants() -> Tenants {
        let db = TestDb::fresh().await;
        let clone = clone_between(TenantId::new(), TenantId::new());
        Tenants {
            clients: PgOAuthClientStore::new(Arc::clone(&db.databases)),
            source: ScopedTenant::for_background(*clone.source()),
            target: ScopedTenant::for_background(*clone.target()),
            clone,
            db,
        }
    }

    impl Tenants {
        async fn copied(&self) {
            copier(&self.db)
                .copy(&self.clone, ClonePart::OAuthApplications)
                .await
                .unwrap();
        }

        async fn saved(&self, row: OAuthClientRow) -> OAuthClient<ResolvedTenant> {
            let client = OAuthClient::reconstitute(row).unwrap();
            self.clients.save(&self.source, &client).await.unwrap();
            client
        }

        async fn in_target(&self) -> Vec<OAuthClient<ResolvedTenant>> {
            self.clients
                .list_all(&self.target, None, &SortOrder::default(), &whole_part())
                .await
                .unwrap()
                .items
        }
    }

    /// Copying a confidential client preserves its public client id and
    /// secret-based credential kind while giving the target a different secret.
    #[tokio::test]
    async fn a_client_arrives_without_its_secret() {
        let at = tenants().await;
        let source = at
            .saved(oauth_client_row("portal", &[GrantType::AuthorizationCode]))
            .await;

        at.copied().await;

        let copied = at.in_target().await;
        assert_eq!(copied.len(), 1);
        assert_eq!(copied[0].client_id_value(), source.client_id_value());
        let (ClientCredential::Secret(theirs), ClientCredential::Secret(ours)) =
            (source.credential(), copied[0].credential())
        else {
            panic!("both clients keep a secret");
        };
        assert_ne!(theirs.current(), ours.current());
    }

    /// A self-registered client becomes administrator-managed in the target.
    #[tokio::test]
    async fn a_copied_client_is_managed_by_the_admins() {
        let at = tenants().await;
        let admitted =
            InitialAccessToken::reconstitute(initial_access_token_row("partners")).unwrap();
        PgInitialAccessTokenStore::new(Arc::clone(&at.db.databases))
            .save(&at.source, &admitted)
            .await
            .unwrap();
        at.saved(OAuthClientRow {
            management: ClientManagement::ByItself {
                registration_token: hash("registration"),
                admitted_with: *admitted.id(),
            },
            ..oauth_client_row("portal", &[GrantType::AuthorizationCode])
        })
        .await;

        at.copied().await;

        assert_eq!(
            at.in_target().await[0].management(),
            &ClientManagement::ByAdmins
        );
    }

    /// A copy made twice leaves one client, keeping the secret the first
    /// copy gave it.
    #[tokio::test]
    async fn copying_twice_leaves_one_copy_with_its_secret() {
        let at = tenants().await;
        at.saved(oauth_client_row("portal", &[GrantType::AuthorizationCode]))
            .await;

        at.copied().await;
        let first = at.in_target().await;
        at.copied().await;
        let second = at.in_target().await;

        assert_eq!(second.len(), 1);
        assert_eq!(first[0].credential(), second[0].credential());
    }

    /// A revoked source client is omitted from the copy, leaving the target
    /// without OAuth clients.
    #[tokio::test]
    async fn a_revoked_client_is_not_copied() {
        let at = tenants().await;
        at.saved(OAuthClientRow {
            status: OAuthClientStatus::Revoked,
            ..oauth_client_row("retired", &[GrantType::AuthorizationCode])
        })
        .await;

        at.copied().await;

        assert!(at.in_target().await.is_empty());
    }
}
