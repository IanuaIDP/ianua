//! The organization's own identity provider, at most one per organization,
//! kept in the platform database.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::organization::OrgIdentityProviderStore;
use ianua_domain::domains::organization::access::identity_provider::OrgIdentityProvider;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ConnectionId, OrganizationId};

use self::record::{ProviderColumns, ProviderRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps an organization to one provider.
const ONE_PER_ORGANIZATION: &str = "org_identity_providers_organization_key";

/// The Postgres store of organizations' identity providers.
pub struct PgOrgIdentityProviderStore {
    databases: Arc<Databases>,
}

impl PgOrgIdentityProviderStore {
    /// A store keeping providers in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl OrgIdentityProviderStore for PgOrgIdentityProviderStore {
    async fn find_for_organization(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Option<OrgIdentityProvider>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                ProviderRecord,
                "queries/org_identity_providers/of_organization.sql",
                organization_id.as_uuid()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        record.map(ProviderRecord::into_provider).transpose()
    }

    async fn save(&self, provider: &OrgIdentityProvider) -> Result<(), DomainError> {
        let columns = ProviderColumns::of(provider)?;
        let written = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            let attempt = sqlx::query_file!(
                "queries/org_identity_providers/save.sql",
                columns.id,
                columns.organization_id,
                columns.name,
                columns.saml,
                columns.oidc,
                columns.email_trust,
                columns.assurance_trust,
                columns.status,
                columns.created_at,
            )
            .execute(connection)
            .await;
            unique_on(attempt, ONE_PER_ORGANIZATION)
        })
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "organization-the-organization-has-an-identity-provider",
                "the organization has an identity provider already"
            ))),
        }
    }

    async fn delete(
        &self,
        organization_id: &OrganizationId,
        id: &ConnectionId,
    ) -> Result<(), DomainError> {
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/org_identity_providers/delete.sql",
                organization_id.as_uuid(),
                id.as_uuid()
            )
            .execute(connection)
            .await?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::organization::OrganizationStore;
    use ianua_domain::domains::federation::connection::{AssuranceTrust, EmailTrust};
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;
    use ianua_domain::domains::organization::access::identity_provider::OrgIdentityProviderRow;
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::Label;

    use super::*;
    use crate::postgres::organization::PgOrganizationStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::organization::{
        org_identity_provider_row, org_oidc_config, org_saml_config, organization_row,
    };

    struct Fixture {
        db: TestDb,
        store: PgOrgIdentityProviderStore,
        acme: OrganizationId,
    }

    /// A fresh database holding Acme, and the store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let acme = an_organization(&db, "acme").await;
        let store = PgOrgIdentityProviderStore::new(Arc::clone(&db.databases));
        Fixture { db, store, acme }
    }

    /// Saves an organization under `slug` through its store.
    async fn an_organization(db: &TestDb, slug: &str) -> OrganizationId {
        let organization = Organization::reconstitute(organization_row(slug, slug)).unwrap();
        PgOrganizationStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&organization)
            .await
            .unwrap();
        *organization.id()
    }

    fn provider(row: OrgIdentityProviderRow) -> OrgIdentityProvider {
        OrgIdentityProvider::reconstitute(row).unwrap()
    }

    fn assert_same(found: &OrgIdentityProvider, saved: &OrgIdentityProvider) {
        assert_eq!(found.id(), saved.id());
        assert_eq!(found.organization_id(), saved.organization_id());
        assert_eq!(found.name(), saved.name());
        assert_eq!(found.config(), saved.config());
        assert_eq!(found.email_trust(), saved.email_trust());
        assert_eq!(found.assurance_trust(), saved.assurance_trust());
        assert_eq!(found.status(), saved.status());
        assert_eq!(found.created_at(), saved.created_at());
    }

    /// Acme's Okta over SAML is found again for Acme, as it was saved.
    #[tokio::test]
    async fn a_saml_provider_is_found_for_its_organization() {
        let fx = fixture().await;
        let okta = provider(org_identity_provider_row(fx.acme, org_saml_config()));

        fx.store.save(&okta).await.unwrap();

        let found = fx.store.find_for_organization(&fx.acme).await.unwrap();
        assert_same(&found.unwrap(), &okta);
    }

    /// Acme's Okta over OIDC reads back with its sealed client secret.
    #[tokio::test]
    async fn an_oidc_provider_is_found_for_its_organization() {
        let fx = fixture().await;
        let okta = provider(org_identity_provider_row(fx.acme, org_oidc_config()));

        fx.store.save(&okta).await.unwrap();

        let found = fx.store.find_for_organization(&fx.acme).await.unwrap();
        assert_same(&found.unwrap(), &okta);
    }

    /// An organization without a provider finds none, rather than failing.
    #[tokio::test]
    async fn an_organization_without_a_provider_finds_none() {
        let fx = fixture().await;

        let found = fx.store.find_for_organization(&fx.acme).await.unwrap();

        assert!(found.is_none());
    }

    /// With Acme's provider saved, looking up Globex's provider returns none.
    #[tokio::test]
    async fn another_organizations_provider_is_not_found() {
        let fx = fixture().await;
        let globex = an_organization(&fx.db, "globex").await;
        let okta = provider(org_identity_provider_row(fx.acme, org_saml_config()));
        fx.store.save(&okta).await.unwrap();

        let found = fx.store.find_for_organization(&globex).await.unwrap();

        assert!(found.is_none());
    }

    /// An admin renames the provider, trusts its addresses and switches it
    /// on: saving again keeps the new values.
    #[tokio::test]
    async fn saving_again_keeps_the_new_values() {
        let fx = fixture().await;
        let okta = provider(org_identity_provider_row(fx.acme, org_saml_config()));
        fx.store.save(&okta).await.unwrap();
        let changed = provider(OrgIdentityProviderRow {
            id: *okta.id(),
            name: Label::new("name", "Acme Okta EU").unwrap(),
            config: org_oidc_config(),
            email_trust: EmailTrust::Authoritative,
            assurance_trust: AssuranceTrust::Trusted,
            status: ConnectionStatus::Active,
            ..org_identity_provider_row(fx.acme, org_saml_config())
        });

        fx.store.save(&changed).await.unwrap();

        let found = fx.store.find_for_organization(&fx.acme).await.unwrap();
        assert_same(&found.unwrap(), &changed);
    }

    /// Saving a second provider for Acme returns a conflict and preserves
    /// every checked field of its first provider.
    #[tokio::test]
    async fn a_second_provider_for_an_organization_is_refused() {
        let fx = fixture().await;
        let first = provider(org_identity_provider_row(fx.acme, org_saml_config()));
        let second = provider(org_identity_provider_row(fx.acme, org_oidc_config()));
        fx.store.save(&first).await.unwrap();

        let saved = fx.store.save(&second).await;

        assert!(matches!(saved, Err(DomainError::Conflict(_))));
        let found = fx.store.find_for_organization(&fx.acme).await.unwrap();
        assert_same(&found.unwrap(), &first);
    }

    /// A removed provider is gone, and removing it again is no error.
    #[tokio::test]
    async fn a_deleted_provider_is_gone() {
        let fx = fixture().await;
        let okta = provider(org_identity_provider_row(fx.acme, org_saml_config()));
        fx.store.save(&okta).await.unwrap();

        fx.store.delete(&fx.acme, okta.id()).await.unwrap();
        fx.store.delete(&fx.acme, okta.id()).await.unwrap();

        assert!(
            fx.store
                .find_for_organization(&fx.acme)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Deleting Acme's provider ID under Globex leaves it findable under Acme.
    #[tokio::test]
    async fn a_provider_is_not_deleted_through_another_organization() {
        let fx = fixture().await;
        let globex = an_organization(&fx.db, "globex").await;
        let okta = provider(org_identity_provider_row(fx.acme, org_saml_config()));
        fx.store.save(&okta).await.unwrap();

        fx.store.delete(&globex, okta.id()).await.unwrap();

        assert!(
            fx.store
                .find_for_organization(&fx.acme)
                .await
                .unwrap()
                .is_some()
        );
    }

    /// Reading a provider whose stored name was made empty returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_provider_is_refused() {
        let fx = fixture().await;
        let okta = provider(org_identity_provider_row(fx.acme, org_saml_config()));
        fx.store.save(&okta).await.unwrap();
        fx.db
            .tamper("UPDATE org_identity_providers SET name = ''")
            .await;

        let read = fx.store.find_for_organization(&fx.acme).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// Reading a provider whose stored SAML settings were changed to require
    /// signed requests returns an infrastructure error.
    #[tokio::test]
    async fn settings_asking_for_signed_requests_are_refused() {
        let fx = fixture().await;
        let okta = provider(org_identity_provider_row(fx.acme, org_saml_config()));
        fx.store.save(&okta).await.unwrap();
        fx.db
            .tamper(
                "UPDATE org_identity_providers \
                 SET saml = jsonb_set(saml, '{value,request_signing}', '\"signed\"')",
            )
            .await;

        let read = fx.store.find_for_organization(&fx.acme).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
