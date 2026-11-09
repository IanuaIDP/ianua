//! One person's accounts across an organization's tenants, kept as a group
//! under their shared address.
//!
//! The group is a platform row; each link names a tenant, so the links sit
//! under row-level security like every tenant table. A group spans tenants
//! on purpose, so its links are read and written as platform work.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::organization::{LinkedIdentityLookup, LinkedIdentityStore};
use ianua_domain::domains::organization::members::linked_identity::LinkedIdentity;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, OrganizationId};
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{LinkColumns, LinkRecord, LinkedIdentityRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps one group per address in an organization.
const ADDRESS_KEY: &str = "org_linked_identities_email_key";

/// The constraint that keeps a tenant account in one group.
const ACCOUNT_KEY: &str = "org_linked_identity_links_account_key";

/// How a save of a group came out.
enum Saved {
    /// The group and exactly its links are written.
    Whole,
    /// Another group of the organization holds the address.
    AddressTaken,
    /// One of its accounts is linked into another group.
    AccountTaken,
}

/// The Postgres store of linked identities.
pub struct PgLinkedIdentityStore {
    databases: Arc<Databases>,
}

impl PgLinkedIdentityStore {
    /// A store keeping linked identities in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// The read a tenant switch makes: the caller's group, by address.
pub struct PgLinkedIdentityLookup {
    databases: Arc<Databases>,
}

impl PgLinkedIdentityLookup {
    /// A lookup reading linked identities from `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// Saves the group's address and identity while reporting an occupied address separately.
async fn write_group(
    connection: &mut PgConnection,
    identity: &LinkedIdentity,
) -> Result<Uniqueness, sqlx::Error> {
    let group = sqlx::query_file!(
        "queries/org_linked_identities/save.sql",
        identity.id().as_uuid(),
        identity.organization_id().as_uuid(),
        identity.email().as_str(),
        identity.created_at()
    )
    .execute(connection)
    .await;
    unique_on(group, ADDRESS_KEY)
}

/// Replaces a group's links, reporting an account already held by another group.
async fn write_links(
    connection: &mut PgConnection,
    id: &Uuid,
    links: &LinkColumns,
) -> Result<Saved, sqlx::Error> {
    sqlx::query_file!(
        "queries/org_linked_identity_links/withdraw_others.sql",
        id,
        &links.tenant_ids
    )
    .execute(&mut *connection)
    .await?;
    let kept = sqlx::query_file!(
        "queries/org_linked_identity_links/keep.sql",
        id,
        &links.tenant_ids,
        &links.user_ids,
        &links.linked_at
    )
    .execute(connection)
    .await;
    Ok(match unique_on(kept, ACCOUNT_KEY)? {
        Uniqueness::Kept => Saved::Whole,
        Uniqueness::Taken => Saved::AccountTaken,
    })
}

/// The group `organization_id` keeps under `email`, with its links.
async fn group_under(
    databases: &Databases,
    organization_id: &OrganizationId,
    email: &Email,
) -> Result<Option<LinkedIdentity>, DomainError> {
    let read = scoped(databases, RowScope::Platform, async |connection| {
        let group = sqlx::query_file_as!(
            LinkedIdentityRecord,
            "queries/org_linked_identities/by_email.sql",
            organization_id.as_uuid(),
            email.as_str()
        )
        .fetch_optional(&mut *connection)
        .await?;
        let Some(group) = group else {
            return Ok(None);
        };
        let links = sqlx::query_file_as!(
            LinkRecord,
            "queries/org_linked_identity_links/of_group.sql",
            group.id
        )
        .fetch_all(connection)
        .await?;
        Ok(Some((group, links)))
    })
    .await?;
    read.map(|(group, links)| group.into_linked_identity(links))
        .transpose()
}

#[async_trait]
impl LinkedIdentityLookup for PgLinkedIdentityLookup {
    async fn find_by_email(
        &self,
        organization_id: &OrganizationId,
        email: &Email,
    ) -> Result<Option<LinkedIdentity>, DomainError> {
        group_under(&self.databases, organization_id, email).await
    }
}

#[async_trait]
impl LinkedIdentityStore for PgLinkedIdentityStore {
    async fn find_by_email(
        &self,
        organization_id: &OrganizationId,
        email: &Email,
    ) -> Result<Option<LinkedIdentity>, DomainError> {
        group_under(&self.databases, organization_id, email).await
    }

    async fn save(&self, identity: &LinkedIdentity) -> Result<(), DomainError> {
        let links = LinkColumns::of(identity);
        let id = identity.id().as_uuid();
        let saved = scoped(&self.databases, RowScope::Platform, async |connection| {
            if write_group(connection, identity).await? == Uniqueness::Taken {
                return Ok(Saved::AddressTaken);
            }
            write_links(connection, id, &links).await
        })
        .await?;
        match saved {
            Saved::Whole => Ok(()),
            Saved::AddressTaken => Err(DomainError::conflict(message!(
                "infra-another-group-of-the-organization-already",
                "another group of the organization already holds this address"
            ))),
            Saved::AccountTaken => Err(DomainError::conflict(message!(
                "infra-an-account-of-this-group-is",
                "an account of this group is linked into another group"
            ))),
        }
    }

    async fn delete(
        &self,
        organization_id: &OrganizationId,
        email: &Email,
    ) -> Result<(), DomainError> {
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file!(
                "queries/org_linked_identities/delete.sql",
                organization_id.as_uuid(),
                email.as_str()
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
    use ianua_app::ports::tenant::TenantStore;
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::domains::organization::members::linked_identity::LinkedIdentityRow;
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::{LinkedIdentityId, TenantId};

    use super::*;
    use crate::postgres::organization::PgOrganizationStore;
    use crate::postgres::tenant::PgTenantStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::organization::{
        linked_identity_row, linked_identity_row_of, organization_row,
    };
    use crate::test_support::rows::tenant::tenant_row;

    struct Fixture {
        db: TestDb,
        store: PgLinkedIdentityStore,
        acme: OrganizationId,
        sales: TenantId,
        design: TenantId,
    }

    /// A fresh database holding Acme with two tenants, and the store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let organization = Organization::reconstitute(organization_row("acme", "Acme")).unwrap();
        PgOrganizationStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&organization)
            .await
            .unwrap();
        let acme = *organization.id();
        let tenants = PgTenantStore::new(Arc::clone(&db.databases), DomainLimits::default());
        let mut ids = Vec::new();
        for slug in ["sales", "design"] {
            let tenant = Tenant::reconstitute(tenant_row(acme, slug)).unwrap();
            tenants.save(&tenant).await.unwrap();
            ids.push(*tenant.id());
        }
        let store = PgLinkedIdentityStore::new(Arc::clone(&db.databases));
        Fixture {
            db,
            store,
            acme,
            sales: ids.remove(0),
            design: ids.remove(0),
        }
    }

    fn group(row: LinkedIdentityRow) -> LinkedIdentity {
        LinkedIdentity::reconstitute(row).unwrap()
    }

    fn ann() -> Email {
        Email::new("ann@acme.example").unwrap()
    }

    fn tenants_of(identity: &LinkedIdentity) -> Vec<TenantId> {
        identity
            .links()
            .iter()
            .map(|link| *link.tenant_id())
            .collect()
    }

    /// Ann links her accounts in two tenants: the group is found by her
    /// address, by the store and by the tenant switch's lookup, with both
    /// links as they were made.
    #[tokio::test]
    async fn a_saved_group_is_found_by_its_address_with_its_links() {
        let fx = fixture().await;
        let saved = group(linked_identity_row(
            fx.acme,
            "ann@acme.example",
            &[fx.sales, fx.design],
        ));

        fx.store.save(&saved).await.unwrap();

        let found = fx
            .store
            .find_by_email(&fx.acme, &ann())
            .await
            .unwrap()
            .unwrap();
        let looked_up = PgLinkedIdentityLookup::new(Arc::clone(&fx.db.databases))
            .find_by_email(&fx.acme, &ann())
            .await
            .unwrap()
            .unwrap();
        for read in [&found, &looked_up] {
            assert_eq!(read.id(), saved.id());
            assert_eq!(read.created_at(), saved.created_at());
            assert_eq!(tenants_of(read), [fx.sales, fx.design]);
            for (read_link, saved_link) in read.links().iter().zip(saved.links()) {
                assert_eq!(read_link.user_id(), saved_link.user_id());
                assert_eq!(read_link.linked_at(), saved_link.linked_at());
            }
        }
    }

    /// An address no group holds, or one held in another organization,
    /// finds nothing.
    #[tokio::test]
    async fn an_unknown_address_finds_no_group() {
        let fx = fixture().await;
        fx.store
            .save(&group(linked_identity_row(
                fx.acme,
                "ann@acme.example",
                &[fx.sales],
            )))
            .await
            .unwrap();

        let elsewhere = fx
            .store
            .find_by_email(&OrganizationId::new(), &ann())
            .await
            .unwrap();
        let nobody = fx
            .store
            .find_by_email(&fx.acme, &Email::new("bob@acme.example").unwrap())
            .await
            .unwrap();

        assert!(elsewhere.is_none());
        assert!(nobody.is_none());
    }

    /// Ann unlinks one tenant: saving the group again keeps exactly the
    /// links it holds now.
    #[tokio::test]
    async fn saving_again_keeps_exactly_the_links_it_holds() {
        let fx = fixture().await;
        let both = group(linked_identity_row(
            fx.acme,
            "ann@acme.example",
            &[fx.sales, fx.design],
        ));
        fx.store.save(&both).await.unwrap();
        let one = group(LinkedIdentityRow {
            id: *both.id(),
            ..linked_identity_row(fx.acme, "ann@acme.example", &[fx.design])
        });

        fx.store.save(&one).await.unwrap();

        let found = fx
            .store
            .find_by_email(&fx.acme, &ann())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tenants_of(&found), [fx.design]);
    }

    /// Saving a second group under Ann's address returns a conflict and
    /// leaves the first group's ID stored.
    #[tokio::test]
    async fn a_second_group_under_one_address_is_refused() {
        let fx = fixture().await;
        let first = group(linked_identity_row(
            fx.acme,
            "ann@acme.example",
            &[fx.sales],
        ));
        fx.store.save(&first).await.unwrap();
        let second = group(LinkedIdentityRow {
            id: LinkedIdentityId::new(),
            ..linked_identity_row(fx.acme, "ann@acme.example", &[fx.design])
        });

        let saved = fx.store.save(&second).await;

        assert!(matches!(saved, Err(DomainError::Conflict(_))));
        let kept = fx
            .store
            .find_by_email(&fx.acme, &ann())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(kept.id(), first.id());
    }

    /// Saving a second group containing an account already linked to
    /// Ann's group returns a conflict.
    #[tokio::test]
    async fn an_account_in_another_group_is_refused() {
        let fx = fixture().await;
        let ann_group = group(linked_identity_row(
            fx.acme,
            "ann@acme.example",
            &[fx.sales],
        ));
        fx.store.save(&ann_group).await.unwrap();
        let taken = ann_group
            .links()
            .first()
            .map(|link| *link.user_id())
            .unwrap();
        let bob = group(linked_identity_row_of(
            fx.acme,
            "bob@acme.example",
            &[(fx.sales, taken)],
        ));

        let refused = fx.store.save(&bob).await;

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
    }

    /// Removing the group under Ann's address removes it with its links.
    #[tokio::test]
    async fn a_deleted_group_is_gone() {
        let fx = fixture().await;
        fx.store
            .save(&group(linked_identity_row(
                fx.acme,
                "ann@acme.example",
                &[fx.sales],
            )))
            .await
            .unwrap();

        fx.store.delete(&fx.acme, &ann()).await.unwrap();

        assert!(
            fx.store
                .find_by_email(&fx.acme, &ann())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Reading a linked group whose stored links reuse one user ID across
    /// both tenants returns an infrastructure error.
    #[tokio::test]
    async fn a_group_that_breaks_a_rule_is_refused() {
        let fx = fixture().await;
        fx.store
            .save(&group(linked_identity_row(
                fx.acme,
                "ann@acme.example",
                &[fx.sales, fx.design],
            )))
            .await
            .unwrap();
        fx.db
            .tamper(
                "ALTER TABLE org_linked_identity_links \
                 DROP CONSTRAINT org_linked_identity_links_account_key",
            )
            .await;
        fx.db
            .tamper(
                "UPDATE org_linked_identity_links \
                 SET user_id = '00000000-0000-0000-0000-000000000001'",
            )
            .await;

        let read = fx.store.find_by_email(&fx.acme, &ann()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
