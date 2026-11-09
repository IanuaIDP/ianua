//! The links between a tenant's accounts and who their owners are at a
//! connection's provider: one per subject and one per account on each
//! connection, each kept by its own constraint.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::federation::FederatedLinkStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::federation::link::FederatedLink;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ConnectionId, FederatedSubject, UserId};

use self::record::{LinkColumns, LinkRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a subject to one account on a connection.
const SUBJECT_KEY: &str = "federated_links_subject_key";

/// The constraint that keeps an account to one subject on a connection.
const ACCOUNT_KEY: &str = "federated_links_pkey";

/// The Postgres store of federated links.
pub struct PgFederatedLinkStore {
    databases: Arc<Databases>,
}

impl PgFederatedLinkStore {
    /// A store keeping links in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgFederatedLinkStore {}

#[async_trait]
impl FederatedLinkStore for PgFederatedLinkStore {
    async fn find_by_subject(
        &self,
        tenant_id: &ScopedTenant,
        connection_id: &ConnectionId,
        subject: &FederatedSubject,
    ) -> Result<Option<FederatedLink<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    LinkRecord,
                    "queries/federated_links/by_subject.sql",
                    tenant_id.as_uuid(),
                    connection_id.as_uuid(),
                    subject.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(LinkRecord::into_link).transpose()
    }

    async fn find_by_user(
        &self,
        tenant_id: &ScopedTenant,
        connection_id: &ConnectionId,
        user_id: &UserId,
    ) -> Result<Option<FederatedLink<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    LinkRecord,
                    "queries/federated_links/by_user.sql",
                    tenant_id.as_uuid(),
                    connection_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(LinkRecord::into_link).transpose()
    }

    async fn list_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<FederatedLink<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    LinkRecord,
                    "queries/federated_links/of_user.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records.into_iter().map(LinkRecord::into_link).collect()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        link: &FederatedLink<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = LinkColumns::of(link);
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = sqlx::query_file!(
                    "queries/federated_links/link.sql",
                    tenant_id.as_uuid(),
                    columns.connection_id,
                    columns.subject,
                    columns.user_id,
                    columns.linked_at,
                    columns.confirmed_at,
                )
                .execute(connection)
                .await;
                unique_on(attempt, SUBJECT_KEY)
                    .or_else(|error| unique_on(Err::<(), _>(error), ACCOUNT_KEY))
            },
        )
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-the-subject-or-the-account-is",
                "the subject or the account is already linked on this connection"
            ))),
        }
    }

    async fn update(
        &self,
        tenant_id: &ScopedTenant,
        link: &FederatedLink<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = LinkColumns::of(link);
        let changed = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/federated_links/confirm.sql",
                    tenant_id.as_uuid(),
                    columns.connection_id,
                    columns.user_id,
                    columns.confirmed_at,
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        if changed.rows_affected() == 0 {
            return Err(DomainError::infra_msg("no such link is kept"));
        }
        Ok(())
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        connection_id: &ConnectionId,
        user_id: &UserId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/federated_links/delete.sql",
                    tenant_id.as_uuid(),
                    connection_id.as_uuid(),
                    user_id.as_uuid()
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::federation::ConnectionStore;
    use ianua_app::ports::identity::UserStore;
    use ianua_domain::domains::federation::connection::FederatedIdpConnection;
    use ianua_domain::domains::federation::link::FederatedLinkRow;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::shared::config::DomainLimits;

    use super::*;
    use crate::postgres::federation::PgConnectionStore;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::federation::{connection_row, link_row, saml_config};
    use crate::test_support::rows::identity::user_row;

    struct Fixture {
        db: TestDb,
        store: PgFederatedLinkStore,
        tenant: ScopedTenant,
        okta: ConnectionId,
        ann: UserId,
        bob: UserId,
    }

    /// A fresh database holding a tenant with Okta and two accounts, Ann
    /// and Bob, and the store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = tenant();
        let okta = a_connection(&db, &tenant).await;
        let users = PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default());
        let [ann, bob] = ["ann@acme.example", "bob@acme.example"]
            .map(|email| User::reconstitute(user_row(email)).unwrap());
        users.save(&tenant, &ann).await.unwrap();
        users.save(&tenant, &bob).await.unwrap();
        Fixture {
            store: PgFederatedLinkStore::new(Arc::clone(&db.databases)),
            okta,
            ann: *ann.id(),
            bob: *bob.id(),
            tenant,
            db,
        }
    }

    /// Saves a connection to Okta in `tenant`.
    async fn a_connection(db: &TestDb, tenant: &ScopedTenant) -> ConnectionId {
        let okta =
            FederatedIdpConnection::reconstitute(connection_row("Okta", saml_config())).unwrap();
        PgConnectionStore::new(Arc::clone(&db.databases))
            .save(tenant, &okta)
            .await
            .unwrap();
        *okta.id()
    }

    fn link(row: FederatedLinkRow) -> FederatedLink<ResolvedTenant> {
        FederatedLink::reconstitute(row).unwrap()
    }

    fn subject(text: &str) -> FederatedSubject {
        FederatedSubject::new(text).unwrap()
    }

    /// Ann's link is found by her subject at Okta and by her account, as it
    /// was saved.
    #[tokio::test]
    async fn a_link_is_found_by_subject_and_by_account() {
        let fx = fixture().await;
        let ann = link(link_row(fx.okta, "okta|ann", fx.ann));
        fx.store.save(&fx.tenant, &ann).await.unwrap();

        let by_subject = fx
            .store
            .find_by_subject(&fx.tenant, &fx.okta, &subject("okta|ann"))
            .await
            .unwrap()
            .unwrap();
        let by_user = fx
            .store
            .find_by_user(&fx.tenant, &fx.okta, &fx.ann)
            .await
            .unwrap()
            .unwrap();

        for found in [&by_subject, &by_user] {
            assert_eq!(found.user_id(), &fx.ann);
            assert_eq!(found.subject(), ann.subject());
            assert_eq!(found.linked_at(), ann.linked_at());
            assert_eq!(found.confirmed_at(), ann.confirmed_at());
        }
    }

    /// A subject nobody is linked by, and an account with no link, find
    /// nothing rather than failing.
    #[tokio::test]
    async fn an_unknown_subject_or_account_finds_nothing() {
        let fx = fixture().await;

        let by_subject = fx
            .store
            .find_by_subject(&fx.tenant, &fx.okta, &subject("okta|nobody"))
            .await
            .unwrap();
        let by_user = fx
            .store
            .find_by_user(&fx.tenant, &fx.okta, &fx.ann)
            .await
            .unwrap();

        assert!(by_subject.is_none());
        assert!(by_user.is_none());
    }

    /// Linking Ann's existing Okta subject to Bob or another subject to
    /// Ann returns a conflict in both cases.
    #[tokio::test]
    async fn a_subject_or_account_linked_twice_is_refused() {
        let fx = fixture().await;
        fx.store
            .save(&fx.tenant, &link(link_row(fx.okta, "okta|ann", fx.ann)))
            .await
            .unwrap();

        let same_subject = fx
            .store
            .save(&fx.tenant, &link(link_row(fx.okta, "okta|ann", fx.bob)))
            .await;
        let same_account = fx
            .store
            .save(&fx.tenant, &link(link_row(fx.okta, "okta|mallory", fx.ann)))
            .await;

        assert!(matches!(same_subject, Err(DomainError::Conflict(_))));
        assert!(matches!(same_account, Err(DomainError::Conflict(_))));
    }

    /// Ann's links at two connections are listed oldest first.
    #[tokio::test]
    async fn an_accounts_links_are_listed_oldest_first() {
        let fx = fixture().await;
        let entra = a_connection(&fx.db, &fx.tenant).await;
        let later = link(FederatedLinkRow {
            linked_at: at(10),
            confirmed_at: at(10),
            ..link_row(fx.okta, "okta|ann", fx.ann)
        });
        let earlier = link(link_row(entra, "entra|ann", fx.ann));
        fx.store.save(&fx.tenant, &later).await.unwrap();
        fx.store.save(&fx.tenant, &earlier).await.unwrap();

        let held = fx.store.list_by_user(&fx.tenant, &fx.ann).await.unwrap();

        let connections: Vec<ConnectionId> =
            held.iter().map(|link| *link.connection_id()).collect();
        assert_eq!(connections, [entra, fx.okta]);
    }

    /// Ann confirms her link again: the new time is kept, and when it was
    /// made stays.
    #[tokio::test]
    async fn an_update_keeps_the_new_confirmation() {
        let fx = fixture().await;
        let ann = link(link_row(fx.okta, "okta|ann", fx.ann));
        fx.store.save(&fx.tenant, &ann).await.unwrap();
        let confirmed = link(FederatedLinkRow {
            confirmed_at: at(30),
            ..link_row(fx.okta, "okta|ann", fx.ann)
        });

        fx.store.update(&fx.tenant, &confirmed).await.unwrap();

        let found = fx
            .store
            .find_by_user(&fx.tenant, &fx.okta, &fx.ann)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.confirmed_at(), at(30));
        assert_eq!(found.linked_at(), at(0));
    }

    /// Updating confirmation on an unsaved link returns an infrastructure
    /// error.
    #[tokio::test]
    async fn an_update_of_a_link_never_kept_is_refused() {
        let fx = fixture().await;

        let updated = fx
            .store
            .update(&fx.tenant, &link(link_row(fx.okta, "okta|ann", fx.ann)))
            .await;

        assert!(matches!(updated, Err(DomainError::Infrastructure(_))));
    }

    /// Unlinking Ann leaves Okta unable to sign her in, and leaves Bob's
    /// link.
    #[tokio::test]
    async fn a_deleted_link_is_gone() {
        let fx = fixture().await;
        fx.store
            .save(&fx.tenant, &link(link_row(fx.okta, "okta|ann", fx.ann)))
            .await
            .unwrap();
        fx.store
            .save(&fx.tenant, &link(link_row(fx.okta, "okta|bob", fx.bob)))
            .await
            .unwrap();

        fx.store
            .delete(&fx.tenant, &fx.okta, &fx.ann)
            .await
            .unwrap();

        let ann = fx
            .store
            .find_by_subject(&fx.tenant, &fx.okta, &subject("okta|ann"))
            .await
            .unwrap();
        let bob = fx
            .store
            .find_by_subject(&fx.tenant, &fx.okta, &subject("okta|bob"))
            .await
            .unwrap();
        assert!(ann.is_none());
        assert!(bob.is_some());
    }

    /// Removing Okta removes every link through it.
    #[tokio::test]
    async fn a_removed_connection_takes_its_links() {
        let fx = fixture().await;
        fx.store
            .save(&fx.tenant, &link(link_row(fx.okta, "okta|ann", fx.ann)))
            .await
            .unwrap();

        PgConnectionStore::new(Arc::clone(&fx.db.databases))
            .delete(&fx.tenant, &fx.okta)
            .await
            .unwrap();

        let held = fx.store.list_by_user(&fx.tenant, &fx.ann).await.unwrap();
        assert!(held.is_empty());
    }

    /// Looking up Acme's connection and subject from Globex returns no link.
    #[tokio::test]
    async fn another_tenants_link_is_not_found() {
        let fx = fixture().await;
        fx.store
            .save(&fx.tenant, &link(link_row(fx.okta, "okta|ann", fx.ann)))
            .await
            .unwrap();

        let found = fx
            .store
            .find_by_subject(&tenant(), &fx.okta, &subject("okta|ann"))
            .await
            .unwrap();

        assert!(found.is_none());
    }

    /// A link with an empty stored subject fails to load as corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_link_is_refused() {
        let fx = fixture().await;
        fx.store
            .save(&fx.tenant, &link(link_row(fx.okta, "okta|ann", fx.ann)))
            .await
            .unwrap();
        fx.db
            .tamper("UPDATE federated_links SET subject = ''")
            .await;

        let read = fx.store.find_by_user(&fx.tenant, &fx.okta, &fx.ann).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
