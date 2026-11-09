//! Pending email address changes on both planes: the two stores of
//! `ports/shared/email_change.rs`, sharing one mapping.
//!
//! A tenant user's change is a tenant row, under row-level security, in the
//! database the tenant lives in, and goes with the user. An organization
//! member's or an operator's is a platform row, kept by the person alone.
//! Either way at most one change waits per person, a new one replacing it,
//! and only the hashes of the mailed links are kept.
//!
//! A change keeps its cancel link for life. Once confirmed or cancelled it
//! takes nothing new from a copy of itself read before, and the save is
//! refused, so of a confirmation and a cancellation read together, or two
//! confirmations, only the first is kept; the other's unit of work rolls
//! back with the refusal. A new change, with a cancel link of its own,
//! still replaces it.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::shared::{OrgEmailChangeStore, TenantEmailChangeStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::identity::account::email_change::PendingEmailChange;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{PrincipalId, TokenHash, UserId};

use self::record::{ChangeColumns, ChangeRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The change `record` holds, if any, rebuilt through the domain's checks.
fn rebuilt(record: Option<ChangeRecord>) -> Result<Option<PendingEmailChange>, DomainError> {
    record.map(ChangeRecord::into_change).transpose()
}

/// A save that wrote `rows`, refused when it wrote none: the change it
/// holds was confirmed or cancelled since it was read.
fn ensure_pending_change_saved(rows: u64) -> Result<(), DomainError> {
    match rows {
        0 => Err(DomainError::conflict(message!(
            "infra-the-address-change-was-confirmed-or",
            "the address change was confirmed or cancelled already"
        ))),
        _ => Ok(()),
    }
}

/// The Postgres store of tenant users' pending email changes.
pub struct PgTenantEmailChangeStore {
    databases: Arc<Databases>,
}

impl PgTenantEmailChangeStore {
    /// A store keeping tenant users' changes in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgTenantEmailChangeStore {}

#[async_trait]
impl TenantEmailChangeStore for PgTenantEmailChangeStore {
    async fn find_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<PendingEmailChange>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ChangeRecord,
                    "queries/email_changes/of_user.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        rebuilt(record)
    }

    async fn find_by_token_hash(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<PendingEmailChange>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ChangeRecord,
                    "queries/email_changes/by_token.sql",
                    tenant_id.as_uuid(),
                    token_hash.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        rebuilt(record)
    }

    async fn find_by_cancel_token_hash(
        &self,
        tenant_id: &ScopedTenant,
        cancel_token_hash: &TokenHash,
    ) -> Result<Option<PendingEmailChange>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ChangeRecord,
                    "queries/email_changes/by_cancel_token.sql",
                    tenant_id.as_uuid(),
                    cancel_token_hash.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        rebuilt(record)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        change: &PendingEmailChange,
    ) -> Result<(), DomainError> {
        let columns = ChangeColumns::of(change);
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/email_changes/save.sql",
                    tenant_id.as_uuid(),
                    columns.principal_id,
                    columns.from_email,
                    columns.new_email,
                    columns.token_hash,
                    columns.cancel_token_hash,
                    columns.state,
                    columns.settled_at,
                    columns.created_at,
                    columns.expires_at,
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        ensure_pending_change_saved(written.rows_affected())
    }

    async fn delete(&self, tenant_id: &ScopedTenant, user_id: &UserId) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/email_changes/delete.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }
}

/// The Postgres store of organization members' and operators' pending
/// email changes, in the platform database.
pub struct PgOrgEmailChangeStore {
    databases: Arc<Databases>,
}

impl PgOrgEmailChangeStore {
    /// A store keeping management accounts' changes in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl OrgEmailChangeStore for PgOrgEmailChangeStore {
    async fn find_by_principal(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Option<PendingEmailChange>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                ChangeRecord,
                "queries/org_email_changes/of_principal.sql",
                principal_id.as_uuid()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        rebuilt(record)
    }

    async fn find_by_token_hash(
        &self,
        token_hash: &TokenHash,
    ) -> Result<Option<PendingEmailChange>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                ChangeRecord,
                "queries/org_email_changes/by_token.sql",
                token_hash.as_str()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        rebuilt(record)
    }

    async fn find_by_cancel_token_hash(
        &self,
        cancel_token_hash: &TokenHash,
    ) -> Result<Option<PendingEmailChange>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                ChangeRecord,
                "queries/org_email_changes/by_cancel_token.sql",
                cancel_token_hash.as_str()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        rebuilt(record)
    }

    async fn save(&self, change: &PendingEmailChange) -> Result<(), DomainError> {
        let columns = ChangeColumns::of(change);
        let written = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/org_email_changes/save.sql",
                columns.principal_id,
                columns.from_email,
                columns.new_email,
                columns.token_hash,
                columns.cancel_token_hash,
                columns.state,
                columns.settled_at,
                columns.created_at,
                columns.expires_at,
            )
            .execute(connection)
            .await
        })
        .await?;
        ensure_pending_change_saved(written.rows_affected())
    }

    async fn delete(&self, principal_id: &PrincipalId) -> Result<(), DomainError> {
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/org_email_changes/delete.sql",
                principal_id.as_uuid()
            )
            .execute(connection)
            .await
            .map(|_| ())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::identity::UserStore;
    use ianua_domain::domains::identity::account::email_change::{ChangeState, EmailChangeRow};
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::{OrgUserId, TenantId};

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::identity::user_row;
    use crate::test_support::rows::shared::{email_change_row, link_hash};

    struct Fixture {
        database: TestDb,
        users: PgUserStore,
        store: PgTenantEmailChangeStore,
        org: PgOrgEmailChangeStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, one tenant, and the stores on it.
    async fn fixture() -> Fixture {
        let database = TestDb::fresh().await;
        let databases = &database.databases;
        Fixture {
            users: PgUserStore::new(Arc::clone(databases), DomainLimits::default()),
            store: PgTenantEmailChangeStore::new(Arc::clone(databases)),
            org: PgOrgEmailChangeStore::new(Arc::clone(databases)),
            tenant: ScopedTenant::for_background(TenantId::new()),
            database,
        }
    }

    impl Fixture {
        /// Ann, a user saved in `tenant`.
        async fn ann(&self, tenant: &ScopedTenant) -> UserId {
            let ann: User<ResolvedTenant> =
                User::reconstitute(user_row("ann@acme.example")).unwrap();
            self.users.save(tenant, &ann).await.unwrap();
            *ann.id()
        }
    }

    fn change(row: EmailChangeRow) -> PendingEmailChange {
        PendingEmailChange::reconstitute(row).unwrap()
    }

    /// Ann's change is found by her, by its link and by its cancel link, as
    /// it was saved.
    #[tokio::test]
    async fn a_users_change_is_found_by_user_and_by_its_links() {
        let db = fixture().await;
        let ann = db.ann(&db.tenant).await;
        let asked = change(email_change_row(ann.into(), "ann@new.example", "link"));

        db.store.save(&db.tenant, &asked).await.unwrap();

        let by_user = db.store.find_by_user(&db.tenant, &ann).await.unwrap();
        let by_link = db
            .store
            .find_by_token_hash(&db.tenant, &link_hash("link"))
            .await
            .unwrap();
        let by_cancel = db
            .store
            .find_by_cancel_token_hash(&db.tenant, &link_hash("cancel-link"))
            .await
            .unwrap();
        for found in [by_user, by_link, by_cancel] {
            let found = found.unwrap();
            assert_eq!(found.principal_id(), asked.principal_id());
            assert_eq!(found.new_email(), asked.new_email());
            assert_eq!(found.from_email(), asked.from_email());
            assert_eq!(found.expires_at(), asked.expires_at());
            assert_eq!(found.stage(), ChangeState::Waiting);
        }
    }

    /// A link nobody was mailed, or another tenant, finds nothing.
    #[tokio::test]
    async fn a_users_change_is_found_only_in_its_tenant() {
        let db = fixture().await;
        let ann = db.ann(&db.tenant).await;
        db.store
            .save(
                &db.tenant,
                &change(email_change_row(ann.into(), "ann@new.example", "link")),
            )
            .await
            .unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        let unknown = db
            .store
            .find_by_token_hash(&db.tenant, &link_hash("other"))
            .await
            .unwrap();
        let theirs = db
            .store
            .find_by_token_hash(&other, &link_hash("link"))
            .await
            .unwrap();

        assert!(unknown.is_none());
        assert!(theirs.is_none());
    }

    /// A new change replaces Ann's earlier one, and a settled one keeps when
    /// it was settled.
    #[tokio::test]
    async fn a_new_change_replaces_the_earlier_one() {
        let db = fixture().await;
        let ann = db.ann(&db.tenant).await;
        db.store
            .save(
                &db.tenant,
                &change(email_change_row(ann.into(), "ann@new.example", "first")),
            )
            .await
            .unwrap();
        let confirmed = change(EmailChangeRow {
            state: ChangeState::Confirmed { at: at(60) },
            ..email_change_row(ann.into(), "ann@other.example", "second")
        });

        db.store.save(&db.tenant, &confirmed).await.unwrap();

        let found = db
            .store
            .find_by_user(&db.tenant, &ann)
            .await
            .unwrap()
            .unwrap();
        let old_link = db
            .store
            .find_by_token_hash(&db.tenant, &link_hash("first"))
            .await
            .unwrap();
        assert_eq!(found.new_email(), confirmed.new_email());
        assert_eq!(found.stage(), ChangeState::Confirmed { at: at(60) });
        assert!(old_link.is_none());
    }

    /// Saving a stale confirmation after Ann's email change is cancelled
    /// conflicts and preserves the cancellation time.
    #[tokio::test]
    async fn a_settled_change_takes_nothing_from_a_stale_copy() {
        let db = fixture().await;
        let ann = db.ann(&db.tenant).await;
        let asked = || email_change_row(ann.into(), "mallory@evil.example", "link");
        db.store.save(&db.tenant, &change(asked())).await.unwrap();
        let cancelled = change(EmailChangeRow {
            state: ChangeState::Cancelled { at: at(30) },
            ..asked()
        });
        db.store.save(&db.tenant, &cancelled).await.unwrap();
        let confirmed = change(EmailChangeRow {
            state: ChangeState::Confirmed { at: at(31) },
            ..asked()
        });

        let saved = db.store.save(&db.tenant, &confirmed).await;

        assert!(matches!(saved, Err(DomainError::Conflict(_))));
        let found = db
            .store
            .find_by_user(&db.tenant, &ann)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.stage(), ChangeState::Cancelled { at: at(30) });
    }

    /// Once a member's email change is confirmed, another confirmation
    /// and a late cancellation both conflict; the first confirmation stays.
    #[tokio::test]
    async fn a_members_settled_change_takes_nothing_from_a_stale_copy() {
        let db = fixture().await;
        let member = PrincipalId::from(OrgUserId::new());
        let asked = || email_change_row(member, "ann@new.example", "link");
        db.org.save(&change(asked())).await.unwrap();
        let confirmed = change(EmailChangeRow {
            state: ChangeState::Confirmed { at: at(30) },
            ..asked()
        });
        db.org.save(&confirmed).await.unwrap();
        let cancelled = change(EmailChangeRow {
            state: ChangeState::Cancelled { at: at(31) },
            ..asked()
        });

        let again = db.org.save(&confirmed).await;
        let late_cancel = db.org.save(&cancelled).await;

        assert!(matches!(again, Err(DomainError::Conflict(_))));
        assert!(matches!(late_cancel, Err(DomainError::Conflict(_))));
        let found = db.org.find_by_principal(&member).await.unwrap().unwrap();
        assert_eq!(found.stage(), ChangeState::Confirmed { at: at(30) });
    }

    /// A deleted change is gone, and a deleted user takes theirs along.
    #[tokio::test]
    async fn a_change_goes_when_deleted_or_with_its_user() {
        let db = fixture().await;
        let ann = db.ann(&db.tenant).await;
        let other = ScopedTenant::for_background(TenantId::new());
        let bob = db.ann(&other).await;
        db.store
            .save(
                &db.tenant,
                &change(email_change_row(ann.into(), "ann@new.example", "a")),
            )
            .await
            .unwrap();
        db.store
            .save(
                &other,
                &change(email_change_row(bob.into(), "bob@new.example", "b")),
            )
            .await
            .unwrap();

        db.store.delete(&db.tenant, &ann).await.unwrap();
        db.users.delete(&other, &bob).await.unwrap();

        assert!(
            db.store
                .find_by_user(&db.tenant, &ann)
                .await
                .unwrap()
                .is_none()
        );
        assert!(db.store.find_by_user(&other, &bob).await.unwrap().is_none());
    }

    /// Saving an email change for an unknown tenant user fails at storage.
    #[tokio::test]
    async fn a_change_for_an_unknown_user_is_refused() {
        let db = fixture().await;

        let saved = db
            .store
            .save(
                &db.tenant,
                &change(email_change_row(UserId::new().into(), "x@new.example", "x")),
            )
            .await;

        assert!(matches!(saved, Err(DomainError::Infrastructure(_))));
    }

    /// An organization member's change is found by them and by both links,
    /// replaced by a new one, and gone once deleted.
    #[tokio::test]
    async fn a_members_change_is_kept_on_the_platform() {
        let db = fixture().await;
        let member = PrincipalId::from(OrgUserId::new());
        let first = change(email_change_row(member, "ann@new.example", "first"));
        db.org.save(&first).await.unwrap();
        let second = change(email_change_row(member, "ann@other.example", "second"));

        db.org.save(&second).await.unwrap();

        let by_member = db.org.find_by_principal(&member).await.unwrap().unwrap();
        let by_link = db
            .org
            .find_by_token_hash(&link_hash("second"))
            .await
            .unwrap();
        let by_cancel = db
            .org
            .find_by_cancel_token_hash(&link_hash("cancel-second"))
            .await
            .unwrap();
        let old = db
            .org
            .find_by_token_hash(&link_hash("first"))
            .await
            .unwrap();
        assert_eq!(by_member.new_email(), second.new_email());
        assert_eq!(by_link.unwrap().principal_id(), &member);
        assert_eq!(by_cancel.unwrap().principal_id(), &member);
        assert!(old.is_none());

        db.org.delete(&member).await.unwrap();

        assert!(db.org.find_by_principal(&member).await.unwrap().is_none());
    }

    /// Invalid new addresses in tenant and management email-change rows
    /// make both stores reject the reads as corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_change_is_refused() {
        let db = fixture().await;
        let ann = db.ann(&db.tenant).await;
        let member = PrincipalId::from(OrgUserId::new());
        db.store
            .save(
                &db.tenant,
                &change(email_change_row(ann.into(), "ann@new.example", "a")),
            )
            .await
            .unwrap();
        db.org
            .save(&change(email_change_row(member, "ann@new.example", "b")))
            .await
            .unwrap();
        db.database
            .tamper(
                "UPDATE email_changes SET new_email = 'not an address'; \
                 UPDATE org_email_changes SET new_email = 'not an address'",
            )
            .await;

        let tenant = db.store.find_by_user(&db.tenant, &ann).await;
        let platform = db.org.find_by_principal(&member).await;

        assert!(matches!(tenant, Err(DomainError::Infrastructure(_))));
        assert!(matches!(platform, Err(DomainError::Infrastructure(_))));
    }
}
