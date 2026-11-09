//! The single-use links mailed to a tenant's users: email verification,
//! magic links and sign-in confirmations, the stores of
//! `ports/identity/tokens.rs`.
//!
//! Every link is one row of `mailed_links`, filed with its purpose, and
//! every lookup names the purpose it expects, so a confirmation link
//! presented where a magic link is expected is unknown there.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::identity::{EmailVerificationToken, SignInLinkStore, VerificationTokenStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::identity::tokens::email_verification::EmailVerification;
use ianua_domain::domains::identity::tokens::purpose::{TenantLinkPurpose, TokenPurpose as _};
use ianua_domain::domains::identity::tokens::secure::SecureToken;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{TokenHash, UserId};
use sqlx::PgConnection;

use self::record::{LinkColumns, LinkRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The link of purpose `P` the tenant mailed with `hash`.
async fn link_by_hash<P: TenantLinkPurpose>(
    databases: &Databases,
    tenant_id: &ScopedTenant,
    hash: &TokenHash,
) -> Result<Option<SecureToken<ResolvedTenant, P>>, DomainError> {
    let record = scoped(databases, RowScope::from(tenant_id), async |connection| {
        sqlx::query_file_as!(
            LinkRecord,
            "queries/mailed_links/by_hash.sql",
            tenant_id.as_uuid(),
            P::NAME,
            hash.as_str()
        )
        .fetch_optional(connection)
        .await
    })
    .await?;
    record.map(LinkRecord::into_link).transpose()
}

/// Keeps `link` of purpose `P` for the tenant.
async fn save_link<P: TenantLinkPurpose>(
    databases: &Databases,
    tenant_id: &ScopedTenant,
    link: &SecureToken<ResolvedTenant, P>,
) -> Result<(), DomainError> {
    let columns = LinkColumns::of(link);
    scoped(databases, RowScope::from(tenant_id), async |connection| {
        write_link(connection, tenant_id, &columns).await
    })
    .await
}

/// Writes the link `columns` hold for the tenant.
async fn write_link(
    connection: &mut PgConnection,
    tenant_id: &ScopedTenant,
    columns: &LinkColumns<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query_file!(
        "queries/mailed_links/save.sql",
        tenant_id.as_uuid(),
        columns.purpose,
        columns.token_hash,
        columns.user_id,
        columns.sent_to,
        columns.created_at,
        columns.expires_at,
        columns.used_at,
    )
    .execute(connection)
    .await
    .map(|_| ())
}

/// The Postgres store of email verification links.
pub struct PgVerificationTokenStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgVerificationTokenStore {}

impl PgVerificationTokenStore {
    /// A store keeping verification links in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl VerificationTokenStore for PgVerificationTokenStore {
    async fn find_by_hash(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<EmailVerificationToken>, DomainError> {
        link_by_hash::<EmailVerification>(&self.databases, tenant_id, token_hash).await
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        token: &EmailVerificationToken,
    ) -> Result<(), DomainError> {
        save_link(&self.databases, tenant_id, token).await
    }

    async fn consume_outstanding(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<(), DomainError> {
        let now = clock::now();
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/mailed_links/spend_outstanding.sql",
                    tenant_id.as_uuid(),
                    EmailVerification::NAME,
                    user_id.as_uuid(),
                    now
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }

    async fn find_latest_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<EmailVerificationToken>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    LinkRecord,
                    "queries/mailed_links/latest_of_user.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid(),
                    EmailVerification::NAME
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(LinkRecord::into_link).transpose()
    }
}

/// The Postgres store of the links that sign a person in or finish their
/// sign-in, one purpose at a time.
pub struct PgSignInLinkStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgSignInLinkStore {}

impl PgSignInLinkStore {
    /// A store keeping sign-in links in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl<P: TenantLinkPurpose + Send + Sync + 'static> SignInLinkStore<P> for PgSignInLinkStore {
    async fn find_by_hash(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<SecureToken<ResolvedTenant, P>>, DomainError> {
        link_by_hash::<P>(&self.databases, tenant_id, token_hash).await
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        token: &SecureToken<ResolvedTenant, P>,
    ) -> Result<(), DomainError> {
        save_link(&self.databases, tenant_id, token).await
    }

    async fn consume(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<bool, DomainError> {
        let removed = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/mailed_links/consume.sql",
                    tenant_id.as_uuid(),
                    P::NAME,
                    token_hash.as_str()
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        Ok(removed.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::identity::UserStore;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::domains::identity::tokens::magic_link::MagicLink;
    use ianua_domain::domains::identity::tokens::secure::SecureTokenRow;
    use ianua_domain::domains::identity::tokens::sign_in_confirmation::SignInConfirmation;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::identity::{from_now, link_row, user_row};

    struct Fixture {
        db: TestDb,
        verification: PgVerificationTokenStore,
        sign_in: PgSignInLinkStore,
        tenant: ScopedTenant,
        ann: UserId,
    }

    /// A fresh database holding Ann in one tenant, and both stores on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let ann: User<ResolvedTenant> = User::reconstitute(user_row("ann@acme.example")).unwrap();
        PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&tenant, &ann)
            .await
            .unwrap();
        Fixture {
            verification: PgVerificationTokenStore::new(Arc::clone(&db.databases)),
            sign_in: PgSignInLinkStore::new(Arc::clone(&db.databases)),
            tenant,
            ann: *ann.id(),
            db,
        }
    }

    fn link<P: TenantLinkPurpose>(row: SecureTokenRow) -> SecureToken<ResolvedTenant, P> {
        SecureToken::reconstitute(row).unwrap()
    }

    fn hash(text: &str) -> TokenHash {
        TokenHash::from_stored(text.to_owned())
    }

    /// Ann's verification link is found by its hash as it was mailed, and
    /// not by a hash nobody was sent, nor from another tenant.
    #[tokio::test]
    async fn a_saved_link_is_found_by_its_hash_in_its_tenant_only() {
        let db = fixture().await;
        let mailed: EmailVerificationToken = link(link_row(db.ann, "h-verify", "ann@acme.example"));
        db.verification.save(&db.tenant, &mailed).await.unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        let found = db
            .verification
            .find_by_hash(&db.tenant, &hash("h-verify"))
            .await
            .unwrap()
            .unwrap();
        let unknown = db
            .verification
            .find_by_hash(&db.tenant, &hash("h-none"))
            .await
            .unwrap();
        let elsewhere = db
            .verification
            .find_by_hash(&other, &hash("h-verify"))
            .await
            .unwrap();

        assert_eq!(found.user_id(), &db.ann);
        assert_eq!(found.sent_to(), mailed.sent_to());
        assert_eq!(found.expires_at(), mailed.expires_at());
        assert!(unknown.is_none());
        assert!(elsewhere.is_none());
    }

    /// A sign-in confirmation hash is absent from magic-link lookup and
    /// remains available through confirmation lookup.
    #[tokio::test]
    async fn a_link_is_found_only_as_its_own_purpose() {
        let db = fixture().await;
        let confirmation: SecureToken<ResolvedTenant, SignInConfirmation> =
            link(link_row(db.ann, "h-confirm", "ann@acme.example"));
        SignInLinkStore::save(&db.sign_in, &db.tenant, &confirmation)
            .await
            .unwrap();

        let as_magic: Option<SecureToken<ResolvedTenant, MagicLink>> =
            SignInLinkStore::find_by_hash(&db.sign_in, &db.tenant, &hash("h-confirm"))
                .await
                .unwrap();
        let as_confirmation: Option<SecureToken<ResolvedTenant, SignInConfirmation>> =
            SignInLinkStore::find_by_hash(&db.sign_in, &db.tenant, &hash("h-confirm"))
                .await
                .unwrap();

        assert!(as_magic.is_none());
        assert!(as_confirmation.is_some());
    }

    /// Consuming a saved magic link succeeds once and returns false on
    /// the second attempt.
    #[tokio::test]
    async fn a_sign_in_link_is_consumed_once() {
        let db = fixture().await;
        let magic: SecureToken<ResolvedTenant, MagicLink> =
            link(link_row(db.ann, "h-magic", "ann@acme.example"));
        SignInLinkStore::save(&db.sign_in, &db.tenant, &magic)
            .await
            .unwrap();

        let first =
            SignInLinkStore::<MagicLink>::consume(&db.sign_in, &db.tenant, &hash("h-magic"))
                .await
                .unwrap();
        let second =
            SignInLinkStore::<MagicLink>::consume(&db.sign_in, &db.tenant, &hash("h-magic"))
                .await
                .unwrap();

        assert!(first);
        assert!(!second);
    }

    /// Mailing a new verification link spends every unused one still in
    /// date, and leaves one that already ran out as it was.
    #[tokio::test]
    async fn outstanding_links_are_spent_and_lapsed_ones_left() {
        let db = fixture().await;
        let live: EmailVerificationToken = link(link_row(db.ann, "h-live", "ann@acme.example"));
        let lapsed: EmailVerificationToken = link(SecureTokenRow {
            created_at: from_now(-7200),
            expires_at: from_now(-3600),
            ..link_row(db.ann, "h-lapsed", "ann@acme.example")
        });
        for token in [&live, &lapsed] {
            db.verification.save(&db.tenant, token).await.unwrap();
        }

        db.verification
            .consume_outstanding(&db.tenant, &db.ann)
            .await
            .unwrap();

        let spent = db
            .verification
            .find_by_hash(&db.tenant, &hash("h-live"))
            .await
            .unwrap();
        let left = db
            .verification
            .find_by_hash(&db.tenant, &hash("h-lapsed"))
            .await
            .unwrap();
        assert!(spent.unwrap().consumed_at().is_some());
        assert!(left.unwrap().consumed_at().is_none());
    }

    /// The latest link mailed to Ann is the newest, spent or not.
    #[tokio::test]
    async fn the_latest_link_is_the_newest_one() {
        let db = fixture().await;
        let last: EmailVerificationToken = link(SecureTokenRow {
            created_at: from_now(-1800),
            ..link_row(db.ann, "h-last", "ann@acme.example")
        });
        let first: EmailVerificationToken = link(link_row(db.ann, "h-first", "ann@acme.example"));
        let between: EmailVerificationToken = link(SecureTokenRow {
            created_at: from_now(-3000),
            ..link_row(db.ann, "h-between", "ann@acme.example")
        });
        for token in [&last, &first, &between] {
            db.verification.save(&db.tenant, token).await.unwrap();
        }

        let latest = db
            .verification
            .find_latest_by_user(&db.tenant, &db.ann)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(latest.token_hash().as_str(), "h-last");
    }

    /// A verification link with an invalid stored recipient address fails
    /// to load as corrupt storage.
    #[tokio::test]
    async fn a_link_to_no_address_is_refused() {
        let db = fixture().await;
        let mailed: EmailVerificationToken = link(link_row(db.ann, "h-verify", "ann@acme.example"));
        db.verification.save(&db.tenant, &mailed).await.unwrap();
        db.db
            .tamper("UPDATE mailed_links SET sent_to = 'nowhere'")
            .await;

        let read = db
            .verification
            .find_by_hash(&db.tenant, &hash("h-verify"))
            .await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
