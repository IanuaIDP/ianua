//! The single-use links mailed to members, in the platform database.
//!
//! One table keeps every kind of link, each row under the word of its kind,
//! and one store serves every kind. Every read and write names the kind it
//! was asked for, so a reset link is never found as a verification.
//!
//! Spending a link writes the use only while the link is unused and says
//! whether it did, so of two requests following one link together only one
//! gets through, and the other is answered as for a link nobody holds.
//! Saving over a used link is refused.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::organization::OrgTokenStore;
use ianua_domain::domains::organization::access::token::OrgToken;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrgUserId, TokenHash};

use self::record::{TokenColumns, TokenRecord};
use self::words::StoredPurpose;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of the links mailed to members, for every kind of
/// link.
pub struct PgOrgTokenStore {
    databases: Arc<Databases>,
}

impl PgOrgTokenStore {
    /// A store keeping mailed links in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl<Purpose: StoredPurpose> OrgTokenStore<Purpose> for PgOrgTokenStore {
    async fn find_by_hash(
        &self,
        hash: &TokenHash,
    ) -> Result<Option<OrgToken<Purpose>>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                TokenRecord,
                "queries/org_tokens/by_hash.sql",
                hash.as_str(),
                Purpose::WORD
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        record.map(TokenRecord::into_token).transpose()
    }

    async fn save(&self, token: &OrgToken<Purpose>) -> Result<(), DomainError> {
        let columns = TokenColumns::of(token);
        let written = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/org_tokens/save.sql",
                columns.token_hash,
                Purpose::WORD,
                columns.org_user_id,
                columns.sent_to,
                columns.created_at,
                columns.expires_at,
                columns.consumed_at,
            )
            .execute(connection)
            .await
        })
        .await?;
        match written.rows_affected() {
            0 => Err(DomainError::conflict(message!(
                "infra-the-link-was-used-already-or",
                "the link was used already, or is of another kind"
            ))),
            _ => Ok(()),
        }
    }

    async fn spend(&self, token: &OrgToken<Purpose>) -> Result<bool, DomainError> {
        let Some(used_at) = token.consumed_at() else {
            return Err(DomainError::invalid(message!(
                "infra-only-a-link-just-used-is",
                "only a link just used is spent"
            )));
        };
        let hash = token.token_hash();
        let spent = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/org_tokens/spend.sql",
                hash.as_str(),
                Purpose::WORD,
                used_at
            )
            .execute(connection)
            .await
        })
        .await?;
        Ok(spent.rows_affected() == 1)
    }

    async fn consume_outstanding(&self, org_user_id: &OrgUserId) -> Result<(), DomainError> {
        let now = clock::now();
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/org_tokens/consume_outstanding.sql",
                org_user_id.as_uuid(),
                Purpose::WORD,
                now
            )
            .execute(connection)
            .await?;
            Ok(())
        })
        .await
    }

    async fn find_latest_by_user(
        &self,
        org_user_id: &OrgUserId,
    ) -> Result<Option<OrgToken<Purpose>>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                TokenRecord,
                "queries/org_tokens/latest_of_member.sql",
                org_user_id.as_uuid(),
                Purpose::WORD
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        record.map(TokenRecord::into_token).transpose()
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::organization::{OrgUserStore, OrganizationStore};
    use ianua_domain::domains::identity::tokens::email_verification::EmailVerification;
    use ianua_domain::domains::identity::tokens::password_reset::PasswordReset;
    use ianua_domain::domains::organization::access::token::OrgTokenRow;
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::Usage;

    use super::*;
    use crate::postgres::organization::{PgOrgUserStore, PgOrganizationStore};
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::organization::{org_token_row, org_user_row, organization_row};

    const ANN: &str = "ann@acme.example";

    /// A fresh database holding Acme and two of its members, and the store
    /// on it.
    async fn fixture() -> (TestDb, PgOrgTokenStore, OrgUserId, OrgUserId) {
        let db = TestDb::fresh().await;
        let acme = Organization::reconstitute(organization_row("acme", "Acme")).unwrap();
        PgOrganizationStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&acme)
            .await
            .unwrap();
        let members = PgOrgUserStore::new(Arc::clone(&db.databases), DomainLimits::default());
        let mut ids = Vec::new();
        for email in [ANN, "bob@acme.example"] {
            let member = OrgUser::reconstitute(org_user_row(*acme.id(), email)).unwrap();
            members.save(&member).await.unwrap();
            ids.push(*member.id());
        }
        let store = PgOrgTokenStore::new(Arc::clone(&db.databases));
        (db, store, ids.remove(0), ids.remove(0))
    }

    fn verification(row: OrgTokenRow) -> OrgToken<EmailVerification> {
        OrgToken::reconstitute(row).unwrap()
    }

    fn reset(row: OrgTokenRow) -> OrgToken<PasswordReset> {
        OrgToken::reconstitute(row).unwrap()
    }

    /// A link issued long ago that is still in date now, so the real clock
    /// finds it outstanding.
    fn in_date(member: OrgUserId, hash: &str) -> OrgTokenRow {
        OrgTokenRow {
            created_at: at(-50_000_000),
            expires_at: at(50_000_000),
            ..org_token_row(member, ANN, hash, 0)
        }
    }

    fn hash(value: &str) -> TokenHash {
        TokenHash::from_stored(value.to_owned())
    }

    async fn verification_of(store: &PgOrgTokenStore, value: &str) -> OrgToken<EmailVerification> {
        OrgTokenStore::<EmailVerification>::find_by_hash(store, &hash(value))
            .await
            .unwrap()
            .unwrap()
    }

    /// Ann's verification link is found by its digest, as it was sent.
    #[tokio::test]
    async fn a_saved_link_is_found_by_its_digest() {
        let (_db, store, ann, _) = fixture().await;
        let link = verification(org_token_row(ann, ANN, "link", 0));

        store.save(&link).await.unwrap();

        let found = verification_of(&store, "link").await;
        assert_eq!(found.org_user_id(), &ann);
        assert_eq!(found.sent_to(), link.sent_to());
        assert_eq!(found.created_at(), at(0));
        assert_eq!(found.expires_at(), at(3600));
        assert!(found.consumed_at().is_none());
    }

    /// A digest nobody was sent finds nothing.
    #[tokio::test]
    async fn an_unknown_link_is_not_found() {
        let (_db, store, _, _) = fixture().await;

        let found = OrgTokenStore::<EmailVerification>::find_by_hash(&store, &hash("none"))
            .await
            .unwrap();

        assert!(found.is_none());
    }

    /// Looking up a saved verification token through the password-reset
    /// store returns no token.
    #[tokio::test]
    async fn a_link_of_one_kind_is_not_found_as_another() {
        let (_db, store, ann, _) = fixture().await;
        store
            .save(&verification(org_token_row(ann, ANN, "link", 0)))
            .await
            .unwrap();

        let as_reset = OrgTokenStore::<PasswordReset>::find_by_hash(&store, &hash("link"))
            .await
            .unwrap();

        assert!(as_reset.is_none());
    }

    /// Following the link records when it was used.
    #[tokio::test]
    async fn saving_a_used_link_keeps_when_it_was_used() {
        let (_db, store, ann, _) = fixture().await;
        store
            .save(&verification(org_token_row(ann, ANN, "link", 0)))
            .await
            .unwrap();
        let used = verification(OrgTokenRow {
            usage: Usage::Used { at: at(60) },
            ..org_token_row(ann, ANN, "link", 0)
        });

        store.save(&used).await.unwrap();

        assert_eq!(
            verification_of(&store, "link").await.consumed_at(),
            Some(at(60))
        );
    }

    /// Saving a second consumed copy of a verification token returns a
    /// conflict and preserves the first consumption time.
    #[tokio::test]
    async fn a_link_is_used_once() {
        let (_db, store, ann, _) = fixture().await;
        store
            .save(&verification(org_token_row(ann, ANN, "link", 0)))
            .await
            .unwrap();
        let first = verification(OrgTokenRow {
            usage: Usage::Used { at: at(60) },
            ..org_token_row(ann, ANN, "link", 0)
        });
        let second = verification(OrgTokenRow {
            usage: Usage::Used { at: at(61) },
            ..org_token_row(ann, ANN, "link", 0)
        });

        store.save(&first).await.unwrap();
        let again = store.save(&second).await;

        assert!(matches!(again, Err(DomainError::Conflict(_))));
        assert_eq!(
            verification_of(&store, "link").await.consumed_at(),
            Some(at(60))
        );
    }

    /// Spending a verification token as a reset returns false; the first
    /// verification spend succeeds, the second returns false, and the first
    /// consumption time remains stored.
    #[tokio::test]
    async fn spending_tells_who_won() {
        let (_db, store, ann, _) = fixture().await;
        store
            .save(&verification(org_token_row(ann, ANN, "link", 0)))
            .await
            .unwrap();
        let first = verification(OrgTokenRow {
            usage: Usage::Used { at: at(60) },
            ..org_token_row(ann, ANN, "link", 0)
        });
        let second = verification(OrgTokenRow {
            usage: Usage::Used { at: at(61) },
            ..org_token_row(ann, ANN, "link", 0)
        });
        let as_reset = reset(OrgTokenRow {
            usage: Usage::Used { at: at(62) },
            ..org_token_row(ann, ANN, "link", 0)
        });

        let wrong_kind = store.spend(&as_reset).await.unwrap();
        let won = store.spend(&first).await.unwrap();
        let lost = store.spend(&second).await.unwrap();

        assert!(!wrong_kind);
        assert!(won);
        assert!(!lost);
        assert_eq!(
            verification_of(&store, "link").await.consumed_at(),
            Some(at(60))
        );
    }

    /// Spending an unused domain token returns a validation error and
    /// leaves its stored consumption time unset.
    #[tokio::test]
    async fn an_unused_link_is_not_spent() {
        let (_db, store, ann, _) = fixture().await;
        let link = verification(org_token_row(ann, ANN, "link", 0));
        store.save(&link).await.unwrap();

        let spent = store.spend(&link).await;

        assert!(matches!(spent, Err(DomainError::Validation(_))));
        assert!(
            verification_of(&store, "link")
                .await
                .consumed_at()
                .is_none()
        );
    }

    /// After outstanding verification tokens are consumed, saving a stale
    /// copy with another consumption time returns a conflict.
    #[tokio::test]
    async fn a_superseded_link_is_not_used() {
        let (_db, store, ann, _) = fixture().await;
        store
            .save(&verification(in_date(ann, "anns")))
            .await
            .unwrap();
        OrgTokenStore::<EmailVerification>::consume_outstanding(&store, &ann)
            .await
            .unwrap();
        let followed = verification(OrgTokenRow {
            usage: Usage::Used { at: at(60) },
            ..in_date(ann, "anns")
        });

        let saved = store.save(&followed).await;

        assert!(matches!(saved, Err(DomainError::Conflict(_))));
    }

    /// Sending a new link spends Ann's outstanding ones of that kind, and
    /// leaves her other kinds and Bob's links as they were.
    #[tokio::test]
    async fn outstanding_links_of_the_kind_are_spent() {
        let (_db, store, ann, bob) = fixture().await;
        save_outstanding_links(&store, ann, bob).await;

        OrgTokenStore::<EmailVerification>::consume_outstanding(&store, &ann)
            .await
            .unwrap();

        assert!(
            verification_of(&store, "anns")
                .await
                .consumed_at()
                .is_some()
        );
        assert!(
            verification_of(&store, "bobs")
                .await
                .consumed_at()
                .is_none()
        );
        let anns_reset = OrgTokenStore::<PasswordReset>::find_by_hash(&store, &hash("anns-reset"))
            .await
            .unwrap()
            .unwrap();
        assert!(anns_reset.consumed_at().is_none());
    }

    /// Saves both members' verification links and Ann's independent password reset.
    async fn save_outstanding_links(store: &PgOrgTokenStore, ann: OrgUserId, bob: OrgUserId) {
        store
            .save(&verification(in_date(ann, "anns")))
            .await
            .unwrap();
        store
            .save(&verification(in_date(bob, "bobs")))
            .await
            .unwrap();
        store
            .save(&reset(in_date(ann, "anns-reset")))
            .await
            .unwrap();
    }

    /// A link already used keeps the time it was used at, and one that ran
    /// out stays unused: neither is outstanding.
    #[tokio::test]
    async fn spent_and_lapsed_links_are_left_as_they_are() {
        let (_db, store, ann, _) = fixture().await;
        let used = verification(OrgTokenRow {
            usage: Usage::Used {
                at: at(-40_000_000),
            },
            ..in_date(ann, "used")
        });
        let lapsed = verification(OrgTokenRow {
            created_at: at(-50_000_000),
            expires_at: at(-49_000_000),
            ..org_token_row(ann, ANN, "lapsed", 0)
        });
        store.save(&used).await.unwrap();
        store.save(&lapsed).await.unwrap();

        OrgTokenStore::<EmailVerification>::consume_outstanding(&store, &ann)
            .await
            .unwrap();

        assert_eq!(
            verification_of(&store, "used").await.consumed_at(),
            Some(at(-40_000_000))
        );
        assert!(
            verification_of(&store, "lapsed")
                .await
                .consumed_at()
                .is_none()
        );
    }

    /// The latest link sent to Ann is the one issued last, used or not, and
    /// only of the kind asked for.
    #[tokio::test]
    async fn the_latest_link_is_the_one_issued_last() {
        let (_db, store, ann, bob) = fixture().await;
        let earlier = verification(org_token_row(ann, ANN, "earlier", 0));
        let later = verification(OrgTokenRow {
            usage: Usage::Used { at: at(200) },
            ..org_token_row(ann, ANN, "later", 100)
        });
        store.save(&later).await.unwrap();
        store.save(&earlier).await.unwrap();
        store
            .save(&reset(org_token_row(ann, ANN, "newest-reset", 500)))
            .await
            .unwrap();

        let latest = OrgTokenStore::<EmailVerification>::find_latest_by_user(&store, &ann)
            .await
            .unwrap()
            .unwrap();
        let none_for_bob = OrgTokenStore::<EmailVerification>::find_latest_by_user(&store, &bob)
            .await
            .unwrap();

        assert_eq!(latest.token_hash(), &hash("later"));
        assert!(none_for_bob.is_none());
    }

    /// Reading a token whose stored recipient was replaced with an invalid
    /// address returns an infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_link_is_refused() {
        let (db, store, ann, _) = fixture().await;
        store
            .save(&verification(org_token_row(ann, ANN, "link", 0)))
            .await
            .unwrap();
        db.tamper("UPDATE org_tokens SET sent_to = 'not an address'")
            .await;

        let read = OrgTokenStore::<EmailVerification>::find_by_hash(&store, &hash("link")).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
