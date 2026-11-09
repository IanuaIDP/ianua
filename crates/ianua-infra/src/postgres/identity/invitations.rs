//! Invitations to join a tenant: each one row of `invitations`, under
//! row-level security, belonging to the invited account it was sent for.
//!
//! A save changes an invitation only while it is open, and is refused once
//! it was accepted, declined or revoked, so of an acceptance and a
//! revocation read together, or two acceptances, only the first is kept;
//! the other's unit of work rolls back with the refusal.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::identity::{InvitationStore, InvitationSweepSortField};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::identity::invitations::invitation::Invitation;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, RoleId, TokenHash, UserId};
use sqlx::PgConnection;
use sqlx::postgres::PgQueryResult;
use time::OffsetDateTime;

use self::record::{InvitationColumns, InvitationRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a link to one invitation.
const TOKEN_KEY: &str = "invitations_token_key";

/// The Postgres store of invitations.
pub struct PgInvitationStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgInvitationStore {}

impl SortColumns for InvitationSweepSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "invitations.created_at",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

impl PgInvitationStore {
    /// A store keeping invitations in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

fn rebuilt_one(
    record: Option<InvitationRecord>,
) -> Result<Option<Invitation<ResolvedTenant>>, DomainError> {
    record.map(InvitationRecord::into_invitation).transpose()
}

fn rebuilt_all(
    records: Vec<InvitationRecord>,
) -> Result<Vec<Invitation<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(InvitationRecord::into_invitation)
        .collect()
}

/// Writes the invitation without reopening a closed row or reusing another link.
async fn write_invitation(
    connection: &mut PgConnection,
    tenant_id: &ScopedTenant,
    columns: &InvitationColumns<'_>,
) -> Result<(Uniqueness, u64), sqlx::Error> {
    let attempt = sqlx::query_file!(
        "queries/invitations/save.sql",
        columns.id,
        tenant_id.as_uuid(),
        columns.user_id,
        columns.email,
        columns.invited_by,
        columns.role_id,
        columns.token_hash,
        columns.status,
        columns.accepted_at,
        columns.message,
        columns.expires_at,
        columns.created_at,
    )
    .execute(connection)
    .await;
    let rows = attempt.as_ref().map_or(0, PgQueryResult::rows_affected);
    unique_on(attempt, TOKEN_KEY).map(|kept| (kept, rows))
}

#[async_trait]
impl InvitationStore for PgInvitationStore {
    async fn latest_pending_for_users(
        &self,
        tenant_id: &ScopedTenant,
        users: &[UserId],
    ) -> Result<Vec<Invitation<ResolvedTenant>>, DomainError> {
        if users.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<_> = users.iter().map(|user| *user.as_uuid()).collect();
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    InvitationRecord,
                    "queries/invitations/latest_pending_for_users.sql",
                    tenant_id.as_uuid(),
                    &ids
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt_all(records)
    }

    async fn find_by_token_hash(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<Invitation<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    InvitationRecord,
                    "queries/invitations/by_token.sql",
                    tenant_id.as_uuid(),
                    token_hash.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        rebuilt_one(record)
    }

    async fn find_pending_by_email(
        &self,
        tenant_id: &ScopedTenant,
        email: &Email,
    ) -> Result<Option<Invitation<ResolvedTenant>>, DomainError> {
        let now = clock::now();
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    InvitationRecord,
                    "queries/invitations/pending_by_email.sql",
                    tenant_id.as_uuid(),
                    email.as_str(),
                    now
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        rebuilt_one(record)
    }

    async fn find_pending_by_user_id(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<Invitation<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    InvitationRecord,
                    "queries/invitations/pending_of_user.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        rebuilt_one(record)
    }

    async fn list_by_user_id(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<Invitation<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    InvitationRecord,
                    "queries/invitations/of_user.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt_all(records)
    }

    async fn list_pending(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<Invitation<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    InvitationRecord,
                    "queries/invitations/pending.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt_all(records)
    }

    async fn find_lapsed(
        &self,
        tenant_id: &ScopedTenant,
        now: OffsetDateTime,
        request: &PageRequest,
    ) -> Result<Page<Invitation<ResolvedTenant>>, DomainError> {
        let sort = SortOrder::<InvitationSweepSortField>::default();
        let keyset = request.keyset(&sort)?;
        let listed = PageQuery::ids("invitations.id", "invitations")
            .filter("invitations.tenant_id = ?", *tenant_id.as_uuid())
            .keep("invitations.status = 'pending'")
            .filter("invitations.expires_at <= ?", now);
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                let records = sqlx::query_file_as!(
                    InvitationRecord,
                    "queries/invitations/lapsed.sql",
                    tenant_id.as_uuid(),
                    now,
                    &ids
                )
                .fetch_all(connection)
                .await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        Ok(keyset.seal(rebuilt_all(records)?))
    }

    async fn count_pending_for_role(
        &self,
        tenant_id: &ScopedTenant,
        role_id: &RoleId,
    ) -> Result<u64, DomainError> {
        let count = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/invitations/pending_for_role.sql",
                    tenant_id.as_uuid(),
                    role_id.as_uuid()
                )
                .fetch_one(connection)
                .await
            },
        )
        .await?;
        u64::try_from(count).map_err(DomainError::infra)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        invitation: &Invitation<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = InvitationColumns::of(invitation)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| write_invitation(connection, tenant_id, &columns).await,
        )
        .await?;
        match written {
            (Uniqueness::Taken, _) => Err(DomainError::conflict(message!(
                "infra-another-invitation-already-has-this-link",
                "another invitation already has this link"
            ))),
            (Uniqueness::Kept, 0) => Err(DomainError::conflict(message!(
                "infra-the-invitation-was-accepted-declined-or",
                "the invitation was accepted, declined or revoked already"
            ))),
            (Uniqueness::Kept, _) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, PageRequest, Sort, SortOrder};
    use ianua_app::ports::authorization::RoleStore;
    use ianua_app::ports::identity::{
        InvitationFilter, InvitationState, UserFilter, UserOrdering, UserSortField, UserStore,
    };
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::identity::invitations::invitation::InvitationRow;
    use ianua_domain::domains::identity::invitations::offer::OfferState;
    use ianua_domain::domains::identity::invitations::status::InvitationStatus;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::{InvitationId, TenantId};
    use time::Duration;

    use super::*;
    use crate::postgres::authorization::PgRoleStore;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::identity::{
        InvitationSeed, from_now, invitation_row, user_row_standing,
    };
    use crate::test_support::rows::{at, authorization};

    struct Fixture {
        db: TestDb,
        store: PgInvitationStore,
        tenant: ScopedTenant,
        ann: UserId,
        bob: UserId,
        role: RoleId,
    }

    impl Fixture {
        /// Stores older, latest, closed and unrequested invitations for a batch lookup.
        async fn save_batch_cases(&self) -> Invitation<ResolvedTenant> {
            let old = invitation(self.ann_row("old", 0));
            let latest = invitation(self.ann_row("latest", 10));
            let closed = invitation(InvitationRow {
                state: OfferState::Revoked,
                ..self.ann_row("closed", 20)
            });
            let omitted = invitation(self.bob_row("bob", 0));
            for item in [&old, &latest, &closed, &omitted] {
                self.store.save(&self.tenant, item).await.unwrap();
            }
            latest
        }

        /// Reads the same open invitation by its link, email and account.
        async fn open_lookups(
            &self,
            sent: &Invitation<ResolvedTenant>,
        ) -> [Option<Invitation<ResolvedTenant>>; 3] {
            let by_link = self
                .store
                .find_by_token_hash(&self.tenant, &hash("h-ann"))
                .await
                .unwrap();
            let by_email = self
                .store
                .find_pending_by_email(&self.tenant, sent.email())
                .await
                .unwrap();
            let by_account = self
                .store
                .find_pending_by_user_id(&self.tenant, &self.ann)
                .await
                .unwrap();
            [by_link, by_email, by_account]
        }

        /// Stores equal-time invitations and returns their expected cursor order.
        async fn save_expiry_cases(&self) -> Vec<InvitationId> {
            let mut expected = Vec::new();
            for token in ["one", "two", "three"] {
                let sent = invitation(self.ann_row(token, 0));
                expected.push(*sent.id());
                self.store.save(&self.tenant, &sent).await.unwrap();
            }
            expected.sort_by_key(|id| *id.as_uuid());
            expected
        }

        /// Adds Cid and invitation rows straddling the exact expiry boundary.
        async fn save_paging_cases(&self, users: &PgUserStore) -> UserId {
            let cid: User<ResolvedTenant> =
                User::reconstitute(user_row_standing("cid@acme.example", UserStatus::Invited))
                    .unwrap();
            users.save(&self.tenant, &cid).await.unwrap();
            let expired = invitation(InvitationRow {
                expires_at: at(100),
                ..self.ann_row("expired", 0)
            });
            let bobs = invitation(self.bob_row("bobs", 10));
            let cids = invitation(invitation_row(InvitationSeed {
                user_id: *cid.id(),
                role_id: self.role,
                email: "cid@acme.example",
                hash: "cids",
                seconds: 20,
            }));
            for item in [&expired, &bobs, &cids] {
                self.store.save(&self.tenant, item).await.unwrap();
            }
            *cid.id()
        }

        /// An invitation for Ann to the fixture's member role.
        fn ann_row(&self, hash: &str, seconds: i64) -> InvitationRow {
            invitation_row(InvitationSeed {
                user_id: self.ann,
                role_id: self.role,
                email: "ann@acme.example",
                hash,
                seconds,
            })
        }

        /// An invitation for Bob to the fixture's member role.
        fn bob_row(&self, hash: &str, seconds: i64) -> InvitationRow {
            invitation_row(InvitationSeed {
                user_id: self.bob,
                role_id: self.role,
                email: "bob@acme.example",
                hash,
                seconds,
            })
        }
    }

    /// A fresh database holding Ann and Bob, both invited, and the role
    /// "member" they are invited to, in one tenant, and the store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let users = PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default());
        let mut invited = Vec::new();
        for email in ["ann@acme.example", "bob@acme.example"] {
            let user: User<ResolvedTenant> =
                User::reconstitute(user_row_standing(email, UserStatus::Invited)).unwrap();
            users.save(&tenant, &user).await.unwrap();
            invited.push(*user.id());
        }
        let member = authorization::role("member");
        PgRoleStore::new(Arc::clone(&db.databases))
            .save(&tenant, &member)
            .await
            .unwrap();
        Fixture {
            store: PgInvitationStore::new(Arc::clone(&db.databases)),
            tenant,
            ann: invited[0],
            bob: invited[1],
            role: *member.id(),
            db,
        }
    }

    /// Ann's invitation to "member" is pending and Bob's was accepted: one
    /// invitation still waits to give the role, and another role has none.
    #[tokio::test]
    async fn the_pending_invitations_giving_a_role_are_counted() {
        let db = fixture().await;
        let anns = invitation(db.ann_row("h-ann", 0));
        let bobs = invitation(InvitationRow {
            state: OfferState::Accepted { at: at(60) },
            ..db.bob_row("h-bob", 0)
        });
        db.store.save(&db.tenant, &anns).await.unwrap();
        db.store.save(&db.tenant, &bobs).await.unwrap();

        let for_member = db
            .store
            .count_pending_for_role(&db.tenant, &db.role)
            .await
            .unwrap();
        let for_another = db
            .store
            .count_pending_for_role(&db.tenant, &RoleId::new())
            .await
            .unwrap();

        assert_eq!((for_member, for_another), (1, 0));
    }

    /// A page batch returns only the latest open invitation of requested users,
    /// retaining expired links while ignoring closed invitations and other tenants.
    #[tokio::test]
    async fn pending_invitation_batches_keep_only_requested_users() {
        let db = fixture().await;
        let latest = db.save_batch_cases().await;

        let found = db
            .store
            .latest_pending_for_users(&db.tenant, &[db.ann, UserId::new(), db.ann])
            .await
            .unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        assert_eq!(ids(&found), [*latest.id()]);
        assert_eq!(found[0].expires_at(), latest.expires_at());
        assert!(
            db.store
                .latest_pending_for_users(&other, &[db.ann])
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            db.store
                .latest_pending_for_users(&db.tenant, &[])
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Invitation predicates narrow the users before keyset paging and count
    /// the same selection, with expiry at the exact boundary already expired.
    #[tokio::test]
    async fn invitation_state_is_applied_before_user_paging() {
        let db = fixture().await;
        let users = PgUserStore::new(Arc::clone(&db.db.databases), DomainLimits::default());
        let cid = db.save_paging_cases(&users).await;
        let filter = invitation_filter(InvitationState::Pending);
        let order = UserOrdering::Column(SortOrder::single(Sort::ascending(UserSortField::Email)));
        let one = PageRequest::first(Limit::new(1).unwrap());

        let first = users.list(&db.tenant, &filter, &order, &one).await.unwrap();
        let second = users
            .list(&db.tenant, &filter, &order, &one.following(&first).unwrap())
            .await
            .unwrap();
        let expired_filter = invitation_filter(InvitationState::Expired);
        let expired_page = users
            .list(&db.tenant, &expired_filter, &order, &one)
            .await
            .unwrap();

        assert_eq!(first.items[0].id(), &db.bob);
        assert_eq!(second.items[0].id(), &cid);
        assert!(!second.has_next());
        assert_eq!(expired_page.items[0].id(), &db.ann);
        assert_eq!(users.count(&db.tenant, &filter).await.unwrap(), 2);
        assert_eq!(users.count(&db.tenant, &expired_filter).await.unwrap(), 1);
    }

    /// Selects an invitation state at the fixture's exact expiry boundary.
    fn invitation_filter(state: InvitationState) -> UserFilter {
        UserFilter {
            invitation: Some(InvitationFilter { state, at: at(100) }),
            ..UserFilter::all()
        }
    }

    /// Saving an invitation naming an unknown role returns an
    /// infrastructure error.
    #[tokio::test]
    async fn an_invitation_to_a_role_nobody_keeps_is_refused() {
        let db = fixture().await;
        let anns = invitation(db.ann_row("h-ann", 0));
        db.store.save(&db.tenant, &anns).await.unwrap();
        let another = invitation(invitation_row(InvitationSeed {
            user_id: db.bob,
            role_id: RoleId::new(),
            email: "bob@acme.example",
            hash: "h-bob",
            seconds: 0,
        }));

        let saved = db.store.save(&db.tenant, &another).await;

        assert!(matches!(saved, Err(DomainError::Infrastructure(_))));
    }

    fn invitation(row: InvitationRow) -> Invitation<ResolvedTenant> {
        Invitation::reconstitute(row).unwrap()
    }

    fn hash(text: &str) -> TokenHash {
        TokenHash::from_stored(text.to_owned())
    }

    fn ids(found: &[Invitation<ResolvedTenant>]) -> Vec<InvitationId> {
        found.iter().map(|invitation| *invitation.id()).collect()
    }

    /// Every invitation sent to Ann's account is listed, newest first,
    /// whatever its status, and none sent to Bob.
    #[tokio::test]
    async fn every_invitation_of_an_account_is_listed() {
        let db = fixture().await;
        let first = invitation(db.ann_row("h-1", 0));
        let second = invitation(db.ann_row("h-2", 10));
        let bobs = invitation(db.bob_row("h-3", 20));
        for each in [&first, &second, &bobs] {
            db.store.save(&db.tenant, each).await.unwrap();
        }

        let listed = db.store.list_by_user_id(&db.tenant, &db.ann).await.unwrap();

        assert_eq!(ids(&listed), [*second.id(), *first.id()]);
    }

    /// Ann's invitation is found by its link, by her address and by her
    /// account while pending; once accepted, saving it again keeps when,
    /// and it is pending no longer.
    #[tokio::test]
    async fn an_invitation_is_found_and_keeps_where_it_stands() {
        let db = fixture().await;
        let sent = invitation(db.ann_row("h-ann", 0));
        db.store.save(&db.tenant, &sent).await.unwrap();

        let lookups = db.open_lookups(&sent).await;
        let accepted = invitation(InvitationRow {
            id: *sent.id(),
            state: OfferState::Accepted { at: at(60) },
            ..db.ann_row("h-ann", 0)
        });
        db.store.save(&db.tenant, &accepted).await.unwrap();
        let found = db
            .store
            .find_by_token_hash(&db.tenant, &hash("h-ann"))
            .await
            .unwrap()
            .unwrap();

        for found in lookups {
            assert_eq!(found.unwrap().id(), sent.id());
        }
        assert_eq!(found.status(), InvitationStatus::Accepted);
        assert_eq!(found.accepted_at(), Some(at(60)));
        assert!(
            db.store
                .find_pending_by_user_id(&db.tenant, &db.ann)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Saving acceptance from a stale copy of a revoked invitation returns
    /// a conflict and preserves its revoked status.
    #[tokio::test]
    async fn a_closed_invitation_is_never_moved_again() {
        let db = fixture().await;
        let anns = || db.ann_row("h-ann", 0);
        let sent = invitation(anns());
        db.store.save(&db.tenant, &sent).await.unwrap();
        let revoked = invitation(InvitationRow {
            id: *sent.id(),
            state: OfferState::Revoked,
            ..anns()
        });
        db.store.save(&db.tenant, &revoked).await.unwrap();
        let accepted = invitation(InvitationRow {
            id: *sent.id(),
            state: OfferState::Accepted { at: at(60) },
            ..anns()
        });

        let saved = db.store.save(&db.tenant, &accepted).await;

        assert!(matches!(saved, Err(DomainError::Conflict(_))));
        let found = db
            .store
            .find_by_token_hash(&db.tenant, &hash("h-ann"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.status(), InvitationStatus::Revoked);
    }

    /// An invitation whose link ran out is still pending for the account,
    /// but no longer found by its address.
    #[tokio::test]
    async fn an_invitation_past_its_link_is_not_found_by_address() {
        let db = fixture().await;
        let lapsed = invitation(InvitationRow {
            created_at: from_now(-86_400),
            expires_at: from_now(-3600),
            ..db.ann_row("h-ann", 0)
        });
        db.store.save(&db.tenant, &lapsed).await.unwrap();

        let by_email = db
            .store
            .find_pending_by_email(&db.tenant, lapsed.email())
            .await
            .unwrap();
        let by_account = db
            .store
            .find_pending_by_user_id(&db.tenant, &db.ann)
            .await
            .unwrap();

        assert!(by_email.is_none());
        assert!(by_account.is_some());
    }

    /// The pending invitations list oldest first, without an accepted one;
    /// those whose link ran out by a moment are found for the sweep.
    #[tokio::test]
    async fn pending_and_lapsed_invitations_are_listed_oldest_first() {
        let db = fixture().await;
        let bobs = invitation(db.bob_row("h-bob", 0));
        let anns = invitation(db.ann_row("h-ann", 100));
        let accepted = invitation(InvitationRow {
            state: OfferState::Accepted { at: at(10) },
            ..db.ann_row("h-old", 0)
        });
        for sent in [&anns, &bobs, &accepted] {
            db.store.save(&db.tenant, sent).await.unwrap();
        }

        let pending = db.store.list_pending(&db.tenant).await.unwrap();
        let lapsed = db
            .store
            .find_lapsed(
                &db.tenant,
                at(50).saturating_add(Duration::days(7)),
                &PageRequest::default(),
            )
            .await
            .unwrap();

        assert_eq!(ids(&pending), [*bobs.id(), *anns.id()]);
        assert_eq!(ids(&lapsed.items), [*bobs.id()]);
    }

    /// The expiry cursor advances past a still-pending failed invitation even
    /// when every row ties on creation time, without repeating or skipping rows.
    #[tokio::test]
    async fn expiry_pages_advance_past_pending_rows_with_equal_times() {
        let db = fixture().await;
        let expected = db.save_expiry_cases().await;
        let mut request = PageRequest::first(Limit::internal(1));
        let cutoff = at(0).saturating_add(Duration::days(7));
        let mut seen = Vec::new();
        loop {
            let page = db
                .store
                .find_lapsed(&db.tenant, cutoff, &request)
                .await
                .unwrap();
            assert_eq!(page.items.len(), 1);
            seen.extend(ids(&page.items));
            let Some(next) = request.following(&page) else {
                break;
            };
            request = next;
        }
        assert_eq!(seen, expected);
        let elsewhere = db
            .store
            .find_lapsed(
                &ScopedTenant::for_background(TenantId::new()),
                cutoff,
                &PageRequest::default(),
            )
            .await
            .unwrap();
        assert!(elsewhere.is_empty());
    }

    /// Saving Bob's invitation with Ann's existing link returns a conflict.
    #[tokio::test]
    async fn a_link_another_invitation_has_is_refused() {
        let db = fixture().await;
        db.store
            .save(&db.tenant, &invitation(db.ann_row("h-same", 0)))
            .await
            .unwrap();

        let second = db
            .store
            .save(&db.tenant, &invitation(db.bob_row("h-same", 0)))
            .await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// A link nobody was sent finds nothing, and another tenant finds none
    /// of Acme's invitations.
    #[tokio::test]
    async fn an_unknown_or_another_tenants_invitation_is_not_found() {
        let db = fixture().await;
        let sent = invitation(db.ann_row("h-ann", 0));
        db.store.save(&db.tenant, &sent).await.unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        assert!(
            db.store
                .find_by_token_hash(&db.tenant, &hash("h-none"))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.store
                .find_by_token_hash(&other, &hash("h-ann"))
                .await
                .unwrap()
                .is_none()
        );
        assert!(db.store.list_pending(&other).await.unwrap().is_empty());
    }

    /// An invitation with an unknown stored sender variant fails to load
    /// as corrupt storage.
    #[tokio::test]
    async fn an_invitation_whose_who_sent_it_does_not_read_is_refused() {
        let db = fixture().await;
        let sent = invitation(db.ann_row("h-ann", 0));
        db.store.save(&db.tenant, &sent).await.unwrap();
        db.db
            .tamper("UPDATE invitations SET invited_by = '{\"v\": 1, \"value\": {\"Nobody\": 1}}'")
            .await;

        let read = db
            .store
            .find_by_token_hash(&db.tenant, &hash("h-ann"))
            .await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
