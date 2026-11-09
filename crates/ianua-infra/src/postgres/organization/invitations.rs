//! Invitations to join an organization, kept in the platform database.
//!
//! An invitation is expired by time alone while its row still reads
//! pending, until the sweep marks it: so a read of the pending invitation
//! to an address checks the time, and a read of a member's pending one, or
//! of the organization's, reads the stored status alone, as a resend needs.
//!
//! A save changes an invitation only while it is open, and is refused once
//! it was accepted, declined or revoked, so of an acceptance and a
//! revocation read together, or two acceptances, only the first is kept;
//! the other's unit of work rolls back with the refusal.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::organization::{OrgInvitationStore, OrgInvitationSweepSortField};
use ianua_domain::domains::organization::members::invitation::OrgInvitation;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, OrgUserId, OrganizationId, TokenHash};
use time::OffsetDateTime;

use self::record::{InvitationColumns, InvitationRecord};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of organization invitations.
pub struct PgOrgInvitationStore {
    databases: Arc<Databases>,
}

impl SortColumns for OrgInvitationSweepSortField {
    fn column(self) -> &'static str {
        match self {
            Self::ExpiresAt => "org_invitations.expires_at",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

impl PgOrgInvitationStore {
    /// A store keeping invitations in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

fn rebuilt(record: Option<InvitationRecord>) -> Result<Option<OrgInvitation>, DomainError> {
    record.map(InvitationRecord::into_invitation).transpose()
}

fn rebuilt_all(records: Vec<InvitationRecord>) -> Result<Vec<OrgInvitation>, DomainError> {
    records
        .into_iter()
        .map(InvitationRecord::into_invitation)
        .collect()
}

#[async_trait]
impl OrgInvitationStore for PgOrgInvitationStore {
    async fn find_by_token_hash(
        &self,
        organization_id: &OrganizationId,
        hash: &TokenHash,
    ) -> Result<Option<OrgInvitation>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                InvitationRecord,
                "queries/org_invitations/by_token_hash.sql",
                organization_id.as_uuid(),
                hash.as_str()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        rebuilt(record)
    }

    async fn find_pending_by_email(
        &self,
        organization_id: &OrganizationId,
        email: &Email,
    ) -> Result<Option<OrgInvitation>, DomainError> {
        let now = clock::now();
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                InvitationRecord,
                "queries/org_invitations/pending_to.sql",
                organization_id.as_uuid(),
                email.as_str(),
                now
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        rebuilt(record)
    }

    async fn find_pending_by_org_user(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
    ) -> Result<Option<OrgInvitation>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                InvitationRecord,
                "queries/org_invitations/pending_for_member.sql",
                organization_id.as_uuid(),
                org_user_id.as_uuid()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        rebuilt(record)
    }

    async fn list_pending(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Vec<OrgInvitation>, DomainError> {
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                InvitationRecord,
                "queries/org_invitations/pending.sql",
                organization_id.as_uuid()
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        rebuilt_all(records)
    }

    async fn list_lapsed(
        &self,
        now: OffsetDateTime,
        request: &PageRequest,
    ) -> Result<Page<OrgInvitation>, DomainError> {
        let sort = SortOrder::<OrgInvitationSweepSortField>::default();
        let keyset = request.keyset(&sort)?;
        let listed = PageQuery::ids("org_invitations.id", "org_invitations")
            .keep("org_invitations.status = 'pending'")
            .filter("org_invitations.expires_at <= ?", now);
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            let ids = listed.fetch(&keyset, &mut *connection).await?;
            let records = sqlx::query_file_as!(
                InvitationRecord,
                "queries/org_invitations/lapsed.sql",
                now,
                &ids
            )
            .fetch_all(connection)
            .await?;
            Ok(in_page_order(&ids, records, |record| record.id))
        })
        .await?;
        Ok(keyset.seal(rebuilt_all(records)?))
    }

    async fn save(&self, invitation: &OrgInvitation) -> Result<(), DomainError> {
        let columns = InvitationColumns::of(invitation);
        let written = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/org_invitations/save.sql",
                columns.id,
                columns.organization_id,
                columns.org_user_id,
                columns.email,
                columns.invited_by,
                columns.token_hash,
                columns.status,
                columns.accepted_at,
                columns.message,
                columns.expires_at,
                columns.created_at,
            )
            .execute(connection)
            .await
        })
        .await?;
        match written.rows_affected() {
            0 => Err(DomainError::conflict(message!(
                "infra-the-invitation-was-accepted-declined-or",
                "the invitation was accepted, declined or revoked already"
            ))),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::Limit;
    use ianua_app::ports::organization::{OrgUserStore, OrganizationStore};
    use ianua_domain::domains::identity::invitations::offer::OfferState;
    use ianua_domain::domains::identity::invitations::status::InvitationStatus;
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::domains::organization::members::invitation::OrgInvitationRow;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::shared::config::DomainLimits;

    use super::*;
    use crate::postgres::organization::{PgOrgUserStore, PgOrganizationStore};
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::organization::{
        OrgInvitationSeed, org_invitation_row, org_user_row, organization_row,
    };

    struct Fixture {
        db: TestDb,
        store: PgOrgInvitationStore,
        organization: OrganizationId,
        ann: OrgUserId,
        bob: OrgUserId,
    }

    /// A fresh database holding Acme with Ann, who invites, and Bob, who is
    /// invited, and the store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let organization = an_organization(&db, "acme").await;
        let ann = a_member(&db, organization, "ann@acme.example").await;
        let bob = a_member(&db, organization, "bob@acme.example").await;
        let store = PgOrgInvitationStore::new(Arc::clone(&db.databases));
        Fixture {
            db,
            store,
            organization,
            ann,
            bob,
        }
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

    /// Saves a member of `organization` at `email` through the member store.
    async fn a_member(db: &TestDb, organization: OrganizationId, email: &str) -> OrgUserId {
        let member = OrgUser::reconstitute(org_user_row(organization, email)).unwrap();
        PgOrgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&member)
            .await
            .unwrap();
        *member.id()
    }

    fn row(db: &Fixture, token: &str) -> OrgInvitationRow {
        org_invitation_row(OrgInvitationSeed {
            organization: db.organization,
            invitee: db.bob,
            invited_by: db.ann,
            email: "bob@acme.example",
            token,
        })
    }

    fn invitation(row: OrgInvitationRow) -> OrgInvitation {
        OrgInvitation::reconstitute(row).unwrap()
    }

    fn hash(token: &str) -> TokenHash {
        TokenHash::from_stored(token.to_owned())
    }

    fn ran_out(row: OrgInvitationRow) -> OrgInvitationRow {
        OrgInvitationRow {
            created_at: at(-400_000_000),
            expires_at: at(-399_000_000),
            ..row
        }
    }

    fn tokens(invitations: &[OrgInvitation]) -> Vec<&str> {
        invitations
            .iter()
            .map(|invitation| invitation.token_hash().as_str())
            .collect()
    }

    /// Ann invites Bob: the invitation is found by its link's hash in Acme,
    /// as it was saved, and not in another organization.
    #[tokio::test]
    async fn a_saved_invitation_is_found_by_its_token_hash() {
        let db = fixture().await;
        let sent = invitation(row(&db, "link"));

        db.store.save(&sent).await.unwrap();

        let found = db
            .store
            .find_by_token_hash(&db.organization, &hash("link"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id(), sent.id());
        assert_eq!(found.org_user_id(), sent.org_user_id());
        assert_eq!(found.invited_by(), sent.invited_by());
        assert_eq!(found.email(), sent.email());
        assert_eq!(found.message(), sent.message());
        assert_eq!(found.expires_at(), sent.expires_at());
        assert_eq!(found.created_at(), sent.created_at());
        let elsewhere = db
            .store
            .find_by_token_hash(&OrganizationId::new(), &hash("link"))
            .await
            .unwrap();
        assert!(elsewhere.is_none());
    }

    /// A hash no link carries finds nothing, rather than failing.
    #[tokio::test]
    async fn an_unknown_token_hash_is_not_found() {
        let db = fixture().await;

        let found = db
            .store
            .find_by_token_hash(&db.organization, &hash("nobody"))
            .await
            .unwrap();

        assert!(found.is_none());
    }

    /// Bob accepts: saving again keeps the acceptance and its time.
    #[tokio::test]
    async fn saving_again_keeps_the_acceptance() {
        let db = fixture().await;
        let sent = invitation(row(&db, "link"));
        db.store.save(&sent).await.unwrap();
        let accepted = invitation(OrgInvitationRow {
            id: *sent.id(),
            state: OfferState::Accepted { at: at(10) },
            ..row(&db, "link")
        });

        db.store.save(&accepted).await.unwrap();

        let found = db
            .store
            .find_by_token_hash(&db.organization, &hash("link"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.status(), InvitationStatus::Accepted);
        assert_eq!(found.accepted_at(), Some(at(10)));
    }

    /// Saving an acceptance after the invitation was revoked returns a
    /// conflict and leaves the invitation revoked.
    #[tokio::test]
    async fn a_closed_invitation_is_never_moved_again() {
        let db = fixture().await;
        let sent = invitation(row(&db, "link"));
        db.store.save(&sent).await.unwrap();
        let revoked = invitation(OrgInvitationRow {
            id: *sent.id(),
            state: OfferState::Revoked,
            ..row(&db, "link")
        });
        db.store.save(&revoked).await.unwrap();
        let accepted = invitation(OrgInvitationRow {
            id: *sent.id(),
            state: OfferState::Accepted { at: at(10) },
            ..row(&db, "link")
        });

        let saved = db.store.save(&accepted).await;

        assert!(matches!(saved, Err(DomainError::Conflict(_))));
        let found = db
            .store
            .find_by_token_hash(&db.organization, &hash("link"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.status(), InvitationStatus::Revoked);
    }

    /// The pending invitation to Bob's address is found while its link
    /// works; one whose link ran out, or one he declined, is not.
    #[tokio::test]
    async fn the_pending_invitation_to_an_address_is_one_whose_link_still_works() {
        let db = fixture().await;
        let address = Email::new("bob@acme.example").unwrap();
        db.store
            .save(&invitation(ran_out(row(&db, "old"))))
            .await
            .unwrap();
        db.store
            .save(&invitation(OrgInvitationRow {
                state: OfferState::Declined,
                ..row(&db, "declined")
            }))
            .await
            .unwrap();
        let before = db
            .store
            .find_pending_by_email(&db.organization, &address)
            .await
            .unwrap();
        db.store.save(&invitation(row(&db, "fresh"))).await.unwrap();

        let found = db
            .store
            .find_pending_by_email(&db.organization, &address)
            .await
            .unwrap()
            .unwrap();

        assert!(before.is_none());
        assert_eq!(found.token_hash(), &hash("fresh"));
    }

    /// Bob's pending invitation is found by his account even after its link
    /// ran out, so a resend reaches it; once accepted it is not.
    #[tokio::test]
    async fn a_members_pending_invitation_is_read_by_its_stored_status() {
        let db = fixture().await;
        let lapsed = invitation(ran_out(row(&db, "old")));
        db.store.save(&lapsed).await.unwrap();

        let found = db
            .store
            .find_pending_by_org_user(&db.organization, &db.bob)
            .await
            .unwrap();
        let for_ann = db
            .store
            .find_pending_by_org_user(&db.organization, &db.ann)
            .await
            .unwrap();

        assert_eq!(found.map(|held| *held.id()), Some(*lapsed.id()));
        assert!(for_ann.is_none());
    }

    /// Acme's pending invitations are listed oldest first, without the ones
    /// answered, and without another organization's.
    #[tokio::test]
    async fn an_organizations_pending_invitations_are_listed_oldest_first() {
        let db = fixture().await;
        let globex = an_organization(&db.db, "globex").await;
        let carol = a_member(&db.db, globex, "carol@globex.example").await;
        db.store
            .save(&invitation(OrgInvitationRow {
                created_at: at(5),
                ..row(&db, "newer")
            }))
            .await
            .unwrap();
        db.store.save(&invitation(row(&db, "older"))).await.unwrap();
        db.store
            .save(&invitation(OrgInvitationRow {
                state: OfferState::Revoked,
                ..row(&db, "revoked")
            }))
            .await
            .unwrap();
        db.store
            .save(&invitation(org_invitation_row(OrgInvitationSeed {
                organization: globex,
                invitee: carol,
                invited_by: carol,
                email: "carol@globex.example",
                token: "theirs",
            })))
            .await
            .unwrap();

        let pending = db.store.list_pending(&db.organization).await.unwrap();

        assert_eq!(tokens(&pending), ["older", "newer"]);
    }

    /// The sweep finds the invitations still pending whose link ran out by
    /// the time it asks, across organizations, and leaves the rest.
    #[tokio::test]
    async fn the_lapsed_invitations_are_the_pending_ones_whose_link_ran_out() {
        let db = fixture().await;
        db.store
            .save(&invitation(OrgInvitationRow {
                expires_at: at(100),
                ..row(&db, "due")
            }))
            .await
            .unwrap();
        db.store
            .save(&invitation(OrgInvitationRow {
                expires_at: at(300),
                ..row(&db, "later")
            }))
            .await
            .unwrap();
        db.store
            .save(&invitation(OrgInvitationRow {
                state: OfferState::Expired,
                expires_at: at(50),
                ..row(&db, "marked")
            }))
            .await
            .unwrap();

        let lapsed = db
            .store
            .list_lapsed(at(200), &PageRequest::default())
            .await
            .unwrap();

        assert_eq!(tokens(&lapsed.items), ["due"]);
    }

    /// Equal expiry times are split by invitation id, and a failed invitation
    /// left pending on the previous page cannot prevent the sweep completing.
    #[tokio::test]
    async fn organization_expiry_pages_advance_past_pending_rows_with_equal_times() {
        let db = fixture().await;
        let mut expected = Vec::new();
        for token in ["one", "two", "three"] {
            let sent = invitation(OrgInvitationRow {
                expires_at: at(100),
                ..row(&db, token)
            });
            expected.push(*sent.id());
            db.store.save(&sent).await.unwrap();
        }
        expected.sort_by_key(|id| *id.as_uuid());
        let mut request = PageRequest::first(Limit::internal(1));
        let mut seen = Vec::new();
        loop {
            let page = db.store.list_lapsed(at(100), &request).await.unwrap();
            assert_eq!(page.items.len(), 1);
            seen.extend(page.items.iter().map(|invitation| *invitation.id()));
            let Some(next) = request.following(&page) else {
                break;
            };
            request = next;
        }
        assert_eq!(seen, expected);
    }

    /// Reading an invitation with an invalid stored email address returns
    /// an infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_invitation_is_refused() {
        let db = fixture().await;
        db.store.save(&invitation(row(&db, "link"))).await.unwrap();
        db.db
            .tamper("UPDATE org_invitations SET email = 'not an address'")
            .await;

        let read = db
            .store
            .find_by_token_hash(&db.organization, &hash("link"))
            .await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
