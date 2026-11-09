//! Members' requests to be erased, kept in the platform database.
//!
//! A request outlives the member it erases: it is the record that the
//! erasure was carried out. A member has at most one request under way at a
//! time, which the table keeps with a unique index.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::identity::ErasureBatch;
use ianua_app::ports::organization::OrgErasureRequestStore;
use ianua_domain::domains::organization::members::privacy::erasure::OrgErasureRequest;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ErasureRequestId, OrgUserId, OrganizationId, TokenHash};

use self::record::{ErasureColumns, ErasureRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The index that keeps a member to one request under way.
const ONE_UNDER_WAY: &str = "org_erasure_requests_one_under_way";

/// The Postgres store of members' erasure requests.
pub struct PgOrgErasureRequestStore {
    databases: Arc<Databases>,
}

impl PgOrgErasureRequestStore {
    /// A store keeping erasure requests in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

fn rebuilt(record: Option<ErasureRecord>) -> Result<Option<OrgErasureRequest>, DomainError> {
    record.map(ErasureRecord::into_request).transpose()
}

#[async_trait]
impl OrgErasureRequestStore for PgOrgErasureRequestStore {
    async fn find_active_by_member(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
    ) -> Result<Option<OrgErasureRequest>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                ErasureRecord,
                "queries/org_erasure_requests/under_way_of_member.sql",
                organization_id.as_uuid(),
                org_user_id.as_uuid()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        rebuilt(record)
    }

    async fn find_by_id(
        &self,
        organization_id: &OrganizationId,
        id: &ErasureRequestId,
    ) -> Result<Option<OrgErasureRequest>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                ErasureRecord,
                "queries/org_erasure_requests/by_id.sql",
                id.as_uuid(),
                organization_id.as_uuid()
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
    ) -> Result<Option<OrgErasureRequest>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                ErasureRecord,
                "queries/org_erasure_requests/by_cancel_token.sql",
                cancel_token_hash.as_str()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        rebuilt(record)
    }

    async fn save(&self, request: &OrgErasureRequest) -> Result<(), DomainError> {
        let columns = ErasureColumns::of(request);
        let written = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            let attempt = sqlx::query_file!(
                "queries/org_erasure_requests/save.sql",
                columns.id,
                columns.organization_id,
                columns.org_user_id,
                columns.reason,
                columns.status,
                columns.completed_at,
                columns.requested_at,
                columns.scheduled_at,
                columns.cancel_token_hash,
                columns.sent_to,
            )
            .execute(connection)
            .await;
            unique_on(attempt, ONE_UNDER_WAY)
        })
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-the-member-already-has-an-erasure",
                "the member already has an erasure under way"
            ))),
        }
    }

    async fn find_due(&self, batch: ErasureBatch) -> Result<Vec<OrgErasureRequest>, DomainError> {
        let limit = i64::try_from(ErasureBatch::LIMIT).map_err(DomainError::infra)?;
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                ErasureRecord,
                "queries/org_erasure_requests/due.sql",
                batch.now,
                batch.after.map(|after| after.scheduled_at),
                batch.after.map(|after| *after.id.as_uuid()),
                limit
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        records
            .into_iter()
            .map(ErasureRecord::into_request)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::identity::ErasurePosition;
    use ianua_app::ports::organization::OrganizationStore;
    use ianua_domain::domains::identity::privacy::erasure::ErasureState;
    use ianua_domain::domains::identity::privacy::erasure_status::ErasureStatus;
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::domains::organization::members::privacy::erasure::OrgErasureRequestRow;
    use ianua_domain::shared::config::DomainLimits;
    use time::Duration;

    use super::*;
    use crate::postgres::organization::PgOrganizationStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::organization::{org_erasure_request_row, organization_row};

    struct Fixture {
        db: TestDb,
        store: PgOrgErasureRequestStore,
        acme: OrganizationId,
    }

    /// A fresh database holding Acme, and the store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let acme = an_organization(&db, "acme").await;
        let store = PgOrgErasureRequestStore::new(Arc::clone(&db.databases));
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

    fn request(row: OrgErasureRequestRow) -> OrgErasureRequest {
        OrgErasureRequest::reconstitute(row).unwrap()
    }

    fn pending(organization: OrganizationId) -> OrgErasureRequest {
        request(org_erasure_request_row(organization, OrgUserId::new()))
    }

    fn in_state(organization: OrganizationId, state: ErasureState) -> OrgErasureRequest {
        request(OrgErasureRequestRow {
            state,
            ..org_erasure_request_row(organization, OrgUserId::new())
        })
    }

    fn ids(requests: &[OrgErasureRequest]) -> Vec<ErasureRequestId> {
        requests.iter().map(|request| *request.id()).collect()
    }

    /// Sam asks to be erased: his request is found by its id, by the token
    /// of its cancel link, and as the one under way for him.
    #[tokio::test]
    async fn a_saved_request_is_found_every_way() {
        let fx = fixture().await;
        let sams = pending(fx.acme);

        fx.store.save(&sams).await.unwrap();

        let by_id = fx.store.find_by_id(&fx.acme, sams.id()).await.unwrap();
        let by_token = fx
            .store
            .find_by_cancel_token_hash(sams.cancel_token_hash())
            .await
            .unwrap();
        let under_way = fx
            .store
            .find_active_by_member(&fx.acme, sams.org_user_id())
            .await
            .unwrap();
        for found in [by_id, by_token, under_way] {
            let found = found.unwrap();
            assert_eq!(found.id(), sams.id());
            assert_eq!(found.org_user_id(), sams.org_user_id());
            assert_eq!(found.reason(), sams.reason());
            assert_eq!(found.state(), sams.state());
            assert_eq!(found.requested_at(), sams.requested_at());
            assert_eq!(found.scheduled_at(), sams.scheduled_at());
            assert_eq!(found.sent_to(), sams.sent_to());
        }
    }

    /// An id, token or member nobody has finds nothing, rather than
    /// failing.
    #[tokio::test]
    async fn an_unknown_request_is_not_found() {
        let fx = fixture().await;
        let unknown = pending(fx.acme);

        assert!(
            fx.store
                .find_by_id(&fx.acme, unknown.id())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            fx.store
                .find_by_cancel_token_hash(unknown.cancel_token_hash())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            fx.store
                .find_active_by_member(&fx.acme, unknown.org_user_id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Acme's erasure request is absent from Globex's lookup by request ID
    /// and from its active-request lookup by member.
    #[tokio::test]
    async fn another_organizations_request_is_absent() {
        let fx = fixture().await;
        let globex = an_organization(&fx.db, "globex").await;
        let sams = pending(fx.acme);
        fx.store.save(&sams).await.unwrap();

        let by_id = fx.store.find_by_id(&globex, sams.id()).await.unwrap();
        let under_way = fx
            .store
            .find_active_by_member(&globex, sams.org_user_id())
            .await
            .unwrap();

        assert!(by_id.is_none());
        assert!(under_way.is_none());
    }

    /// A cancelled or completed request is no longer the one under way.
    #[tokio::test]
    async fn a_finished_request_is_not_under_way() {
        let fx = fixture().await;
        let cancelled = in_state(fx.acme, ErasureState::Cancelled);
        fx.store.save(&cancelled).await.unwrap();

        let under_way = fx
            .store
            .find_active_by_member(&fx.acme, cancelled.org_user_id())
            .await
            .unwrap();

        assert!(under_way.is_none());
    }

    /// The sweep finishes Sam's erasure: saving again keeps the new
    /// standing and when it completed.
    #[tokio::test]
    async fn saving_again_keeps_the_new_standing() {
        let fx = fixture().await;
        let sams = pending(fx.acme);
        fx.store.save(&sams).await.unwrap();
        let done_at = sams.scheduled_at().saturating_add(Duration::hours(1));
        let completed = request(OrgErasureRequestRow {
            id: *sams.id(),
            org_user_id: *sams.org_user_id(),
            cancel_token_hash: sams.cancel_token_hash().clone(),
            state: ErasureState::Completed { at: done_at },
            ..org_erasure_request_row(fx.acme, *sams.org_user_id())
        });

        fx.store.save(&completed).await.unwrap();

        let found = fx.store.find_by_id(&fx.acme, sams.id()).await.unwrap();
        assert_eq!(
            found.unwrap().state(),
            ErasureState::Completed { at: done_at }
        );
    }

    /// Saving a second pending erasure request for the same member returns
    /// a conflict.
    #[tokio::test]
    async fn a_second_request_under_way_is_refused() {
        let fx = fixture().await;
        let sam = OrgUserId::new();
        fx.store
            .save(&request(org_erasure_request_row(fx.acme, sam)))
            .await
            .unwrap();

        let second = fx
            .store
            .save(&request(org_erasure_request_row(fx.acme, sam)))
            .await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// The sweep finds every organization's pending requests whose grace
    /// period is over and the failed ones, the longest due first, and
    /// leaves the rest.
    #[tokio::test]
    async fn the_due_requests_are_found_longest_due_first() {
        let fx = fixture().await;
        let globex = an_organization(&fx.db, "globex").await;
        let early = request(OrgErasureRequestRow {
            requested_at: at(-86_400),
            scheduled_at: at(-86_400).saturating_add(Duration::days(7)),
            ..org_erasure_request_row(globex, OrgUserId::new())
        });
        let due = pending(fx.acme);
        let failed = in_state(fx.acme, ErasureState::Failed);
        let held = in_state(fx.acme, ErasureState::Held);
        let not_yet = request(OrgErasureRequestRow {
            requested_at: at(86_400 * 3),
            scheduled_at: at(86_400 * 3).saturating_add(Duration::days(7)),
            ..org_erasure_request_row(fx.acme, OrgUserId::new())
        });
        for request in [&due, &early, &failed, &held, &not_yet] {
            fx.store.save(request).await.unwrap();
        }
        let now = due.scheduled_at().saturating_add(Duration::hours(1));

        let found = fx.store.find_due(ErasureBatch::first(now)).await.unwrap();

        let mut expected = vec![*due.id(), *failed.id()];
        expected.sort_by_key(|id| *id.as_uuid());
        expected.insert(0, *early.id());
        assert_eq!(ids(&found), expected);
        assert!(
            found
                .iter()
                .all(|request| request.status() != ErasureStatus::Held)
        );
    }

    /// Equal due times across organizations span bounded pages. Failed
    /// requests remain eligible next sweep but do not repeat within this walk.
    #[tokio::test]
    async fn organization_erasure_batches_advance_over_timestamp_ties() {
        let fx = fixture().await;
        let globex = an_organization(&fx.db, "globex").await;
        let expected = save_tied_requests(&fx, globex).await;
        let mut batch = ErasureBatch::first(at(50).saturating_add(Duration::days(7)));
        let first = fx.store.find_due(batch).await.unwrap();
        assert_eq!(first.len(), ErasureBatch::LIMIT);
        let last = first.last().unwrap();
        batch.after = Some(position(last));

        let second = fx.store.find_due(batch).await.unwrap();

        assert_eq!(second.len(), 1);
        let found: Vec<_> = first
            .iter()
            .chain(&second)
            .map(|asked| *asked.id())
            .collect();
        assert_eq!(found, expected);
        assert_eq!(first[0].status(), ErasureStatus::Failed);
        let last = second.last().unwrap();
        batch.after = Some(position(last));
        assert!(fx.store.find_due(batch).await.unwrap().is_empty());
        assert_eq!(
            fx.store
                .find_due(ErasureBatch::first(batch.now))
                .await
                .unwrap()[0]
                .id(),
            &expected[0]
        );
    }

    /// Stores a full batch plus one across two organizations, including one retryable failure.
    async fn save_tied_requests(fx: &Fixture, globex: OrganizationId) -> Vec<ErasureRequestId> {
        let mut expected = Vec::new();
        for index in 1..=501 {
            let id = ErasureRequestId::from_uuid(uuid::Uuid::from_u128(index));
            let organization = match index % 2 {
                0 => globex,
                _ => fx.acme,
            };
            let asked = request(OrgErasureRequestRow {
                id,
                state: match index {
                    1 => ErasureState::Failed,
                    _ => ErasureState::Pending,
                },
                ..org_erasure_request_row(organization, OrgUserId::new())
            });
            fx.store.save(&asked).await.unwrap();
            expected.push(id);
        }
        expected
    }

    /// The stable sweep cursor immediately after a returned erasure request.
    fn position(request: &OrgErasureRequest) -> ErasurePosition {
        ErasurePosition {
            scheduled_at: request.scheduled_at(),
            id: *request.id(),
        }
    }

    /// Reading an erasure request whose stored recipient address is invalid
    /// returns an infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_request_is_refused() {
        let fx = fixture().await;
        let sams = pending(fx.acme);
        fx.store.save(&sams).await.unwrap();
        fx.db
            .tamper("UPDATE org_erasure_requests SET sent_to = 'not an address'")
            .await;

        let read = fx.store.find_by_id(&fx.acme, sams.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
