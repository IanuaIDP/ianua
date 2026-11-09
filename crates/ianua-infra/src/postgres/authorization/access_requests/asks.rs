//! Just-in-time access requests: asked, answered, withdrawn or run out.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, Sort, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authorization::{
    AccessRequestFilter, AccessRequestSortField, AccessRequestStore,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authorization::access_request::{
    ANSWER_WINDOW, AccessRequest, AccessRequestStatus,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::AccessRequestId;
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

use self::record::{AccessRequestColumns, AccessRequestRecord};
use crate::postgres::authorization::principals::kind_word;
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of access requests.
pub struct PgAccessRequestStore {
    databases: Arc<Databases>,
}

impl PgAccessRequestStore {
    /// A store keeping access requests in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgAccessRequestStore {}

/// The records of the requests of `tenant_id` that `ids` names, in no
/// order.
async fn requests_of(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    ids: &[Uuid],
) -> Result<Vec<AccessRequestRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        AccessRequestRecord,
        "queries/access_requests/by_ids.sql",
        tenant_id,
        ids
    )
    .fetch_all(connection)
    .await
}

fn rebuilt(
    records: Vec<AccessRequestRecord>,
) -> Result<Vec<AccessRequest<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(AccessRequestRecord::into_request)
        .collect()
}

impl SortColumns for AccessRequestSortField {
    fn column(self) -> &'static str {
        match self {
            Self::RequestedAt => "requested_at",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

/// The ids of the requests of `tenant_id` that `filter` keeps.
fn listed(tenant_id: &ScopedTenant, filter: AccessRequestFilter) -> PageQuery<'static> {
    let every =
        PageQuery::ids("id", "access_requests").filter("tenant_id = ?", *tenant_id.as_uuid());
    match filter {
        AccessRequestFilter::All => every,
        AccessRequestFilter::Pending => {
            every.filter("status = ?", AccessRequestStatus::Pending.as_str())
        }
        AccessRequestFilter::AskedBy(principal) => every
            .filter("requester_kind = ?", kind_word(&principal))
            .filter("requester_id = ?", principal.id()),
    }
}

/// Writes the checked request columns and reports whether its pending state still matched.
async fn write_request(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    columns: &AccessRequestColumns<'_>,
) -> Result<u64, sqlx::Error> {
    let approver = columns.approver.as_ref();
    let done = sqlx::query_file!(
        "queries/access_requests/save.sql",
        columns.id,
        tenant_id,
        columns.requester.kind,
        columns.requester.id,
        columns.requester.person,
        columns.asked,
        columns.asked_id,
        columns.reason,
        columns.length_seconds,
        columns.status,
        approver.map(|human| human.kind),
        approver.map(|human| human.id),
        approver.map(|human| human.person),
        columns.answered_at,
        columns.requested_at,
    )
    .execute(connection)
    .await?;
    Ok(done.rows_affected())
}

#[async_trait]
impl AccessRequestStore for PgAccessRequestStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AccessRequestId,
    ) -> Result<Option<AccessRequest<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| requests_of(connection, tenant_id.as_uuid(), &ids).await,
        )
        .await?;
        Ok(rebuilt(records)?.pop())
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
        filter: AccessRequestFilter,
        page: &PageRequest,
    ) -> Result<Page<AccessRequest<ResolvedTenant>>, DomainError> {
        let order = SortOrder::<AccessRequestSortField>::default();
        let keyset = page.keyset(&order)?;
        let listed = listed(tenant_id, filter);
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                let records = requests_of(connection, tenant_id.as_uuid(), &ids).await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        Ok(keyset.seal(rebuilt(records)?))
    }

    async fn find_lapsed(
        &self,
        tenant_id: &ScopedTenant,
        now: OffsetDateTime,
        page: &PageRequest,
    ) -> Result<Page<AccessRequest<ResolvedTenant>>, DomainError> {
        let asked_by = now.saturating_sub(ANSWER_WINDOW);
        let order = SortOrder::single(Sort::ascending(AccessRequestSortField::RequestedAt));
        let keyset = page.keyset(&order)?;
        let listed =
            listed(tenant_id, AccessRequestFilter::Pending).filter("requested_at <= ?", asked_by);
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                let records = requests_of(connection, tenant_id.as_uuid(), &ids).await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        Ok(keyset.seal(rebuilt(records)?))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        request: &AccessRequest<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = AccessRequestColumns::of(request);
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| write_request(connection, tenant_id.as_uuid(), &columns).await,
        )
        .await?;
        match written {
            0 => Err(DomainError::conflict(message!(
                "infra-this-request-was-already-answered-withdrawn",
                "this request was already answered, withdrawn or run out"
            ))),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::Limit;
    use ianua_domain::domains::authorization::access_request::{AccessRequestRow, AskedAccess};
    use ianua_domain::types::{RoleId, UserId};
    use time::Duration;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::{
        approved_request, human, pending_request, pending_request_row, tenant,
    };

    /// A fresh database, the store on it, and a tenant whose people ask.
    async fn fixture() -> (TestDb, PgAccessRequestStore, ScopedTenant) {
        let db = TestDb::fresh().await;
        let store = PgAccessRequestStore::new(Arc::clone(&db.databases));
        (db, store, tenant())
    }

    fn ids(page: &Page<AccessRequest<ResolvedTenant>>) -> Vec<AccessRequestId> {
        page.items.iter().map(|request| *request.id()).collect()
    }

    /// Lists the requested page, requiring the store to read it successfully.
    async fn list_requests(
        store: &PgAccessRequestStore,
        tenant: &ScopedTenant,
        filter: AccessRequestFilter,
        page: &PageRequest,
    ) -> Page<AccessRequest<ResolvedTenant>> {
        store.list(tenant, filter, page).await.unwrap()
    }

    /// Saves three equally old pending requests with deterministic cursor tie-breakers.
    async fn pending_ties(
        store: &PgAccessRequestStore,
        tenant: &ScopedTenant,
    ) -> Vec<AccessRequestId> {
        let mut expected = Vec::new();
        for index in 1..=3 {
            let request = AccessRequest::reconstitute(AccessRequestRow {
                id: AccessRequestId::from_uuid(Uuid::from_u128(index)),
                ..pending_request_row("ann@acme.example", at(0))
            })
            .unwrap();
            expected.push(*request.id());
            store.save(tenant, &request).await.unwrap();
        }
        expected
    }

    /// Saves two pending requests and one answered request in creation order.
    async fn requests_in_creation_order(
        store: &PgAccessRequestStore,
        tenant: &ScopedTenant,
    ) -> [AccessRequest<ResolvedTenant>; 3] {
        let oldest = pending_request("ann@acme.example", at(0));
        let middle = pending_request("cy@acme.example", at(1));
        let newest = approved_request(
            &pending_request("dee@acme.example", at(2)),
            "bob@acme.example",
            at(3),
        );
        for request in [&oldest, &middle, &newest] {
            store.save(tenant, request).await.unwrap();
        }
        [oldest, middle, newest]
    }

    /// A pending request, and then its approval, read back as saved: who
    /// asked, for what, and who answered when.
    #[tokio::test]
    async fn a_request_and_its_answer_read_back_as_saved() {
        let (_db, store, acme) = fixture().await;
        let asked = pending_request("ann@acme.example", at(0));
        store.save(&acme, &asked).await.unwrap();
        let approved = approved_request(&asked, "bob@acme.example", at(10));

        let before = store.find_by_id(&acme, asked.id()).await.unwrap().unwrap();
        store.save(&acme, &approved).await.unwrap();
        let after = store.find_by_id(&acme, asked.id()).await.unwrap().unwrap();

        assert_eq!(before.requester(), asked.requester());
        assert_eq!(before.asked(), asked.asked());
        assert_eq!(before.length(), asked.length());
        assert_eq!(before.answer(), asked.answer());
        assert_eq!(after.status(), AccessRequestStatus::Approved);
        assert_eq!(after.answer(), approved.answer());
    }

    /// A second approval based on a pending copy conflicts, leaving the
    /// first approver's answer unchanged.
    #[tokio::test]
    async fn a_request_already_answered_takes_no_second_answer() {
        let (_db, store, acme) = fixture().await;
        let asked = pending_request("ann@acme.example", at(0));
        store.save(&acme, &asked).await.unwrap();
        let first = approved_request(&asked, "bob@acme.example", at(10));
        let second = approved_request(&asked, "cy@acme.example", at(11));
        store.save(&acme, &first).await.unwrap();

        let answered_again = store.save(&acme, &second).await;

        let kept = store.find_by_id(&acme, asked.id()).await.unwrap().unwrap();
        assert!(matches!(answered_again, Err(DomainError::Conflict(_))));
        assert_eq!(kept.answer(), first.answer());
    }

    /// An id nobody has finds nothing, and another tenant finds none of
    /// this one's requests.
    #[tokio::test]
    async fn an_unknown_or_foreign_request_is_not_found() {
        let (_db, store, acme) = fixture().await;
        let asked = pending_request("ann@acme.example", at(0));
        store.save(&acme, &asked).await.unwrap();
        let globex = tenant();

        let unknown = store
            .find_by_id(&acme, &AccessRequestId::new())
            .await
            .unwrap();
        let foreign = store.find_by_id(&globex, asked.id()).await.unwrap();
        let listed = store
            .list(
                &globex,
                AccessRequestFilter::All,
                &PageRequest::first(Limit::new(10).unwrap()),
            )
            .await
            .unwrap();

        assert!(unknown.is_none());
        assert!(foreign.is_none());
        assert!(listed.items.is_empty());
    }

    /// Requests are listed newest first, page by page, and narrowed to the
    /// pending ones or to those one account asked.
    #[tokio::test]
    async fn a_list_is_newest_first_and_narrowed_by_its_filter() {
        let (_db, store, acme) = fixture().await;
        let [oldest, middle, newest] = requests_in_creation_order(&store, &acme).await;

        let page_one = list_requests(
            &store,
            &acme,
            AccessRequestFilter::All,
            &PageRequest::first(Limit::new(2).unwrap()),
        )
        .await;
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = list_requests(&store, &acme, AccessRequestFilter::All, &after).await;
        let everything = PageRequest::first(Limit::new(10).unwrap());
        let pending = list_requests(&store, &acme, AccessRequestFilter::Pending, &everything).await;
        let by_ann = list_requests(
            &store,
            &acme,
            AccessRequestFilter::AskedBy(oldest.requester().principal()),
            &everything,
        )
        .await;

        assert_eq!(ids(&page_one), [*newest.id(), *middle.id()]);
        assert_eq!(ids(&page_two), [*oldest.id()]);
        assert_eq!(ids(&pending), [*middle.id(), *oldest.id()]);
        assert_eq!(ids(&by_ann), [*oldest.id()]);
    }

    /// The sweep finds the pending requests asked a full answer window
    /// ago, and leaves newer and answered ones.
    #[tokio::test]
    async fn the_requests_whose_window_closed_are_found() {
        let (_db, store, acme) = fixture().await;
        let now = at(0)
            .saturating_add(ANSWER_WINDOW)
            .saturating_add(Duration::hours(1));
        let stale = pending_request("ann@acme.example", at(0));
        let fresh = pending_request("cy@acme.example", now);
        let answered = approved_request(
            &pending_request("dee@acme.example", at(0)),
            "bob@acme.example",
            at(5),
        );
        for request in [&stale, &fresh, &answered] {
            store.save(&acme, request).await.unwrap();
        }

        let lapsed = store
            .find_lapsed(&acme, now, &PageRequest::first(Limit::new(10).unwrap()))
            .await
            .unwrap();

        assert_eq!(lapsed.items.len(), 1);
        assert_eq!(lapsed.items[0].id(), stale.id());
    }

    /// Equal-time requests page oldest first without repeating requests left
    /// pending, and neither fresh nor foreign requests enter this sweep.
    #[tokio::test]
    async fn lapsed_request_pages_advance_past_pending_timestamp_ties() {
        let (_db, store, acme) = fixture().await;
        let cutoff = at(0).saturating_add(ANSWER_WINDOW);
        let expected = pending_ties(&store, &acme).await;
        store
            .save(&tenant(), &pending_request("other@globex.example", at(0)))
            .await
            .unwrap();
        store
            .save(&acme, &pending_request("new@acme.example", cutoff))
            .await
            .unwrap();
        let first = store
            .find_lapsed(&acme, cutoff, &PageRequest::first(Limit::new(2).unwrap()))
            .await
            .unwrap();

        let second = store
            .find_lapsed(
                &acme,
                cutoff,
                &PageRequest::new(first.next.clone(), Limit::new(2).unwrap()),
            )
            .await
            .unwrap();

        assert_eq!(ids(&first), expected[..2]);
        assert_eq!(ids(&second), expected[2..]);
        assert!(!second.has_next());
    }

    /// Replacing the stored approver with the requester makes the request
    /// read fail as corrupt storage.
    #[tokio::test]
    async fn a_request_answered_by_its_asker_is_refused() {
        let (db, store, acme) = fixture().await;
        let asked = approved_request(
            &pending_request("ann@acme.example", at(0)),
            "bob@acme.example",
            at(5),
        );
        store.save(&acme, &asked).await.unwrap();
        db.tamper(
            "UPDATE access_requests SET approver_kind = requester_kind, \
             approver_id = requester_id, approver_person = requester_person",
        )
        .await;

        let read = store.find_by_id(&acme, asked.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// A request for a role is kept as one, and reads back as asking for
    /// that role.
    #[tokio::test]
    async fn a_request_for_a_role_reads_back_as_one() {
        let (_db, store, acme) = fixture().await;
        let role = RoleId::new();
        let asked = AccessRequest::reconstitute(AccessRequestRow {
            asked: AskedAccess::Role(role),
            requester: human(UserId::new(), "ann@acme.example"),
            ..pending_request_row("ann@acme.example", at(0))
        })
        .unwrap();

        store.save(&acme, &asked).await.unwrap();

        let found = store.find_by_id(&acme, asked.id()).await.unwrap().unwrap();
        assert_eq!(found.asked(), AskedAccess::Role(role));
    }
}
