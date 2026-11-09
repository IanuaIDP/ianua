//! Records of authorization decisions: each answer an app's access check
//! gave, and each request the tenant's policy decided.
//!
//! A record is evidence, written once on the path of the request it
//! decided and never changed. Who asked and what was decided are kept;
//! no credential ever is.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authorization::{
    DecisionFilter, DecisionRecord, DecisionRecordSortField, DecisionRecordStore,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::errors::DomainError;

use self::record::{DecisionBatchColumns, DecisionColumns, KeptDecision, version_column};
use crate::postgres::authorization::principals::kind_word;
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::stored::StoredWord as _;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of decision records.
pub struct PgDecisionRecordStore {
    databases: Arc<Databases>,
}

impl PgDecisionRecordStore {
    /// A store keeping decision records in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgDecisionRecordStore {}

impl SortColumns for DecisionRecordSortField {
    fn column(self) -> &'static str {
        match self {
            Self::DecidedAt => "decided_at",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

/// The ids of the records of `tenant_id` that `filter` keeps.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` for a version past the column's
/// range, which no tenant reaches.
fn searched(
    tenant_id: &ScopedTenant,
    filter: &DecisionFilter,
) -> Result<PageQuery<'static>, DomainError> {
    let mut query =
        PageQuery::ids("id", "decision_records").filter("tenant_id = ?", *tenant_id.as_uuid());
    if let Some(subject) = &filter.subject {
        query = query
            .filter("subject_kind = ?", kind_word(subject))
            .filter("subject_id = ?", subject.id());
    }
    if let Some(verdict) = filter.verdict {
        query = query.filter("verdict = ?", verdict.word());
    }
    if let Some(version) = filter.policy_version {
        query = query.filter("policy_version = ?", version_column(version)?);
    }
    if let Some(rule) = &filter.rule {
        query = query.filter("rule = ?", rule.as_str().to_owned());
    }
    if let Some(since) = filter.since {
        query = query.filter("decided_at >= ?", since);
    }
    Ok(query)
}

#[async_trait]
impl DecisionRecordStore for PgDecisionRecordStore {
    async fn record_all(
        &self,
        tenant_id: &ScopedTenant,
        records: &[DecisionRecord],
    ) -> Result<(), DomainError> {
        if records.is_empty() {
            return Ok(());
        }
        let columns = DecisionBatchColumns::of(records)?;
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/decision_records/record_all.sql",
                    &columns.ids,
                    tenant_id.as_uuid(),
                    &columns.asked_by,
                    &columns.subject_kinds,
                    &columns.subject_ids,
                    &columns.verdicts,
                    &columns.policy_versions as &[Option<i32>],
                    &columns.rules as &[Option<String>],
                    &columns.bases,
                    &columns.decided_at,
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn record(
        &self,
        tenant_id: &ScopedTenant,
        record: &DecisionRecord,
    ) -> Result<(), DomainError> {
        let columns = DecisionColumns::of(record)?;
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/decision_records/record.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.asked_by,
                    columns.subject_kind,
                    columns.subject_id,
                    columns.verdict,
                    columns.policy_version,
                    columns.rule,
                    columns.basis,
                    columns.decided_at,
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn search(
        &self,
        tenant_id: &ScopedTenant,
        filter: &DecisionFilter,
        page: &PageRequest,
    ) -> Result<Page<DecisionRecord>, DomainError> {
        let order = SortOrder::<DecisionRecordSortField>::default();
        let keyset = page.keyset(&order)?;
        let listed = searched(tenant_id, filter)?;
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                let records = sqlx::query_file_as!(
                    KeptDecision,
                    "queries/decision_records/by_ids.sql",
                    tenant_id.as_uuid(),
                    &ids
                )
                .fetch_all(connection)
                .await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        let records = records
            .into_iter()
            .map(KeptDecision::into_record)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(keyset.seal(records))
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::Limit;
    use ianua_app::ports::authorization::{MatchedRule, Verdict};
    use ianua_domain::domains::authorization::policy::version::PolicyVersion;
    use ianua_domain::types::{DecisionRecordId, Label, PrincipalRef, UserId};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::{
        allowed_check, policy_decision, refused_check, tenant,
    };

    /// A fresh database, the store on it, and a tenant whose decisions are
    /// recorded.
    async fn fixture() -> (TestDb, PgDecisionRecordStore, ScopedTenant) {
        let db = TestDb::fresh().await;
        let store = PgDecisionRecordStore::new(Arc::clone(&db.databases));
        (db, store, tenant())
    }

    fn everything() -> PageRequest {
        PageRequest::first(Limit::new(50).unwrap())
    }

    fn ids(page: &Page<DecisionRecord>) -> Vec<DecisionRecordId> {
        page.items.iter().map(|record| record.id).collect()
    }

    fn rule(name: &str) -> Label {
        Label::new("rule", name).unwrap()
    }

    /// Reads one decision page with the supplied filter and cursor.
    async fn search_records(
        store: &PgDecisionRecordStore,
        tenant: &ScopedTenant,
        filter: &DecisionFilter,
        page: &PageRequest,
    ) -> Page<DecisionRecord> {
        store.search(tenant, filter, page).await.unwrap()
    }

    /// Reads the complete small fixture through one decision filter.
    async fn filtered(
        store: &PgDecisionRecordStore,
        tenant: &ScopedTenant,
        filter: &DecisionFilter,
    ) -> Page<DecisionRecord> {
        search_records(store, tenant, filter, &everything()).await
    }

    /// Confirms that the newest-first page retains each recorded decision's evidence.
    fn assert_recorded(page: &Page<DecisionRecord>, records: &[DecisionRecord]) {
        assert_eq!(
            ids(page),
            records
                .iter()
                .rev()
                .map(|record| record.id)
                .collect::<Vec<_>>()
        );
        for (read, written) in page.items.iter().zip(records.iter().rev()) {
            assert_eq!(read.subject, written.subject);
            assert_eq!(read.decided_at, written.decided_at);
            assert_eq!(read.verdict(), written.verdict());
        }
    }

    /// Separately identifiable subject, verdict, rule and default decision records.
    struct SearchRecords {
        allowed: DecisionRecord,
        denied: DecisionRecord,
        by_rule: DecisionRecord,
        by_default: DecisionRecord,
    }

    impl SearchRecords {
        /// Confirms that the full search crosses the cursor in newest-first order.
        fn assert_pages(&self, first: &Page<DecisionRecord>, last: &Page<DecisionRecord>) {
            assert_eq!(
                ids(first),
                [self.by_default.id, self.by_rule.id, self.denied.id]
            );
            assert_eq!(ids(last), [self.allowed.id]);
        }

        /// Proves that subject and verdict filters keep the matching recorded evidence.
        async fn assert_subject_filters(
            &self,
            store: &PgDecisionRecordStore,
            tenant: &ScopedTenant,
        ) {
            let of_ann = filtered(
                store,
                tenant,
                &DecisionFilter {
                    subject: Some(self.allowed.subject),
                    ..DecisionFilter::default()
                },
            )
            .await;
            let refused = filtered(
                store,
                tenant,
                &DecisionFilter {
                    verdict: Some(Verdict::Denied),
                    ..DecisionFilter::default()
                },
            )
            .await;
            assert_eq!(ids(&of_ann), [self.allowed.id]);
            assert!(ids(&refused).contains(&self.denied.id));
        }

        /// Proves version, named-rule and lower-time-bound filtering independently.
        async fn assert_policy_filters(
            &self,
            store: &PgDecisionRecordStore,
            tenant: &ScopedTenant,
            version: PolicyVersion,
        ) {
            let of_second = DecisionFilter {
                policy_version: Some(version),
                ..DecisionFilter::default()
            };
            let of_rule = DecisionFilter {
                rule: Some(rule("block-admin")),
                ..DecisionFilter::default()
            };
            let lately = DecisionFilter {
                since: Some(at(2)),
                ..DecisionFilter::default()
            };
            let found = async |filter: &DecisionFilter| ids(&filtered(store, tenant, filter).await);
            assert_eq!(found(&of_second).await, [self.by_rule.id]);
            assert_eq!(found(&of_rule).await, [self.by_rule.id]);
            assert_eq!(found(&lately).await, [self.by_default.id, self.by_rule.id]);
        }
    }

    /// A recorded decision reads back with who asked, whom it was about,
    /// what it rested on and when.
    #[tokio::test]
    async fn a_recorded_decision_reads_back_as_recorded() {
        let (_db, store, acme) = fixture().await;
        let ann = PrincipalRef::User(UserId::new());
        let checked = allowed_check(ann, at(0));

        store.record(&acme, &checked).await.unwrap();

        let page = store
            .search(&acme, &DecisionFilter::default(), &everything())
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        let read = &page.items[0];
        assert_eq!(read.id, checked.id);
        assert_eq!(read.subject, ann);
        assert_eq!(read.decided_at, at(0));
        assert_eq!(read.verdict(), Verdict::Allowed);
    }

    /// A batch retains allowed, denied and policy evidence in its tenant.
    /// A conflicting row refuses the entire next batch, leaving the saved records intact.
    #[tokio::test]
    async fn decision_batches_are_atomic_and_tenant_scoped() {
        let (_db, store, acme) = fixture().await;
        let ann = PrincipalRef::User(UserId::new());
        let records = [
            allowed_check(ann, at(0)),
            refused_check(ann, at(1)),
            policy_decision(PolicyVersion::FIRST, MatchedRule::Default, at(2)),
        ];
        store.record_all(&acme, &records).await.unwrap();
        store.record_all(&acme, &[]).await.unwrap();

        let page = search_records(&store, &acme, &DecisionFilter::default(), &everything()).await;
        assert_recorded(&page, &records);
        assert!(
            search_records(&store, &tenant(), &DecisionFilter::default(), &everything())
                .await
                .items
                .is_empty()
        );
        let mut conflict = refused_check(ann, at(4));
        conflict.id = records[0].id;
        let attempt = store
            .record_all(&acme, &[allowed_check(ann, at(3)), conflict])
            .await;
        assert!(attempt.is_err());
        let after = search_records(&store, &acme, &DecisionFilter::default(), &everything()).await;
        assert_eq!(ids(&after), ids(&page));
    }

    /// Records are newest first, page by page, and each filter keeps only
    /// what it names.
    #[tokio::test]
    async fn a_search_is_newest_first_and_narrowed_by_each_filter() {
        let (_db, store, acme) = fixture().await;
        let ann = PrincipalRef::User(UserId::new());
        let second = PolicyVersion::FIRST.next().unwrap();
        let allowed = allowed_check(ann, at(0));
        let denied = refused_check(PrincipalRef::User(UserId::new()), at(1));
        let by_rule = policy_decision(second, MatchedRule::Rule(rule("block-admin")), at(2));
        let by_default = policy_decision(PolicyVersion::FIRST, MatchedRule::Default, at(3));
        for record in [&allowed, &denied, &by_rule, &by_default] {
            store.record(&acme, record).await.unwrap();
        }
        let page_one = search_records(
            &store,
            &acme,
            &DecisionFilter::default(),
            &PageRequest::first(Limit::new(3).unwrap()),
        )
        .await;
        let after = PageRequest::new(page_one.next.clone(), Limit::new(3).unwrap());
        let page_two = search_records(&store, &acme, &DecisionFilter::default(), &after).await;
        let records = SearchRecords {
            allowed,
            denied,
            by_rule,
            by_default,
        };
        records.assert_subject_filters(&store, &acme).await;
        records.assert_policy_filters(&store, &acme, second).await;
        records.assert_pages(&page_one, &page_two);
    }

    /// A decision recorded in Acme is absent from another tenant's search.
    #[tokio::test]
    async fn another_tenants_decisions_are_invisible() {
        let (_db, store, acme) = fixture().await;
        store
            .record(
                &acme,
                &allowed_check(PrincipalRef::User(UserId::new()), at(0)),
            )
            .await
            .unwrap();

        let page = store
            .search(&tenant(), &DecisionFilter::default(), &everything())
            .await
            .unwrap();

        assert!(page.items.is_empty());
    }

    /// A stored allowed verdict paired with a denied basis makes the
    /// decision search fail as corrupt storage.
    #[tokio::test]
    async fn a_record_filed_under_the_wrong_verdict_is_refused() {
        let (db, store, acme) = fixture().await;
        store
            .record(
                &acme,
                &refused_check(PrincipalRef::User(UserId::new()), at(0)),
            )
            .await
            .unwrap();
        db.tamper("UPDATE decision_records SET verdict = 'allowed'")
            .await;

        let read = store
            .search(&acme, &DecisionFilter::default(), &everything())
            .await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
