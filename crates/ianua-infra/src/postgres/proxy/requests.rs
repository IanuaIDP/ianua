//! The records of proxied requests: written by the gateway, many in one
//! statement, and searched by a tenant's admins.
//!
//! A record is a tenant row in the database the tenant lives in, under
//! row-level security. A batch is written per tenant, each tenant's
//! records in one statement. A search reads the correlation ids of its
//! page in the order asked for, then those rows with the one by-ids query.
//! Records past the tenant's retention are removed oldest first, a bounded
//! number per statement.

mod filters;
mod record;
mod words;

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::future::try_join_all;
use ianua_app::listing::Listing;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::proxy::{
    ProxyAccessLogSink, ProxyRequestLog, ProxyRequestRecord, RequestRecordFilter,
    RequestRecordPage, RequestRecordRetention, RequestRecordSortField,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

use self::filters::narrowed;
use self::record::{RequestBatch, RequestRecord};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres sink the gateway writes request records to.
pub struct PgProxyAccessLogSink {
    databases: Arc<Databases>,
}

impl PgProxyAccessLogSink {
    /// A sink writing request records to `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Writes `batch`, one tenant's records, in one statement.
    async fn write_tenant(&self, tenant: TenantId, batch: RequestBatch) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::Tenant(tenant),
            async |connection| write_batch(connection, tenant.as_uuid(), &batch).await,
        )
        .await
    }
}

/// Writes `batch` of `tenant`'s records.
/// The checked statement keeps every column's bind visible in SQL order.
#[allow(clippy::too_many_lines)]
async fn write_batch(
    connection: &mut PgConnection,
    tenant: &Uuid,
    batch: &RequestBatch,
) -> Result<(), sqlx::Error> {
    sqlx::query_file!(
        "queries/proxy_request_records/write.sql",
        tenant,
        &batch.correlation_ids,
        &batch.principals,
        &batch.principal_ids as &[Option<Uuid>],
        &batch.delegation_ids as &[Option<Uuid>],
        &batch.on_behalf_kinds as &[Option<String>],
        &batch.on_behalf_ids as &[Option<Uuid>],
        &batch.consumer_credentials as &[Option<String>],
        &batch.person_ids as &[Option<Uuid>],
        &batch.route_ids as &[Option<Uuid>],
        &batch.service_ids as &[Option<Uuid>],
        &batch.ip_addresses,
        &batch.methods,
        &batch.paths,
        &batch.outcomes,
        &batch.statuses,
        &batch.reasons as &[Option<String>],
        &batch.decided_by as &[Option<String>],
        &batch.decided_by_stage_ids as &[Option<Uuid>],
        &batch.rules as &[Option<String>],
        &batch.durations,
        &batch.classifications,
        &batch.occurred_at as &[OffsetDateTime],
        &batch.policy_versions as &[Option<i64>],
        &batch.closed_reasons as &[Option<String>],
        &batch.closed_ats as &[Option<OffsetDateTime>],
    )
    .execute(connection)
    .await?;
    Ok(())
}

#[async_trait]
impl ProxyAccessLogSink for PgProxyAccessLogSink {
    /// Writes `records`, each tenant's in one statement in the database the
    /// tenant lives in.
    async fn write_batch(&self, records: &[ProxyRequestRecord]) -> Result<(), DomainError> {
        let mut by_tenant: HashMap<TenantId, Vec<&ProxyRequestRecord>> = HashMap::new();
        for record in records {
            by_tenant.entry(record.tenant_id).or_default().push(record);
        }
        try_join_all(
            by_tenant
                .into_iter()
                .map(|(tenant, records)| self.write_tenant(tenant, RequestBatch::of(records))),
        )
        .await?;
        Ok(())
    }
}

/// The Postgres search of a tenant's request records.
pub struct PgProxyRequestLog {
    databases: Arc<Databases>,
}

impl PgProxyRequestLog {
    /// A search of the request records in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgProxyRequestLog {}

impl SortColumns for RequestRecordSortField {
    fn column(self) -> &'static str {
        match self {
            Self::OccurredAt => "occurred_at",
            Self::Status => "status",
            Self::Duration => "duration_ms",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

/// The records of `tenant` that `ids` names, in no order.
async fn records_of(
    connection: &mut PgConnection,
    tenant: &Uuid,
    ids: &[Uuid],
) -> Result<Vec<RequestRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        RequestRecord,
        "queries/proxy_request_records/by_ids.sql",
        tenant,
        ids
    )
    .fetch_all(connection)
    .await
}

#[async_trait]
impl ProxyRequestLog for PgProxyRequestLog {
    async fn search(
        &self,
        tenant_id: &ScopedTenant,
        listing: Listing<'_, &RequestRecordFilter, RequestRecordSortField>,
    ) -> Result<RequestRecordPage, DomainError> {
        let keyset = listing.keyset()?;
        let tenant = *tenant_id.as_uuid();
        let listed = narrowed(
            PageQuery::ids("correlation_id", "proxy_request_records")
                .filter("tenant_id = ?", tenant),
            listing.filter,
        );
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                let records = records_of(connection, &tenant, &ids).await?;
                Ok(in_page_order(&ids, records, |record| record.correlation_id))
            },
        )
        .await?;
        let records = records
            .into_iter()
            .map(RequestRecord::into_request)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(keyset.seal(records))
    }
}

/// The Postgres removal of a tenant's request records past its retention.
pub struct PgRequestRecordRetention {
    databases: Arc<Databases>,
}

impl PgRequestRecordRetention {
    /// A removal of the request records in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgRequestRecordRetention {}

#[async_trait]
impl RequestRecordRetention for PgRequestRecordRetention {
    async fn forget_before(
        &self,
        tenant_id: &ScopedTenant,
        before: OffsetDateTime,
        most: NonZeroU32,
    ) -> Result<u64, DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/proxy_request_records/forget_before.sql",
                    tenant_id.as_uuid(),
                    before,
                    i64::from(most.get()),
                )
                .execute(connection)
                .await
                .map(|done| done.rows_affected())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, PageRequest, Sort, SortOrder};
    use ianua_app::ports::proxy::{DecidedByFilter, DecisionFilter, RecordSubject};
    use ianua_domain::domains::authorization::policy::version::PolicyVersion;
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::proxy::observation::{
        DecidingRule, DecidingStage, GatewayCheck, ObservedPrincipal, RequestOutcome, RouteMatch,
        RulingPolicy, TunnelClose, TunnelCloseReason,
    };
    use ianua_domain::domains::proxy::stages::stage::StageKindName;
    use ianua_domain::types::{
        AgentId, DelegationId, Label, PrincipalRef, RouteId, ServiceId, StageId, UserId,
    };

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::proxy::{allowed, request_record};

    struct Fixture {
        db: TestDb,
        tenant: ScopedTenant,
        sink: PgProxyAccessLogSink,
        log: PgProxyRequestLog,
    }

    /// A fresh database, a tenant, and the sink and the search on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            sink: PgProxyAccessLogSink::new(Arc::clone(&db.databases)),
            log: PgProxyRequestLog::new(Arc::clone(&db.databases)),
            tenant: ScopedTenant::for_background(TenantId::new()),
            db,
        }
    }

    fn denied(decided_by: DecidingStage, rule: DecidingRule) -> RequestOutcome {
        RequestOutcome::Denied {
            status: 403,
            reason: "Outside Office Hours".to_owned(),
            decided_by,
            rule,
        }
    }

    async fn search(
        db: &Fixture,
        filter: &RequestRecordFilter,
        sort: &SortOrder<RequestRecordSortField>,
        page: &PageRequest,
    ) -> RequestRecordPage {
        db.log
            .search(&db.tenant, Listing { filter, sort, page })
            .await
            .unwrap()
    }

    async fn found(db: &Fixture, filter: &RequestRecordFilter) -> Vec<time::OffsetDateTime> {
        let page = PageRequest::first(Limit::new(50).unwrap());
        search(db, filter, &SortOrder::default(), &page)
            .await
            .items
            .iter()
            .map(|record| record.occurred_at)
            .collect()
    }

    /// Ann's WebSocket is recorded allowed when it opens. Later Tess
    /// suspends her and the gateway writes the record again with its close:
    /// the row keeps the first decision and gains the close, and the first
    /// close stands when the record is written once more.
    #[tokio::test]
    async fn a_close_reaches_the_record_written_when_it_opened() {
        let db = fixture().await;
        let opened = request_record(*db.tenant, allowed(101), 5, 1);
        let close = TunnelClose {
            reason: TunnelCloseReason::AccessEnded,
            at: at(2),
        };
        db.sink.record(opened.clone()).await.unwrap();

        let closed = ProxyRequestRecord {
            closed: Some(close),
            ..opened.clone()
        };
        db.sink.record(closed).await.unwrap();
        db.sink
            .record(ProxyRequestRecord {
                closed: Some(TunnelClose {
                    reason: TunnelCloseReason::CheckFailed,
                    at: close.at,
                }),
                ..opened
            })
            .await
            .unwrap();

        let page = PageRequest::first(Limit::new(10).unwrap());
        let read = search(
            &db,
            &RequestRecordFilter::default(),
            &SortOrder::default(),
            &page,
        )
        .await;
        assert_eq!(read.items.len(), 1, "one record for the one request");
        assert_eq!(read.items[0].status(), 101);
        assert_eq!(read.items[0].closed, Some(close));
    }

    /// A record and its close queued into one batch are written as one row.
    #[tokio::test]
    async fn a_record_and_its_close_in_one_batch_are_one_row() {
        let db = fixture().await;
        let opened = request_record(*db.tenant, allowed(101), 5, 1);
        let close = TunnelClose {
            reason: TunnelCloseReason::CheckFailed,
            at: opened.occurred_at,
        };
        let closed = ProxyRequestRecord {
            closed: Some(close),
            ..opened.clone()
        };

        db.sink.write_batch(&[opened, closed]).await.unwrap();

        let page = PageRequest::first(Limit::new(10).unwrap());
        let read = search(
            &db,
            &RequestRecordFilter::default(),
            &SortOrder::default(),
            &page,
        )
        .await;
        assert_eq!(read.items.len(), 1);
        assert_eq!(read.items[0].closed, Some(close));
    }

    /// A written record reads back with everything it held: who asked, the
    /// route, the refusal with its stage and rule, and the levels found.
    #[tokio::test]
    async fn a_written_record_reads_back_whole() {
        let db = fixture().await;
        let record = refused_agent_record(*db.tenant);

        db.sink.record(record.clone()).await.unwrap();

        let page = PageRequest::first(Limit::new(10).unwrap());
        let read = search(
            &db,
            &RequestRecordFilter::default(),
            &SortOrder::default(),
            &page,
        )
        .await;
        let back = &read.items[0];
        assert_eq!(back.principal, record.principal);
        assert_eq!(back.route, record.route);
        assert_eq!(back.outcome, record.outcome);
        assert_eq!(back.classification, record.classification);
        assert_eq!(back.policy, record.policy);
        assert_eq!(back.ip_address, record.ip_address);
        assert_eq!(back.duration_ms, 12);
    }

    /// Builds an attributed agent request refused by a named policy stage and rule.
    fn refused_agent_record(tenant: TenantId) -> ProxyRequestRecord {
        let ann = UserId::new();
        let stage = StageId::new();
        ProxyRequestRecord {
            principal: ObservedPrincipal::Agent {
                agent_id: AgentId::new(),
                delegation_id: DelegationId::new(),
                on_behalf_of: PrincipalRef::User(ann),
            },
            route: RouteMatch::Matched {
                route_id: RouteId::new(),
                service_id: ServiceId::new(),
            },
            classification: vec![DataClassLevel::Restricted, DataClassLevel::Confidential],
            policy: RulingPolicy::Tenant(PolicyVersion::parse(7).unwrap()),
            ..request_record(
                tenant,
                denied(
                    DecidingStage::Stage {
                        stage_id: stage,
                        kind: StageKindName::Policy,
                    },
                    DecidingRule::Named(Label::new("name", "contractors off hours").unwrap()),
                ),
                12,
                1,
            )
        }
    }

    /// A batch of three tenants' records is written at once, and each
    /// tenant searches its own alone, newest first, page by page.
    #[tokio::test]
    async fn a_batch_lands_with_each_tenant_and_pages_newest_first() {
        let db = fixture().await;
        let other = TenantId::new();
        let batch: Vec<ProxyRequestRecord> = (1..=3)
            .map(|s| request_record(*db.tenant, allowed(200), 5, s))
            .chain(std::iter::once(request_record(other, allowed(200), 5, 9)))
            .collect();

        db.sink.write_batch(&batch).await.unwrap();

        let order = SortOrder::default();
        let first = PageRequest::first(Limit::new(2).unwrap());
        let page_one = search(&db, &RequestRecordFilter::default(), &order, &first).await;
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = search(&db, &RequestRecordFilter::default(), &order, &after).await;
        let times: Vec<_> = page_one
            .items
            .iter()
            .chain(&page_two.items)
            .map(|record| record.occurred_at)
            .collect();
        assert_eq!(times, [at(3), at(2), at(1)]);
        assert!(!page_two.has_next());
    }

    /// A search narrows by decision, by the check that refused, by rule,
    /// by the reason's text in any case, by route, by who asked and by
    /// time.
    #[tokio::test]
    async fn a_search_narrows_by_each_filter() {
        let db = fixture().await;
        let examples = SearchExamples {
            ann: UserId::new(),
            route: RouteId::new(),
            stage: StageId::new(),
            rule: Label::new("name", "contractors off hours").unwrap(),
        };
        save_filter_examples(&db, &examples).await;

        assert_decision_filters(&db).await;
        assert_check_filters(&db).await;
        assert_subject_filters(&db, examples).await;
    }

    /// Identifiers shared by the stored records and their filter expectations.
    struct SearchExamples {
        ann: UserId,
        route: RouteId,
        stage: StageId,
        rule: Label,
    }

    /// Saves an allowed route, a gateway refusal and an attributed policy refusal.
    async fn save_filter_examples(db: &Fixture, examples: &SearchExamples) {
        let by_gateway = request_record(
            *db.tenant,
            denied(
                DecidingStage::Gateway(GatewayCheck::Route),
                DecidingRule::Unnamed,
            ),
            5,
            2,
        );
        let by_stage = stage_example(*db.tenant, examples);
        let let_through = ProxyRequestRecord {
            route: RouteMatch::Matched {
                route_id: examples.route,
                service_id: ServiceId::new(),
            },
            ..request_record(*db.tenant, allowed(200), 5, 1)
        };
        db.sink
            .write_batch(&[let_through, by_gateway, by_stage])
            .await
            .unwrap();
    }

    /// Builds the refused agent record carrying the rule and person used by filters.
    fn stage_example(tenant: TenantId, examples: &SearchExamples) -> ProxyRequestRecord {
        ProxyRequestRecord {
            principal: ObservedPrincipal::Agent {
                agent_id: AgentId::new(),
                delegation_id: DelegationId::new(),
                on_behalf_of: PrincipalRef::User(examples.ann),
            },
            ..request_record(
                tenant,
                denied(
                    DecidingStage::Stage {
                        stage_id: examples.stage,
                        kind: StageKindName::Policy,
                    },
                    DecidingRule::Named(examples.rule.clone()),
                ),
                5,
                3,
            )
        }
    }

    /// Applies one filter choice to otherwise unrestricted record criteria.
    fn filter(change: fn(&mut RequestRecordFilter)) -> RequestRecordFilter {
        let mut filter = RequestRecordFilter::default();
        change(&mut filter);
        filter
    }

    /// Checks allowed and refused decisions select their respective records.
    async fn assert_decision_filters(db: &Fixture) {
        assert_eq!(
            found(db, &filter(|f| f.decision = DecisionFilter::Allowed)).await,
            [at(1)]
        );
        assert_eq!(
            found(db, &filter(|f| f.decision = DecisionFilter::Refused)).await,
            [at(3), at(2)]
        );
    }

    /// Checks gateway and stage-kind filters select the check responsible for refusal.
    async fn assert_check_filters(db: &Fixture) {
        assert_eq!(
            found(
                db,
                &filter(|f| f.decided_by = DecidedByFilter::Gateway(GatewayCheck::Route))
            )
            .await,
            [at(2)]
        );
        assert_eq!(
            found(
                db,
                &filter(|f| f.decided_by = DecidedByFilter::StageKind(StageKindName::Policy))
            )
            .await,
            [at(3)]
        );
    }

    /// Checks combined rule, person, reason, route and time criteria.
    async fn assert_subject_filters(db: &Fixture, examples: SearchExamples) {
        assert_eq!(
            found(
                db,
                &RequestRecordFilter {
                    decided_by: DecidedByFilter::Stage(examples.stage),
                    rule: Some(examples.rule),
                    subject: Some(RecordSubject::User(examples.ann)),
                    reason_contains: Some("office".to_owned()),
                    ..RequestRecordFilter::default()
                }
            )
            .await,
            [at(3)]
        );
        assert_eq!(
            found(
                db,
                &RequestRecordFilter {
                    route: Some(examples.route),
                    after: Some(at(0)),
                    before: Some(at(2)),
                    ..RequestRecordFilter::default()
                }
            )
            .await,
            [at(1)]
        );
    }

    /// A search by status pages through the statuses in order.
    #[tokio::test]
    async fn a_search_reads_by_status() {
        let db = fixture().await;
        db.sink
            .write_batch(&[
                request_record(*db.tenant, allowed(503), 5, 1),
                request_record(*db.tenant, allowed(200), 5, 2),
                request_record(*db.tenant, allowed(404), 5, 3),
            ])
            .await
            .unwrap();
        let order = SortOrder::single(Sort::ascending(RequestRecordSortField::Status));
        let first = PageRequest::first(Limit::new(2).unwrap());

        let page_one = search(&db, &RequestRecordFilter::default(), &order, &first).await;
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = search(&db, &RequestRecordFilter::default(), &order, &after).await;

        let statuses: Vec<u16> = page_one
            .items
            .iter()
            .chain(&page_two.items)
            .map(ProxyRequestRecord::status)
            .collect();
        assert_eq!(statuses, [200, 404, 503]);
    }

    /// A tenant with a database of its own keeps its records there.
    #[tokio::test]
    async fn a_tenant_apart_keeps_its_records_in_its_own_database() {
        let db = fixture().await;
        let own = TestDb::fresh().await;
        db.db.databases.register(*db.tenant, own.as_dedicated());

        db.sink
            .record(request_record(*db.tenant, allowed(200), 5, 1))
            .await
            .unwrap();

        assert_eq!(found(&db, &RequestRecordFilter::default()).await, [at(1)]);
        db.db.databases.deregister(&db.tenant);
        assert!(found(&db, &RequestRecordFilter::default()).await.is_empty());
    }

    /// An invalid client IP address in storage makes the request log
    /// search fail as corrupt storage.
    #[tokio::test]
    async fn a_record_with_an_address_that_does_not_read_is_refused() {
        let db = fixture().await;
        db.sink
            .record(request_record(*db.tenant, allowed(200), 5, 1))
            .await
            .unwrap();
        db.db
            .tamper("UPDATE proxy_request_records SET ip_address = 'nowhere'")
            .await;
        let page = PageRequest::first(Limit::new(10).unwrap());

        let read = db
            .log
            .search(
                &db.tenant,
                Listing {
                    filter: &RequestRecordFilter::default(),
                    sort: &SortOrder::default(),
                    page: &page,
                },
            )
            .await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// Acme's retention has passed two of its three records. A statement
    /// allowed one removes the oldest; the next removes the other; the
    /// newest stays, and so does Globex's record from the same time.
    #[tokio::test]
    async fn records_past_the_retention_go_oldest_first_and_only_the_tenants() {
        let db = fixture().await;
        let globex = ScopedTenant::for_background(TenantId::new());
        let batch: Vec<ProxyRequestRecord> = (1..=3)
            .map(|s| request_record(*db.tenant, allowed(200), 5, s))
            .chain(std::iter::once(request_record(*globex, allowed(200), 5, 1)))
            .collect();
        db.sink.write_batch(&batch).await.unwrap();
        let retention = PgRequestRecordRetention::new(Arc::clone(&db.db.databases));
        let (one, ten) = (NonZeroU32::MIN, NonZeroU32::new(10).unwrap());

        let first = retention
            .forget_before(&db.tenant, at(3), one)
            .await
            .unwrap();
        let after_first = found(&db, &RequestRecordFilter::default()).await;
        let second = retention
            .forget_before(&db.tenant, at(3), ten)
            .await
            .unwrap();

        assert_eq!((first, second), (1, 1));
        assert_eq!(after_first, [at(3), at(2)]);
        assert_eq!(found(&db, &RequestRecordFilter::default()).await, [at(3)]);
        assert_foreign_record_kept(&db, &globex).await;
    }

    /// Verifies retention left the other tenant's single record available.
    async fn assert_foreign_record_kept(db: &Fixture, globex: &ScopedTenant) {
        let page = PageRequest::first(Limit::new(10).unwrap());
        let kept = db
            .log
            .search(
                globex,
                Listing {
                    filter: &RequestRecordFilter::default(),
                    sort: &SortOrder::default(),
                    page: &page,
                },
            )
            .await
            .unwrap();
        assert_eq!(kept.items.len(), 1, "Globex's record is its own");
    }
}
