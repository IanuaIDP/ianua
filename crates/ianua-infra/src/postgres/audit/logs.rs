//! The audit logs as their readers page through them: a tenant's own, an
//! organization's across its tenants, and the platform's across every
//! record.
//!
//! A page's ids are read from each place the log is kept, in the list's
//! order past the cursor; the rows of those ids are read with the one
//! by-ids query of their table, the tenant user who acted joined beside
//! them; and the names of the members, operators and tenants on the page
//! are read once from the platform database.

pub(crate) mod filters;
pub(crate) mod record;
pub(crate) mod sources;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::listing::{Cursor, Limit, PageRequest, Sort, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::audit::{
    AuditExportSource, AuditLogEntry, AuditLogFilter, AuditLogPage, AuditLogSortField, ExportPage,
    ExportPageStart, OrgAuditLogStore, PlatformAuditLogStore, TenantAuditLogStore,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::audit::access::{AuditLogOf, OrgLogView};
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;

use self::filters::Narrowing;
use self::sources::{
    OwnRecords, PageSelection, Source, Tenants, reached_history_tenants, read_page, sources_of,
};
use crate::postgres::foundation::pool::Databases;

/// The Postgres store of a tenant's own audit log.
pub struct PgTenantAuditLogStore {
    databases: Arc<Databases>,
    limits: DomainLimits,
}

impl PgTenantAuditLogStore {
    /// A store reading audit logs from `databases`, the names it shows
    /// checked against `limits`.
    #[must_use]
    pub fn new(databases: Arc<Databases>, limits: DomainLimits) -> Self {
        Self { databases, limits }
    }
}

impl TenantScoped for PgTenantAuditLogStore {}

#[async_trait]
impl TenantAuditLogStore for PgTenantAuditLogStore {
    async fn query(
        &self,
        tenant_id: &ScopedTenant,
        filter: &AuditLogFilter,
        sort: &SortOrder<AuditLogSortField>,
        page: &PageRequest,
    ) -> Result<AuditLogPage, DomainError> {
        let keyset = page.keyset(sort)?;
        let narrowing = Narrowing::of_log(filter).without_tenant();
        let sources = vec![Source::Tenant(**tenant_id)];
        read_page(
            &self.databases,
            sources,
            &PageSelection {
                narrowing: &narrowing,
                keyset: &keyset,
            },
            &self.limits,
        )
        .await
    }
}

/// The Postgres store of an organization's audit log: its own records and
/// those retained from the tenants its reader reaches, including deleted
/// tenants.
pub struct PgOrgAuditLogStore {
    databases: Arc<Databases>,
    limits: DomainLimits,
}

impl PgOrgAuditLogStore {
    /// A store reading audit logs from `databases`, the names it shows
    /// checked against `limits`.
    #[must_use]
    pub fn new(databases: Arc<Databases>, limits: DomainLimits) -> Self {
        Self { databases, limits }
    }
}

#[async_trait]
impl OrgAuditLogStore for PgOrgAuditLogStore {
    async fn query(
        &self,
        view: &OrgLogView,
        filter: &AuditLogFilter,
        sort: &SortOrder<AuditLogSortField>,
        page: &PageRequest,
    ) -> Result<AuditLogPage, DomainError> {
        let keyset = page.keyset(sort)?;
        let narrowing = Narrowing::of_log(filter);
        let tenants =
            reached_history_tenants(&self.databases, view.organization(), view.reach()).await?;
        let sources = sources_of(
            &self.databases,
            Tenants::Only(&tenants),
            OwnRecords::Of(*view.organization()),
            &narrowing,
        );
        read_page(
            &self.databases,
            sources,
            &PageSelection {
                narrowing: &narrowing,
                keyset: &keyset,
            },
            &self.limits,
        )
        .await
    }
}

/// The Postgres store of the platform's whole audit log, for operators.
pub struct PgPlatformAuditLogStore {
    databases: Arc<Databases>,
    limits: DomainLimits,
}

impl PgPlatformAuditLogStore {
    /// A store reading audit logs from `databases`, the names it shows
    /// checked against `limits`.
    #[must_use]
    pub fn new(databases: Arc<Databases>, limits: DomainLimits) -> Self {
        Self { databases, limits }
    }
}

#[async_trait]
impl PlatformAuditLogStore for PgPlatformAuditLogStore {
    async fn query(
        &self,
        filter: &AuditLogFilter,
        sort: &SortOrder<AuditLogSortField>,
        page: &PageRequest,
    ) -> Result<AuditLogPage, DomainError> {
        let keyset = page.keyset(sort)?;
        let narrowing = Narrowing::of_log(filter);
        let sources = sources_of(
            &self.databases,
            Tenants::Every,
            OwnRecords::Every,
            &narrowing,
        );
        read_page(
            &self.databases,
            sources,
            &PageSelection {
                narrowing: &narrowing,
                keyset: &keyset,
            },
            &self.limits,
        )
        .await
    }
}

/// How long one export page may take before it is given up on.
const PAGE_TIMEOUT: Duration = Duration::from_secs(5);

/// The Postgres read of the audit logs for their exports: a keyset page at
/// a time, newest first, never past the moment the export covers, given up
/// on after a few seconds so the worker tries again later.
pub struct PgAuditExportSource {
    databases: Arc<Databases>,
    limits: DomainLimits,
}

impl PgAuditExportSource {
    /// A read of the audit logs in `databases`, the names it shows checked
    /// against `limits`.
    #[must_use]
    pub fn new(databases: Arc<Databases>, limits: DomainLimits) -> Self {
        Self { databases, limits }
    }

    /// The places `page`'s log is kept, narrowed as `narrowing` says and
    /// as far into its tenants as whoever asked for the export reached.
    async fn sources(
        &self,
        page: &ExportPage<'_>,
        narrowing: &Narrowing,
    ) -> Result<Vec<Source>, DomainError> {
        match page.log {
            AuditLogOf::Tenant(tenant) => Ok(vec![Source::Tenant(tenant)]),
            AuditLogOf::Organization(organization) => {
                let tenants =
                    reached_history_tenants(&self.databases, &organization, page.filter.reach())
                        .await?;
                Ok(sources_of(
                    &self.databases,
                    Tenants::Only(&tenants),
                    OwnRecords::Of(organization),
                    narrowing,
                ))
            }
            AuditLogOf::Platform => Ok(sources_of(
                &self.databases,
                Tenants::Every,
                OwnRecords::Every,
                narrowing,
            )),
        }
    }

    /// The records `page` asks for.
    async fn read(&self, page: ExportPage<'_>) -> Result<Vec<AuditLogEntry>, DomainError> {
        let narrowing = narrowing_of(&page);
        let order = SortOrder::single(Sort::descending(AuditLogSortField::OccurredAt));
        let after = match page.start {
            ExportPageStart::Newest => None,
            ExportPageStart::OlderThan(last) => Some(Cursor::at(
                &order,
                vec![last.occurred_at.into(), last.id.as_uuid().into()],
            )),
        };
        let request = PageRequest::new(after, Limit::internal(page.limit.get()));
        let keyset = request.keyset(&order)?;
        let sources = self.sources(&page, &narrowing).await?;
        let read = read_page(
            &self.databases,
            sources,
            &PageSelection {
                narrowing: &narrowing,
                keyset: &keyset,
            },
            &self.limits,
        )
        .await?;
        Ok(read.items)
    }
}

/// What `page` is narrowed to: its filter, never past the moment it
/// covers, and for a tenant's log never another tenant's records.
fn narrowing_of(page: &ExportPage<'_>) -> Narrowing {
    let narrowing = Narrowing::of_export(page.filter, page.until);
    match page.log {
        AuditLogOf::Tenant(_) => narrowing.without_tenant(),
        AuditLogOf::Organization(_) | AuditLogOf::Platform => narrowing,
    }
}

#[async_trait]
impl AuditExportSource for PgAuditExportSource {
    async fn page(&self, page: ExportPage<'_>) -> Result<Vec<AuditLogEntry>, DomainError> {
        tokio::time::timeout(PAGE_TIMEOUT, self.read(page))
            .await
            .map_err(DomainError::infra)?
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use ianua_app::ports::audit::{AuditLogCursor, NamedInRecord};
    use ianua_app::ports::identity::UserStore;
    use ianua_app::ports::tenant::TenantStore;
    use ianua_app::services::identity::sign_ins::sign_ins_of;
    use ianua_domain::domains::audit::access::LogReach;
    use ianua_domain::domains::audit::builder::AuditContext;
    use ianua_domain::domains::audit::export::filter::{AuditExportFilter, AuditExportFilterParts};
    use ianua_domain::domains::audit::record::AuditTarget;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::test_support::events::{
        sample_account_locked_out, sample_email_changed, sample_login_failed_at,
        sample_login_succeeded, sample_organization_event,
    };
    use ianua_domain::types::{
        ActedBy, ActorRef, Email, Fact, IpAddress, OrganizationId, TenantId, UserId,
    };

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::postgres::tenant::PgTenantStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::audit::{
        failed_sign_in, recorded, recorded_as, saved_organization, saved_tenant_of,
    };
    use crate::test_support::rows::identity::user_row;

    struct Fixture {
        db: TestDb,
        organization: OrganizationId,
        tenant: ScopedTenant,
        store: PgTenantAuditLogStore,
    }

    /// A fresh database holding Acme and one of its tenants, and the
    /// tenant log's store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let tenant = saved_tenant_of(&db.databases, organization).await;
        let store = PgTenantAuditLogStore::new(Arc::clone(&db.databases), DomainLimits::default());
        Fixture {
            db,
            organization,
            tenant,
            store,
        }
    }

    /// The default newest-first order and a first page of the requested size.
    fn newest_first(limit: u32) -> (SortOrder<AuditLogSortField>, PageRequest) {
        (
            SortOrder::default(),
            PageRequest::first(Limit::new(limit).unwrap()),
        )
    }

    /// The fixture tenant's first fifty records matching a filter.
    async fn tenant_log(db: &Fixture, filter: &AuditLogFilter) -> AuditLogPage {
        let (order, page) = newest_first(50);
        db.store
            .query(&db.tenant, filter, &order, &page)
            .await
            .unwrap()
    }

    /// The occurrence times in the same order as the returned records.
    fn times(page: &AuditLogPage) -> Vec<time::OffsetDateTime> {
        page.items.iter().map(|entry| entry.occurred_at).collect()
    }

    /// The fixture organization's first fifty records matching a filter.
    async fn organization_log(db: &Fixture, filter: &AuditLogFilter) -> AuditLogPage {
        let store = PgOrgAuditLogStore::new(Arc::clone(&db.db.databases), DomainLimits::default());
        let (order, page) = newest_first(50);
        store
            .query(&every_tenant(db.organization), filter, &order, &page)
            .await
            .unwrap()
    }

    /// The whole of `organization`'s log, as its owner reads it.
    fn every_tenant(organization: OrganizationId) -> OrgLogView {
        OrgLogView::new(organization, LogReach::Every)
    }

    /// The fixture organization's records as far as `reach` shows them,
    /// and only those of `tenant` when one is named.
    async fn reached_log(db: &Fixture, reach: LogReach, tenant: Option<TenantId>) -> AuditLogPage {
        let store = PgOrgAuditLogStore::new(Arc::clone(&db.db.databases), DomainLimits::default());
        let (order, page) = newest_first(50);
        let filter = AuditLogFilter {
            tenant_id: tenant,
            ..AuditLogFilter::default()
        };
        store
            .query(
                &OrgLogView::new(db.organization, reach),
                &filter,
                &order,
                &page,
            )
            .await
            .unwrap()
    }

    /// A first page narrowed to the account or address named by a record.
    async fn named_log(db: &Fixture, names: NamedInRecord) -> AuditLogPage {
        tenant_log(
            db,
            &AuditLogFilter {
                names: Some(names),
                ..AuditLogFilter::default()
            },
        )
        .await
    }

    /// Event type, time window, target and address predicates for independent reads.
    fn individual_filters() -> [AuditLogFilter; 5] {
        [
            AuditLogFilter {
                event_type: Some("authentication.login".to_owned()),
                ..Default::default()
            },
            AuditLogFilter {
                event_type: Some("tenant.".to_owned()),
                ..Default::default()
            },
            AuditLogFilter {
                after: Some(at(0)),
                before: Some(at(2)),
                ..Default::default()
            },
            AuditLogFilter {
                target: Some("user-7".to_owned()),
                ..Default::default()
            },
            AuditLogFilter {
                ip_address: Some(IpAddress::new("203.0.113.7").unwrap()),
                ..Default::default()
            },
        ]
    }

    /// Listing a deleted tenant retains its record without including a foreign tenant.
    async fn assert_retained_listing(db: &Fixture, theirs: TenantId) {
        let all = organization_log(db, &AuditLogFilter::default()).await;
        assert_eq!(times(&all), [at(1)]);
        let selected = organization_log(
            db,
            &AuditLogFilter {
                tenant_id: Some(*db.tenant),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(times(&selected), [at(1)]);
        let foreign = organization_log(
            db,
            &AuditLogFilter {
                tenant_id: Some(theirs),
                ..Default::default()
            },
        )
        .await;
        assert!(foreign.items.is_empty());
    }

    /// Exporting the organization retains exactly the deleted tenant's earlier record.
    async fn assert_retained_export(db: &Fixture) {
        let source =
            PgAuditExportSource::new(Arc::clone(&db.db.databases), DomainLimits::default());
        let filter = AuditExportFilter::default();
        let exported = source
            .page(ExportPage {
                log: AuditLogOf::Organization(db.organization),
                filter: &filter,
                until: at(3),
                start: ExportPageStart::Newest,
                limit: NonZeroU32::new(50).unwrap(),
            })
            .await
            .unwrap();
        assert_eq!(
            exported
                .iter()
                .map(|entry| entry.occurred_at)
                .collect::<Vec<_>>(),
            [at(1)]
        );
    }

    /// Three sign-ins of Acme's tenant are paged newest first, two then
    /// one, each page after the last.
    #[tokio::test]
    async fn a_tenants_log_is_read_newest_first_page_by_page() {
        let db = fixture().await;
        let events = (1..=3).map(|s| failed_sign_in(*db.tenant, s)).collect();
        recorded(&db.db.databases, events).await;
        let (order, first) = newest_first(2);

        let page_one = db
            .store
            .query(&db.tenant, &AuditLogFilter::default(), &order, &first)
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = db
            .store
            .query(&db.tenant, &AuditLogFilter::default(), &order, &after)
            .await
            .unwrap();

        assert_eq!(times(&page_one), [at(3), at(2)]);
        assert_eq!(times(&page_two), [at(1)]);
        assert!(!page_two.has_next());
        assert_eq!(page_one.items[0].tenant_id, Some(*db.tenant));
        assert!(page_one.items[0].tenant_slug.is_some());
    }

    /// Naming another tenant in the filter still returns only the scoped
    /// tenant's record.
    #[tokio::test]
    async fn a_tenants_log_holds_its_own_records_alone() {
        let db = fixture().await;
        let other = saved_tenant_of(&db.db.databases, db.organization).await;
        recorded(
            &db.db.databases,
            vec![failed_sign_in(*db.tenant, 1), failed_sign_in(*other, 2)],
        )
        .await;

        let read = tenant_log(
            &db,
            &AuditLogFilter {
                tenant_id: Some(*other),
                ..AuditLogFilter::default()
            },
        )
        .await;

        assert_eq!(times(&read), [at(1)]);
    }

    /// The log narrows by event type, time, target and address, each on
    /// its own.
    #[tokio::test]
    async fn a_log_narrows_by_each_filter() {
        let db = fixture().await;
        let tenant = *db.tenant;
        let context = AuditContext::system()
            .with_target_id(AuditTarget::Entity("user-7".to_owned()))
            .with_request(
                Fact::Known(IpAddress::new("203.0.113.7").unwrap()),
                Fact::Unknown,
            );
        recorded(&db.db.databases, vec![failed_sign_in(tenant, 1)]).await;
        recorded_as(&db.db.databases, vec![failed_sign_in(tenant, 5)], &context).await;

        let [by_type, other_type, window, targeted, from_address] = individual_filters();
        let by_type = tenant_log(&db, &by_type).await;
        let other_type = tenant_log(&db, &other_type).await;
        let window = tenant_log(&db, &window).await;
        let targeted = tenant_log(&db, &targeted).await;
        let from_address = tenant_log(&db, &from_address).await;

        assert_eq!(by_type.items.len(), 2);
        assert!(other_type.items.is_empty());
        assert_eq!(times(&window), [at(1)]);
        assert_eq!(times(&targeted), [at(5)]);
        assert_eq!(targeted.items[0].target.id(), Some("user-7"));
        assert_eq!(times(&from_address), [at(5)]);
    }

    /// A filter by the person a record names keeps the failed sign-ins at
    /// their address, however its case was typed, and the lockouts of
    /// their account; a record naming someone else is left out.
    #[tokio::test]
    async fn a_log_narrows_to_the_records_naming_a_person() {
        let db = fixture().await;
        let tenant = *db.tenant;
        let ann = UserId::new();
        recorded(
            &db.db.databases,
            vec![
                failed_sign_in(tenant, 1),
                sample_account_locked_out(tenant, ann, at(2)),
                sample_account_locked_out(tenant, UserId::new(), at(3)),
            ],
        )
        .await;

        let at_address = named_log(
            &db,
            NamedInRecord::Address(Email::new("ANN@acme.test").unwrap()),
        )
        .await;
        let of_account = named_log(&db, NamedInRecord::Account(ann)).await;
        let elsewhere = named_log(
            &db,
            NamedInRecord::Address(Email::new("bob@acme.test").unwrap()),
        )
        .await;

        assert_eq!(times(&at_address), [at(1)]);
        assert_eq!(times(&of_account), [at(2)]);
        assert!(elsewhere.items.is_empty());
    }

    /// Ann's sign-in history includes her success, lockout and failed attempts
    /// at addresses while she held them, newest first. It excludes Bob's
    /// success and attempts before or after her ownership of each address.
    #[tokio::test]
    async fn a_persons_sign_ins_are_read_by_account_and_held_address() {
        let db = fixture().await;
        let tenant = *db.tenant;
        let (ann, bob) = (UserId::new(), UserId::new());
        recorded(
            &db.db.databases,
            vec![
                sample_login_failed_at(tenant, "ann@new.test", at(3)),
                sample_login_failed_at(tenant, "ann@old.test", at(5)),
                sample_login_succeeded(tenant, 30, at(8)).with_actor(ActorRef::User(ann)),
                sample_email_changed(tenant, ann, ("ann@old.test", "ann@new.test"), at(10)),
                sample_login_failed_at(tenant, "ann@old.test", at(15)),
                sample_login_failed_at(tenant, "ANN@new.test", at(20)),
                sample_account_locked_out(tenant, ann, at(25)),
                sample_login_succeeded(tenant, 30, at(30)).with_actor(ActorRef::User(bob)),
            ],
        )
        .await;
        let current = Email::new("ann@new.test").unwrap();
        let of = sign_ins_of(&db.store, &db.tenant, &ann, &current)
            .await
            .unwrap();

        let read = tenant_log(
            &db,
            &AuditLogFilter {
                sign_ins_of: Some(of),
                ..AuditLogFilter::default()
            },
        )
        .await;

        assert_eq!(times(&read), [at(25), at(20), at(8), at(5)]);
    }

    /// Ann, a tenant user, is shown by her name and address; the platform's
    /// own work is shown as the system. A filter by Ann keeps hers alone.
    #[tokio::test]
    async fn an_actor_is_shown_by_name_and_filtered_by() {
        let db = fixture().await;
        let ann = User::reconstitute(user_row("ann@acme.test")).unwrap();
        PgUserStore::new(Arc::clone(&db.db.databases), DomainLimits::default())
            .save(&db.tenant, &ann)
            .await
            .unwrap();
        let hers = failed_sign_in(*db.tenant, 2).with_actor(ActorRef::User(*ann.id()));
        recorded(&db.db.databases, vec![failed_sign_in(*db.tenant, 1), hers]).await;

        let all = tenant_log(&db, &AuditLogFilter::default()).await;
        let by_ann = tenant_log(
            &db,
            &AuditLogFilter {
                actor: Some(ActorRef::User(*ann.id())),
                ..AuditLogFilter::default()
            },
        )
        .await;

        assert_eq!(all.items[0].actor_display, "ann@acme.test (ann@acme.test)");
        assert_eq!(all.items[1].actor_display, "System");
        assert_eq!(times(&by_ann), [at(2)]);
    }

    /// A list by event type pages in that order, ties broken by id.
    #[tokio::test]
    async fn a_log_reads_by_event_type() {
        let db = fixture().await;
        let tenant = *db.tenant;
        let succeeded = sample_login_succeeded(tenant, 30, at(9));
        recorded(&db.db.databases, vec![failed_sign_in(tenant, 1), succeeded]).await;
        let order = SortOrder::single(Sort::ascending(AuditLogSortField::EventType));
        let page = PageRequest::first(Limit::new(10).unwrap());

        let read = db
            .store
            .query(&db.tenant, &AuditLogFilter::default(), &order, &page)
            .await
            .unwrap();

        let types: Vec<&str> = read.items.iter().map(|e| e.event_type.as_str()).collect();
        assert_eq!(
            types,
            [
                "authentication.login_failed",
                "authentication.login_succeeded"
            ]
        );
    }

    /// Acme's log holds its own records and those of each of its tenants,
    /// one of them in a database of its own, and none of another
    /// organization's; a filter by one tenant keeps that tenant's alone.
    #[tokio::test]
    async fn an_organizations_log_spans_its_tenants() {
        let db = fixture().await;
        let own = TestDb::fresh().await;
        let apart = saved_tenant_of(&db.db.databases, db.organization).await;
        db.db.databases.register(*apart, own.as_dedicated());
        let globex = saved_organization(&db.db.databases).await;
        let theirs = saved_tenant_of(&db.db.databases, globex).await;
        recorded(
            &db.db.databases,
            vec![
                sample_organization_event(db.organization, at(1)),
                failed_sign_in(*db.tenant, 2),
                failed_sign_in(*apart, 3),
                failed_sign_in(*theirs, 4),
                sample_organization_event(globex, at(5)),
            ],
        )
        .await;
        let all = organization_log(&db, &AuditLogFilter::default()).await;
        let of_apart = organization_log(
            &db,
            &AuditLogFilter {
                tenant_id: Some(*apart),
                ..AuditLogFilter::default()
            },
        )
        .await;

        assert_eq!(times(&all), [at(3), at(2), at(1)]);
        assert_eq!(times(&of_apart), [at(3)]);
    }

    /// An organization filtering for another organization's tenant receives
    /// no records.
    #[tokio::test]
    async fn an_organizations_log_holds_no_other_tenant() {
        let db = fixture().await;
        let globex = saved_organization(&db.db.databases).await;
        let theirs = saved_tenant_of(&db.db.databases, globex).await;
        recorded(&db.db.databases, vec![failed_sign_in(*theirs, 1)]).await;
        let store = PgOrgAuditLogStore::new(Arc::clone(&db.db.databases), DomainLimits::default());
        let (order, page) = newest_first(50);

        let read = store
            .query(
                &every_tenant(db.organization),
                &AuditLogFilter {
                    tenant_id: Some(*theirs),
                    ..AuditLogFilter::default()
                },
                &order,
                &page,
            )
            .await
            .unwrap();

        assert!(read.items.is_empty());
    }

    /// Max reaches one of Acme's two tenants. He reads that tenant's
    /// records and Acme's own, and asked for the other by name reads
    /// nothing, as he would a tenant with no records.
    #[tokio::test]
    async fn a_reader_of_an_organizations_log_sees_only_the_tenants_reached() {
        let db = fixture().await;
        let other = saved_tenant_of(&db.db.databases, db.organization).await;
        recorded(
            &db.db.databases,
            vec![
                sample_organization_event(db.organization, at(1)),
                failed_sign_in(*db.tenant, 2),
                failed_sign_in(*other, 3),
            ],
        )
        .await;
        let reach = LogReach::Tenants(vec![*db.tenant]);

        let all = reached_log(&db, reach.clone(), None).await;
        let named = reached_log(&db, reach, Some(*other)).await;

        assert_eq!(times(&all), [at(2), at(1)]);
        assert!(named.items.is_empty());
    }

    /// Vic reaches no tenant, one kept in a database of its own included.
    /// He reads Acme's own records alone.
    #[tokio::test]
    async fn a_reader_reaching_no_tenant_sees_only_the_organizations_own_records() {
        let db = fixture().await;
        let own = TestDb::fresh().await;
        let apart = saved_tenant_of(&db.db.databases, db.organization).await;
        db.db.databases.register(*apart, own.as_dedicated());
        recorded(
            &db.db.databases,
            vec![
                sample_organization_event(db.organization, at(1)),
                failed_sign_in(*db.tenant, 2),
                failed_sign_in(*apart, 3),
            ],
        )
        .await;

        let read = reached_log(&db, LogReach::Tenants(Vec::new()), None).await;

        assert_eq!(times(&read), [at(1)]);
    }

    /// An export Max asked for holds Acme's own records and his tenant's,
    /// and none of the other's.
    #[tokio::test]
    async fn an_export_is_narrowed_as_its_asker_was() {
        let db = fixture().await;
        let other = saved_tenant_of(&db.db.databases, db.organization).await;
        recorded(
            &db.db.databases,
            vec![
                sample_organization_event(db.organization, at(1)),
                failed_sign_in(*db.tenant, 2),
                failed_sign_in(*other, 3),
            ],
        )
        .await;
        let source =
            PgAuditExportSource::new(Arc::clone(&db.db.databases), DomainLimits::default());
        let filter = AuditExportFilter::from_stored(
            AuditExportFilterParts::default(),
            LogReach::Tenants(vec![*db.tenant]),
        )
        .unwrap();

        let exported = source
            .page(ExportPage {
                log: AuditLogOf::Organization(db.organization),
                filter: &filter,
                until: at(10),
                start: ExportPageStart::Newest,
                limit: NonZeroU32::new(50).unwrap(),
            })
            .await
            .unwrap();

        let exported: Vec<_> = exported.iter().map(|entry| entry.occurred_at).collect();
        assert_eq!(exported, [at(2), at(1)]);
    }

    /// After tenant deletion, its organization can still list and export the
    /// retained record, including a list filtered to that tenant. Another
    /// organization's records remain excluded.
    #[tokio::test]
    async fn an_organizations_log_and_export_retain_a_deleted_tenants_records() {
        let db = fixture().await;
        let globex = saved_organization(&db.db.databases).await;
        let theirs = saved_tenant_of(&db.db.databases, globex).await;
        recorded(
            &db.db.databases,
            vec![failed_sign_in(*db.tenant, 1), failed_sign_in(*theirs, 2)],
        )
        .await;
        let tenants = PgTenantStore::new(Arc::clone(&db.db.databases), DomainLimits::default());
        let mut tenant = tenants.find_by_id(&db.tenant).await.unwrap().unwrap();
        let _archived =
            ianua_domain::shared::clock::freeze(tenant.created_at() + time::Duration::days(1));
        tenant.archive(ActedBy::Platform).unwrap();
        let _later =
            ianua_domain::shared::clock::freeze(tenant.updated_at() + time::Duration::days(31));
        tenant.delete(ActedBy::Platform).unwrap();
        tenants.save(&tenant).await.unwrap();
        assert_retained_listing(&db, *theirs).await;
        assert_retained_export(&db).await;
    }

    /// The platform's log holds every record, of every organization and
    /// tenant, a tenant with a database of its own included, paged across
    /// all of them.
    #[tokio::test]
    async fn the_platforms_log_holds_every_record() {
        let db = fixture().await;
        let own = TestDb::fresh().await;
        let apart = saved_tenant_of(&db.db.databases, db.organization).await;
        db.db.databases.register(*apart, own.as_dedicated());
        recorded(
            &db.db.databases,
            vec![
                sample_organization_event(db.organization, at(1)),
                failed_sign_in(*db.tenant, 2),
                failed_sign_in(*apart, 3),
            ],
        )
        .await;
        let store =
            PgPlatformAuditLogStore::new(Arc::clone(&db.db.databases), DomainLimits::default());
        let (order, first) = newest_first(2);

        let page_one = store
            .query(&AuditLogFilter::default(), &order, &first)
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = store
            .query(&AuditLogFilter::default(), &order, &after)
            .await
            .unwrap();

        assert_eq!(times(&page_one), [at(3), at(2)]);
        assert_eq!(times(&page_two), [at(1)]);
        assert_eq!(page_two.items[0].tenant_id, None);
    }

    /// Reading the audit log rejects a stored record with an unknown event
    /// type as corrupt.
    #[tokio::test]
    async fn a_record_of_an_unknown_event_type_is_refused() {
        let db = fixture().await;
        recorded(&db.db.databases, vec![failed_sign_in(*db.tenant, 1)]).await;
        db.db
            .tamper(
                "SET session_replication_role = replica; \
                 UPDATE audit_records SET event_type = 'wizard.cast'; \
                 SET session_replication_role = origin;",
            )
            .await;
        let (order, page) = newest_first(10);

        let read = db
            .store
            .query(&db.tenant, &AuditLogFilter::default(), &order, &page)
            .await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// An export of Acme's tenant reads its records newest first, a page at
    /// a time from just older than the last one written, and never one
    /// written after the moment it covers.
    #[tokio::test]
    async fn an_export_reads_its_log_page_by_page_up_to_its_moment() {
        let db = fixture().await;
        let events = (1..=4).map(|s| failed_sign_in(*db.tenant, s)).collect();
        recorded(&db.db.databases, events).await;
        let source =
            PgAuditExportSource::new(Arc::clone(&db.db.databases), DomainLimits::default());
        let filter = AuditExportFilter::default();
        let page = |start| ExportPage {
            log: AuditLogOf::Tenant(*db.tenant),
            filter: &filter,
            until: at(3),
            start,
            limit: NonZeroU32::new(2).unwrap(),
        };

        let first = source.page(page(ExportPageStart::Newest)).await.unwrap();
        let last = AuditLogCursor::past(&first[1]);
        let second = source
            .page(page(ExportPageStart::OlderThan(last)))
            .await
            .unwrap();

        let read: Vec<_> = first.iter().chain(&second).map(|e| e.occurred_at).collect();
        assert_eq!(read, [at(3), at(2), at(1)]);
    }

    /// The platform's export reads an organization's records and a tenant's
    /// alike.
    #[tokio::test]
    async fn the_platforms_export_reads_every_record() {
        let db = fixture().await;
        recorded(
            &db.db.databases,
            vec![
                sample_organization_event(db.organization, at(1)),
                failed_sign_in(*db.tenant, 2),
            ],
        )
        .await;
        let source =
            PgAuditExportSource::new(Arc::clone(&db.db.databases), DomainLimits::default());
        let filter = AuditExportFilter::default();

        let read = source
            .page(ExportPage {
                log: AuditLogOf::Platform,
                filter: &filter,
                until: at(10),
                start: ExportPageStart::Newest,
                limit: NonZeroU32::new(10).unwrap(),
            })
            .await
            .unwrap();

        assert_eq!(read.len(), 2);
    }

    /// A tenant with no records reads an empty last page.
    #[tokio::test]
    async fn a_tenant_with_no_records_reads_nothing() {
        let db = fixture().await;
        let unknown = ScopedTenant::for_background(TenantId::new());
        let (order, page) = newest_first(10);

        let read = db
            .store
            .query(&unknown, &AuditLogFilter::default(), &order, &page)
            .await
            .unwrap();

        assert!(read.items.is_empty());
        assert!(!read.has_next());
    }
}
