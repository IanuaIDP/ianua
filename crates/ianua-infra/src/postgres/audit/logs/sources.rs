//! Where an audit log is read from, and how one page is read from them.
//!
//! A tenant's records live in the database the tenant lives in; an
//! organization's and the platform's in the platform database. No query
//! reaches across databases, so a log spanning tenants reads one page from
//! each place it is kept, at once, and keeps the first of them in its
//! order: each place answers its own first rows past the cursor, so the
//! first of all of them are the log's.

use std::collections::BTreeSet;

use futures_util::future::try_join_all;
use ianua_app::listing::{Keyset, Page, SortOrder};
use ianua_app::ports::audit::{AuditLogEntry, AuditLogSortField};
use ianua_domain::domains::audit::access::LogReach;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrganizationId, TenantId};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::postgres::audit::logs::filters::Narrowing;
use crate::postgres::audit::logs::record::{
    EntryRecord, MemberNameRecord, Names, OperatorNameRecord, TenantNameRecord,
};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// One place a log's records are kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Source {
    /// One tenant's records, in the database it lives in.
    Tenant(TenantId),
    /// The records of the tenants in the platform database: these, or
    /// every one of them.
    SharedTenants(Option<Vec<Uuid>>),
    /// The organization and platform records: this organization's, or
    /// every one.
    Platform(Option<OrganizationId>),
}

/// Which of the records that belong to no tenant a log spanning tenants
/// holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnRecords {
    /// One organization's.
    Of(OrganizationId),
    /// Every organization's and the platform's.
    Every,
}

/// Which tenants' records a log holds.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Tenants<'a> {
    /// These tenants'.
    Only(&'a [Uuid]),
    /// Every tenant's.
    Every,
}

impl Tenants<'_> {
    fn holds(self, tenant: &Uuid) -> bool {
        match self {
            Self::Only(tenants) => tenants.contains(tenant),
            Self::Every => true,
        }
    }

    /// Selected tenant ids that remain in the shared database, or no restriction.
    fn shared(self, apart: &BTreeSet<Uuid>) -> Option<Vec<Uuid>> {
        match self {
            Self::Only(tenants) => Some(
                tenants
                    .iter()
                    .copied()
                    .filter(|tenant| !apart.contains(tenant))
                    .collect(),
            ),
            Self::Every => None,
        }
    }
}

impl SortColumns for AuditLogSortField {
    fn column(self) -> &'static str {
        match self {
            Self::OccurredAt => "occurred_at",
            Self::EventType => "event_type",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

/// The sources of the log of `tenants` and `own` records, narrowed to the
/// one tenant a filter names when it does: the tenants in the platform
/// database read at once, each with a database of its own read there.
pub(crate) fn sources_of(
    databases: &Databases,
    tenants: Tenants<'_>,
    own: OwnRecords,
    narrowing: &Narrowing,
) -> Vec<Source> {
    if let Some(tenant) = narrowing.tenant() {
        return tenants
            .holds(&tenant)
            .then(|| Source::Tenant(TenantId::from_uuid(tenant)))
            .into_iter()
            .collect();
    }
    let apart: BTreeSet<Uuid> = databases
        .with_own_database()
        .iter()
        .map(|tenant| *tenant.as_uuid())
        .filter(|tenant| tenants.holds(tenant))
        .collect();
    let shared = tenants.shared(&apart);
    let unchained = match own {
        OwnRecords::Of(organization) => Source::Platform(Some(organization)),
        OwnRecords::Every => Source::Platform(None),
    };
    [unchained, Source::SharedTenants(shared)]
        .into_iter()
        .chain(
            apart
                .into_iter()
                .map(|tenant| Source::Tenant(TenantId::from_uuid(tenant))),
        )
        .collect()
}

/// The tenants `organization` holds, every one not deleted, from the
/// platform database.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when they cannot be read.
pub(crate) async fn organization_tenants(
    databases: &Databases,
    organization: &OrganizationId,
) -> Result<Vec<Uuid>, DomainError> {
    scoped(databases, RowScope::Unscoped, async |connection| {
        sqlx::query_file_scalar!(
            "queries/tenants/of_organization.sql",
            organization.as_uuid()
        )
        .fetch_one(connection)
        .await
    })
    .await
}

/// The tenants of `organization` whose retained history its reader sees,
/// as `reach` says: a tenant it does not hold is read from nowhere.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when their identities cannot be read.
pub(crate) async fn reached_history_tenants(
    databases: &Databases,
    organization: &OrganizationId,
    reach: &LogReach,
) -> Result<Vec<Uuid>, DomainError> {
    let mut tenants = organization_history_tenants(databases, organization).await?;
    tenants.retain(|tenant| reach.holds(&TenantId::from_uuid(*tenant)));
    Ok(tenants)
}

/// The organization's tenants whose retained history remains readable,
/// including deleted tenants that no longer count as live capacity.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when their identities cannot be read.
async fn organization_history_tenants(
    databases: &Databases,
    organization: &OrganizationId,
) -> Result<Vec<Uuid>, DomainError> {
    scoped(databases, RowScope::Unscoped, async |connection| {
        sqlx::query_file_scalar!(
            "queries/tenants/for_organization_history.sql",
            organization.as_uuid()
        )
        .fetch_one(connection)
        .await
    })
    .await
}

/// The filter and cursor defining one page across every log source.
pub(crate) struct PageSelection<'a, 'sort> {
    /// The same record restrictions applied to each source.
    pub(crate) narrowing: &'a Narrowing,
    /// The common order, cursor and limit used when merging sources.
    pub(crate) keyset: &'a Keyset<'sort, SortOrder<AuditLogSortField>>,
}

/// One page of the log kept in `sources`, as `selection` asks for it, with
/// the names its entries show.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a source cannot be read, or
/// holds a row this release cannot read.
pub(crate) async fn read_page(
    databases: &Databases,
    sources: Vec<Source>,
    selection: &PageSelection<'_, '_>,
    limits: &DomainLimits,
) -> Result<Page<AuditLogEntry>, DomainError> {
    let PageSelection { narrowing, keyset } = *selection;
    let read = try_join_all(
        sources
            .into_iter()
            .map(|source| read_source(databases, source, narrowing, keyset)),
    )
    .await?;
    let page = keyset.cut(read.into_iter().flatten().collect());
    let names = names_of(databases, &page.items, limits).await?;
    page.try_map(|record| record.into_entry(&names))
}

/// The first rows of `source` past the cursor, in the page's order.
async fn read_source(
    databases: &Databases,
    source: Source,
    narrowing: &Narrowing,
    keyset: &Keyset<'_, SortOrder<AuditLogSortField>>,
) -> Result<Vec<EntryRecord>, DomainError> {
    let (scope, query, table) = located(source);
    let listed = narrowing.applied(query);
    scoped(databases, scope, async |connection| {
        let ids = listed.fetch(keyset, &mut *connection).await?;
        let records = table.entries(connection, &ids).await?;
        Ok(in_page_order(&ids, records, |record| record.id))
    })
    .await
}

/// Where `source`'s rows are read: the scope, the ids of its rows, and the
/// table they are then read from.
fn located(source: Source) -> (RowScope, PageQuery<'static>, Table) {
    let records = PageQuery::ids("id", "audit_records");
    match source {
        Source::Tenant(tenant) => (
            RowScope::Tenant(tenant),
            records.filter("tenant_id = ?", *tenant.as_uuid()),
            Table::Tenants(Some(vec![*tenant.as_uuid()])),
        ),
        Source::SharedTenants(Some(tenants)) => (
            RowScope::Platform,
            records.filter("tenant_id = ANY(?)", tenants.clone()),
            Table::Tenants(Some(tenants)),
        ),
        Source::SharedTenants(None) => (RowScope::Platform, records, Table::Tenants(None)),
        Source::Platform(organization) => (
            RowScope::Unscoped,
            of_organization(organization),
            Table::Platform,
        ),
    }
}

/// The ids of the platform's records, of one organization or of all.
fn of_organization(organization: Option<OrganizationId>) -> PageQuery<'static> {
    let query = PageQuery::ids("id", "platform_audit_records");
    match organization {
        Some(organization) => query.filter("organization_id = ?", *organization.as_uuid()),
        None => query,
    }
}

/// The table a source's rows are read from by their ids.
enum Table {
    /// A tenant's records: those of these tenants, or of any.
    Tenants(Option<Vec<Uuid>>),
    /// The organization and platform records.
    Platform,
}

impl Table {
    async fn entries(
        &self,
        connection: &mut PgConnection,
        ids: &[Uuid],
    ) -> Result<Vec<EntryRecord>, sqlx::Error> {
        match self {
            Self::Tenants(tenants) => {
                sqlx::query_file_as!(
                    EntryRecord,
                    "queries/audit_records/entries.sql",
                    tenants.as_deref(),
                    ids
                )
                .fetch_all(connection)
                .await
            }
            Self::Platform => {
                sqlx::query_file_as!(
                    EntryRecord,
                    "queries/platform_audit_records/entries.sql",
                    ids
                )
                .fetch_all(connection)
                .await
            }
        }
    }
}

/// The ids whose names `records` show: their tenants', and the members'
/// and operators' who acted.
fn named_ids(records: &[EntryRecord]) -> [Vec<Uuid>; 3] {
    let mut tenants = BTreeSet::new();
    let mut members = BTreeSet::new();
    let mut operators = BTreeSet::new();
    for (tenant, member, operator) in records.iter().map(EntryRecord::named) {
        tenants.extend(tenant);
        members.extend(member);
        operators.extend(operator);
    }
    [tenants, members, operators].map(|ids| ids.into_iter().collect())
}

/// The names `records` show, read once from the platform database.
async fn names_of(
    databases: &Databases,
    records: &[EntryRecord],
    limits: &DomainLimits,
) -> Result<Names, DomainError> {
    let [tenants, members, operators] = named_ids(records);
    let (tenants, members, operators) = scoped(databases, RowScope::Unscoped, async |connection| {
        let tenants = sqlx::query_file_as!(
            TenantNameRecord,
            "queries/tenants/audit_names.sql",
            &tenants
        )
        .fetch_all(&mut *connection)
        .await?;
        let members = sqlx::query_file_as!(
            MemberNameRecord,
            "queries/org_users/audit_names.sql",
            &members
        )
        .fetch_all(&mut *connection)
        .await?;
        let operators = sqlx::query_file_as!(
            OperatorNameRecord,
            "queries/operators/audit_names.sql",
            &operators
        )
        .fetch_all(connection)
        .await?;
        Ok((tenants, members, operators))
    })
    .await?;
    Names::of(tenants, members, operators, limits)
}
