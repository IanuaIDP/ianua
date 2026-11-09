//! The figures the metrics are made of, each read from one database for
//! some of its tenants, and the spread of a reader's tenants over the
//! databases they live in.
//!
//! A tenant's sign-ins are its audit records, its traffic its request
//! records, its people and sessions its own tables. An organization's
//! figures are its tenants' figures added up: the tenants in the platform
//! database read in one query, each with a database of its own read
//! there, all at once.

use futures_util::future::try_join_all;
use ianua_domain::domains::metrics::{Granularity, MetricsWindow};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;
use crate::postgres::metrics::tenant::record::{
    BucketRecord, DurationRecord, DurationsRecord, OutcomesRecord,
};

/// How recent a moment is for the live tables to answer for it; anything
/// older is read from the snapshots.
const LIVE_WINDOW: Duration = Duration::hours(1);

/// Whether the live tables still answer for `at`.
pub(crate) fn is_live(at: OffsetDateTime) -> bool {
    at >= clock::now().saturating_sub(LIVE_WINDOW)
}

/// The unit a window's series is bucketed by, as `date_trunc` names it.
pub(crate) fn bucket_unit(window: &MetricsWindow) -> &'static str {
    match window.granularity() {
        Granularity::Hourly => "hour",
        Granularity::Daily => "day",
    }
}

/// An organization's tenants by where they are read: those in the
/// platform database together, and each with a database of its own alone.
pub(crate) struct Spread {
    shared: Vec<Uuid>,
    alone: Vec<TenantId>,
}

impl Spread {
    /// `tenants`, spread over the databases `databases` knows of.
    pub(crate) fn of(databases: &Databases, tenants: Vec<Uuid>) -> Self {
        let own = databases.with_own_database();
        let (alone, shared): (Vec<Uuid>, Vec<Uuid>) = tenants
            .into_iter()
            .partition(|tenant| own.iter().any(|apart| apart.as_uuid() == tenant));
        Self {
            shared,
            alone: alone.into_iter().map(TenantId::from_uuid).collect(),
        }
    }

    /// What `read` answers for each place the tenants are read, at once.
    ///
    /// # Errors
    ///
    /// The first error a read answers.
    pub(crate) async fn gather<T, F, Fut>(&self, read: F) -> Result<Vec<T>, DomainError>
    where
        F: Fn(RowScope, Vec<Uuid>) -> Fut,
        Fut: Future<Output = Result<T, DomainError>>,
    {
        let shared =
            (!self.shared.is_empty()).then(|| read(RowScope::Platform, self.shared.clone()));
        let alone = self
            .alone
            .iter()
            .map(|tenant| read(RowScope::Tenant(*tenant), vec![*tenant.as_uuid()]));
        try_join_all(shared.into_iter().chain(alone)).await
    }
}

/// The sign-ins of `tenants` that succeeded and failed in `window`.
pub(crate) async fn outcomes(
    databases: &Databases,
    scope: RowScope,
    tenants: Vec<Uuid>,
    window: &MetricsWindow,
) -> Result<OutcomesRecord, DomainError> {
    scoped(databases, scope, async |connection| {
        sqlx::query_file_as!(
            OutcomesRecord,
            "queries/audit_records/sign_in_outcomes.sql",
            &tenants,
            window.start(),
            window.end()
        )
        .fetch_one(connection)
        .await
    })
    .await
}

/// The sign-ins of `tenants` in `window`, per bucket of the window's own
/// granularity.
pub(crate) async fn series(
    databases: &Databases,
    scope: RowScope,
    tenants: Vec<Uuid>,
    window: &MetricsWindow,
) -> Result<Vec<BucketRecord>, DomainError> {
    let unit = bucket_unit(window);
    scoped(databases, scope, async |connection| {
        sqlx::query_file_as!(
            BucketRecord,
            "queries/audit_records/sign_in_series.sql",
            &tenants,
            window.start(),
            window.end(),
            unit
        )
        .fetch_all(connection)
        .await
    })
    .await
}

/// The measured times of the successful sign-ins of `tenants` in `window`.
pub(crate) async fn durations(
    databases: &Databases,
    scope: RowScope,
    tenants: Vec<Uuid>,
    window: &MetricsWindow,
) -> Result<DurationsRecord, DomainError> {
    scoped(databases, scope, async |connection| {
        sqlx::query_file_as!(
            DurationsRecord,
            "queries/audit_records/sign_in_durations.sql",
            &tenants,
            window.start(),
            window.end()
        )
        .fetch_one(connection)
        .await
    })
    .await
}

/// When anyone of `tenants` last signed in, if anyone ever did.
pub(crate) async fn last_sign_in(
    databases: &Databases,
    scope: RowScope,
    tenants: Vec<Uuid>,
) -> Result<Option<OffsetDateTime>, DomainError> {
    scoped(databases, scope, async |connection| {
        sqlx::query_file_scalar!("queries/audit_records/last_sign_in.sql", &tenants)
            .fetch_one(connection)
            .await
    })
    .await
}

/// How many people of `tenants` there were at `at`, counted live.
pub(crate) async fn people_at(
    databases: &Databases,
    scope: RowScope,
    tenants: Vec<Uuid>,
    at: OffsetDateTime,
) -> Result<i64, DomainError> {
    scoped(databases, scope, async |connection| {
        sqlx::query_file_scalar!("queries/users/counted_at.sql", &tenants, at)
            .fetch_one(connection)
            .await
    })
    .await
}

/// How many sessions of `tenants` were active at `at`, counted live.
pub(crate) async fn sessions_at(
    databases: &Databases,
    scope: RowScope,
    tenants: Vec<Uuid>,
    at: OffsetDateTime,
) -> Result<i64, DomainError> {
    scoped(databases, scope, async |connection| {
        sqlx::query_file_scalar!("queries/sessions/active_at.sql", &tenants, at)
            .fetch_one(connection)
            .await
    })
    .await
}

/// The requests of `tenants` in `window`, by how long they took.
pub(crate) async fn requests(
    databases: &Databases,
    scope: RowScope,
    tenants: Vec<Uuid>,
    window: &MetricsWindow,
) -> Result<Vec<DurationRecord>, DomainError> {
    scoped(databases, scope, async |connection| {
        sqlx::query_file_as!(
            DurationRecord,
            "queries/proxy_request_records/by_duration.sql",
            &tenants,
            window.start(),
            window.end()
        )
        .fetch_all(connection)
        .await
    })
    .await
}
