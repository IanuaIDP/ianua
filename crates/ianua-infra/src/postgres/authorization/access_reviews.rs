//! Review headers and immutable holder snapshots, read independently in pages.
//! Header locks serialize mutations within the caller's atomic unit of work.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authorization::{
    AccessReviewFilter, AccessReviewSortField, AccessReviewStore, OverdueReview,
    OverdueReviewSortField, ReviewItemSortField,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authorization::access_review::{
    AccessReview, AccessReviewDraft, ReviewItem,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AccessReviewId, PrincipalRef};
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

use self::record::{
    AccessReviewRecord, DecisionColumns, OverdueReviewRecord, ReviewItemRecord, ReviewerColumns,
    ScopeColumns, SuggestionColumns,
};
use crate::postgres::authorization::principals::kind_word;
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::stored::StoredWord as _;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of review headers and paged holder snapshots.
pub struct PgAccessReviewStore {
    databases: Arc<Databases>,
}

impl PgAccessReviewStore {
    /// Uses the existing tenant router and ambient unit of work.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Hydrates only selected parent headers, preserving their page order.
    async fn reviews(
        &self,
        tenant: &ScopedTenant,
        select: impl AsyncFnOnce(&mut PgConnection) -> Result<Vec<Uuid>, sqlx::Error>,
    ) -> Result<Vec<AccessReview<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                let ids = select(&mut *connection).await?;
                let records = sqlx::query_file_as!(
                    AccessReviewRecord,
                    "queries/access_reviews/by_ids.sql",
                    tenant.as_uuid(),
                    &ids
                )
                .fetch_all(connection)
                .await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        records
            .into_iter()
            .map(AccessReviewRecord::into_review)
            .collect()
    }
}

impl TenantScoped for PgAccessReviewStore {}

impl SortColumns for AccessReviewSortField {
    /// Maps the fixed parent creation order to storage.
    fn column(self) -> &'static str {
        "started_at"
    }
    /// Every review records its creation time.
    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

impl SortColumns for OverdueReviewSortField {
    /// Maps the sweep's stable deadline order to storage.
    fn column(self) -> &'static str {
        "due"
    }
    /// Every review records a deadline.
    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

impl SortColumns for ReviewItemSortField {
    /// Snapshot positions never change after creation.
    fn column(self) -> &'static str {
        "position"
    }
    /// Every holder has one positive snapshot position.
    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

/// Builds the parent selector without reading holder rows.
fn listed(tenant: &ScopedTenant, filter: AccessReviewFilter) -> PageQuery<'static> {
    let every = PageQuery::ids("id", "access_reviews").filter("tenant_id = ?", *tenant.as_uuid());
    match filter {
        AccessReviewFilter::All => every,
        AccessReviewFilter::Open => every.keep("status = 'open'"),
    }
}

/// Refuses silent loss of a row that a locked command expected to update.
fn ensure_one_saved(rows: u64) -> Result<(), DomainError> {
    if rows != 1 {
        return Err(DomainError::infra_msg("the locked review row disappeared"));
    }
    Ok(())
}

#[async_trait]
impl AccessReviewStore for PgAccessReviewStore {
    async fn start(
        &self,
        tenant: &ScopedTenant,
        draft: AccessReviewDraft<ResolvedTenant>,
    ) -> Result<AccessReview<ResolvedTenant>, DomainError> {
        let reviewers = ReviewerColumns::of(draft.reviewers());
        let scope = ScopeColumns::of(draft.scope());
        let count = scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/access_reviews/start.sql",
                    tenant.as_uuid(),
                    draft.id().as_uuid(),
                    draft.name().as_str(),
                    scope.kind,
                    scope.id,
                    &reviewers.kinds as &[&str],
                    &reviewers.ids,
                    &reviewers.persons as &[&str],
                    draft.due(),
                    draft.unanswered().word(),
                    draft.started_at()
                )
                .fetch_one(connection)
                .await
            },
        )
        .await?;
        draft.started(u64::try_from(count).map_err(DomainError::infra)?)
    }

    async fn hold(
        &self,
        tenant: &ScopedTenant,
        id: &AccessReviewId,
    ) -> Result<Option<AccessReview<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                sqlx::query_file_as!(
                    AccessReviewRecord,
                    "queries/access_reviews/hold.sql",
                    tenant.as_uuid(),
                    id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(AccessReviewRecord::into_review).transpose()
    }

    async fn find_by_id(
        &self,
        tenant: &ScopedTenant,
        id: &AccessReviewId,
    ) -> Result<Option<AccessReview<ResolvedTenant>>, DomainError> {
        let ids = vec![*id.as_uuid()];
        Ok(self.reviews(tenant, async |_| Ok(ids)).await?.pop())
    }

    async fn list(
        &self,
        tenant: &ScopedTenant,
        filter: AccessReviewFilter,
        page: &PageRequest,
    ) -> Result<Page<AccessReview<ResolvedTenant>>, DomainError> {
        let order = SortOrder::<AccessReviewSortField>::default();
        let keyset = page.keyset(&order)?;
        let selector = listed(tenant, filter);
        let reviews = self
            .reviews(tenant, async |connection| {
                selector.fetch(&keyset, connection).await
            })
            .await?;
        Ok(keyset.seal(reviews))
    }

    async fn find_overdue(
        &self,
        tenant: &ScopedTenant,
        now: OffsetDateTime,
        page: &PageRequest,
    ) -> Result<Page<OverdueReview>, DomainError> {
        let order = SortOrder::<OverdueReviewSortField>::default();
        let keyset = page.keyset(&order)?;
        let selector = listed(tenant, AccessReviewFilter::Open).filter("due <= ?", now);
        let records = scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                let ids = selector.fetch(&keyset, &mut *connection).await?;
                let records = sqlx::query_file_as!(
                    OverdueReviewRecord,
                    "queries/access_reviews/overdue_positions.sql",
                    tenant.as_uuid(),
                    &ids
                )
                .fetch_all(connection)
                .await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        Ok(keyset.seal(
            records
                .into_iter()
                .map(|record| OverdueReview {
                    id: AccessReviewId::from_uuid(record.id),
                    due: record.due,
                })
                .collect(),
        ))
    }

    async fn list_items(
        &self,
        tenant: &ScopedTenant,
        review: &AccessReview<ResolvedTenant>,
        page: &PageRequest,
    ) -> Result<Page<ReviewItem>, DomainError> {
        let order = SortOrder::<ReviewItemSortField>::default();
        let keyset = page.keyset(&order)?;
        let selector = PageQuery::ids("position", "access_review_items")
            .filter("tenant_id = ?", *tenant.as_uuid())
            .filter("review_id = ?", *review.id().as_uuid());
        let records = scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                let positions = selector.fetch_positions(&keyset, &mut *connection).await?;
                sqlx::query_file_as!(
                    ReviewItemRecord,
                    "queries/access_review_items/by_positions.sql",
                    tenant.as_uuid(),
                    review.id().as_uuid(),
                    &positions
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        let items = records
            .into_iter()
            .map(|record| record.into_item(review))
            .collect::<Result<_, _>>()?;
        Ok(keyset.seal(items))
    }

    async fn find_item(
        &self,
        tenant: &ScopedTenant,
        review: &AccessReview<ResolvedTenant>,
        holder: &PrincipalRef,
    ) -> Result<Option<ReviewItem>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                sqlx::query_file_as!(
                    ReviewItemRecord,
                    "queries/access_review_items/of_holder.sql",
                    tenant.as_uuid(),
                    review.id().as_uuid(),
                    kind_word(holder),
                    holder.id()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(|record| record.into_item(review)).transpose()
    }

    async fn find_items(
        &self,
        tenant: &ScopedTenant,
        review: &AccessReview<ResolvedTenant>,
        holders: &[PrincipalRef],
    ) -> Result<Vec<ReviewItem>, DomainError> {
        let kinds: Vec<&str> = holders.iter().map(kind_word).collect();
        let ids: Vec<Uuid> = holders.iter().map(PrincipalRef::id).collect();
        let records = scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                sqlx::query_file_as!(
                    ReviewItemRecord,
                    "queries/access_review_items/of_holders.sql",
                    tenant.as_uuid(),
                    review.id().as_uuid(),
                    &kinds as &[&str],
                    &ids
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(|record| record.into_item(review))
            .collect()
    }

    async fn save_suggestions(
        &self,
        tenant: &ScopedTenant,
        items: &[ReviewItem],
    ) -> Result<(), DomainError> {
        let Some(first) = items.first() else {
            return Ok(());
        };
        let columns = SuggestionColumns::of(items)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                sqlx::query_file!(
                    "queries/access_review_items/suggest.sql",
                    tenant.as_uuid(),
                    first.review_id().as_uuid(),
                    &columns.positions,
                    &columns.choices as &[&str],
                    &columns.reasons as &[&str]
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        if u64::try_from(columns.positions.len()).ok() != Some(written.rows_affected()) {
            return Err(DomainError::infra_msg("a locked review item disappeared"));
        }
        Ok(())
    }

    async fn save_item(&self, tenant: &ScopedTenant, item: &ReviewItem) -> Result<(), DomainError> {
        let columns = DecisionColumns::of(item);
        let position = i64::try_from(item.position()).map_err(DomainError::infra)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                sqlx::query_file!(
                    "queries/access_review_items/save.sql",
                    tenant.as_uuid(),
                    item.review_id().as_uuid(),
                    position,
                    columns.choice,
                    columns.reviewer_kind,
                    columns.reviewer_id,
                    columns.reviewer_person
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        ensure_one_saved(written.rows_affected())
    }

    async fn save(
        &self,
        tenant: &ScopedTenant,
        review: &AccessReview<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let pending = i64::try_from(review.pending_count()).map_err(DomainError::infra)?;
        let removed = i64::try_from(review.remove_count()).map_err(DomainError::infra)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                sqlx::query_file!(
                    "queries/access_reviews/save.sql",
                    tenant.as_uuid(),
                    review.id().as_uuid(),
                    review.status().word(),
                    pending,
                    removed
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        ensure_one_saved(written.rows_affected())
    }
}

#[cfg(test)]
mod tests;
