//! Port for reading the per-(day, category) activity counts behind the
//! contribution calendar.
//!
//! This is a control-plane port: the subject (organization or tenant)
//! travels in [`ActivityScope`], so it does **not** extend
//! [`TenantScoped`]. Implementations aggregate audit events per UTC day
//! and [`ActivityCategory`]; classifying events into categories,
//! zero-filling quiet cells, and grading intensity levels is the
//! domain's job ([`ActivityCalendar`]).
//!
//! [`TenantScoped`]: crate::ports::TenantScoped
//! [`ActivityCategory`]: ianua_domain::domains::activity::ActivityCategory
//! [`ActivityCalendar`]: ianua_domain::domains::activity::ActivityCalendar

use async_trait::async_trait;
use ianua_domain::domains::activity::{ActivityScope, CalendarRange, DailyCategoryCount};
use ianua_domain::shared::errors::DomainError;

/// Reads per-(UTC-day, category) audit event counts for an organization or tenant.
#[async_trait]
pub trait ActivityStore: Send + Sync {
    /// Counts audit events per UTC day and category within `range`,
    /// ascending by day then by stored category name. Cells without
    /// events are omitted.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the counts cannot be read.
    async fn daily_category_counts(
        &self,
        scope: &ActivityScope,
        range: &CalendarRange,
    ) -> Result<Vec<DailyCategoryCount>, DomainError>;
}
