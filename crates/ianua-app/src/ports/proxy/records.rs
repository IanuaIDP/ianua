//! Searching the request records the proxy keeps.
//!
//! An admin asking why Ann was refused at 9:14 searches the log for refusals
//! of her, on that route, in that hour, and reads which check refused her
//! and under which rule. The records are kept as long as the tenant's
//! retention says, and removed after.

use std::num::NonZeroU32;

use async_trait::async_trait;
use ianua_domain::domains::proxy::observation::GatewayCheck;
use ianua_domain::domains::proxy::stages::stage::StageKindName;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentId, ConsumerId, Label, RouteId, StageId, UserId};
use time::OffsetDateTime;

use crate::define_sort_field;
use crate::listing::{Listing, Page, SortKey, SortKeys};
use crate::ports::TenantScoped;
use crate::ports::proxy::ProxyRequestRecord;
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// Field a request record search can be ordered by.
    pub enum RequestRecordSortField {
        /// Order by when the request finished.
        OccurredAt => "occurred_at",
        /// Order by the status returned to the client.
        Status => "status",
        /// Order by how long the request took.
        Duration => "duration_ms",
    }
    default = OccurredAt;
    default direction = Desc;
}

/// Which decision a searched record carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DecisionFilter {
    /// Any decision.
    #[default]
    Any,
    /// Only requests let through.
    Allowed,
    /// Only requests refused, or ended without a decision, which the proxy
    /// also refuses.
    Refused,
}

/// Which check a searched refusal was made by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DecidedByFilter {
    /// Any check, or none.
    #[default]
    Any,
    /// This gateway check, before any stage ran.
    Gateway(GatewayCheck),
    /// This stage of a pipeline.
    Stage(StageId),
    /// Any stage of this kind, in whichever pipeline.
    StageKind(StageKindName),
}

/// Who a searched record says was asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordSubject {
    /// This tenant user, directly or as the person an agent acted for.
    User(UserId),
    /// Restrict results to requests made by this agent identity.
    Agent(AgentId),
    /// This machine identity.
    Consumer(ConsumerId),
}

/// What a request record search narrows to. Every condition set must hold.
#[derive(Debug, Clone, Default)]
pub struct RequestRecordFilter {
    /// Allowed or refused requests.
    pub decision: DecisionFilter,
    /// The check that refused the request.
    pub decided_by: DecidedByFilter,
    /// The named tenant policy rule the request was refused under.
    pub rule: Option<Label>,
    /// Text the refusal's reason contains, ignoring case.
    pub reason_contains: Option<String>,
    /// The route the request matched.
    pub route: Option<RouteId>,
    /// Who was asking.
    pub subject: Option<RecordSubject>,
    /// Only requests finished at or after this time.
    pub after: Option<OffsetDateTime>,
    /// Only requests finished before this time.
    pub before: Option<OffsetDateTime>,
}

/// A request finishes once, so its correlation id breaks ties.
impl SortKeys<RequestRecordSortField> for ProxyRequestRecord {
    fn sort_key(&self, field: RequestRecordSortField) -> SortKey {
        match field {
            RequestRecordSortField::OccurredAt => self.occurred_at.into(),
            RequestRecordSortField::Status => u32::from(self.status()).into(),
            RequestRecordSortField::Duration => self.duration_ms.into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.correlation_id.as_uuid().into()
    }
}

/// One page of a request record search.
pub type RequestRecordPage = Page<ProxyRequestRecord>;

/// Dyn-safe port for searching the request records a
/// [`ProxyAccessLogSink`](crate::ports::proxy::ProxyAccessLogSink) wrote.
#[async_trait]
pub trait ProxyRequestLog: Send + Sync + TenantScoped {
    /// The tenant's records `listing` asks for, with how many match.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the records cannot be read.
    async fn search(
        &self,
        tenant_id: &ScopedTenant,
        listing: Listing<'_, &RequestRecordFilter, RequestRecordSortField>,
    ) -> Result<RequestRecordPage, DomainError>;
}

/// Dyn-safe port removing a tenant's request records once its retention
/// has passed them.
#[async_trait]
pub trait RequestRecordRetention: Send + Sync + TenantScoped {
    /// Removes at most `most` of the tenant's request records that finished
    /// before `before`, oldest first, and returns how many went. Each call
    /// is its own short statement, so a tenant with millions of old records
    /// never holds a lock for long.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when they cannot be removed;
    /// nothing is removed then.
    async fn forget_before(
        &self,
        tenant_id: &ScopedTenant,
        before: OffsetDateTime,
        most: NonZeroU32,
    ) -> Result<u64, DomainError>;
}
