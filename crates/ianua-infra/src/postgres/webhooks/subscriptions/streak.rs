//! Counting one try on a webhook's failure streak, and keeping the try, in
//! one statement: the domain's rule from `record_success` and
//! `record_failure`, run where two tries at once cannot both read the same
//! streak.

use ianua_app::ports::webhooks::StreakChange;
use ianua_domain::domains::webhooks::delivery::{DeliveryAttempt, WebhookDeliveryStatus};
use ianua_domain::types::{FailureOutcome, TenantId};
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::webhooks::subscriptions::history::DeliveryColumns;

/// One try to count: its columns, when it is counted, and the streak that
/// switches the webhook off.
pub(super) struct Counting<'a> {
    pub(super) columns: DeliveryColumns<'a>,
    pub(super) now: OffsetDateTime,
    pub(super) limit: i64,
}

/// Keeps and counts the try `counting` describes, answering its webhook's
/// id and what counting a failure came to, or nothing when the webhook is
/// gone.
pub(super) async fn count(
    connection: &mut PgConnection,
    tenant: &TenantId,
    counting: &Counting<'_>,
) -> Result<Option<(Uuid, FailureOutcome)>, sqlx::Error> {
    let columns = &counting.columns;
    let counted = sqlx::query_file!(
        "queries/webhook_subscriptions/count_delivery.sql",
        tenant.as_uuid(),
        columns.subscription_id,
        counting.now,
        counting.limit,
        columns.id,
        columns.message_id,
        columns.event_type,
        columns.status,
        columns.response_code,
        columns.duration_ms,
        columns.attempt_number,
        columns.attempted_at,
    )
    .fetch_optional(connection)
    .await?;
    Ok(counted.map(|counted| {
        let outcome = if counted.switched_off {
            FailureOutcome::Disabled
        } else {
            FailureOutcome::Counted
        };
        (counted.id, outcome)
    }))
}

/// What `attempt` did to its webhook's streak, given what counting a
/// failure came to.
pub(super) fn change_of(attempt: &DeliveryAttempt, failure: FailureOutcome) -> StreakChange {
    match attempt.status() {
        WebhookDeliveryStatus::Success => StreakChange::Delivered,
        WebhookDeliveryStatus::Failed
        | WebhookDeliveryStatus::Timeout
        | WebhookDeliveryStatus::Unreachable => StreakChange::Failed(failure),
    }
}
