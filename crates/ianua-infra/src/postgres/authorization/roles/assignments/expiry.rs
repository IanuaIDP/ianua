//! Bounded expired-assignment selection with composite cursor seeks.

use ianua_app::ports::authorization::{AssignmentPosition, HoldingBatch};
use ianua_app::tenancy::ScopedTenant;
use sqlx::PgConnection;

use crate::postgres::authorization::principals::kind_word;
use crate::postgres::authorization::roles::assignments::record::AssignmentRecord;

/// Reads one bounded expired-assignment batch using a direct composite seek
/// after the first batch, so prepared query plans can use the complete index.
pub(super) async fn lapsed_assignments(
    connection: &mut PgConnection,
    tenant: &ScopedTenant,
    batch: &HoldingBatch<AssignmentPosition>,
) -> Result<Vec<AssignmentRecord>, sqlx::Error> {
    let Some(last) = batch.after else {
        return sqlx::query_file_as!(
            AssignmentRecord,
            "queries/role_assignments/lapsed.sql",
            tenant.as_uuid(),
            batch.now
        )
        .fetch_all(connection)
        .await;
    };
    sqlx::query_file_as!(
        AssignmentRecord,
        "queries/role_assignments/lapsed_after.sql",
        tenant.as_uuid(),
        batch.now,
        last.expires_at,
        last.role_id.as_uuid(),
        kind_word(&last.principal),
        last.principal.id()
    )
    .fetch_all(connection)
    .await
}
