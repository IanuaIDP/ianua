//! Algorithm migration handlers: moving a tenant's signing from one
//! algorithm to another, planned, started, promoted and completed, or
//! cancelled and rolled back.

use axum::extract::State;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::crypto::CryptoState;

use crate::dto::crypto::{
    MigrationResponse, NewKeyResponse, PlanMigrationBody, RollbackMigrationBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::response::NoContent;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/crypto/migration",
    tag = "Crypto",
    responses(
        (status = 200, description = "Success", body = MigrationResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No migration under way", body = ErrorBody)
    )
)]
/// Active algorithm migration
///
/// Returns the tenant's current algorithm migration: source and target
/// algorithms, source and target key ids, `status`, and timestamps. There
/// is at most one active migration per tenant; `status` is one of
/// `planned`, `in_progress`, `validating`, `completed`, `rolled_back`,
/// `cancelled`. Returns `404` when no migration is active. Records nothing.
/// Requires `Crypto(View)`.
pub(crate) async fn get_migration(
    State(crypto): State<CryptoState>,
    tenant: TenantCaller,
) -> Result<Json<MigrationResponse>, ApiError> {
    let migration = crypto.get_migration.execute(&tenant.caller, ()).await?;
    Ok(Json(MigrationResponse::from(migration)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/crypto/migration/plan",
    tag = "Crypto",
    request_body = PlanMigrationBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No key signs now", body = ErrorBody),
        (status = 409, description = "A migration is already under way", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Plan an algorithm migration
///
/// Schedules a migration from the active key's algorithm to the given
/// `target_algorithm`, starting in `planned` status. No keys are created
/// yet; that happens at `start`. Returns `404` if there is no key set or
/// active key, `409` if a migration is already active (one at a time per
/// tenant), and `422` if the target algorithm is the current one.
///
/// Records `crypto.migration_planned`. Requires `Crypto(Update)`.
pub(crate) async fn plan_migration(
    State(crypto): State<CryptoState>,
    tenant: TenantCaller,
    Json(body): Json<PlanMigrationBody>,
) -> Result<NoContent, ApiError> {
    crypto
        .plan_migration
        .execute(&tenant.caller, &tenant.auditor, body.target_algorithm)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/crypto/migration/start",
    tag = "Crypto",
    responses(
        (status = 200, description = "Success", body = NewKeyResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No migration under way", body = ErrorBody),
        (status = 422, description = "The migration is not planned", body = ErrorBody)
    )
)]
/// Start a planned migration
///
/// Generates the target-algorithm key and adds it to the key set: both
/// keys now sign (dual-signing), while the old key remains the primary
/// signer. Returns the new key's `key_id`.
///
/// `planned -> in_progress`. Returns `404` if no migration is active, or
/// `422` if it is not `planned`. Records `crypto.migration_started`.
/// Requires `Crypto(Update)`.
pub(crate) async fn start_migration(
    State(crypto): State<CryptoState>,
    tenant: TenantCaller,
) -> Result<Json<NewKeyResponse>, ApiError> {
    let key_id = crypto
        .start_migration
        .execute(&tenant.caller, &tenant.auditor, ())
        .await?;
    Ok(Json(NewKeyResponse { key_id }))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/crypto/migration/promote",
    tag = "Crypto",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No migration under way", body = ErrorBody),
        (status = 422, description = "The migration is not in progress", body = ErrorBody)
    )
)]
/// Promote the new key to primary
///
/// Makes the migration's target key the sole signer and rotates the source
/// key out. Relying parties should refresh their JWKS cache.
///
/// `in_progress -> validating`. Returns `404` if no migration is active,
/// or `422` if it is not `in_progress`. Records
/// `crypto.migration_promoted`. Requires `Crypto(Update)`.
pub(crate) async fn promote_migration(
    State(crypto): State<CryptoState>,
    tenant: TenantCaller,
) -> Result<NoContent, ApiError> {
    crypto
        .promote_migration
        .execute(&tenant.caller, &tenant.auditor, ())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/crypto/migration/rollback",
    tag = "Crypto",
    request_body = RollbackMigrationBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No migration under way", body = ErrorBody),
        (status = 422, description = "The migration already ended, or no reason", body = ErrorBody)
    )
)]
/// Roll back a migration
///
/// Aborts an active migration: the target key created during the migration
/// is revoked and the migration ends. A `reason` is required and is
/// recorded on the audit event.
///
/// `in_progress | validating -> rolled_back` (terminal). Returns `404` if
/// no migration is active, or `422` if it already ended. Records
/// `crypto.migration_rolled_back`. Requires `Crypto(Update)`.
pub(crate) async fn rollback_migration(
    State(crypto): State<CryptoState>,
    tenant: TenantCaller,
    Json(body): Json<RollbackMigrationBody>,
) -> Result<NoContent, ApiError> {
    crypto
        .rollback_migration
        .execute(&tenant.caller, &tenant.auditor, body.reason()?)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/crypto/migration/complete",
    tag = "Crypto",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No migration under way", body = ErrorBody),
        (status = 422, description = "The migration is not validating", body = ErrorBody)
    )
)]
/// Complete a migration
///
/// Finalizes the migration: the source key is revoked if it is still
/// published, and the target key is the only active signer.
///
/// `validating -> completed` (terminal). Returns `404` if no migration is
/// active, or `422` if it is not `validating`. Records
/// `crypto.migration_completed`. Requires `Crypto(Update)`.
pub(crate) async fn complete_migration(
    State(crypto): State<CryptoState>,
    tenant: TenantCaller,
) -> Result<NoContent, ApiError> {
    crypto
        .complete_migration
        .execute(&tenant.caller, &tenant.auditor, ())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/crypto/migration/cancel",
    tag = "Crypto",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No migration under way", body = ErrorBody),
        (status = 422, description = "The migration is not planned", body = ErrorBody)
    )
)]
/// Cancel a planned migration
///
/// Discards a migration before any keys are created. Once a migration has
/// started, use rollback instead; cancel refuses from `in_progress`.
///
/// `planned -> cancelled` (terminal). Returns `404` if no migration is
/// active, or `422` if it is not `planned`. Records
/// `crypto.migration_cancelled`. Requires `Crypto(Update)`.
pub(crate) async fn cancel_migration(
    State(crypto): State<CryptoState>,
    tenant: TenantCaller,
) -> Result<NoContent, ApiError> {
    crypto
        .cancel_migration
        .execute(&tenant.caller, &tenant.auditor, ())
        .await?;
    Ok(NoContent)
}
