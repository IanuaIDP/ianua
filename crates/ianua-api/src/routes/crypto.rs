//! Crypto endpoints: a tenant's signing keys, its public JWKS document, its
//! published assertion keys, and algorithm migrations.

use std::time::Duration;

use axum::Router;
use utoipa::OpenApi;

use crate::dto::crypto::{
    JwkEntry, JwksResponse, KeySetResponse, MigrationResponse, NewKeyResponse, PlanMigrationBody,
    RollbackMigrationBody, RotateKeyBody, SigningKeyResponse,
};
use crate::handlers::crypto::{assertions, keys, migrations};
use crate::method::{get, post};
use crate::middleware::ip_rate_limit::{ip_rate_limit, per_address};
use crate::state::ApiState;

/// The tenant's published signing keys, read by anyone checking its
/// tokens, and its assertion keys, read by the services behind the
/// gateway, limited per client address.
pub(crate) fn public_routes(state: &ApiState) -> Router<ApiState> {
    let tenant = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}";
    let limiter = per_address(
        state,
        state.http.rate.api_default_per_minute,
        Duration::from_secs(60),
    );
    Router::new()
        .route(&format!("{tenant}/.well-known/jwks.json"), get(keys::jwks))
        .route(
            &format!("{tenant}/.well-known/ianua-assertion-keys.json"),
            get(assertions::assertion_keys),
        )
        .layer(axum::middleware::from_fn_with_state(limiter, ip_rate_limit))
}

/// The crypto endpoints for a signed-in caller.
pub(crate) fn routes() -> Router<ApiState> {
    let tenant = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}";
    let crypto = format!("{tenant}/crypto");
    key_routes(&crypto).merge(migration_routes(&crypto))
}

/// Registers signing key inspection, rotation and revocation.
fn key_routes(crypto: &str) -> Router<ApiState> {
    Router::new()
        .route(&format!("{crypto}/keys"), get(keys::get_key_set))
        .route(&format!("{crypto}/keys/rotate"), post(keys::rotate_key))
        .route(
            &format!("{crypto}/keys/{{id}}/revoke"),
            post(keys::revoke_key),
        )
}

/// Registers the lifecycle of an algorithm migration.
fn migration_routes(crypto: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{crypto}/migration"),
            get(migrations::get_migration),
        )
        .route(
            &format!("{crypto}/migration/plan"),
            post(migrations::plan_migration),
        )
        .route(
            &format!("{crypto}/migration/start"),
            post(migrations::start_migration),
        )
        .route(
            &format!("{crypto}/migration/promote"),
            post(migrations::promote_migration),
        )
        .route(
            &format!("{crypto}/migration/rollback"),
            post(migrations::rollback_migration),
        )
        .route(
            &format!("{crypto}/migration/complete"),
            post(migrations::complete_migration),
        )
        .route(
            &format!("{crypto}/migration/cancel"),
            post(migrations::cancel_migration),
        )
}

/// The crypto part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        keys::get_key_set,
        keys::rotate_key,
        keys::revoke_key,
        keys::jwks,
        assertions::assertion_keys,
        migrations::get_migration,
        migrations::plan_migration,
        migrations::start_migration,
        migrations::promote_migration,
        migrations::rollback_migration,
        migrations::complete_migration,
        migrations::cancel_migration,
    ),
    components(schemas(
        KeySetResponse,
        SigningKeyResponse,
        NewKeyResponse,
        RotateKeyBody,
        MigrationResponse,
        PlanMigrationBody,
        RollbackMigrationBody,
        JwksResponse,
        JwkEntry,
    ))
)]
pub(crate) struct Document;
