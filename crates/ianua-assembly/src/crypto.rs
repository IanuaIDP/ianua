//! The crypto use cases the API serves: a tenant's signing keys, their
//! rotation and revocation, the public JWKS document, moving the tenant
//! to another signing algorithm, and the published assertion keys
//! upstreams check `X-Ianua-Assertion` with.
//!
//! Rotating keys by age and revoking them once their grace is over run on
//! the server's worker, not here; so do the assertion keys' sweeps.

use std::sync::Arc;

use ianua_app::use_cases::crypto::{assertions, keys, migrations};
use ianua_domain::domains::crypto::rotation::KeyRotationSchedule;

use crate::deps::{Adapters, Settings};

/// The crypto use cases.
#[derive(Clone)]
pub struct CryptoState {
    pub get_key_set: Arc<keys::GetUseCase>,
    pub get_jwks: Arc<keys::GetJwksUseCase>,
    pub get_assertion_keys: Arc<assertions::GetPublishedUseCase>,
    pub rotate_key: Arc<keys::RotateUseCase>,
    pub revoke_key: Arc<keys::RevokeUseCase>,
    pub get_migration: Arc<migrations::GetUseCase>,
    pub plan_migration: Arc<migrations::PlanUseCase>,
    pub start_migration: Arc<migrations::StartUseCase>,
    pub promote_migration: Arc<migrations::PromoteUseCase>,
    pub rollback_migration: Arc<migrations::RollbackUseCase>,
    pub complete_migration: Arc<migrations::CompleteUseCase>,
    pub cancel_migration: Arc<migrations::CancelUseCase>,
}

/// Builds the crypto use cases over `a`, publishing a rotated key in the
/// JWKS document for as long as `s` says.
pub fn build(a: &Adapters, s: &Settings) -> CryptoState {
    CryptoState {
        get_key_set: Arc::new(keys::GetUseCase::new(keys::GetPorts {
            key_store: a.signing_key_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        get_jwks: Arc::new(published_keys(a, s)),
        get_assertion_keys: Arc::new(published_assertions(a)),
        rotate_key: Arc::new(keys::RotateUseCase::new(keys::RotatePorts {
            key_store: a.signing_key_store.clone(),
            key_generator: a.key_generator.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        revoke_key: Arc::new(keys::RevokeUseCase::new(keys::RevokePorts {
            key_store: a.signing_key_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        get_migration: Arc::new(migrations::GetUseCase::new(migrations::GetPorts {
            migration_store: a.migration_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        plan_migration: Arc::new(plan_migration(a)),
        start_migration: Arc::new(start_migration(a)),
        promote_migration: Arc::new(promote_migration(a)),
        rollback_migration: Arc::new(rollback_migration(a)),
        complete_migration: Arc::new(complete_migration(a)),
        cancel_migration: Arc::new(migrations::CancelUseCase::new(migrations::CancelPorts {
            migration_store: a.migration_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
    }
}

/// Publishes signing keys with the deployment's JWKS retirement grace.
fn published_keys(a: &Adapters, s: &Settings) -> keys::GetJwksUseCase {
    keys::GetJwksUseCase::new(
        keys::GetJwksPorts {
            key_store: a.signing_key_store.clone(),
            decoder: a.public_key_decoder.clone(),
        },
        s.tunables.jwks_grace,
    )
}

/// Publishes gateway assertion keys for their fixed overlap period.
fn published_assertions(a: &Adapters) -> assertions::GetPublishedUseCase {
    assertions::GetPublishedUseCase::new(
        assertions::GetPublishedPorts {
            keys: a.assertion_key_store.clone(),
            decoder: a.public_key_decoder.clone(),
        },
        KeyRotationSchedule::FOR_ASSERTION_KEYS.overlap(),
    )
}

/// Plans an algorithm migration against the tenant's existing signing keys.
fn plan_migration(a: &Adapters) -> migrations::PlanUseCase {
    migrations::PlanUseCase::new(migrations::PlanPorts {
        key_store: a.signing_key_store.clone(),
        migration_store: a.migration_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Starts an authorized migration with newly generated signing material.
fn start_migration(a: &Adapters) -> migrations::StartUseCase {
    migrations::StartUseCase::new(migrations::StartPorts {
        key_store: a.signing_key_store.clone(),
        key_generator: a.key_generator.clone(),
        migration_store: a.migration_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Promotes migration keys through the tenant's migration state checks.
fn promote_migration(a: &Adapters) -> migrations::PromoteUseCase {
    migrations::PromoteUseCase::new(migrations::PromotePorts {
        key_store: a.signing_key_store.clone(),
        migration_store: a.migration_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Restores the previous keys through the tenant's migration state checks.
fn rollback_migration(a: &Adapters) -> migrations::RollbackUseCase {
    migrations::RollbackUseCase::new(migrations::RollbackPorts {
        key_store: a.signing_key_store.clone(),
        migration_store: a.migration_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Completes a migration against its stored keys and tenant authority.
fn complete_migration(a: &Adapters) -> migrations::CompleteUseCase {
    migrations::CompleteUseCase::new(migrations::CompletePorts {
        key_store: a.signing_key_store.clone(),
        migration_store: a.migration_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}
