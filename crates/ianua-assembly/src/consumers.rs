//! The consumer use cases the API serves: a tenant's machine identities,
//! their credentials, quota, clearance and lifecycle.

use std::sync::Arc;

use ianua_app::services::issuers::TenantIssuers;
use ianua_app::use_cases::consumers;

use crate::deps::{Adapters, Settings};

/// The consumer use cases.
#[derive(Clone)]
pub struct ConsumerState {
    pub create: Arc<consumers::CreateUseCase>,
    pub get: Arc<consumers::GetUseCase>,
    pub list: Arc<consumers::ListUseCase>,
    pub rename: Arc<consumers::RenameUseCase>,
    pub describe: Arc<consumers::DescribeUseCase>,
    pub change_clearance: Arc<consumers::ChangeClearanceUseCase>,
    pub change_quota: Arc<consumers::ChangeQuotaUseCase>,
    pub disable: Arc<consumers::DisableUseCase>,
    pub enable: Arc<consumers::EnableUseCase>,
    pub rotate: Arc<consumers::RotateCredentialUseCase>,
    pub end_overlap: Arc<consumers::EndCredentialOverlapUseCase>,
    pub change_expiry: Arc<consumers::ChangeCredentialExpiryUseCase>,
    pub delete: Arc<consumers::DeleteUseCase>,
}

/// Builds the consumer use cases over `a`, naming the platform's address
/// from `s` for the tenant's own token issuer.
pub fn build(a: &Adapters, s: &Settings) -> ConsumerState {
    let store = || a.consumer_store.clone();
    let authorities = || a.tenant_authorities.clone();
    ConsumerState {
        create: Arc::new(create(a, s)),
        get: Arc::new(consumers::GetUseCase::new(consumers::GetPorts {
            consumer_store: store(),
            tenant_authorities: authorities(),
        })),
        list: Arc::new(consumers::ListUseCase::new(consumers::ListPorts {
            consumer_store: store(),
            tenant_authorities: authorities(),
        })),
        rename: Arc::new(rename(a)),
        describe: Arc::new(describe(a)),
        change_clearance: Arc::new(change_clearance(a)),
        change_quota: Arc::new(change_quota(a)),
        disable: Arc::new(consumers::DisableUseCase::new(consumers::DisablePorts {
            consumer_store: store(),
            tenant_authorities: authorities(),
        })),
        enable: Arc::new(consumers::EnableUseCase::new(consumers::EnablePorts {
            consumer_store: store(),
            tenant_authorities: authorities(),
        })),
        rotate: Arc::new(rotate(a, s)),
        end_overlap: Arc::new(end_overlap(a)),
        change_expiry: Arc::new(change_expiry(a)),
        delete: Arc::new(delete(a)),
    }
}

/// Updates a machine identity's description under tenant authority.
fn describe(a: &Adapters) -> consumers::DescribeUseCase {
    consumers::DescribeUseCase::new(consumers::DescribePorts {
        consumer_store: a.consumer_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Deletes a machine identity after checking the caller's tenant authority.
fn delete(a: &Adapters) -> consumers::DeleteUseCase {
    consumers::DeleteUseCase::new(consumers::DeletePorts {
        consumer_store: a.consumer_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Creates a machine identity with a generated credential and tenant plan limits.
fn create(a: &Adapters, s: &Settings) -> consumers::CreateUseCase {
    consumers::CreateUseCase::new(consumers::CreatePorts {
        consumer_store: a.consumer_store.clone(),
        limit_enforcer: a.limit_enforcer.clone(),
        issuers: issuers(a, s),
        tenant_authorities: a.tenant_authorities.clone(),
        key_generator: a.consumer_key_generator.clone(),
    })
}

/// Renames a machine identity under the caller's tenant authority.
fn rename(a: &Adapters) -> consumers::RenameUseCase {
    consumers::RenameUseCase::new(consumers::RenamePorts {
        consumer_store: a.consumer_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Applies clearance changes through the consumer aggregate's authority checks.
fn change_clearance(a: &Adapters) -> consumers::ChangeClearanceUseCase {
    consumers::ChangeClearanceUseCase::new(consumers::ChangeClearancePorts {
        consumer_store: a.consumer_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Applies quota changes through the consumer aggregate's authority checks.
fn change_quota(a: &Adapters) -> consumers::ChangeQuotaUseCase {
    consumers::ChangeQuotaUseCase::new(consumers::ChangeQuotaPorts {
        consumer_store: a.consumer_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Rotates consumer credentials with current access records and tenant issuer checks.
fn rotate(a: &Adapters, s: &Settings) -> consumers::RotateCredentialUseCase {
    consumers::RotateCredentialUseCase::new(consumers::RotateCredentialPorts {
        consumer_store: a.consumer_store.clone(),
        access_records: a.access_record_store.clone(),
        issuers: issuers(a, s),
        tenant_authorities: a.tenant_authorities.clone(),
        key_generator: a.consumer_key_generator.clone(),
    })
}

/// Ends the old credential's overlap under the caller's tenant authority.
fn end_overlap(a: &Adapters) -> consumers::EndCredentialOverlapUseCase {
    consumers::EndCredentialOverlapUseCase::new(consumers::EndCredentialOverlapPorts {
        consumer_store: a.consumer_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Changes credential expiry through the consumer aggregate's authority checks.
fn change_expiry(a: &Adapters) -> consumers::ChangeCredentialExpiryUseCase {
    consumers::ChangeCredentialExpiryUseCase::new(consumers::ChangeCredentialExpiryPorts {
        consumer_store: a.consumer_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Works out each tenant's own token issuer, which no consumer may trust.
fn issuers(a: &Adapters, s: &Settings) -> TenantIssuers {
    TenantIssuers::new(
        a.tenant_store.clone(),
        a.organization_store.clone(),
        s.app_base_url.clone(),
    )
}
