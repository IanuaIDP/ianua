//! What linking accounts and switching between them must pass: the
//! tenants are the organization's, and a switch starts from a finished
//! sign-in the target workspace admits.

use crate::domains::identity::account::control::ensure_holder;
use crate::domains::organization::lifecycle::Organization;
use crate::domains::organization::members::linked_identity::TenantSwitch;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::TenantId;

/// Refuses `tenant_id` unless it is one of `organization`'s tenants.
pub(super) fn ensure_tenant_of(
    organization: &Organization,
    tenant_id: &TenantId,
) -> Result<(), DomainError> {
    if !organization.owns_tenant(tenant_id) {
        return Err(DomainError::forbidden(message!(
            "organization-the-tenant-does-not-belong-to",
            "the tenant does not belong to the organization"
        )));
    }
    Ok(())
}

/// Refuses a switch unless the caller's sign-in is to the source account
/// and has finished. A sign-in still owing a step carries nothing.
pub(super) fn ensure_signed_in_to_source<S: TenantScope, T: TenantScope>(
    request: &TenantSwitch<'_, S, T>,
) -> Result<(), DomainError> {
    ensure_holder(request.signed_in, request.from.user.id())?;
    if !request.signed_in.progress().is_complete() {
        return Err(DomainError::forbidden(message!(
            "organization-only-a-finished-sign-in-switches",
            "only a finished sign-in switches to a linked account"
        )));
    }
    Ok(())
}

/// Asks the tenant a switch lands in whether it admits the sign-in, as
/// every other way in asks it, and whether the sign-in meets its baseline.
pub(super) fn ensure_target_admits<S: TenantScope, T: TenantScope>(
    request: &TenantSwitch<'_, S, T>,
) -> Result<(), DomainError> {
    if *request.target_tenant.id() != request.to.tenant_id {
        return Err(DomainError::forbidden(message!(
            "organization-the-switch-names-a-different-tenant",
            "the switch names a different tenant than the one it lands in"
        )));
    }
    request
        .target_tenant
        .admits_sign_in(request.signed_in.progress().method(), request.client_ip)
        .map(drop)
        .map_err(|_| {
            DomainError::forbidden(message!(
                "organization-the-target-workspace-does-not-admit",
                "the target workspace does not admit this sign-in"
            ))
        })
}
