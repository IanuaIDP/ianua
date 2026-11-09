//! Loading the tenant's branding, the customized email template a caller
//! names, the tenant's mail provider, and where the caller's own mail goes.

use ianua_domain::domains::branding::config::TenantBranding;
use ianua_domain::domains::branding::email_template::{EmailTemplate, TemplateSlot};
use ianua_domain::domains::branding::mail_provider::TenantMailProvider;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::Email;

use crate::acting::TenantAuthorities;
use crate::context::{CallerContext, CallerIdentity};
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::branding::{BrandingStore, EmailTemplateStore, TenantMailProviderStore};
use crate::ports::organization::OrgUserStore;
use crate::tenancy::ScopedTenant;

/// The tenant's mail provider, or the platform's own mail when it never
/// named one.
///
/// # Errors
///
/// `AppError::Internal` on storage failure.
pub(super) async fn current_mail_provider(
    store: &dyn TenantMailProviderStore,
    tenant: &ScopedTenant,
) -> Result<TenantMailProvider<ResolvedTenant>, AppError> {
    Ok(store
        .find(tenant)
        .await
        .or_internal()?
        .unwrap_or_else(TenantMailProvider::platform_mail))
}

/// The address of the person `caller` came as: a user of the tenant signed
/// in to it, or a member of its organization.
///
/// # Errors
///
/// - `AppError::Unauthenticated` when the session no longer counts, or the
///   member is gone.
/// - `AppError::Forbidden` when the caller came as an operator, who has no
///   address in the tenant.
/// - `AppError::Internal` on storage failure.
pub(super) async fn caller_address(
    authorities: &dyn TenantAuthorities,
    members: &dyn OrgUserStore,
    caller: &CallerContext,
) -> Result<Email, AppError> {
    match caller.identity() {
        CallerIdentity::TenantUser(_) => {
            let person = authorities.signed_in(caller).await?;
            Ok(person.account.email().clone())
        }
        CallerIdentity::OrgUser(member_id) => members
            .find_by_id_in_org(&caller.organization_id(), member_id)
            .await
            .or_internal()?
            .map(|member| member.email().clone())
            .ok_or(AppError::Unauthenticated),
        CallerIdentity::Operator(_) => Err(AppError::Forbidden(message!(
            "branding-a-test-mail-goes-to-the",
            "a test mail goes to the person asking for it"
        ))),
    }
}

/// The tenant's branding, or the defaults when none was saved yet.
///
/// # Errors
///
/// `AppError::Internal` on storage failure.
pub(super) async fn current_branding(
    store: &dyn BrandingStore,
    tenant: &ScopedTenant,
) -> Result<TenantBranding<ResolvedTenant>, AppError> {
    Ok(store
        .find(tenant)
        .await
        .or_internal()?
        .unwrap_or_else(TenantBranding::default_branding))
}

/// The tenant's customized template in `slot`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant wrote no template for that email
///   and locale.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_template(
    store: &dyn EmailTemplateStore,
    tenant: &ScopedTenant,
    slot: &TemplateSlot,
) -> Result<EmailTemplate, AppError> {
    store
        .find(tenant, slot)
        .await
        .or_internal()?
        .or_not_found(message!(
            "branding-no-custom-template-to-reset",
            "no custom template to reset"
        ))
}
