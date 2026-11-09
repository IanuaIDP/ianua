//! Loading the records the organization use cases start from: a member,
//! the organization's owners, a token, a passkey, a device, a session, and
//! the name a record gives a tenant.
//!
//! Each lookup that names a member's record confines it to the member or
//! organization the caller acts for, so a record of someone else reads as
//! absent.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::passkey::PasskeyCredential;
use ianua_domain::domains::authentication::device_trust::TrustedDevice;
use ianua_domain::domains::authentication::recovery::codes::RecoveryCodeSet;
use ianua_domain::domains::identity::tokens::purpose::TokenPurpose;
use ianua_domain::domains::organization::access::api_key::OrgApiKey;
use ianua_domain::domains::organization::access::passkey::OrgPasskeyCeremony;
use ianua_domain::domains::organization::access::session::OrgSession;
use ianua_domain::domains::organization::access::token::OrgToken;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::invitation::OrgInvitation;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::message;
use ianua_domain::types::{
    CeremonyId, EventLabel, OrgApiKeyId, OrgUserId, OrganizationId, PasskeyId, SessionId, TenantId,
    TenantSlug, TokenHash, TrustedDeviceId,
};

use crate::acting::organization::OrgActor;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::organization::{
    OrgApiKeyStore, OrgInvitationStore, OrgPasskeyCeremonyStore, OrgPasskeyStore,
    OrgRecoveryCodeStore, OrgSessionStore, OrgTokenStore, OrgTrustedDeviceStore, OrgUserStore,
};
use crate::ports::tenant::TenantStore;
pub(in crate::use_cases::organization) use crate::services::lookup::existing_organization;

/// The tenant of `organization_id` that `slug` names.
///
/// # Errors
///
/// - `AppError::NotFound` if the organization has no such tenant.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::organization) async fn existing_tenant_named(
    store: &dyn TenantStore,
    organization_id: &OrganizationId,
    slug: &TenantSlug,
) -> Result<Arc<Tenant>, AppError> {
    store
        .find_by_slug_in_org(slug, organization_id)
        .await
        .or_internal()?
        .or_not_found(message!("app-tenant-not-found", "tenant not found"))
}

/// The recovery codes of the member `member`, as they stand.
///
/// # Errors
///
/// - `AppError::NotFound` if the member holds none.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::organization) async fn existing_member_recovery_codes(
    store: &dyn OrgRecoveryCodeStore,
    member: &OrgUserId,
) -> Result<RecoveryCodeSet<ResolvedOrganization>, AppError> {
    store
        .find_by_user(member)
        .await
        .or_internal()?
        .or_not_found(message!(
            "authentication-no-recovery-codes",
            "no recovery codes"
        ))
}

/// The member `id` of `organization_id`.
///
/// A member of another organization reads as absent, so an owner of one
/// organization never reaches a member of another.
///
/// # Errors
///
/// - `AppError::NotFound` if the organization has no such member.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::organization) async fn existing_member(
    store: &dyn OrgUserStore,
    organization_id: &OrganizationId,
    id: &OrgUserId,
) -> Result<OrgUser, AppError> {
    store
        .find_by_id_in_org(organization_id, id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "organization-org-user-not-found",
            "org user not found"
        ))
}

/// The member held within this organization until the current unit of work
/// finishes, for a change that must recheck their committed role.
///
/// # Errors
///
/// - `AppError::NotFound` if the organization has no such member.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::organization) async fn existing_held_member(
    store: &dyn OrgUserStore,
    organization_id: &OrganizationId,
    id: &OrgUserId,
) -> Result<OrgUser, AppError> {
    store
        .hold_by_id_in_org(organization_id, id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "organization-org-user-not-found",
            "org user not found"
        ))
}

/// The owners of `organization_id` as they stand now, for the domain's
/// check that a change keeps an active owner. Holds ownership changes until
/// the current unit of work ends; call before reading the member being changed.
///
/// # Errors
///
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::organization) async fn current_owners(
    store: &dyn OrgUserStore,
    organization_id: &OrganizationId,
) -> Result<Vec<OrgUser>, AppError> {
    store.hold_ownership(organization_id).await.or_internal()?;
    store.list_owners(organization_id).await.or_internal()
}

/// The pending invitation the organization sent `org_user_id`, whether or
/// not it has run out of time.
///
/// # Errors
///
/// - `AppError::NotFound` if no invitation is pending for them.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::organization) async fn existing_pending_invitation(
    store: &dyn OrgInvitationStore,
    organization_id: &OrganizationId,
    org_user_id: &OrgUserId,
) -> Result<OrgInvitation, AppError> {
    store
        .find_pending_by_org_user(organization_id, org_user_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "identity-no-pending-invitation",
            "no pending invitation"
        ))
}

/// The API key `id` of `organization_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the organization has no such key.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::organization) async fn existing_api_key(
    store: &dyn OrgApiKeyStore,
    organization_id: &OrganizationId,
    id: &OrgApiKeyId,
) -> Result<OrgApiKey, AppError> {
    store
        .find_by_id(id)
        .await
        .or_internal()?
        .filter(|key| key.organization_id() == organization_id)
        .or_not_found(message!("oauth-api-key-not-found", "API key not found"))
}

/// The trusted device `id`, provided `member` owns it.
///
/// # Errors
///
/// - `AppError::NotFound` if the member has no such device.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::organization) async fn owned_trusted_device(
    store: &dyn OrgTrustedDeviceStore,
    member: &OrgUserId,
    id: &TrustedDeviceId,
) -> Result<TrustedDevice<ResolvedOrganization>, AppError> {
    store
        .find_by_id(member, id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "authentication-device-not-found",
            "device not found"
        ))
}

/// The token whose hash is `hash`, spent or not.
///
/// # Errors
///
/// - `AppError::NotFound` if no such token was ever issued.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::organization) async fn existing_token<Purpose>(
    store: &dyn OrgTokenStore<Purpose>,
    hash: &TokenHash,
) -> Result<OrgToken<Purpose>, AppError>
where
    Purpose: TokenPurpose + Send + Sync + 'static,
{
    store
        .find_by_hash(hash)
        .await
        .or_internal()?
        .or_not_found(message!(
            "organization-invalid-or-expired-link",
            "invalid or expired link"
        ))
}

/// The passkey ceremony with `id`, whichever member it was opened for.
///
/// # Errors
///
/// - `AppError::NotFound` if no such ceremony is held.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::organization) async fn existing_ceremony(
    store: &dyn OrgPasskeyCeremonyStore,
    id: &CeremonyId,
) -> Result<OrgPasskeyCeremony, AppError> {
    store
        .find_by_id(id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "authentication-passkey-challenge-not-found",
            "passkey challenge not found"
        ))
}

/// One of `member`'s passkeys by id. Another member's passkey reads as
/// absent.
///
/// # Errors
///
/// - `AppError::NotFound` if the member has no such passkey.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::organization) async fn member_passkey(
    store: &dyn OrgPasskeyStore,
    member: &OrgUserId,
    id: &PasskeyId,
) -> Result<PasskeyCredential<ResolvedOrganization>, AppError> {
    store
        .list_by_user(member)
        .await
        .or_internal()?
        .into_iter()
        .find(|passkey| passkey.id() == id)
        .or_not_found(message!(
            "authentication-passkey-not-found",
            "passkey not found"
        ))
}

/// The org session with `id` of `organization_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the organization has no such session.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::organization) async fn existing_org_session(
    store: &dyn OrgSessionStore,
    organization_id: &OrganizationId,
    id: &SessionId,
) -> Result<OrgSession, AppError> {
    store
        .find_by_id(id)
        .await
        .or_internal()?
        .filter(|session| session.organization_id() == organization_id)
        .or_not_found(message!("app-session-not-found", "session not found"))
}

/// The session `actor` acts through, as stored, for a change of how they
/// sign in to keep it.
///
/// # Errors
///
/// - `AppError::Unauthenticated` when the session no longer counts, or the
///   member acts through a key.
/// - `AppError::NotFound` when the session is gone.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::organization) async fn owned_org_session(
    store: &dyn OrgSessionStore,
    organization: &Organization,
    actor: &OrgActor,
) -> Result<OrgSession, AppError> {
    let id = actor
        .control()?
        .session()
        .map(|session| *session.id())
        .ok_or(AppError::Unauthenticated)?;
    existing_org_session(store, organization.id(), &id).await
}

/// How an audit record names the tenant `tenant_id`: its name, or its id
/// when the tenant cannot be read. A name never fails the change it names.
pub(in crate::use_cases::organization) async fn tenant_label(
    store: &dyn TenantStore,
    tenant_id: &TenantId,
) -> EventLabel {
    let name = store
        .find_by_id(tenant_id)
        .await
        .ok()
        .flatten()
        .map_or_else(
            || tenant_id.to_string(),
            |tenant| tenant.display_name().to_string(),
        );
    EventLabel::of(&name)
}
