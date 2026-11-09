//! What the SCIM user use cases share: how far the directory reaches over
//! one account, and the confirmation link every address it sends gets.
//! The directory never proves an address, so its holder always confirms
//! it by link.

use ianua_domain::domains::federation::account_privilege::AccountPrivilege;
use ianua_domain::domains::federation::scim::{DirectoryControl, ScimEndpoint};
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::identity::account::user_status::UserStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::types::UserId;

use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{AccessRecordStore, Holder};
use crate::services::identity::link_scopes::TenantLinkScopes;
use crate::tenancy::ScopedTenant;
use crate::use_cases::identity::email::VerificationLinks;

/// Where the link confirming an unproven address is made, and where it
/// points.
pub(super) struct ConfirmationMail<'a> {
    /// Makes, keeps and mails the link.
    pub(super) links: &'a VerificationLinks,
    /// The tenant's own link scope, from its records.
    pub(super) scopes: &'a TenantLinkScopes,
}

/// The directory acting on one account, and whether that account holds
/// built-in permissions, both read from the tenant's records now.
pub(super) struct DirectoryReach {
    /// The directory's check for letting in, shutting out and moving the
    /// account.
    pub(super) control: DirectoryControl,
    /// Whether the account holds built-in permissions.
    pub(super) privilege: AccountPrivilege,
}

/// How far `endpoint`'s directory reaches over `account`, worked out from
/// the account's own records and the tenant's count of administrators,
/// never from the request and never from every record of the tenant. Both
/// are read under the tenant's hold on its grants, since every caller goes
/// on to change the account, so shutting out the last two administrators
/// at once is counted one after the other.
///
/// # Errors
///
/// - `AppError::Forbidden` when the endpoint is switched off.
/// - `AppError::Internal` when the records cannot be read, or name a role
///   or group that is not there.
pub(super) async fn directory_reach(
    records: &dyn AccessRecordStore,
    tenant: &ScopedTenant,
    endpoint: &ScimEndpoint<ResolvedTenant>,
    account: &UserId,
) -> Result<DirectoryReach, AppError> {
    records.hold_grants(tenant).await.or_internal()?;
    let held = records
        .load_held_by(tenant, Holder::user(*account))
        .await
        .or_internal()?;
    let administrators = records.count_administrators(tenant).await.or_internal()?;
    let access = held.access(**tenant);
    let now = clock::now();
    let control = endpoint
        .control_over(&access, account, administrators, now)
        .map_err(AppError::from_domain)?;
    let privilege = access
        .privilege_of(account, now)
        .map_err(AppError::from_domain)?;
    Ok(DirectoryReach { control, privilege })
}

/// Mails `user` a link to confirm their address while it is unproven and
/// the account may still be let in, and notes on the account that it went
/// out once the mailer took it. A mailer that refuses fails nothing: the
/// person can ask for another link.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant or its organization is not on
///   record.
/// - `AppError::Internal` when the link cannot be made or stored.
pub(super) async fn confirmation_mailed(
    mail: ConfirmationMail<'_>,
    tenant: &ScopedTenant,
    user: &mut User<ResolvedTenant>,
) -> Result<(), AppError> {
    if !awaits_confirmation(user) {
        return Ok(());
    }
    let scope = mail.scopes.of(tenant).await?;
    mail.links.send(tenant, user, &scope).await?.note_on(user);
    Ok(())
}

/// Whether `user`'s address is unproven while the account may be let in:
/// active, or waiting on the address. A switched-off or locked account
/// gets no link until the directory lets it back in.
fn awaits_confirmation(user: &User<ResolvedTenant>) -> bool {
    !user.email_verified()
        && matches!(
            user.status(),
            UserStatus::Active | UserStatus::PendingVerification
        )
}
