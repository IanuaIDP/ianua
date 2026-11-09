//! Working out what someone may do to another person's account, or their
//! own, from the tenant's records, which every use case acting on an
//! account asks first.
//!
//! Only the account's own records are read, with the tenant's count of
//! administrators for whether it is the last one, never the whole tenant.

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::granter::{AccountControl, Departure, right_for};
use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::shared::clock;
use ianua_domain::types::UserId;

use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{AccessRecordStore, Holder};
use crate::tenancy::ScopedTenant;

/// `actor` acting on `account` to do `action`, with what the account holds
/// and whether it is the tenant's last administrator read from the
/// tenant's records now.
///
/// What the account holds is never the caller's word, so a check made here
/// is the only way a use case acts on someone else's sign-in.
///
/// The user right `action` needs is checked before any record is read. Sam
/// holds no user right. Without that order, he names made-up ids and real
/// ones, is told "not found" for one and "forbidden" for the other, and
/// learns who has an account. The aggregate checks the rest, what the
/// account holds, once it is loaded.
///
/// # Errors
///
/// - `AppError::Forbidden` when `actor` lacks the user right `action`
///   needs, or was worked out in another tenant.
/// - `AppError::Internal` when the records cannot be read, or name a role
///   or group that is not there.
pub(in crate::use_cases) async fn account_control<'a>(
    records: &dyn AccessRecordStore,
    tenant: &ScopedTenant,
    actor: &'a TenantAuthority,
    account: &UserId,
    action: AccountAction,
) -> Result<AccountControl<'a>, AppError> {
    actor
        .ensure_holds(right_for(action))
        .map_err(AppError::from_domain)?;
    let held = records
        .load_held_by(tenant, Holder::user(*account))
        .await
        .or_internal()?;
    let administrators = records.count_administrators(tenant).await.or_internal()?;
    held.access(**tenant)
        .account_control(actor, account, administrators, clock::now())
        .map_err(AppError::from_domain)
}

/// Reads [`account_control`] under a grant hold lasting until the unit settles,
/// so concurrent removals cannot each count the other last administrator.
/// Checks the user's right before taking the hold.
///
/// # Errors
///
/// - `AppError::Forbidden` when `actor` lacks the user right `action`
///   needs, or was worked out in another tenant.
/// - `AppError::Internal` when the hold cannot be taken, or the records
///   cannot be read or name a role or group that is not there.
pub(in crate::use_cases) async fn account_control_to_shut_out<'a>(
    records: &dyn AccessRecordStore,
    tenant: &ScopedTenant,
    actor: &'a TenantAuthority,
    account: &UserId,
    action: AccountAction,
) -> Result<AccountControl<'a>, AppError> {
    actor
        .ensure_holds(right_for(action))
        .map_err(AppError::from_domain)?;
    records.hold_grants(tenant).await.or_internal()?;
    account_control(records, tenant, actor, account, action).await
}

/// `account` closing itself, with whether the tenant keeps an administrator
/// read from the tenant's records now, counted under the tenant's hold on
/// its grants, so two last administrators leaving at once cannot both go.
///
/// # Errors
///
/// - `AppError::Internal` when the records cannot be read, or name a role
///   or group that is not there.
pub(in crate::use_cases::identity) async fn departure(
    records: &dyn AccessRecordStore,
    tenant: &ScopedTenant,
    account: &UserId,
) -> Result<Departure, AppError> {
    records.hold_grants(tenant).await.or_internal()?;
    let held = records
        .load_held_by(tenant, Holder::user(*account))
        .await
        .or_internal()?;
    let administrators = records.count_administrators(tenant).await.or_internal()?;
    held.access(**tenant)
        .departure_of(account, administrators)
        .map_err(AppError::from_domain)
}
