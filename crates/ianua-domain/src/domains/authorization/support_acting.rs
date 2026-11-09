//! What a support admin holds while acting as a tenant user through a
//! support impersonation the person approved, or the tenant let the admin
//! decide.

use time::OffsetDateTime;

use crate::domains::authorization::authority::{Holdings, TenantAccess, TenantAuthority};
use crate::domains::identity::account::control::SignedInPerson;
use crate::domains::identity::account::user::User;
use crate::domains::identity::impersonation::SupportImpersonation;
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::types::{Human, HumanAccount, PersonKey, PrincipalRef};

/// What the admin `admin` holds acting as `account` through `impersonation`
/// at `now`, in the tenant `access` was read from: what the account holds
/// there now, and never more.
///
/// It is checked as
/// [`SupportImpersonation::ensure_usable`] checks, on every use, so the
/// window running out, an end either side asked for or a lock on the
/// account stops the admin at once. Break-glass access is the person's own,
/// given for their emergency, so it is not carried.
///
/// # Errors
///
/// - The cases [`SupportImpersonation::ensure_usable`] lists.
/// - The cases
///   [`TenantGrants::administrators`](crate::domains::authorization::stewardship::TenantGrants::administrators)
///   lists, for records that name a role or group that is not there.
pub fn acting_as<T: TenantScope>(
    impersonation: &SupportImpersonation<T>,
    access: &TenantAccess<'_, T>,
    admin: &impl SignedInPerson<T>,
    account: &User<T>,
    now: OffsetDateTime,
) -> Result<TenantAuthority, DomainError> {
    impersonation.ensure_usable(admin, account, now)?;
    let acted_as = PrincipalRef::User(*account.id());
    Ok(TenantAuthority::assemble(
        Human::new(
            HumanAccount::User(*account.id()),
            PersonKey::of(account.email()),
        ),
        access.tenant,
        access.standing_of(acted_as)?,
        Holdings::default(),
    ))
}
