//! What a test says someone holds, without the records behind it.
//!
//! A control borrows the authority it reads, and test helpers hand controls
//! back to their callers. So these keep each authority for the rest of the
//! test run.

use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::granter::HeldByGranter;
use crate::domains::authorization::permission::{CustomPermission, SystemPermission, UserAction};
use crate::types::{Human, HumanAccount, PersonKey, TenantId, UserId};

/// What someone who may add users holds, for a test that opens accounts
/// and is not about who opens them.
#[must_use]
pub fn user_adder() -> HeldByGranter<'static> {
    HeldByGranter::assumed(&[SystemPermission::Users(UserAction::Create)], &[])
}

/// Someone a test does not name who may update users, and so change the
/// tenant's attribute schema, and sees no sensitive attribute.
#[must_use]
pub fn user_editor() -> &'static TenantAuthority {
    anyone_holding(&[SystemPermission::Users(UserAction::Update)])
}

/// `who`, holding `system` and `custom` in `tenant`.
#[must_use]
pub fn assumed_authority(
    who: &Human,
    tenant: TenantId,
    system: &[SystemPermission],
    custom: &[CustomPermission],
) -> &'static TenantAuthority {
    Box::leak(Box::new(TenantAuthority::assumed(
        who.clone(),
        tenant,
        system,
        custom,
    )))
}

/// Someone a test does not name, holding `system` in a tenant of their own.
///
/// # Panics
///
/// Never: the address is a constant valid one.
#[must_use]
pub fn anyone_holding(system: &[SystemPermission]) -> &'static TenantAuthority {
    let someone = Human::new(
        HumanAccount::User(UserId::new()),
        PersonKey::new("someone@example.test").expect("a valid address"),
    );
    assumed_authority(&someone, TenantId::new(), system, &[])
}
