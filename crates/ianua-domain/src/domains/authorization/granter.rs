//! What someone handing out permissions holds, and the rule that keeps them
//! from handing out more.
//!
//! A person may put a permission on a role, a key or a group only when they
//! hold it themselves. The one exception is app-defined permissions, which
//! someone with the right to escalate may hand out without holding them.

use crate::domains::authorization::authority::{Holdings, TenantAuthority};
use crate::domains::authorization::permission::{
    CustomPermission, RoleAction, SystemPermission, UserAction,
};
use crate::domains::authorization::stewardship::Stewardship;
use crate::domains::identity::account::control::{AccountAction, DepartureCheck, ProfileEditor};
use crate::domains::identity::account::creator::{AccountCreator, AccountOpening};
use crate::domains::identity::sealed::Sealed;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::UserId;

/// What a person handing out permissions holds right now.
///
/// It holds their standing rights only: what their roles and groups give
/// them. What an active break-glass grant adds is for using during the
/// emergency, not for handing on. Ann gets "manage roles" for two hours.
/// If that counted here, she would write it into a role of her own, assign
/// it to herself and keep it after the grant ends.
///
/// Nobody writes it by hand. It comes from
/// [`TenantAuthority::standing`](crate::domains::authorization::authority::TenantAuthority::standing),
/// which works it out from what the tenant stores. A list a use case wrote
/// itself would grant whatever it names.
#[derive(Debug, Clone, Copy)]
pub struct HeldByGranter<'a> {
    system: &'a [SystemPermission],
    custom: &'a [CustomPermission],
}

/// What a change hands to the people it reaches: the built-in and
/// app-defined permissions they gain.
#[derive(Debug, Clone, Copy)]
pub struct Handout<'a> {
    /// The built-in permissions handed out.
    pub system: &'a [SystemPermission],
    /// The app-defined permissions handed out.
    pub custom: &'a [CustomPermission],
}

impl Handout<'_> {
    /// A change that hands out nothing.
    pub const NOTHING: Handout<'static> = Handout {
        system: &[],
        custom: &[],
    };
}

/// Someone acting on another account's sign-in: its password, address,
/// second factor, status or linked identities.
///
/// Whoever controls how an account signs in holds everything it holds. So
/// acting on it hands that out. The actor needs the right for the action,
/// and must hold all the account holds. Sam may edit users. Without this
/// check, Sam resets the password of Ann, an admin, signs in as her and
/// holds what she holds. And Bob, who holds nothing, would take over Carol,
/// who holds nothing either.
///
/// It is worked out for one account and passes for no other. So a check
/// made for Bob cannot be used on Ann. Only
/// [`TenantAccess::account_control`](crate::domains::authorization::authority::TenantAccess::account_control)
/// makes one, from the tenant's records,
/// so what the account holds and whether it is the last administrator are
/// never the caller's word.
#[derive(Debug, Clone)]
pub struct AccountControl<'a> {
    actor: &'a TenantAuthority,
    account: UserId,
    stewardship: Stewardship,
    target: Holdings,
}

impl<'a> AccountControl<'a> {
    /// `actor` acting on `account`, which holds `target`, as the tenant's
    /// records say.
    pub(crate) fn new(
        actor: &'a TenantAuthority,
        account: UserId,
        stewardship: Stewardship,
        target: Holdings,
    ) -> Self {
        Self {
            actor,
            account,
            stewardship,
            target,
        }
    }

    /// `actor` acting on `account`, which holds `target` and stands as
    /// `stewardship` says, as a test says, without the records behind it.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn assumed(
        actor: &'a TenantAuthority,
        account: UserId,
        stewardship: Stewardship,
        target: Handout<'_>,
    ) -> Self {
        Self::new(
            actor,
            account,
            stewardship,
            Holdings::of(target.system.to_vec(), target.custom.to_vec()),
        )
    }

    /// The person acting.
    #[must_use]
    pub fn actor(&self) -> &'a TenantAuthority {
        self.actor
    }

    /// The account acted on.
    #[must_use]
    pub fn account(&self) -> &UserId {
        &self.account
    }

    /// Refuses `action` on `account` unless the actor may do it.
    ///
    /// The actor's rights are checked before the last administrator is.
    /// Sam holds no user right. Without that order, he tries to lock out
    /// each account in turn, and the one refused as a conflict is the
    /// tenant's only administrator.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when this check was made for another
    ///   account.
    /// - [`DomainError::Forbidden`] when the actor lacks the user right
    ///   `action` needs. See [`right_for`].
    /// - [`DomainError::Forbidden`] when the account holds more than the
    ///   actor, in the cases [`HeldByGranter::ensure_may_hand_out`] lists.
    /// - [`DomainError::Conflict`] when `action` shuts out or erases the
    ///   tenant's last administrator, which would leave nobody able to run
    ///   it.
    pub fn ensure_allowed(
        &self,
        account: &UserId,
        action: AccountAction,
    ) -> Result<(), DomainError> {
        if self.account != *account {
            return Err(DomainError::forbidden(message!(
                "authorization-the-check-was-made-for-another",
                "the check was made for another account"
            )));
        }
        self.actor.ensure_holds(right_for(action))?;
        self.actor
            .standing()
            .ensure_may_give(&self.target.handout())
            .map_err(|_| {
                DomainError::forbidden(message!(
                    "authorization-the-account-holds-more-than-the",
                    "the account holds more than the person acting on it"
                ))
            })?;
        self.ensure_keeps_an_administrator(action)
    }

    /// Refuses shutting out or erasing the tenant's last administrator.
    fn ensure_keeps_an_administrator(&self, action: AccountAction) -> Result<(), DomainError> {
        if !matches!(action, AccountAction::ShutOut | AccountAction::Erase) {
            return Ok(());
        }
        self.stewardship.ensure_not_last()
    }
}

/// A person closing their own account, with whether the tenant keeps an
/// administrator worked out from the tenant's records.
///
/// Only
/// [`TenantAccess::departure_of`](crate::domains::authorization::authority::TenantAccess::departure_of)
/// makes one, so whether the account is the last administrator is never
/// the caller's word. It is worked out for one account and passes for no
/// other.
#[derive(Debug, Clone, Copy)]
pub struct Departure {
    account: UserId,
    stewardship: Stewardship,
}

impl Departure {
    /// `account` leaving, standing as `stewardship` says.
    pub(crate) fn new(account: UserId, stewardship: Stewardship) -> Self {
        Self {
            account,
            stewardship,
        }
    }

    /// `account` leaving, standing as `stewardship` says, as a test says,
    /// without the records behind it.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn assumed(account: UserId, stewardship: Stewardship) -> Self {
        Self::new(account, stewardship)
    }
}

impl Sealed for Departure {}

impl DepartureCheck for Departure {
    fn ensure_may_leave(&self, account: &UserId) -> Result<(), DomainError> {
        if self.account != *account {
            return Err(DomainError::forbidden(message!(
                "authorization-the-check-was-made-for-another",
                "the check was made for another account"
            )));
        }
        self.stewardship.ensure_not_last()
    }
}

/// The user right acting on someone else's account needs.
///
/// Changing how they sign in, recording a withdrawal for them, or changing
/// their name, language, timezone or directory records needs the right to
/// update users. Shutting them out and letting them back in both
/// need the right to deactivate users, so someone who may only edit
/// profiles cannot undo a lock a security admin set. Erasing them needs the
/// right to delete users. Asking for a copy of their data needs the right
/// to view them. Acting as them needs full control of users.
#[must_use]
pub fn right_for(action: AccountAction) -> SystemPermission {
    let user_action = match action {
        AccountAction::ChangeSignIn
        | AccountAction::RecordForThem
        | AccountAction::EditProfile
        | AccountAction::EditRecords => UserAction::Update,
        AccountAction::ShutOut | AccountAction::LetIn => UserAction::Deactivate,
        AccountAction::Erase => UserAction::Delete,
        AccountAction::Export => UserAction::View,
        AccountAction::Impersonate => UserAction::Manage,
    };
    SystemPermission::Users(user_action)
}

impl crate::domains::identity::sealed::Sealed for AccountControl<'_> {}

impl crate::domains::identity::account::control::AccountControlCheck for AccountControl<'_> {
    fn ensure_allowed(&self, account: &UserId, action: AccountAction) -> Result<(), DomainError> {
        AccountControl::ensure_allowed(self, account, action)
    }
}

impl<T: TenantScope> ProfileEditor<T> for AccountControl<'_> {
    fn ensure_may_edit(&self, account: &UserId) -> Result<(), DomainError> {
        self.ensure_allowed(account, AccountAction::EditProfile)
    }
}

impl Sealed for HeldByGranter<'_> {}

/// A person opens an account, registered or invited, with the right to
/// create users.
impl<T: TenantScope> AccountCreator<T> for HeldByGranter<'_> {
    fn ensure_may_open(&self, _opening: AccountOpening) -> Result<(), DomainError> {
        self.ensure_holds(SystemPermission::Users(UserAction::Create))
    }
}

impl<'a> HeldByGranter<'a> {
    /// What someone holds, as this crate worked it out.
    pub(crate) fn new(system: &'a [SystemPermission], custom: &'a [CustomPermission]) -> Self {
        Self { system, custom }
    }

    /// What a test says someone holds, without the records behind it.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn assumed(system: &'a [SystemPermission], custom: &'a [CustomPermission]) -> Self {
        Self::new(system, custom)
    }

    /// The built-in permissions they hold.
    #[must_use]
    pub fn system(&self) -> &'a [SystemPermission] {
        self.system
    }

    /// The app-defined permissions they hold, with what the catalogue's
    /// ladders confer on them.
    #[must_use]
    pub fn custom(&self) -> &'a [CustomPermission] {
        self.custom
    }

    /// Whether they hold `right`, as it is or through a wider permission.
    #[must_use]
    pub fn holds(&self, right: SystemPermission) -> bool {
        self.system.iter().any(|held| held.implies(&right))
    }

    /// Refuses unless they hold `right`.
    ///
    /// Holdings a permission is not enough to hand it on. Sam may manage
    /// users but not touch roles. Without this, he writes "manage users"
    /// into a new role and gives it to Bob, though only people who may
    /// manage roles should shape them.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when they do not hold `right`.
    pub fn ensure_holds(&self, right: SystemPermission) -> Result<(), DomainError> {
        if self.holds(right) {
            return Ok(());
        }
        Err(DomainError::forbidden(message!(
            "authorization-this-needs",
            format!("this needs {right}")
        )))
    }

    /// Refuses a change to something that grants `grants`, unless they hold
    /// `right` and could hand out all it grants.
    ///
    /// Taking rights away gives nobody anything, but it can still harm. Sam
    /// may edit roles and view users. Without this, he strips "manage roles"
    /// from the admin role and shuts Ann, the admin, out of her own work. So
    /// a person changes only what they could have made.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when they do not hold `right`.
    /// - [`DomainError::Forbidden`] when it grants more than they hold.
    pub fn ensure_controls(
        &self,
        right: SystemPermission,
        grants: &Handout<'_>,
    ) -> Result<(), DomainError> {
        self.ensure_holds(right)?;
        self.ensure_may_give(grants).map_err(|_| {
            DomainError::forbidden(message!(
                "authorization-it-grants-more-than-the-person",
                "it grants more than the person changing it holds"
            ))
        })
    }

    /// Refuses `handout` when it gives more than the granter holds.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] in the cases [`Self::ensure_may_hand_out`] lists.
    pub fn ensure_may_give(&self, handout: &Handout<'_>) -> Result<(), DomainError> {
        self.ensure_may_hand_out(handout.system, handout.custom)
    }

    /// Refuses a hand-out that gives more than the granter holds.
    ///
    /// Sam may view users but not manage them. Without this check, Sam puts
    /// "manage users" on a role he holds and gains it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `system` names a built-in permission
    ///   the granter lacks.
    /// - [`DomainError::Forbidden`] when `custom` names an app-defined
    ///   permission the granter lacks, and they may not escalate.
    pub fn ensure_may_hand_out(
        &self,
        system: &[SystemPermission],
        custom: &[CustomPermission],
    ) -> Result<(), DomainError> {
        if !SystemPermission::can_delegate(self.system, system) {
            return Err(DomainError::forbidden(message!(
                "authorization-a-permission-can-be-handed-out",
                "a permission can be handed out only by someone who holds it"
            )));
        }
        if custom.is_empty()
            || self.holds(SystemPermission::Roles(RoleAction::Escalate))
            || CustomPermission::can_delegate(self.custom, custom)
        {
            return Ok(());
        }
        Err(DomainError::forbidden(message!(
            "authorization-an-app-permission-can-be-handed",
            "an app permission can be handed out only by someone who holds it"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::authority::anyone_holding;

    fn custom(text: &str) -> CustomPermission {
        CustomPermission::parse(text).unwrap()
    }

    /// A user viewer can delegate viewing, but cannot grant user management or
    /// invoice refunds that they do not hold.
    #[test]
    fn a_granter_hands_out_only_what_they_hold() {
        let viewer = [SystemPermission::Users(UserAction::View)];
        let granter = HeldByGranter::assumed(&viewer, &[]);

        assert!(
            granter
                .ensure_may_hand_out(&[SystemPermission::Users(UserAction::View)], &[])
                .is_ok()
        );
        assert!(matches!(
            granter.ensure_may_hand_out(&[SystemPermission::ManageUsers], &[]),
            Err(DomainError::Forbidden(_))
        ));
        assert!(matches!(
            granter.ensure_may_hand_out(&[], &[custom("invoices:refund")]),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A user editor can change sign-in for an account with equal rights, but
    /// cannot do so for an account that also manages roles.
    #[test]
    fn only_someone_holding_what_an_account_holds_acts_on_it() {
        let sam = [SystemPermission::Users(UserAction::Update)];
        let actor = anyone_holding(&sam);
        let account = UserId::new();
        let on = |target: &'static [SystemPermission]| {
            AccountControl::assumed(
                actor,
                account,
                Stewardship::OthersAdminister,
                Handout {
                    system: target,
                    custom: &[],
                },
            )
        };

        assert!(matches!(
            on(&[
                SystemPermission::Users(UserAction::Update),
                SystemPermission::Roles(RoleAction::Manage)
            ])
            .ensure_allowed(&account, AccountAction::ChangeSignIn),
            Err(DomainError::Forbidden(_))
        ));
        assert!(
            on(&[SystemPermission::Users(UserAction::Update)])
                .ensure_allowed(&account, AccountAction::ChangeSignIn)
                .is_ok()
        );
    }

    /// Account-control authority computed for Bob cannot authorize changing Ann's sign-in.
    #[test]
    fn a_check_made_for_one_account_passes_for_no_other() {
        let sam = [SystemPermission::Users(UserAction::Update)];
        let bob = UserId::new();
        let for_bob = AccountControl::assumed(
            anyone_holding(&sam),
            bob,
            Stewardship::OthersAdminister,
            Handout::NOTHING,
        );

        let on_ann = for_bob.ensure_allowed(&UserId::new(), AccountAction::ChangeSignIn);

        assert!(matches!(on_ann, Err(DomainError::Forbidden(_))));
    }

    /// A caller with no rights cannot change Carol's sign-in, shut her out or
    /// erase her. User-update rights allow changing sign-in but not shutting her out.
    #[test]
    fn acting_on_an_account_needs_the_right_for_the_action() {
        let carol = UserId::new();
        let acting = |held: &'static [SystemPermission], action| {
            AccountControl::assumed(
                anyone_holding(held),
                carol,
                Stewardship::OthersAdminister,
                Handout::NOTHING,
            )
            .ensure_allowed(&carol, action)
        };
        let updater: &'static [SystemPermission] = &[SystemPermission::Users(UserAction::Update)];

        for action in [
            AccountAction::ChangeSignIn,
            AccountAction::ShutOut,
            AccountAction::Erase,
        ] {
            assert!(matches!(
                acting(&[], action),
                Err(DomainError::Forbidden(_))
            ));
        }
        assert!(acting(updater, AccountAction::ChangeSignIn).is_ok());
        assert!(matches!(
            acting(updater, AccountAction::ShutOut),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A granter holds only the right to escalate roles. They may still hand
    /// out the app permission "invoices:refund" without holding it.
    #[test]
    fn a_granter_who_may_escalate_hands_out_app_permissions() {
        let escalator = [SystemPermission::Roles(RoleAction::Escalate)];
        let granter = HeldByGranter::assumed(&escalator, &[]);

        assert!(
            granter
                .ensure_may_hand_out(&[], &[custom("invoices:refund")])
                .is_ok()
        );
    }

    /// A role editor cannot change a role granting user-management rights they
    /// lack. Holding both role and user management authorizes the change.
    #[test]
    fn only_someone_holding_all_a_thing_grants_may_change_it() {
        let admin_grants = Handout {
            system: &[SystemPermission::ManageUsers],
            custom: &[],
        };
        let sam = HeldByGranter::assumed(
            &[
                SystemPermission::Roles(RoleAction::Update),
                SystemPermission::Users(UserAction::View),
            ],
            &[],
        );
        let ann = HeldByGranter::assumed(
            &[SystemPermission::ManageRoles, SystemPermission::ManageUsers],
            &[],
        );
        let update = SystemPermission::Roles(RoleAction::Update);

        assert!(matches!(
            sam.ensure_controls(update, &admin_grants),
            Err(DomainError::Forbidden(_))
        ));
        assert!(ann.ensure_controls(update, &admin_grants).is_ok());
    }

    /// Role management authorizes role edits, while user management does not.
    #[test]
    fn a_right_is_held_only_through_its_own_area() {
        let bob = HeldByGranter::assumed(&[SystemPermission::ManageUsers], &[]);
        let ann = HeldByGranter::assumed(&[SystemPermission::ManageRoles], &[]);
        let update = SystemPermission::Roles(RoleAction::Update);

        assert!(matches!(
            bob.ensure_holds(update),
            Err(DomainError::Forbidden(_))
        ));
        assert!(ann.ensure_holds(update).is_ok());
    }

    /// Even a fully authorized caller cannot shut out or erase the last
    /// administrator, while changing her sign-in remains allowed.
    #[test]
    fn the_last_administrator_is_never_shut_out() {
        let ann = UserId::new();
        let control = AccountControl::assumed(
            anyone_holding(SystemPermission::all()),
            ann,
            Stewardship::LastAdministrator,
            Handout::NOTHING,
        );

        assert!(matches!(
            control.ensure_allowed(&ann, AccountAction::ShutOut),
            Err(DomainError::Conflict(_))
        ));
        assert!(matches!(
            control.ensure_allowed(&ann, AccountAction::Erase),
            Err(DomainError::Conflict(_))
        ));
        assert!(
            control
                .ensure_allowed(&ann, AccountAction::ChangeSignIn)
                .is_ok()
        );
    }

    /// A caller without user rights receives a forbidden error for shutting out
    /// or erasing the last administrator, concealing the stewardship conflict.
    #[test]
    fn someone_without_the_right_never_learns_who_the_last_administrator_is() {
        let ann = UserId::new();
        let control = AccountControl::assumed(
            anyone_holding(&[]),
            ann,
            Stewardship::LastAdministrator,
            Handout::NOTHING,
        );

        for action in [AccountAction::ShutOut, AccountAction::Erase] {
            assert!(matches!(
                control.ensure_allowed(&ann, action),
                Err(DomainError::Forbidden(_))
            ));
        }
    }
}
