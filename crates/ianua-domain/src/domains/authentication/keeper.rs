//! Who may rename or take away an account's ways in, and end its sessions:
//! the account's holder, from their own sign-in, or an admin with the right
//! for it.

use crate::domains::authentication::sessions::sign_in_progress::SignedIn;
use crate::domains::identity::account::control::{AccountAction, AccountControlCheck};
use crate::domains::identity::sealed::Sealed;
use crate::isolation::SecurityScope;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{PrincipalId, UserId};

/// Whoever may rename or take away a way in of an account on plane `S`, such
/// as a passkey, a remembered device or a directory certificate, or end one
/// of its sessions.
///
/// The holder may, from their own finished sign-in: each of these only names
/// or takes away what they hold, so an open session is enough. Anyone else
/// needs the right for the action and must hold all the account holds. Sam
/// may only view users. Without this, he revokes Ann's passkeys and
/// remembered devices and ends her sessions in the middle of an incident.
///
/// Authentication answers for the holder with [`SignedIn`], and
/// authorization for an admin with its account control. Authentication sits
/// below authorization, so it names only the rule that control answers.
pub trait AccountKeeper<S: SecurityScope>: Sealed {
    /// Refuses `action` on the ways in or sessions of `account` unless this
    /// keeper may take it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when someone else is signed in.
    /// - [`DomainError::Forbidden`] when an admin lacks the right for
    ///   `action`, holds less than the account, or the check was made for
    ///   another account.
    /// - [`DomainError::Conflict`] when `action` shuts out the tenant's last
    ///   administrator.
    fn ensure_may(&self, account: &PrincipalId, action: AccountAction) -> Result<(), DomainError>;

    /// Whether this is the holder of `account`, acting from their own
    /// sign-in, rather than an admin acting on it.
    fn is_holder_of(&self, account: &PrincipalId) -> bool;
}

impl<S: SecurityScope> AccountKeeper<S> for SignedIn<S> {
    fn ensure_may(&self, account: &PrincipalId, _action: AccountAction) -> Result<(), DomainError> {
        if self.subject() == *account {
            return Ok(());
        }
        Err(DomainError::forbidden(message!(
            "authentication-only-the-account-s-holder-or",
            "only the account's holder, or an admin acting on it, may do this"
        )))
    }

    fn is_holder_of(&self, account: &PrincipalId) -> bool {
        self.subject() == *account
    }
}

/// What takes every way in of one account on plane `S` away at once,
/// because the account passes to whoever answers a new invitation to it.
///
/// The account is the same, but its holder may not be. Bob left and his
/// account was closed; his address now reaches Carol. Without this, Carol
/// is asked at her first sign-in for Bob's authenticator, and Bob's passkey
/// still opens the account once she sets a password. So nothing the account
/// held before is kept: its second factor, the recovery codes that stand in
/// for it, and its passkeys all go.
///
/// Only the context that reopens the account answers it, from the reopening
/// itself, so no caller writes an answer that always agrees.
pub trait FactorWithdrawal<S: SecurityScope>: Sealed {
    /// Whether this takes away the ways in of `account`.
    fn withdraws_from(&self, account: &PrincipalId) -> bool;
}

/// Whose doing a change to an account's ways in was.
///
/// The record of the change names the account only when someone else made
/// it. The holder is the record's actor already, while an admin who removed
/// Ann's passkey is not the account that lost it: a receiver reading the
/// actor would end the admin's sessions and leave Ann's open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangedBy<A> {
    /// The account's own holder, from their own sign-in.
    Holder,
    /// Someone else acting on the account, such as an admin: the account.
    SomeoneElse(A),
}

impl<A: Copy + Into<PrincipalId>> ChangedBy<A> {
    /// Whose doing a change `keeper` makes to `account` is.
    pub fn of<S: SecurityScope>(keeper: &impl AccountKeeper<S>, account: A) -> Self {
        if keeper.is_holder_of(&account.into()) {
            return Self::Holder;
        }
        Self::SomeoneElse(account)
    }
}

impl<T: TenantScope, C: AccountControlCheck> AccountKeeper<T> for C {
    fn ensure_may(&self, account: &PrincipalId, action: AccountAction) -> Result<(), DomainError> {
        self.ensure_allowed(&UserId::from_uuid(*account.as_uuid()), action)
    }

    fn is_holder_of(&self, _account: &PrincipalId) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::sessions::sign_in_progress::finished_sign_in_of;
    use crate::domains::authorization::granter::{AccountControl, Handout};
    use crate::domains::authorization::permission::{SystemPermission, UserAction};
    use crate::domains::authorization::stewardship::Stewardship;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::authority::anyone_holding;

    fn admin_holding(
        rights: &'static [SystemPermission],
        account: UserId,
    ) -> AccountControl<'static> {
        AccountControl::assumed(
            anyone_holding(rights),
            account,
            Stewardship::OthersAdminister,
            Handout::NOTHING,
        )
    }

    fn keeps<K: AccountKeeper<ResolvedTenant>>(
        keeper: &K,
        account: UserId,
        action: AccountAction,
    ) -> Result<(), DomainError> {
        keeper.ensure_may(&account.into(), action)
    }

    /// Ann, signed in, forgets one of her own devices. It is allowed.
    #[test]
    fn the_holder_keeps_their_own_ways_in() {
        let ann = UserId::new();

        let allowed = keeps(
            &finished_sign_in_of::<ResolvedTenant>(ann.into()),
            ann,
            AccountAction::ChangeSignIn,
        );

        assert!(allowed.is_ok());
    }

    /// A signed-in person cannot obtain authority to change another account's sign-in.
    #[test]
    fn someone_else_signed_in_keeps_nothing_of_anothers() {
        let ann = UserId::new();
        let mallory = finished_sign_in_of::<ResolvedTenant>(UserId::new().into());

        let refused = keeps(&mallory, ann, AccountAction::ChangeSignIn);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Viewing users does not authorize shutting them out; deactivation authority does.
    #[test]
    fn ending_someones_sessions_needs_the_right_to_shut_them_out() {
        static VIEWER: [SystemPermission; 1] = [SystemPermission::Users(UserAction::View)];
        static DEACTIVATOR: [SystemPermission; 1] =
            [SystemPermission::Users(UserAction::Deactivate)];
        let ann = UserId::new();

        let by_sam = keeps(&admin_holding(&VIEWER, ann), ann, AccountAction::ShutOut);
        let by_fay = keeps(
            &admin_holding(&DEACTIVATOR, ann),
            ann,
            AccountAction::ShutOut,
        );

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(by_fay.is_ok());
    }
}
