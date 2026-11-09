//! A member acting on another member's account, as identity's account
//! rules ask: resetting their second factor, letting them in or shutting
//! them out. A member's account as an email change checks it is here too.
//!
//! Whoever controls how an account signs in can become it. So the rules are
//! the organization's own for acting on a member: the member right for the
//! action, and only an owner acts on an owner.

use crate::domains::identity::account::control::{AccountAction, AccountControlCheck};
use crate::domains::identity::account::email_change::ChangingAccount;
use crate::domains::identity::sealed::Sealed;
use crate::domains::organization::members::control::OrgControl;
use crate::domains::organization::members::org_user::OrgUser;
use crate::domains::organization::members::org_user_authority::ensure_may_act_on;
use crate::domains::organization::members::permission::{MemberAction, OrgPermission};
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{OrgUserId, OrganizationId, PrincipalId, UserId};

/// A member acting on one other member's account, as they stand now.
///
/// It is made for one account and passes for no other. Sam is a plain
/// member. Without it, he resets the second factor of Ann, an owner, signs
/// in with her password and reaches every tenant.
#[derive(Debug, Clone, Copy)]
pub struct OrgAccountControl<'a> {
    by: OrgControl<'a>,
    target: &'a OrgUser,
}

impl<'a> OrgAccountControl<'a> {
    /// `by` acting on `target`, freshly loaded.
    #[must_use]
    pub fn new(by: OrgControl<'a>, target: &'a OrgUser) -> Self {
        Self { by, target }
    }

    /// Refuses `action` on the member this was made for unless `by` may
    /// take it: never on their own account, which changes only through
    /// steps that prove them, and otherwise with the member right for it,
    /// an owner's account only by an owner.
    fn ensure_may(&self, action: AccountAction) -> Result<(), DomainError> {
        if self.by.is_member(self.target.id()) {
            return Err(DomainError::forbidden(message!(
                "organization-a-member-s-own-account-changes",
                "a member's own account changes only through steps that prove them"
            )));
        }
        ensure_may_act_on(self.target, &self.by, member_right_for(action)?)
    }

    /// Refuses `action` on `member` unless this control was made for that
    /// member and `by` may take it. Reading what is kept about a member,
    /// such as their consent history, is [`AccountAction::Export`]: Ada, an
    /// admin, may view members, yet reads no owner's history.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the control was made for another
    ///   member, or `by` may not take `action` on this one.
    pub fn ensure_on(&self, member: &OrgUserId, action: AccountAction) -> Result<(), DomainError> {
        if member != self.target.id() {
            return Err(DomainError::forbidden(message!(
                "authorization-the-check-was-made-for-another",
                "the check was made for another account"
            )));
        }
        self.ensure_may(action)
    }
}

/// Refuses `by` taking `action` on another member's account in
/// `organization_id` unless they carry the member right it needs, whoever
/// the member is. It is checked before the account is read, so someone
/// without the right is refused the same for a member who exists and one
/// who does not. Whether an owner's account is out of reach is
/// [`OrgAccountControl::ensure_on`]'s to say once it is read.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when `by` does not carry the right, or
///   nobody may take `action`.
pub fn ensure_may_act_on_others(
    by: &OrgControl<'_>,
    organization_id: &OrganizationId,
    action: AccountAction,
) -> Result<(), DomainError> {
    by.ensure_may(
        organization_id,
        OrgPermission::Members(member_right_for(action)?),
    )
}

/// The member right `action` on someone else's account needs. Changing how
/// they sign in, letting them in or shutting them out, recording for them
/// and editing their profile or records need the right to update members;
/// erasing them the right to remove members; reading what is kept about
/// them the right to view members.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] for acting as them, which nobody may.
fn member_right_for(action: AccountAction) -> Result<MemberAction, DomainError> {
    match action {
        AccountAction::ChangeSignIn
        | AccountAction::LetIn
        | AccountAction::ShutOut
        | AccountAction::RecordForThem
        | AccountAction::EditProfile
        | AccountAction::EditRecords => Ok(MemberAction::Update),
        AccountAction::Erase => Ok(MemberAction::Remove),
        AccountAction::Export => Ok(MemberAction::View),
        AccountAction::Impersonate => Err(DomainError::forbidden(message!(
            "organization-nobody-acts-as-a-member-of",
            "nobody acts as a member of the organization"
        ))),
    }
}

impl<'a> From<&'a OrgUser> for ChangingAccount<'a> {
    fn from(user: &'a OrgUser) -> Self {
        Self::of(
            (*user.id()).into(),
            user.email(),
            user.credentials_changed_at(),
        )
    }
}

impl Sealed for OrgAccountControl<'_> {}

impl AccountControlCheck for OrgAccountControl<'_> {
    fn ensure_allowed(&self, account: &UserId, action: AccountAction) -> Result<(), DomainError> {
        if PrincipalId::from_uuid(*account.as_uuid()) != PrincipalId::from(*self.target.id()) {
            return Err(DomainError::forbidden(message!(
                "authorization-the-check-was-made-for-another",
                "the check was made for another account"
            )));
        }
        self.ensure_may(action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::mfa::enrollment::{
        EnrolledFactor, EnrollmentState, MfaEnrollment, MfaEnrollmentError, MfaEnrollmentRow,
        RecentFailures,
    };
    use crate::domains::authentication::mfa::enrollment_status::MfaEnrollmentStatus;
    use crate::domains::organization::members::control::tests::{
        acting, founder, joined_as, member_of, session_of,
    };
    use crate::domains::organization::members::membership::OrgRole;
    use crate::isolation::organization::scope::ResolvedOrganization;
    use crate::types::{SealedSecret, TokenHash};

    /// A second factor in force on `member`'s account.
    fn factor_of(member: &OrgUser) -> MfaEnrollment<ResolvedOrganization> {
        let now = crate::shared::clock::now();
        MfaEnrollment::reconstitute(MfaEnrollmentRow {
            subject_id: (*member.id()).into(),
            factor: EnrolledFactor::Totp(SealedSecret::new("encrypted_xyz").unwrap()),
            state: EnrollmentState::from_stored(
                MfaEnrollmentStatus::Verified,
                Some(now),
                Some(TokenHash::from_stored("recovery_hash".to_owned())),
                None,
            )
            .unwrap(),
            failures: RecentFailures::Clear,
            enrolled_at: now,
        })
        .unwrap()
    }

    /// `member`'s factor, reset by `by` through a control made for `target`.
    fn reset(
        member: &OrgUser,
        by: &OrgUser,
        target: &OrgUser,
    ) -> Result<MfaEnrollment<ResolvedOrganization>, MfaEnrollmentError> {
        let session = session_of(by);
        let control = OrgAccountControl::new(acting(by, &session), target);
        let mut factor = factor_of(member);
        factor.reset_by_admin(&control)?;
        Ok(factor)
    }

    /// Sam lost his phone. Ann, an owner, resets his second factor, and he
    /// sets up a new one at his next sign-in.
    #[test]
    fn an_owner_resets_a_members_second_factor() {
        let ann = founder();
        let sam = member_of(&ann);

        let factor = reset(&sam, &ann, &sam).unwrap();

        assert!(!factor.is_active());
    }

    /// A member cannot reset an owner's second factor through account
    /// control.
    #[test]
    fn a_plain_member_does_not_reset_an_owners_second_factor() {
        let ann = founder();
        let sam = member_of(&ann);

        let refused = reset(&ann, &sam, &ann);

        assert_eq!(refused.err(), Some(MfaEnrollmentError::AccountHoldsMore));
    }

    /// A control naming Sam cannot reset Lou's second factor, even when
    /// exercised by an owner.
    #[test]
    fn a_control_acts_only_on_the_account_it_was_made_for() {
        let ann = founder();
        let (sam, lou) = (member_of(&ann), member_of(&ann));

        let refused = reset(&lou, &ann, &sam);

        assert_eq!(refused.err(), Some(MfaEnrollmentError::AccountHoldsMore));
    }

    /// An owner cannot use administrative account control to reset their
    /// own second factor.
    #[test]
    fn a_member_does_not_reset_their_own_second_factor_this_way() {
        let ann = founder();

        let refused = reset(&ann, &ann, &ann);

        assert_eq!(refused.err(), Some(MfaEnrollmentError::AccountHoldsMore));
    }

    /// Whether `by` may read what is kept about `target`.
    fn reads(by: &OrgUser, target: &OrgUser) -> Result<(), DomainError> {
        let session = session_of(by);
        OrgAccountControl::new(acting(by, &session), target)
            .ensure_on(target.id(), AccountAction::Export)
    }

    /// Ann, an owner, reads Sam's consent history to answer his request.
    #[test]
    fn an_owner_reads_what_is_kept_about_a_member() {
        let ann = founder();
        let sam = member_of(&ann);

        assert!(reads(&ann, &sam).is_ok());
    }

    /// An admin's account control cannot authorize exporting an owner's
    /// records.
    #[test]
    fn an_admin_does_not_read_what_is_kept_about_an_owner() {
        let ann = founder();
        let ada = joined_as(&ann, OrgRole::Admin);

        let refused = reads(&ada, &ann);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }
}
