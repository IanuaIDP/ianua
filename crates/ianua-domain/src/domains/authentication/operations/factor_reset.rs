//! A tenant admin clearing every second factor of a user's account at once:
//! the enrollment in force and every passkey, for someone who lost their
//! device and their recovery codes.
//!
//! Without it, such a user is locked out for good. The account keeps its
//! password, and its next sign-in sets up a new factor if the tenant asks for
//! one. The clearing touches several records, none of which is the reset
//! itself, so a [`FactorReset`] stands for it and raises its record.

use std::marker::PhantomData;

use crate::domains::authentication::credentials::passkey::PasskeyCredential;
use crate::domains::authentication::events::credential::FactorsReset;
use crate::domains::authentication::mfa::enrollment::MfaEnrollment;
use crate::domains::identity::account::control::{AccountAction, AccountControlCheck};
use crate::domains::identity::account::user::User;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::types::{EventLabel, PrincipalId};

/// The enrollment an account has, as a reset finds it.
pub enum EnrollmentHeld<'a, T: TenantScope> {
    /// The account's enrollment, in force, pending or already off.
    Enrolled(&'a mut MfaEnrollment<T>),
    /// The account never set a factor up.
    NoneSetUp,
}

/// Every second factor one account holds, loaded for a reset.
pub struct HeldByAccount<'a, T: TenantScope> {
    /// The account's enrollment.
    pub enrollment: EnrollmentHeld<'a, T>,
    /// The account's passkeys. The caller deletes each once the reset is
    /// made.
    pub passkeys: &'a mut [PasskeyCredential<T>],
}

/// An admin's reset of one account's second factors, with its record.
#[derive(Debug)]
pub struct FactorReset<T: TenantScope> {
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> FactorReset<T> {
    /// Turns off `account`'s enrollment in force and removes every one of
    /// its passkeys, as `control` decides.
    ///
    /// Whoever clears a factor can sign in in its place. Sam may edit users.
    /// Without the check, he clears the factors of Ann, an admin, and signs
    /// in as her with a password he set. So `control` must hold all the
    /// account holds, as for any change of how it signs in. Everything is
    /// checked before anything changes, so a refused reset leaves every
    /// factor as it was. A setup never confirmed stays as it is: it is not
    /// in force, and starting again gives it up.
    ///
    /// Raises `authentication.factors_reset` naming the account, with how
    /// many factors were cleared. The enrollment raises
    /// `authentication.mfa_unenrolled` and each passkey
    /// `authentication.passkey_removed` as well.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `control` refuses changing how
    ///   `account` signs in: it was made for another account, the admin
    ///   lacks the right to update users, or the account holds more than
    ///   the admin.
    /// - [`DomainError::Forbidden`] when the enrollment or a passkey is
    ///   another account's.
    pub fn by_admin(
        account: &User<T>,
        held: HeldByAccount<'_, T>,
        control: &impl AccountControlCheck,
    ) -> Result<Self, DomainError> {
        control.ensure_allowed(account.id(), AccountAction::ChangeSignIn)?;
        ensure_all_held_by(account, &held)?;
        let HeldByAccount {
            enrollment,
            passkeys,
        } = held;
        let factors_reset = turn_off_in_force(enrollment, control)?;
        for passkey in passkeys.iter_mut() {
            passkey.remove(control)?;
        }
        let mut reset = Self {
            raised: Raised::default(),
            _scope: PhantomData,
        };
        reset.raised.raise(FactorsReset {
            user_id: *account.id(),
            user_label: EventLabel::of(account.email().as_str()),
            enrollments_turned_off: factors_reset,
            passkeys_removed: passkeys.len(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(reset)
    }
}

impl<T: TenantScope> Raises for FactorReset<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// Refuses a reset whose enrollment or passkeys belong to another account
/// than `account`.
fn ensure_all_held_by<T: TenantScope>(
    account: &User<T>,
    held: &HeldByAccount<'_, T>,
) -> Result<(), DomainError> {
    let owner = PrincipalId::from(*account.id());
    let enrollment_is_theirs = match &held.enrollment {
        EnrollmentHeld::Enrolled(enrollment) => enrollment.subject_id() == owner,
        EnrollmentHeld::NoneSetUp => true,
    };
    let passkeys_are_theirs = held
        .passkeys
        .iter()
        .all(|passkey| passkey.user_id() == account.id());
    if enrollment_is_theirs && passkeys_are_theirs {
        return Ok(());
    }
    Err(DomainError::forbidden(message!(
        "authentication-a-factor-to-reset-belongs-to",
        "a factor to reset belongs to another account"
    )))
}

/// Turns off the enrollment when it is in force, and says how many were
/// turned off.
fn turn_off_in_force<T: TenantScope>(
    enrollment: EnrollmentHeld<'_, T>,
    control: &impl AccountControlCheck,
) -> Result<usize, DomainError> {
    let EnrollmentHeld::Enrolled(enrollment) = enrollment else {
        return Ok(0);
    };
    if !enrollment.is_active() {
        return Ok(0);
    }
    enrollment.reset_by_admin(control).map_err(|_| {
        DomainError::forbidden(message!(
            "authentication-the-account-holds-more-than-the-2",
            "the account holds more than the person resetting its factors"
        ))
    })?;
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::credentials::passkey::{
        AuthenticatorType, KeyAttestation, RegisterPasskeyParams,
    };
    use crate::domains::authentication::mfa::enrollment::{
        EnrolledFactor, EnrollmentState, MfaEnrollmentRow, RecentFailures,
    };
    use crate::domains::authentication::mfa::enrollment_status::MfaEnrollmentStatus;
    use crate::domains::authentication::sessions::fresh_sign_in::fresh_proof_of;
    use crate::domains::authorization::granter::{AccountControl, Handout};
    use crate::domains::authorization::permission::{RoleAction, SystemPermission, UserAction};
    use crate::domains::authorization::stewardship::Stewardship;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::builders::{label, user};
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{PasskeyCredentialId, SealedSecret, TokenHash, UserId};

    static EDITOR: [SystemPermission; 1] = [SystemPermission::Users(UserAction::Update)];
    static EDITOR_AND_ROLES: [SystemPermission; 2] = [
        SystemPermission::Users(UserAction::Update),
        SystemPermission::Roles(RoleAction::Manage),
    ];

    fn editor_on(
        account: &User<ResolvedTenant>,
        holds: &'static [SystemPermission],
    ) -> AccountControl<'static> {
        AccountControl::assumed(
            anyone_holding(&EDITOR),
            *account.id(),
            Stewardship::OthersAdminister,
            Handout {
                system: holds,
                custom: &[],
            },
        )
    }

    fn factor_in_force(account: &User<ResolvedTenant>) -> MfaEnrollment<ResolvedTenant> {
        let now = crate::shared::clock::now();
        MfaEnrollment::reconstitute(MfaEnrollmentRow {
            subject_id: (*account.id()).into(),
            factor: EnrolledFactor::Totp(SealedSecret::new("sealed").unwrap()),
            state: EnrollmentState::from_stored(
                MfaEnrollmentStatus::Verified,
                Some(now),
                Some(TokenHash::from_stored("codes".to_owned())),
                None,
            )
            .unwrap(),
            failures: RecentFailures::Clear,
            enrolled_at: now,
        })
        .unwrap()
    }

    fn passkey_of(account: &User<ResolvedTenant>, id: u8) -> PasskeyCredential<ResolvedTenant> {
        let params = RegisterPasskeyParams {
            user_id: *account.id(),
            credential_id: PasskeyCredentialId::new(vec![id]).unwrap(),
            public_key: vec![1, 2, 3],
            authenticator_type: AuthenticatorType::Platform,
            attestation: KeyAttestation::Unattested,
            name: label("Laptop"),
        };
        PasskeyCredential::register(params, &fresh_proof_of((*account.id()).into())).unwrap()
    }

    /// Bob lost his phone and his codes. An admin who holds all Bob holds
    /// clears his authenticator and both passkeys, and the reset is
    /// recorded naming Bob with what it cleared.
    #[test]
    fn an_admin_clears_every_factor_of_an_account() {
        let bob = user(UserId::new(), "bob@acme.com");
        let mut factor = factor_in_force(&bob);
        let mut passkeys = [passkey_of(&bob, 1), passkey_of(&bob, 2)];

        let mut reset = FactorReset::by_admin(
            &bob,
            HeldByAccount {
                enrollment: EnrollmentHeld::Enrolled(&mut factor),
                passkeys: &mut passkeys,
            },
            &editor_on(&bob, &EDITOR),
        )
        .unwrap();

        assert!(!factor.is_active());
        let events = raised(&mut reset);
        assert_eq!(
            events[0].event_type().as_str(),
            "authentication.factors_reset"
        );
        assert_eq!(events[0].payload().get("enrollments_turned_off"), Some("1"));
        assert_eq!(events[0].payload().get("passkeys_removed"), Some("2"));
    }

    /// An administrator with fewer rights cannot reset Ann's factor, which remains active.
    #[test]
    fn an_admin_cannot_clear_the_factors_of_someone_who_holds_more() {
        let ann = user(UserId::new(), "ann@acme.com");
        let mut factor = factor_in_force(&ann);

        let refused = FactorReset::by_admin(
            &ann,
            HeldByAccount {
                enrollment: EnrollmentHeld::Enrolled(&mut factor),
                passkeys: &mut [],
            },
            &editor_on(&ann, &EDITOR_AND_ROLES),
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(factor.is_active());
    }

    /// Including another account's passkey refuses Bob's reset, leaves his
    /// factor active, and raises no event on his passkey.
    #[test]
    fn a_reset_touching_another_accounts_passkey_changes_nothing() {
        let bob = user(UserId::new(), "bob@acme.com");
        let ann = user(UserId::new(), "ann@acme.com");
        let mut factor = factor_in_force(&bob);
        let mut passkeys = [passkey_of(&bob, 1), passkey_of(&ann, 2)];
        for passkey in &mut passkeys {
            raised_names(passkey);
        }

        let refused = FactorReset::by_admin(
            &bob,
            HeldByAccount {
                enrollment: EnrollmentHeld::Enrolled(&mut factor),
                passkeys: &mut passkeys,
            },
            &editor_on(&bob, &EDITOR),
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(factor.is_active());
        assert!(raised(&mut passkeys[0]).is_empty());
    }

    /// Carol only ever registered passkeys. The reset removes them and
    /// records that no enrollment was turned off.
    #[test]
    fn an_account_with_only_passkeys_is_reset_too() {
        let carol = user(UserId::new(), "carol@acme.com");
        let mut passkeys = [passkey_of(&carol, 7)];

        let mut reset = FactorReset::by_admin(
            &carol,
            HeldByAccount {
                enrollment: EnrollmentHeld::NoneSetUp,
                passkeys: &mut passkeys,
            },
            &editor_on(&carol, &EDITOR),
        )
        .unwrap();

        let events = raised(&mut reset);
        assert_eq!(events[0].payload().get("enrollments_turned_off"), Some("0"));
        assert_eq!(events[0].payload().get("passkeys_removed"), Some("1"));
    }
}
