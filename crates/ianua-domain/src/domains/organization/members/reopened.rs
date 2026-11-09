//! A closed member account opened again for a new invitation, and what it
//! loses with that.

use crate::domains::authentication::keeper::FactorWithdrawal;
use crate::domains::identity::sealed::Sealed;
use crate::domains::organization::events::invitations::OrgUserReopened;
use crate::domains::organization::members::org_user::OrgUser;
use crate::isolation::organization::scope::ResolvedOrganization;
use crate::shared::events::event::DomainEvent;
use crate::types::{Email, OrgUserId, OrganizationId, PrincipalId};

/// Proof that a closed member account was opened again for a new
/// invitation, just now.
///
/// The account passes to whoever answers the invitation, who may not be the
/// person who held it. Only
/// [`OrgUser::reopen_for_invitation`](crate::domains::organization::members::org_user::OrgUser::reopen_for_invitation)
/// makes it, and it takes away the ways in that account held and no
/// other's: its second factor and its passkeys.
#[derive(Debug)]
pub struct ReopenedAccount {
    account: OrgUserId,
    organization_id: OrganizationId,
    email: Email,
}

/// What a reopened account lost, as the caller counted while taking it
/// away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Withdrawn {
    /// How many tenants it reached.
    pub tenants: usize,
    /// How many second factors and passkeys it held.
    pub factors: usize,
}

impl ReopenedAccount {
    /// The proof for `member`, reopened just now.
    pub(in crate::domains::organization::members) fn of(member: &OrgUser) -> Self {
        Self {
            account: *member.id(),
            organization_id: *member.organization_id(),
            email: member.email().clone(),
        }
    }

    /// The record of the reopening, once what the account held is taken
    /// away: `organization.org_user_reopened`, naming the address invited
    /// again and how much the account lost.
    #[must_use]
    pub fn recorded(&self, withdrawn: Withdrawn) -> DomainEvent {
        DomainEvent::organization(Box::new(OrgUserReopened {
            organization_id: self.organization_id,
            org_user_id: self.account,
            email: self.email.clone(),
            tenants_withdrawn: withdrawn.tenants,
            factors_withdrawn: withdrawn.factors,
            occurred_at: crate::shared::clock::now(),
        }))
    }
}

impl Sealed for ReopenedAccount {}

impl FactorWithdrawal<ResolvedOrganization> for ReopenedAccount {
    fn withdraws_from(&self, account: &PrincipalId) -> bool {
        PrincipalId::from(self.account) == *account
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::credentials::passkey::{
        AuthenticatorType, KeyAttestation, PasskeyCredential, RegisterPasskeyParams,
    };
    use crate::domains::authentication::mfa::enrollment::{
        EnrolledFactor, EnrollmentState, MfaEnrollment, MfaEnrollmentError, MfaEnrollmentRow,
        RecentFailures, app_setup_of,
    };
    use crate::domains::authentication::mfa::enrollment_status::MfaEnrollmentStatus;
    use crate::domains::authentication::sessions::fresh_sign_in::fresh_proof_of;
    use crate::shared::errors::DomainError;
    use crate::test_support::builders::label;
    use crate::types::{PasskeyCredentialId, SealedSecret, TokenHash};

    /// The proof that `member`'s account was reopened just now.
    fn reopened(member: OrgUserId) -> ReopenedAccount {
        ReopenedAccount {
            account: member,
            organization_id: OrganizationId::new(),
            email: Email::new("bob@acme.com").unwrap(),
        }
    }

    /// Bob's account is reopened after he lost one tenant and his
    /// authenticator app. The record names his address and both counts.
    #[test]
    fn the_record_of_a_reopening_counts_what_was_withdrawn() {
        let bob = OrgUserId::new();

        let event = reopened(bob).recorded(Withdrawn {
            tenants: 1,
            factors: 1,
        });

        let payload = event.payload();
        assert_eq!(
            event.event_type().to_string(),
            "organization.org_user_reopened"
        );
        assert_eq!(payload.get("email"), Some("bob@acme.com"));
        assert_eq!(payload.get("tenants_withdrawn"), Some("1"));
        assert_eq!(payload.get("factors_withdrawn"), Some("1"));
    }

    /// `member`'s authenticator app, in force.
    fn factor_of(member: OrgUserId) -> MfaEnrollment<ResolvedOrganization> {
        let now = crate::shared::clock::now();
        MfaEnrollment::reconstitute(MfaEnrollmentRow {
            subject_id: member.into(),
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

    /// `member`'s authenticator app, set up and never confirmed.
    fn setup_of(member: OrgUserId) -> MfaEnrollment<ResolvedOrganization> {
        app_setup_of(member.into())
    }

    /// `member`'s security key.
    fn passkey_of(member: OrgUserId) -> PasskeyCredential<ResolvedOrganization> {
        let params = RegisterPasskeyParams {
            user_id: member,
            credential_id: PasskeyCredentialId::new(vec![1, 2, 3, 4]).unwrap(),
            public_key: vec![5, 6, 7, 8],
            authenticator_type: AuthenticatorType::CrossPlatform,
            attestation: KeyAttestation::Unattested,
            name: label("YubiKey 5"),
        };
        PasskeyCredential::register(params, &fresh_proof_of(member.into())).unwrap()
    }

    /// Bob's account is reopened for a new invitation to his address. His
    /// authenticator app is off, so whoever accepts is never asked for it
    /// and his recovery codes stand in for nothing.
    #[test]
    fn a_reopening_turns_off_the_accounts_second_factor() {
        let bob = OrgUserId::new();
        let mut factor = factor_of(bob);

        factor.withdraw(&reopened(bob)).unwrap();

        assert!(!factor.is_active());
        assert_eq!(factor.status(), MfaEnrollmentStatus::Disabled);
    }

    /// Bob started setting up an authenticator app and never confirmed it.
    /// Reopening his account gives the setup up, so his app never confirms
    /// it later.
    #[test]
    fn a_reopening_gives_up_a_setup_never_confirmed() {
        let bob = OrgUserId::new();
        let mut setup = setup_of(bob);

        setup.withdraw(&reopened(bob)).unwrap();

        assert!(!setup.is_pending());
    }

    /// Bob's factor was already turned off. Reopening leaves it as it is.
    #[test]
    fn a_factor_already_off_stays_off() {
        let bob = OrgUserId::new();
        let mut factor = factor_of(bob);
        factor.withdraw(&reopened(bob)).unwrap();
        let off_at = factor.disabled_at();

        factor.withdraw(&reopened(bob)).unwrap();

        assert_eq!(factor.disabled_at(), off_at);
    }

    /// Proof of Bob's reopening cannot withdraw Ann's authenticator or
    /// authorize removal of her passkey; her authenticator stays active.
    #[test]
    fn a_reopening_takes_nothing_from_another_account() {
        let (bob, ann) = (OrgUserId::new(), OrgUserId::new());
        let reopened = reopened(bob);
        let mut anns_factor = factor_of(ann);

        let factor = anns_factor.withdraw(&reopened);
        let passkey = passkey_of(ann).ensure_withdrawn_by(&reopened);

        assert_eq!(factor, Err(MfaEnrollmentError::NotThisAccount));
        assert!(anns_factor.is_active());
        assert!(matches!(passkey, Err(DomainError::Forbidden(_))));
    }

    /// Bob's security key goes with his reopened account.
    #[test]
    fn a_reopening_lets_the_accounts_passkeys_go() {
        let bob = OrgUserId::new();

        let removable = passkey_of(bob).ensure_withdrawn_by(&reopened(bob));

        assert!(removable.is_ok());
    }
}
