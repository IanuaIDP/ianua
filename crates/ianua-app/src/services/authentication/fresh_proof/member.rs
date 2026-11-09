//! Proving a member of an organization again: their password with a code
//! from their second factor, or their passkey.

use ianua_domain::domains::authentication::risk_engine::origin::AttemptOrigin;
use ianua_domain::domains::authentication::sessions::fresh_sign_in::FreshSignIn;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::org_user::{OrgPassword, OrgUser};
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{PasswordHash, PrincipalId};

use crate::error::AppError;
use crate::ports::authentication::CountedAccount;
use crate::services::authentication::account_factor::FactorAnswer;
use crate::services::authentication::fresh_proof::{FreshProofStep, with_factor};
use crate::services::authentication::member_factor::MemberFactor;
use crate::services::authentication::passkey_answer::{MemberPasskeyAnswering, PresentedAssertion};
use crate::services::authentication::sign_in_counts::CountedAt;
use crate::services::authentication::sign_in_steps::CodeCheck;

/// A member's password typed again, with the code they gave.
pub(super) struct MemberPassword<'a> {
    /// The member proving who they are.
    pub(super) member: &'a OrgUser,
    /// Their organization, whose lockout settings count wrong passwords.
    pub(super) organization: &'a Organization,
    /// The password as typed.
    pub(super) password: &'a Secret,
    /// The code their authenticator shows, if they gave one.
    pub(super) code: Option<&'a str>,
    /// Where the password was typed, whose lockout on the account it
    /// counts against.
    pub(super) from: AttemptOrigin,
}

impl FreshProofStep {
    /// The member's password typed again, after their factor answered.
    pub(super) async fn member_by_password(
        &self,
        given: MemberPassword<'_>,
    ) -> Result<FreshSignIn, AppError> {
        let member = given.member;
        let stored = stored_password(member)?;
        let factor = self.member_factor_answer(member, given.code).await?;
        let rate_policy = given
            .organization
            .auth_config()
            .limits()
            .lockout()
            .map_err(AppError::from_domain)?;
        let at = CountedAt {
            account: CountedAccount::Organization {
                organization: member.organization_id(),
                email: member.email(),
            },
            origin: given.from,
            policy: &rate_policy,
        };
        let principal = PrincipalId::from(*member.id());
        self.counted_check(at, given.password, stored, |check| {
            FreshSignIn::by_password(principal, check, with_factor(&factor))
        })
        .await
    }

    /// A member's passkey's answer to a sign-in challenge.
    pub(super) async fn member_by_passkey(
        &self,
        presented: &PresentedAssertion,
    ) -> Result<FreshSignIn, AppError> {
        let answering = MemberPasskeyAnswering {
            passkeys: self.ports.members.member_passkeys.as_ref(),
            ceremonies: self.ports.members.member_ceremonies.as_ref(),
            members: self.ports.members.members.as_ref(),
            verifier: self.ports.passkeys.passkey_verifier.as_ref(),
        };
        let answered = answering.answered(presented).await?;
        FreshSignIn::by_passkey(answered.spent).map_err(AppError::from_domain)
    }

    async fn member_factor_answer(
        &self,
        member: &OrgUser,
        code: Option<&str>,
    ) -> Result<FactorAnswer, AppError> {
        let factor = MemberFactor {
            enrollments: self.ports.members.member_enrollments.as_ref(),
            check: CodeCheck {
                encryptor: self.ports.factors.encryptor.as_ref(),
                verifier: self.ports.factors.verifier.as_ref(),
                lockout: self.lockout,
            },
        };
        factor
            .answer(member.organization_id(), member.id(), code)
            .await
    }
}

/// The member's stored password hash.
///
/// # Errors
///
/// Returns `AppError::Forbidden` when the member has no password.
fn stored_password(member: &OrgUser) -> Result<&PasswordHash, AppError> {
    match member.password_hash() {
        OrgPassword::Set(hash) => Ok(hash),
        OrgPassword::NotSet => Err(AppError::Forbidden(message!(
            "authentication-this-member-has-no-password-prove",
            "this member has no password; prove it is you with your passkey"
        ))),
    }
}

/// The refusal of a mailed link as a member's proof.
pub(super) fn member_mailbox_refused() -> AppError {
    AppError::Forbidden(message!(
        "authentication-a-member-proves-who-they-are",
        "a member proves who they are with their password or passkey, not a mailed link"
    ))
}

/// The refusal of a directory bind as a member's proof: members never bind
/// to a tenant's directory.
pub(super) fn member_bind_refused() -> AppError {
    AppError::Forbidden(message!(
        "authentication-a-member-proves-who-they-are-2",
        "a member proves who they are with their password or passkey, not a directory bind"
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::domains::authentication::credentials::passkey_ceremony::TargetedPurpose;
    use ianua_domain::domains::organization::access::passkey::OrgPasskeyCeremony;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::test_support::fakes::{FakeHasher, FakeMfaVerifier};
    use ianua_domain::types::{CeremonyId, Fact, Lifetime, OrganizationId};

    use super::*;
    use crate::ports::authentication::CountedAccount;
    use crate::ports::organization::{OrgPasskeyCeremonyStore, OrgUserStore};
    use crate::services::authentication::fresh_proof::{
        FactorProof, FreshProofPorts, FreshProofs, MemberProof, PasskeyProof, PasswordProof,
        ReenteredProof,
    };
    use crate::services::authentication::sign_in_counts::SignInCounts;
    use crate::test_support::authentication::{
        FakeEncryptor, FakeMfaEnrollmentStore, FakePasskeyVerifier, FakeSignInAttemptCounts,
        Holder, PASSKEY_CEREMONY_STATE, hashing_with, lockout, passkey_credential_id,
    };
    use crate::test_support::organization::{
        FakeOrgPasskeyCeremonyStore, FakeOrgPasskeyStore, FakeOrgUserStore, test_org,
        test_org_owner,
    };
    use crate::test_support::{Fake, block_on};

    const PASSWORD: &str = "correct horse battery staple";
    const RIGHT_CODE: &str = "123456";

    /// `olivia`'s authenticator, kept for her own organization.
    fn member(olivia: &OrgUser) -> Holder {
        Holder::member_of(*olivia.organization_id(), *olivia.id())
    }

    struct Fixture {
        olivia: OrgUser,
        acme: Organization,
        attempts: Arc<FakeSignInAttemptCounts>,
        ceremonies: Arc<FakeOrgPasskeyCeremonyStore>,
        step: FreshProofStep,
    }

    impl Fixture {
        /// Builds a member proof fixture with the chosen enrolled factors.
        fn with(enrollments: impl FnOnce(&OrgUser) -> FakeMfaEnrollmentStore) -> Self {
            let organization_id = OrganizationId::new();
            let olivia = test_org_owner(organization_id, "olivia@acme.test", PASSWORD);
            let attempts = Arc::new(FakeSignInAttemptCounts::default());
            let ceremonies = Arc::new(FakeOrgPasskeyCeremonyStore::new());
            let ports = FreshProofPorts {
                password: PasswordProof {
                    hashing: hashing_with(Arc::new(FakeHasher)),
                    attempts: SignInCounts::new(attempts.clone(), Fake::fake()),
                    ..PasswordProof::fakes()
                },
                factors: member_factors(),
                passkeys: PasskeyProof {
                    passkey_verifier: Arc::new(FakePasskeyVerifier::succeeding()),
                    ..PasskeyProof::fakes()
                },
                members: member_proof(&olivia, enrollments(&olivia), ceremonies.clone()),
                ..FreshProofPorts::fakes()
            };
            Self {
                acme: test_org(organization_id, "acme"),
                olivia,
                attempts,
                ceremonies,
                step: FreshProofStep::new(lockout(), ports),
            }
        }

        fn without_factor() -> Self {
            Self::with(|_| FakeMfaEnrollmentStore::empty())
        }

        fn prove(&self, proof: ReenteredProof) -> Result<FreshSignIn, AppError> {
            block_on(
                self.step
                    .prove_member(&self.olivia, &self.acme, proof, unobserved()),
            )
        }

        fn wrong_passwords(&self) -> u64 {
            self.attempts.on_account(CountedAccount::Organization {
                organization: self.olivia.organization_id(),
                email: self.olivia.email(),
            })
        }

        fn sign_in_challenge(&self) -> CeremonyId {
            let ceremony = OrgPasskeyCeremony::open(
                *self.olivia.id(),
                TargetedPurpose::Authentication,
                PASSKEY_CEREMONY_STATE.to_vec(),
                Lifetime::seconds(300).unwrap(),
            );
            block_on(self.ceremonies.save(&ceremony)).unwrap();
            *ceremony.id()
        }
    }

    /// Opens the stored factor secret and accepts the member's known code.
    fn member_factors() -> FactorProof {
        FactorProof {
            encryptor: Arc::new(FakeEncryptor),
            verifier: Arc::new(FakeMfaVerifier {
                valid_code: RIGHT_CODE.to_owned(),
            }),
            ..FactorProof::fakes()
        }
    }

    /// Stores the member and supplies her factors and passkey ceremonies.
    fn member_proof(
        member: &OrgUser,
        enrollments: FakeMfaEnrollmentStore,
        ceremonies: Arc<FakeOrgPasskeyCeremonyStore>,
    ) -> MemberProof {
        let members = FakeOrgUserStore::empty();
        block_on(members.save(member)).unwrap();
        MemberProof {
            members: Arc::new(members),
            member_enrollments: Arc::new(enrollments),
            member_passkeys: Arc::new(FakeOrgPasskeyStore::with_passkey(
                *member.organization_id(),
                *member.id(),
            )),
            member_ceremonies: ceremonies,
        }
    }

    fn unobserved() -> AttemptOrigin {
        AttemptOrigin::of(Fact::Unknown)
    }

    fn typed(password: &str, code: Option<&str>) -> ReenteredProof {
        ReenteredProof::Password {
            password: Secret::new(password),
            code: code.map(str::to_owned),
        }
    }

    /// Olivia, an owner, types her password again. It proves her.
    #[test]
    fn the_right_password_proves_the_member() {
        let fixture = Fixture::without_factor();

        let fresh = fixture.prove(typed(PASSWORD, None)).unwrap();

        assert_eq!(fresh.account(), PrincipalId::from(*fixture.olivia.id()));
        assert_eq!(fixture.wrong_passwords(), 0);
    }

    /// Re-entering a wrong password for Olivia is forbidden and adds one
    /// failed attempt to her organization's account counter.
    #[test]
    fn a_wrong_password_is_refused_and_counted() {
        let fixture = Fixture::without_factor();

        let result = fixture.prove(typed("guess", None));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.wrong_passwords(), 1);
    }

    /// Ten wrong passwords trigger lockout for Olivia's proof attempts.
    /// The correct password is then refused from the same unknown origin.
    #[test]
    fn a_locked_out_member_is_refused_even_the_right_password() {
        let fixture = Fixture::without_factor();
        for _ in 0..10 {
            let _ = fixture.prove(typed("guess", None));
        }

        let result = fixture.prove(typed(PASSWORD, None));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Olivia has a second factor and types only her password. She is
    /// asked for a code too.
    #[test]
    fn a_member_with_a_factor_must_give_its_code() {
        let fixture = Fixture::with(|olivia| FakeMfaEnrollmentStore::active_for(member(olivia)));

        let result = fixture.prove(typed(PASSWORD, None));

        assert!(matches!(result, Err(AppError::StepUpRequired)));
    }

    /// Olivia types her password and her code. Together they prove her.
    #[test]
    fn the_password_and_the_code_prove_the_member() {
        let fixture = Fixture::with(|olivia| FakeMfaEnrollmentStore::active_for(member(olivia)));

        let result = fixture.prove(typed(PASSWORD, Some(RIGHT_CODE)));

        assert!(result.is_ok());
    }

    /// Olivia's password and factor code prove her once; repeating the
    /// same pair is forbidden.
    #[test]
    fn a_replayed_code_is_refused() {
        let fixture = Fixture::with(|olivia| FakeMfaEnrollmentStore::active_for(member(olivia)));
        fixture.prove(typed(PASSWORD, Some(RIGHT_CODE))).unwrap();

        let replayed = fixture.prove(typed(PASSWORD, Some(RIGHT_CODE)));

        assert!(matches!(replayed, Err(AppError::Forbidden(_))));
    }

    /// The organization proof path rejects a mailed link as forbidden
    /// even when the member has no second factor.
    #[test]
    fn a_mailed_link_is_refused_for_a_member() {
        let fixture = Fixture::without_factor();

        let result = fixture.prove(ReenteredProof::Mailbox {
            link: Secret::new("link"),
            code: None,
        });

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Olivia answers a sign-in challenge with her passkey. It proves her.
    #[test]
    fn a_passkey_answer_proves_the_member() {
        let fixture = Fixture::without_factor();
        let ceremony_id = fixture.sign_in_challenge();

        let fresh = fixture
            .prove(ReenteredProof::Passkey(PresentedAssertion {
                ceremony_id,
                credential_id: passkey_credential_id(),
                response: b"signed".to_vec(),
            }))
            .unwrap();

        assert_eq!(fresh.account(), PrincipalId::from(*fixture.olivia.id()));
    }

    /// A member with no stored password cannot obtain fresh proof by
    /// presenting one; the password attempt is forbidden.
    #[test]
    fn a_member_without_a_password_is_refused_a_password_proof() {
        let organization_id = OrganizationId::new();
        let mallory = crate::test_support::organization::test_org_user(
            organization_id,
            "mallory@acme.test",
            OrgRole::Member,
        );
        let fixture = Fixture::without_factor();

        let result = block_on(fixture.step.prove_member(
            &mallory,
            &test_org(organization_id, "acme"),
            typed(PASSWORD, None),
            unobserved(),
        ));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
