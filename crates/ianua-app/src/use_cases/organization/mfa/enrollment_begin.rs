//! A member starting to set up an authenticator app: a new secret, shown
//! once as the QR the app scans, kept as a pending enrollment until a code
//! confirms it.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::enrollment::{
    EnrolledFactor, MfaEnrollment, MfaMethod,
};
use ianua_domain::domains::authentication::mfa::offer::FactorOffer;
use ianua_domain::domains::authentication::mfa::verifier::{MfaVerifier, TotpSeed};
use ianua_domain::domains::authentication::sessions::mfa_factor::{FactorProved, MfaFactor};
use ianua_domain::domains::organization::events::access::OrgMfaEnrollmentStarted as EnrollmentStartedEvent;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::types::{ActorRef, Label, OtpauthUrl, PrincipalId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::organization::OrgMfaEnrollmentStore;
use crate::services::authentication::refused::already_enrolled;
use crate::services::authentication::sign_in_steps::SeedHolder;
use crate::use_case::Command;
use crate::use_cases::authentication::mfa::SetupProof;
use crate::use_cases::organization::mfa::setter::{
    MemberFactorSetter, MemberLeave, MemberSetterPorts, Setter, SettingFrom,
    begun_member_enrollment, give_up_member_enrollment,
};

/// What a member scans to set up their authenticator app.
pub struct OrgMfaEnrollmentStarted {
    /// The `otpauth://` URI for the QR code. It carries the secret.
    pub otpauth_uri: OtpauthUrl,
}

/// The ports [`OrgBeginUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OrgBeginPorts {
    /// Where members' enrollments are kept.
    pub enrollment_store: Arc<dyn OrgMfaEnrollmentStore>,
    /// Seals and opens the secret.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Makes the secret and the QR's URI.
    pub verifier: Arc<dyn MfaVerifier>,
    /// Who sets up the factor, and what lets them.
    pub setters: MemberSetterPorts,
}

/// Starts setting up a member's authenticator app.
pub struct OrgBeginUseCase {
    issuer: Label,
    ports: OrgBeginPorts,
}

impl OrgBeginUseCase {
    /// A use case working through `ports`, listing members in the
    /// authenticator under `issuer`.
    #[must_use]
    pub fn new(issuer: Label, ports: OrgBeginPorts) -> Self {
        Self { issuer, ports }
    }

    /// Gives up `enrollment`, a setup waiting to be confirmed, on `leave`,
    /// so a new secret replaces it.
    async fn give_up(
        &self,
        member: &OrgUser,
        mut enrollment: MfaEnrollment<ResolvedOrganization>,
        leave: &MemberLeave,
    ) -> Result<(), AppError> {
        give_up_member_enrollment(&mut enrollment, leave)?;
        self.ports
            .enrollment_store
            .save(member.id(), &enrollment)
            .await
            .or_internal()
    }

    /// A new secret for `member`, kept as their pending enrollment begun on
    /// `leave`, with its start recorded through `auditor`.
    async fn recorded_fresh(
        &self,
        auditor: &RequestAuditor,
        member: &OrgUser,
        offer: &FactorOffer,
        leave: &MemberLeave,
    ) -> Result<OrgMfaEnrollmentStarted, AppError> {
        let started = self.fresh(member, offer, leave).await?;
        auditor
            .dispatch_by(
                &ActorRef::OrgUser(*member.id()),
                vec![EnrollmentStartedEvent::observed(member)],
            )
            .await
            .or_internal()?;
        Ok(started)
    }

    /// A new secret, kept as the member's pending enrollment begun on
    /// `leave` under the organization's `offer`.
    async fn fresh(
        &self,
        member: &OrgUser,
        offer: &FactorOffer,
        leave: &MemberLeave,
    ) -> Result<OrgMfaEnrollmentStarted, AppError> {
        let seed = self.ports.verifier.generate_secret().or_internal()?;
        let place =
            SeedHolder::Member(*member.organization_id()).place(PrincipalId::from(*member.id()));
        let sealed = self
            .ports
            .encryptor
            .encrypt(seed.expose(), &place)
            .await
            .or_internal()?;
        let factor = EnrolledFactor::Totp(sealed);
        let enrollment = begun_member_enrollment(member.id(), factor, offer, leave)?;
        self.ports
            .enrollment_store
            .save(member.id(), &enrollment)
            .await
            .or_internal()?;
        self.scannable(&seed, member)
    }

    /// The `otpauth://` URI an authenticator scans for `seed`, listing the
    /// member under the issuer and their address.
    fn scannable(
        &self,
        seed: &TotpSeed,
        member: &OrgUser,
    ) -> Result<OrgMfaEnrollmentStarted, AppError> {
        let raw = self.ports.verifier.build_otpauth_uri(
            seed,
            self.issuer.as_str(),
            member.email().as_str(),
        );
        let otpauth_uri = OtpauthUrl::new(raw.expose()).or_internal()?;
        Ok(OrgMfaEnrollmentStarted { otpauth_uri })
    }
}

impl Command for OrgBeginUseCase {
    type Caller = MemberFactorSetter;
    type Input = SetupProof;
    type Output = Result<OrgMfaEnrollmentStarted, AppError>;

    /// Starts setting up `setter`'s authenticator app on `proof`, and
    /// records `organization.org_mfa_enrollment_started`.
    ///
    /// An enrollment already waiting to be confirmed is given up and a new
    /// secret replaces it, so a setup's secret is only ever shown once.
    /// Owen starts setting up his authenticator. Mallory, holding his
    /// password, signs in and is asked to set one up too. Without this, she
    /// is handed Owen's secret and reads his codes from then on. Starting
    /// again records the new start, and the member scans the new QR.
    /// A sign-in that spent a recovery code and still owes enrollment may
    /// replace the lost factor. Its enrollment proof must remain fresh;
    /// ordinary password sign-ins cannot replace an active authenticator.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid session or key-based caller; `Forbidden` for disabled/unoffered authenticators or inadequate setup proof.
    /// - `AppError::StepUpRequired` for a missing held-factor code; `NotFound` for a missing member, organization or waiting session.
    /// - `AppError::Conflict` for an active authenticator outside waiting-sign-in recovery.
    /// - `AppError::Internal` on secret generation, sealing or storage failure.
    async fn execute(
        &self,
        setter: &MemberFactorSetter,
        auditor: &RequestAuditor,
        proof: SetupProof,
    ) -> Result<OrgMfaEnrollmentStarted, AppError> {
        let found = self.ports.setters.setter(setter).await?;
        let offer = found
            .organization
            .auth_config()
            .offer_factor(MfaMethod::Totp)
            .map_err(AppError::from_domain)?;
        let leave = self.ports.setters.leave(&found, proof).await?;
        let held = self
            .ports
            .enrollment_store
            .find_by_user(found.member.id())
            .await
            .or_internal()?;
        match held {
            Some(enrollment) if enrollment.is_active() && !recovering(&found) => {
                Err(already_enrolled())
            }
            Some(enrollment) if enrollment.is_pending() => {
                self.give_up(&found.member, enrollment, &leave).await?;
                self.recorded_fresh(auditor, &found.member, &offer, &leave)
                    .await
            }
            _ => {
                self.recorded_fresh(auditor, &found.member, &offer, &leave)
                    .await
            }
        }
    }
}

/// Whether the setter's waiting session already spent a recovery code.
/// The caller obtains its fresh enrollment leave before using this to
/// replace an active factor, so a password-only or completed session cannot
/// turn the active-factor conflict into permission to replace it.
fn recovering(setter: &Setter) -> bool {
    matches!(&setter.from, SettingFrom::WaitingSignIn(session)
        if session.mfa_method() == FactorProved::Proved(MfaFactor::RecoveryCode))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::test_support::fakes::FakeMfaVerifier;
    use ianua_domain::types::{OrganizationId, SealedSecret, TenantId};

    use super::*;
    use crate::context::{OrgCaller, OrgCredential};
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::authentication::{
        FakeEncryptor, FakeMfaEnrollmentStore, Holder, enrolled_secret, right_password, seed_place,
        wrong_password,
    };
    use crate::test_support::organization::{
        RecordingOrgSessionStore, org_session_for, org_store_with, org_user_store_with, test_org,
        test_org_user,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_session_id};
    use crate::use_cases::organization::mfa::setter::PendingMemberSession;

    struct Setup {
        olivia: OrgCaller,
        enrollments: Arc<FakeMfaEnrollmentStore>,
        audit: Arc<FakeEventDispatcher>,
        use_case: OrgBeginUseCase,
    }

    impl Setup {
        fn with(
            enrollments: impl FnOnce(&OrgCaller) -> FakeMfaEnrollmentStore,
            actors: FakeOrgActors,
        ) -> Self {
            let organization_id = OrganizationId::new();
            let member = test_org_user(organization_id, "olivia@acme.test", OrgRole::Member);
            let olivia = OrgCaller::new(
                *member.id(),
                OrgCredential::Session(test_session_id()),
                organization_id,
            );
            let enrollments = Arc::new(enrollments(&olivia));
            let use_case = OrgBeginUseCase::new(
                Label::new("issuer", "Ianua").unwrap(),
                OrgBeginPorts {
                    enrollment_store: enrollments.clone(),
                    setters: MemberSetterPorts {
                        org_actors: Arc::new(actors),
                        members: Arc::new(org_user_store_with([member])),
                        ..MemberSetterPorts::fakes()
                    },
                    ..OrgBeginPorts::fakes()
                },
            );
            Self {
                olivia,
                enrollments,
                audit: Arc::new(FakeEventDispatcher::new()),
                use_case,
            }
        }

        fn new() -> Self {
            Self::with(
                |_| FakeMfaEnrollmentStore::empty(),
                FakeOrgActors::in_role(OrgRole::Member),
            )
        }

        fn begin(&self, proof: SetupProof) -> Result<OrgMfaEnrollmentStarted, AppError> {
            block_on(self.use_case.execute(
                &MemberFactorSetter::SignedIn(self.olivia.clone()),
                &test_auditor(self.audit.clone()),
                proof,
            ))
        }

        /// Starts from a stored waiting sign-in, using only the enrollment
        /// authority its proved factor and remaining obligation supply.
        fn begin_waiting(
            &mut self,
            progress: SignInProgressRow,
        ) -> Result<OrgMfaEnrollmentStarted, AppError> {
            let organization = self.olivia.organization_id();
            let session = org_session_for(
                *self.olivia.member(),
                organization,
                TenantId::new(),
                progress,
            );
            let pending = PendingMemberSession {
                session_id: *session.id(),
                member: *self.olivia.member(),
            };
            self.use_case.ports.setters.sessions =
                Arc::new(RecordingOrgSessionStore::holding([session]));
            self.use_case.ports.setters.organizations =
                org_store_with([test_org(organization, "acme")]);
            block_on(self.use_case.execute(
                &MemberFactorSetter::SigningIn(pending),
                &test_auditor(self.audit.clone()),
                SetupProof::OwedBySignIn,
            ))
        }

        fn sealed_secret(&self) -> Option<SealedSecret> {
            self.enrollments
                .enrollment_of(*self.olivia.member())
                .and_then(|enrollment| enrollment.factor().sealed_secret().cloned())
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Olivia's authenticator, kept for her own organization.
    fn olivias(olivia: &OrgCaller) -> Holder {
        Holder::member_of(olivia.organization_id(), *olivia.member())
    }

    /// The secret begin makes for Olivia is sealed for her own
    /// authenticator in her own organization, the place every check of her
    /// codes opens it from.
    #[test]
    fn the_secret_is_sealed_for_the_members_authenticator() {
        let setup = Setup::with(
            |_| FakeMfaEnrollmentStore::empty(),
            FakeOrgActors::in_role(OrgRole::Member),
        );

        setup.begin(reentered()).unwrap();

        let seed = FakeMfaVerifier {
            valid_code: "123456".to_owned(),
        }
        .generate_secret()
        .unwrap();
        assert_eq!(
            setup.sealed_secret(),
            Some(FakeEncryptor::sealed_for(
                seed.expose(),
                &seed_place(olivias(&setup.olivia))
            ))
        );
    }

    fn reentered() -> SetupProof {
        SetupProof::Reentered(right_password())
    }

    /// Olivia, a member, types her password again and starts setting up
    /// her authenticator. She gets a QR, a pending enrollment is kept, and
    /// the start is recorded.
    #[test]
    fn begin_creates_pending_enrollment_and_returns_uri() {
        let setup = Setup::new();

        let started = setup.begin(reentered()).unwrap();

        assert!(started.otpauth_uri.as_str().starts_with("otpauth://"));
        let enrollment = setup
            .enrollments
            .enrollment_of(*setup.olivia.member())
            .unwrap();
        assert!(enrollment.is_pending());
        assert_eq!(
            setup.recorded(),
            vec!["organization.org_mfa_enrollment_started"]
        );
    }

    /// Restarting a pending enrollment replaces its stored secret and
    /// records a new enrollment start.
    #[test]
    fn begin_replaces_the_secret_of_a_pending_enrollment() {
        let setup = Setup::with(
            |olivia| FakeMfaEnrollmentStore::pending_for(olivias(olivia)),
            FakeOrgActors::in_role(OrgRole::Member),
        );

        setup.begin(reentered()).unwrap();

        assert_ne!(
            setup.sealed_secret(),
            Some(enrolled_secret(olivias(&setup.olivia)))
        );
        assert_eq!(
            setup.recorded(),
            vec!["organization.org_mfa_enrollment_started"]
        );
    }

    /// Olivia already has an authenticator in force. Starting another is
    /// a conflict.
    #[test]
    fn begin_rejects_if_already_active() {
        let setup = Setup::with(
            |olivia| FakeMfaEnrollmentStore::active_for(*olivia.member()),
            FakeOrgActors::in_role(OrgRole::Member),
        );

        let result = setup.begin(reentered());

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// A member who spent a recovery code still owes enrollment under the
    /// organization's stronger baseline. The lost factor is replaced by a
    /// pending secret, so recovery can proceed to confirmation.
    #[test]
    fn a_recovery_sign_in_can_replace_the_lost_active_factor() {
        let mut setup = Setup::with(
            |olivia| FakeMfaEnrollmentStore::active_for(*olivia.member()),
            FakeOrgActors::in_role(OrgRole::Member),
        );
        setup
            .begin_waiting(SignInProgressRow {
                method: AuthMethod::Password,
                factor: FactorProved::Proved(MfaFactor::RecoveryCode),
                owed: SecondFactor::Enrol,
            })
            .unwrap();
        assert!(
            setup
                .enrollments
                .enrollment_of(*setup.olivia.member())
                .unwrap()
                .is_pending()
        );
        assert_eq!(
            setup.recorded(),
            ["organization.org_mfa_enrollment_started"]
        );
    }

    /// A password sign-in still owing factor verification cannot replace
    /// that factor; it stays active and no enrollment start is recorded.
    #[test]
    fn a_password_sign_in_cannot_replace_the_factor_it_owes() {
        let mut setup = Setup::with(
            |olivia| FakeMfaEnrollmentStore::active_for(*olivia.member()),
            FakeOrgActors::in_role(OrgRole::Member),
        );
        let result = setup.begin_waiting(SignInProgressRow {
            method: AuthMethod::Password,
            factor: FactorProved::NoneYet,
            owed: SecondFactor::Verify,
        });
        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(
            setup
                .enrollments
                .enrollment_of(*setup.olivia.member())
                .unwrap()
                .is_active()
        );
        assert!(setup.recorded().is_empty());
    }

    /// A wrong password cannot authorize enrollment, and no secret is stored.
    #[test]
    fn a_wrong_password_is_refused() {
        let setup = Setup::new();

        let result = setup.begin(SetupProof::Reentered(wrong_password()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.sealed_secret().is_none());
    }

    /// A signed-in member cannot use pending-sign-in authority to start enrollment.
    #[test]
    fn a_signed_in_member_cannot_claim_a_waiting_sign_in() {
        let setup = Setup::new();

        let result = setup.begin(SetupProof::OwedBySignIn);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot start authenticator enrollment.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::with(
            |_| FakeMfaEnrollmentStore::empty(),
            FakeOrgActors::refusing(Refusal::SignedOut),
        );

        let result = setup.begin(reentered());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Starting enrollment propagates the organization actor's forbidden response.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let setup = Setup::with(
            |_| FakeMfaEnrollmentStore::empty(),
            FakeOrgActors::refusing(Refusal::Forbidden),
        );

        let result = setup.begin(reentered());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An API key cannot authorize authenticator enrollment in place of a session.
    #[test]
    fn a_key_caller_is_refused() {
        let setup = Setup::with(
            |_| FakeMfaEnrollmentStore::empty(),
            FakeOrgActors::through_key(OrgRole::Member, Vec::new()),
        );

        let result = setup.begin(reentered());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
