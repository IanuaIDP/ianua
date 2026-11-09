//! A member confirming a newly scanned authenticator with a code from it:
//! the factor comes into force, a fresh set of recovery codes is shown
//! once, and a sign-in that waited for the factor is let in.
//!
//! A new factor is a change of how the member signs in, so it ends every
//! session opened before it. The session the member set it up from is kept
//! through it, proved by the code that confirmed the factor.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::enrollment::{
    AnsweredCode, LockoutPolicy, MfaEnrollment,
};
use ianua_domain::domains::authentication::recovery::codes::RecoveryCodeSet;
use ianua_domain::domains::authentication::risk_engine::step_up::StepUpPolicy;
use ianua_domain::domains::authentication::sessions::proved_factor::ProvedFactor;
use ianua_domain::domains::organization::access::session::OrgSession;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, TokenHash};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::RecoveryCodeGenerator;
use crate::ports::organization::OrgRecoveryCodeStore;
use crate::use_case::Command;
use crate::use_cases::organization::mfa::codes::{MemberCodePorts, member_enrollment_waiting};
use crate::use_cases::organization::mfa::raise::{MemberSessionRaise, answer};
use crate::use_cases::organization::mfa::setter::{
    MemberFactorSetter, MemberSetterPorts, SettingFrom, refused_member_setup,
};

/// How many recovery codes a confirmed factor comes with, and a new set
/// replaces it with.
pub(in crate::use_cases::organization::mfa) const MEMBER_RECOVERY_CODES: u8 = 10;

/// The ports [`OrgConfirmUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OrgConfirmPorts {
    /// The member's second factor, and what checks its codes.
    pub codes: MemberCodePorts,
    /// Makes the recovery codes.
    pub recovery_generator: Arc<dyn RecoveryCodeGenerator>,
    /// Keeps the members' recovery codes.
    pub recovery_store: Arc<dyn OrgRecoveryCodeStore>,
    /// Who confirms the factor, and the sign-in waiting for it.
    pub setters: MemberSetterPorts,
}

/// A code from a newly scanned authenticator.
pub struct OrgConfirmRequest {
    /// The code it shows.
    pub code: String,
}

/// The recovery codes a confirmed factor comes with, shown once and never
/// kept. They are secrets, so this has no `Debug`.
pub struct OrgEnrollmentConfirmed {
    /// Raw fallback secrets shown only when enrollment is confirmed.
    pub recovery_codes: Vec<Secret>,
}

/// The session a member confirms a factor from.
enum ConfirmedFrom {
    /// Their own finished session, kept through the change.
    OwnSession(Box<OrgSession>),
    /// A sign-in waiting for this factor, let in by it.
    WaitingSignIn(Box<OrgSession>),
}

impl ConfirmedFrom {
    /// The session, finished or waiting.
    fn session(&self) -> &OrgSession {
        match self {
            Self::OwnSession(session) | Self::WaitingSignIn(session) => session,
        }
    }

    /// Carries this session through the change `member` just made, on the
    /// `code` that confirmed the new factor: a finished session is kept
    /// through it, a waiting sign-in is let in by it under `policy`.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the code was proved for another member,
    ///   the session is not a finished one of the member, or the waiting
    ///   sign-in does not take the factor.
    /// - `AppError::Conflict` when the waiting sign-in already proved a
    ///   factor at least as strong.
    fn carry_through(
        &mut self,
        member: &OrgUser,
        policy: &StepUpPolicy,
        code: &AnsweredCode,
    ) -> Result<(), AppError> {
        let proof = ProvedFactor::by_code(code);
        match self {
            Self::OwnSession(session) => session
                .keep_through_own_factor_addition(member, proof)
                .map_err(AppError::from_domain),
            Self::WaitingSignIn(session) => answer(session, member, proof, policy),
        }
    }
}

/// Confirms a member's newly scanned authenticator.
pub struct OrgConfirmUseCase {
    lockout: LockoutPolicy,
    ports: OrgConfirmPorts,
}

impl OrgConfirmUseCase {
    /// A use case working through `ports`, locking the factor under
    /// `lockout`.
    #[must_use]
    pub fn new(lockout: LockoutPolicy, ports: OrgConfirmPorts) -> Self {
        Self { lockout, ports }
    }

    /// Puts `enrollment` in force on `answered`, with a fresh set of
    /// recovery codes, and hands back the codes to show once.
    async fn put_in_force(
        &self,
        enrollment: &mut MfaEnrollment<ResolvedOrganization>,
        answered: &AnsweredCode,
    ) -> Result<(RecoveryCodeSet<ResolvedOrganization>, Vec<Secret>), AppError> {
        let pairs = self
            .ports
            .recovery_generator
            .generate_batch(MEMBER_RECOVERY_CODES)
            .await
            .or_internal()?;
        let (shown, hashes): (Vec<Secret>, Vec<TokenHash>) =
            pairs.into_iter().map(|pair| (pair.raw, pair.hash)).unzip();
        let digest = recovery_codes_digest(&hashes);
        let codes = RecoveryCodeSet::generate(enrollment.subject_id(), hashes, answered)
            .map_err(AppError::from_domain)?;
        enrollment
            .verify(answered, digest)
            .map_err(|refused| refused_member_setup(&refused))?;
        Ok((codes, shown))
    }

    /// Saves the confirmed factor, its recovery codes and the member whose
    /// way of signing in changed.
    async fn keep(
        &self,
        member: &OrgUser,
        enrollment: &MfaEnrollment<ResolvedOrganization>,
        codes: &RecoveryCodeSet<ResolvedOrganization>,
    ) -> Result<(), AppError> {
        self.ports
            .codes
            .enrollment_store
            .save(member.id(), enrollment)
            .await
            .or_internal()?;
        self.ports
            .recovery_store
            .save(member.id(), codes)
            .await
            .or_internal()?;
        self.ports.setters.members.save(member).await.or_internal()
    }

    /// The session `setter` confirms the factor from: the waiting sign-in
    /// already found, or a signed-in member's own session, loaded before
    /// the change would end it.
    async fn confirmed_from(
        &self,
        setter: &MemberFactorSetter,
        from: SettingFrom,
    ) -> Result<ConfirmedFrom, AppError> {
        match (from, setter) {
            (SettingFrom::WaitingSignIn(session), _) => Ok(ConfirmedFrom::WaitingSignIn(session)),
            (SettingFrom::SignedIn(_), MemberFactorSetter::SignedIn(caller)) => {
                let session = self.ports.setters.own_session(caller).await?;
                Ok(ConfirmedFrom::OwnSession(Box::new(session)))
            }
            (SettingFrom::SignedIn(_), MemberFactorSetter::SigningIn(_)) => {
                Err(AppError::Unauthenticated)
            }
        }
    }

    /// Saves the session the factor was set up from, carried through it.
    async fn keep_session(&self, from: &ConfirmedFrom) -> Result<(), AppError> {
        MemberSessionRaise {
            sessions: self.ports.setters.sessions.as_ref(),
        }
        .keep(from.session())
        .await
    }
}

impl Command for OrgConfirmUseCase {
    type Caller = MemberFactorSetter;
    type Input = OrgConfirmRequest;
    type Output = Result<OrgEnrollmentConfirmed, AppError>;

    /// Confirms `setter`'s pending authenticator with `request.code`, and
    /// records `organization.org_mfa_enrolled`. A sign-in waiting for this
    /// factor is let in by the same code.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` for an empty/oversized code; `Unauthenticated` for an invalid session or key-based caller.
    /// - `AppError::Forbidden` when the originating session cannot survive setup or accept the code, or the code is wrong/spent.
    /// - `AppError::NotFound` for no pending enrollment or another member's waiting sign-in.
    /// - `AppError::AccountLocked` after too many wrong codes; `Internal` on decryption or storage failure.
    async fn execute(
        &self,
        setter: &MemberFactorSetter,
        auditor: &RequestAuditor,
        request: OrgConfirmRequest,
    ) -> Result<OrgEnrollmentConfirmed, AppError> {
        crate::input::validate_short_code("totp_code", &request.code)?;
        let mut found = self.ports.setters.setter(setter).await?;
        let mut from = self.confirmed_from(setter, found.from).await?;
        let member_id = *found.member.id();
        let store = self.ports.codes.enrollment_store.as_ref();
        let mut enrollment = member_enrollment_waiting(store, &member_id).await?;
        let answered = self
            .ports
            .codes
            .checked(self.lockout, *found.member.organization_id())
            .answered(&member_id, &mut enrollment, &request.code)
            .await?;
        let (codes, recovery_codes) = self.put_in_force(&mut enrollment, &answered).await?;
        found.member.record_mfa_enrolled();
        let policy = found.organization.auth_config().step_up_policy();
        from.carry_through(&found.member, policy, &answered)?;
        self.keep(&found.member, &enrollment, &codes).await?;
        self.keep_session(&from).await?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(member_id), found.member.take_events())
            .await
            .or_internal()?;
        Ok(OrgEnrollmentConfirmed { recovery_codes })
    }
}

/// The one hash standing for the whole set of recovery codes shown, kept
/// on the confirmed factor.
fn recovery_codes_digest(hashes: &[TokenHash]) -> TokenHash {
    let each = hashes.iter().map(TokenHash::as_str).collect::<Vec<_>>();
    TokenHash::from_stored(each.join(","))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authentication::sessions::mfa_factor::FactorProved;
    use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;
    use ianua_domain::domains::organization::access::session::{OrgSessionRow, SessionPlace};
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{CredentialChange, Fact, OrgUserId, SessionId, TenantId};

    use super::*;
    use crate::ports::organization::{OrgSessionStore, OrgUserStore};
    use crate::test_support::acting::{FakeOrgActors, Refusal, caller_session};
    use crate::test_support::authentication::{FakeMfaEnrollmentStore, lockout};
    use crate::test_support::organization::{
        FakeOrgRecoveryCodeStore, FakeOrgUserStore, RecordingOrgSessionStore, org_store_with,
        stored_caller, test_org,
    };
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_org_caller, test_session_id,
    };
    use crate::use_cases::organization::mfa::setter::PendingMemberSession;

    const RIGHT_CODE: &str = "123456";

    struct Setup {
        enrollments: Arc<FakeMfaEnrollmentStore>,
        codes: Arc<FakeOrgRecoveryCodeStore>,
        members: Arc<FakeOrgUserStore>,
        sessions: Arc<RecordingOrgSessionStore>,
        audit: Arc<FakeEventDispatcher>,
        use_case: OrgConfirmUseCase,
    }

    impl Setup {
        fn with(enrollments: FakeMfaEnrollmentStore, actors: FakeOrgActors) -> Self {
            let enrollments = Arc::new(enrollments);
            let codes = Arc::new(FakeOrgRecoveryCodeStore::new());
            let members = Arc::new(FakeOrgUserStore::empty());
            let olivia = stored_caller(OrgRole::Member, "pw");
            block_on(members.save(&olivia)).unwrap();
            let sessions = Arc::new(RecordingOrgSessionStore::holding([caller_session(&olivia)]));
            let use_case = OrgConfirmUseCase::new(
                lockout(),
                OrgConfirmPorts {
                    codes: MemberCodePorts {
                        enrollment_store: enrollments.clone(),
                        ..MemberCodePorts::fakes()
                    },
                    recovery_store: codes.clone(),
                    setters: setters(actors, members.clone(), sessions.clone()),
                    ..OrgConfirmPorts::fakes()
                },
            );
            Self {
                enrollments,
                codes,
                members,
                sessions,
                audit: Arc::new(FakeEventDispatcher::new()),
                use_case,
            }
        }

        fn pending() -> Self {
            Self::with(
                FakeMfaEnrollmentStore::pending_for(*test_org_caller().member()),
                FakeOrgActors::in_role(OrgRole::Member),
            )
        }

        fn confirm_as(
            &self,
            setter: &MemberFactorSetter,
            code: &str,
        ) -> Result<OrgEnrollmentConfirmed, AppError> {
            block_on(self.use_case.execute(
                setter,
                &test_auditor(self.audit.clone()),
                OrgConfirmRequest {
                    code: code.to_owned(),
                },
            ))
        }

        fn confirm(&self, code: &str) -> Result<OrgEnrollmentConfirmed, AppError> {
            self.confirm_as(&MemberFactorSetter::SignedIn(test_org_caller()), code)
        }

        fn is_active(&self) -> bool {
            self.enrollments
                .enrollment_of(*test_org_caller().member())
                .is_some_and(|enrollment| enrollment.is_active())
        }

        fn sign_in_waiting(&self, member: OrgUserId) -> SessionId {
            let session = waiting_session_of(member);
            let id = *session.id();
            block_on(self.sessions.save(&session)).unwrap();
            id
        }

        fn stored_session(&self, id: SessionId) -> OrgSession {
            block_on(self.sessions.find_by_id(&id)).unwrap().unwrap()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Resolves factor setup against the stored member, their session and Acme.
    fn setters(
        actors: FakeOrgActors,
        members: Arc<FakeOrgUserStore>,
        sessions: Arc<RecordingOrgSessionStore>,
    ) -> MemberSetterPorts {
        let caller = test_org_caller();
        MemberSetterPorts {
            org_actors: Arc::new(actors),
            members,
            organizations: org_store_with([test_org(caller.organization_id(), "acme")]),
            sessions,
            ..MemberSetterPorts::fakes()
        }
    }

    /// A fresh password sign-in of `member` in Acme, waiting for them to set
    /// up the factor the organization requires.
    fn waiting_session_of(member: OrgUserId) -> OrgSession {
        let now = clock::now();
        OrgSession::reconstitute(OrgSessionRow {
            id: SessionId::new(),
            org_user_id: member,
            organization_id: test_org_caller().organization_id(),
            place: SessionPlace::Tenant(TenantId::new()),
            refresh_token_hash: TokenHash::from_stored("refresh".to_owned()),
            progress: SignInProgressRow {
                method: AuthMethod::Password,
                factor: FactorProved::NoneYet,
                owed: SecondFactor::Enrol,
            },
            ip_address: Fact::Unknown,
            user_agent: Fact::Unknown,
            status: SessionStatus::Active,
            created_at: now,
            last_active_at: now,
            expires_at: now + time::Duration::hours(8),
            kept_through: CredentialChange::Never,
        })
        .unwrap()
    }

    /// A finished sign-in of `member` half an hour ago, on another device.
    fn signed_in_earlier(member: OrgUserId) -> OrgSession {
        let now = clock::now();
        let earlier = now - time::Duration::minutes(30);
        OrgSession::reconstitute(OrgSessionRow {
            id: SessionId::new(),
            org_user_id: member,
            organization_id: test_org_caller().organization_id(),
            place: SessionPlace::Tenant(TenantId::new()),
            refresh_token_hash: TokenHash::from_stored("phone".to_owned()),
            progress: SignInProgressRow {
                method: AuthMethod::Password,
                factor: FactorProved::NoneYet,
                owed: SecondFactor::NotOwed,
            },
            ip_address: Fact::Unknown,
            user_agent: Fact::Unknown,
            status: SessionStatus::Active,
            created_at: earlier,
            last_active_at: now,
            expires_at: now + time::Duration::hours(8),
            kept_through: CredentialChange::Never,
        })
        .unwrap()
    }

    fn signing_in(session_id: SessionId, member: OrgUserId) -> MemberFactorSetter {
        MemberFactorSetter::SigningIn(PendingMemberSession { session_id, member })
    }

    /// Olivia, a member, confirms her new authenticator with its code. It
    /// comes into force, she is shown ten recovery codes, the codes are
    /// kept, and the enrollment is recorded.
    #[test]
    fn confirm_activates_enrollment_and_returns_codes() {
        let setup = Setup::pending();

        let confirmed = setup.confirm(RIGHT_CODE).unwrap();

        assert!(setup.is_active());
        assert_eq!(confirmed.recovery_codes.len(), 10);
        assert!(setup.codes.holds_codes(test_org_caller().member()));
        assert_eq!(setup.recorded(), vec!["organization.org_mfa_enrolled"]);
    }

    /// Olivia confirms her new authenticator. Her way of signing in
    /// changed, so devices she remembered before stop counting.
    #[test]
    fn confirming_records_a_credential_change() {
        let setup = Setup::pending();

        setup.confirm(RIGHT_CODE).unwrap();

        let olivia = block_on(setup.members.find_by_id(test_org_caller().member()))
            .unwrap()
            .unwrap();
        assert!(matches!(
            olivia.credentials_changed_at(),
            CredentialChange::At { .. }
        ));
    }

    /// Olivia, signed in on her laptop, sets up an authenticator app and
    /// confirms it with its code. Her laptop session keeps counting; the
    /// session on her phone, opened before the change, no longer does.
    #[test]
    fn the_session_the_factor_was_set_up_from_is_kept_and_earlier_ones_end() {
        let setup = Setup::pending();
        let olivia = *test_org_caller().member();

        setup.confirm(RIGHT_CODE).unwrap();

        let member = block_on(setup.members.find_by_id(&olivia))
            .unwrap()
            .unwrap();
        let laptop = setup.stored_session(test_session_id());
        assert_eq!(laptop.kept_through(), member.credentials_changed_at());
        assert!(laptop.counts_for(&member));
        assert!(!signed_in_earlier(olivia).counts_for(&member));
    }

    /// A wrong enrollment code is forbidden and does not mark the session
    /// as preserved through a credential change.
    #[test]
    fn a_guessed_code_keeps_no_session() {
        let setup = Setup::pending();

        let result = setup.confirm("000000");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        let laptop = setup.stored_session(test_session_id());
        assert_eq!(laptop.kept_through(), CredentialChange::Never);
    }

    /// Olivia's sign-in waits for her to set up the factor her organization
    /// requires. Confirming it with its code lets that sign-in in.
    #[test]
    fn confirming_a_first_factor_completes_the_sign_in_that_waited_for_it() {
        let setup = Setup::pending();
        let olivia = *test_org_caller().member();
        let session_id = setup.sign_in_waiting(olivia);

        setup
            .confirm_as(&signing_in(session_id, olivia), RIGHT_CODE)
            .unwrap();

        assert!(setup.stored_session(session_id).mfa_satisfied());
    }

    /// Setting up her first factor changes how Olivia signs in, which ends
    /// sessions from before it. The sign-in the factor finished is kept
    /// through that change, so it counts the moment it is let in.
    #[test]
    fn the_sign_in_a_first_factor_finished_is_kept_through_the_change() {
        let setup = Setup::pending();
        let olivia = *test_org_caller().member();
        let session_id = setup.sign_in_waiting(olivia);

        setup
            .confirm_as(&signing_in(session_id, olivia), RIGHT_CODE)
            .unwrap();

        let member = block_on(setup.members.find_by_id(&olivia))
            .unwrap()
            .unwrap();
        let session = setup.stored_session(session_id);
        assert_eq!(session.kept_through(), member.credentials_changed_at());
        assert!(session.counts_for(&member));
    }

    /// A waiting sign-in named under another member is not found, and the
    /// pending authenticator is not activated.
    #[test]
    fn a_first_factor_cannot_complete_someone_elses_sign_in() {
        let setup = Setup::pending();
        let session_id = setup.sign_in_waiting(*test_org_caller().member());

        let result = setup.confirm_as(&signing_in(session_id, OrgUserId::new()), RIGHT_CODE);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(!setup.is_active());
    }

    /// A wrong confirmation code is forbidden, increments failed attempts
    /// and leaves the authenticator inactive.
    #[test]
    fn confirm_wrong_code_returns_forbidden_and_persists_attempt() {
        let setup = Setup::pending();

        let result = setup.confirm("000000");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.enrollments.failed_attempts(), 1);
        assert!(!setup.is_active());
    }

    /// Olivia sends a code with nothing waiting to be confirmed. It is not
    /// found.
    #[test]
    fn confirm_no_pending_returns_not_found() {
        let setup = Setup::with(
            FakeMfaEnrollmentStore::empty(),
            FakeOrgActors::in_role(OrgRole::Member),
        );

        let result = setup.confirm(RIGHT_CODE);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Olivia's authenticator is already in force. There is nothing to
    /// confirm.
    #[test]
    fn confirm_already_active_returns_not_found() {
        let setup = Setup::with(
            FakeMfaEnrollmentStore::active_for(*test_org_caller().member()),
            FakeOrgActors::in_role(OrgRole::Member),
        );

        let result = setup.confirm(RIGHT_CODE);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Five wrong confirmation codes trigger lockout, which rejects a
    /// subsequent correct code.
    #[test]
    fn confirm_locks_after_max_attempts() {
        let setup = Setup::pending();
        for _ in 0..5 {
            let _ = setup.confirm("000000");
        }

        let result = setup.confirm(RIGHT_CODE);

        assert!(matches!(result, Err(AppError::AccountLocked(_))));
    }

    /// Olivia mistypes four times, one short of the lock, then types the
    /// right code. It is accepted.
    #[test]
    fn confirm_allows_just_under_max_attempts() {
        let setup = Setup::pending();
        for _ in 0..4 {
            let _ = setup.confirm("000000");
        }

        let result = setup.confirm(RIGHT_CODE);

        assert!(result.is_ok());
    }

    /// A signed-out session cannot confirm enrollment, and the factor
    /// remains inactive.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::with(
            FakeMfaEnrollmentStore::pending_for(*test_org_caller().member()),
            FakeOrgActors::refusing(Refusal::SignedOut),
        );

        let result = setup.confirm(RIGHT_CODE);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(!setup.is_active());
    }

    /// An API key cannot authorize authenticator confirmation.
    #[test]
    fn a_key_caller_is_refused() {
        let setup = Setup::with(
            FakeMfaEnrollmentStore::pending_for(*test_org_caller().member()),
            FakeOrgActors::through_key(OrgRole::Member, Vec::new()),
        );

        let result = setup.confirm(RIGHT_CODE);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
