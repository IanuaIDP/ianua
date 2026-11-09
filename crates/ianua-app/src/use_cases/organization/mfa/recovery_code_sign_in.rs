//! A member answering their sign-in's second factor with a recovery code,
//! for someone who lost their authenticator.
//!
//! A recovery code stands in for the factor, so it shares the factor's
//! lock: switching between the two buys no extra guesses. Under an
//! organization that asks for more than a password, a recovery code alone
//! leaves the member owing a new factor to set up.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::enrollment::{
    CodeRefused, LockoutPolicy, MfaEnrollment,
};
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::recovery::codes::{RecoveryAttempt, RecoveryCodeSet};
use ianua_domain::domains::authentication::sessions::proved_factor::ProvedFactor;
use ianua_domain::domains::organization::events::access::OrgMfaVerified;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, OrgUserId, TokenHash};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::RecoveryCodeGenerator;
use crate::ports::organization::{
    OrgMfaEnrollmentStore, OrgRecoveryCodeStore, OrgSessionStore, OrgUserStore, OrganizationStore,
};
use crate::services::authentication::sign_in_steps::recovery_refused;
use crate::use_case::Command;
use crate::use_cases::organization::lookup::{
    existing_member, existing_member_recovery_codes, existing_organization,
};
use crate::use_cases::organization::mfa::codes::member_enrollment_in_force;
use crate::use_cases::organization::mfa::raise::{MemberSessionRaise, answer};
use crate::use_cases::organization::mfa::setter::{PendingMemberSession, waiting_session};

/// The ports [`OrgRecoveryCodeSignInUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OrgRecoveryCodeSignInPorts {
    /// The sign-in the code is given for.
    pub sessions: Arc<dyn OrgSessionStore>,
    /// The organization, for its step-up policy.
    pub organizations: Arc<dyn OrganizationStore>,
    /// The member signing in, as they stand now.
    pub members: Arc<dyn OrgUserStore>,
    /// The second factor whose lock recovery codes share.
    pub enrollment_store: Arc<dyn OrgMfaEnrollmentStore>,
    /// The member's recovery codes.
    pub recovery_store: Arc<dyn OrgRecoveryCodeStore>,
    /// Hashes a typed code the way the codes are stored.
    pub recovery_generator: Arc<dyn RecoveryCodeGenerator>,
}

/// A recovery code offered in place of a member's second factor. The code
/// is a secret, so this has no `Debug`.
pub struct OrgRecoveryCodeSignInRequest {
    /// The recovery code as typed.
    pub raw_code: Secret,
}

/// Answers a member's sign-in second factor with a recovery code.
pub struct OrgRecoveryCodeSignInUseCase {
    lockout: LockoutPolicy,
    ports: OrgRecoveryCodeSignInPorts,
}

/// A recovery code spent on the member's codes, with its hash, the factor
/// it stood in for and the proof it gives, before any is stored.
struct Redeemed {
    codes: RecoveryCodeSet<ResolvedOrganization>,
    hash: TokenHash,
    factor: MfaEnrollment<ResolvedOrganization>,
    proof: ProvedFactor,
}

impl OrgRecoveryCodeSignInUseCase {
    /// A use case working through `ports`, locking the factor under
    /// `lockout`.
    #[must_use]
    pub fn new(lockout: LockoutPolicy, ports: OrgRecoveryCodeSignInPorts) -> Self {
        Self { lockout, ports }
    }

    /// The member's codes with the typed one spent, not yet stored: the
    /// code stays unspent unless the sign-in takes it. A refused code is
    /// saved with the factor, so a wrong one counts towards its lock.
    async fn redeemed(&self, member: &OrgUserId, raw_code: &Secret) -> Result<Redeemed, AppError> {
        let store = self.ports.enrollment_store.as_ref();
        let mut factor = member_enrollment_in_force(store, member).await?;
        let mut codes =
            existing_member_recovery_codes(self.ports.recovery_store.as_ref(), member).await?;
        let hash = self.ports.recovery_generator.hash_raw(raw_code);
        let redeemed = codes.redeem(RecoveryAttempt {
            hash: &hash,
            factor: &mut factor,
            lockout: self.lockout,
        });
        match redeemed {
            Ok(proof) => Ok(Redeemed {
                codes,
                hash,
                factor,
                proof,
            }),
            Err(refused) => {
                self.save_factor(member, &factor).await?;
                Err(recovery_refused(refused))
            }
        }
    }

    /// Stores the code `hash` of `codes` as used, unless another sign-in
    /// spent it first, which refuses this one as if the code were wrong.
    async fn spend(
        &self,
        member: &OrgUserId,
        codes: &RecoveryCodeSet<ResolvedOrganization>,
        hash: &TokenHash,
    ) -> Result<(), AppError> {
        let spent = self
            .ports
            .recovery_store
            .spend(member, codes, hash)
            .await
            .or_internal()?;
        if !spent {
            return Err(recovery_refused(CodeRefused::Wrong));
        }
        Ok(())
    }

    /// Saves the factor the code stood in for, its lock as it now stands.
    async fn save_factor(
        &self,
        member: &OrgUserId,
        factor: &MfaEnrollment<ResolvedOrganization>,
    ) -> Result<(), AppError> {
        self.ports
            .enrollment_store
            .save(member, factor)
            .await
            .or_internal()
    }

    /// Where the raised sign-in is saved.
    fn raise(&self) -> MemberSessionRaise<'_> {
        MemberSessionRaise {
            sessions: self.ports.sessions.as_ref(),
        }
    }
}

impl Command for OrgRecoveryCodeSignInUseCase {
    type Caller = PendingMemberSession;
    type Input = OrgRecoveryCodeSignInRequest;
    type Output = Result<SecondFactor, AppError>;

    /// Spends `request.raw_code`, records it on the member's sign-in as the
    /// domain allows, and records `organization.org_mfa_verified`. Answers
    /// what the sign-in still owes: [`SecondFactor::Enrol`] when the member
    /// must set up a new factor before they are let in. Of two sign-ins
    /// offering one code at once, only one gets through.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` for an empty/oversized code; `NotFound` for an unknown/foreign sign-in, missing member/organization, or no active factor/recovery codes.
    /// - `AppError::Forbidden` for a foreign/spent code, concurrent spend or sign-in that cannot accept it.
    /// - `AppError::Conflict` for an already proved factor; `AccountLocked` after wrong codes; `Internal` on storage failure.
    async fn execute(
        &self,
        pending: &PendingMemberSession,
        auditor: &RequestAuditor,
        request: OrgRecoveryCodeSignInRequest,
    ) -> Result<SecondFactor, AppError> {
        crate::input::validate_token("recovery_code", request.raw_code.expose())?;
        let mut session = waiting_session(self.ports.sessions.as_ref(), pending).await?;
        let organization_id = *session.organization_id();
        let organization =
            existing_organization(self.ports.organizations.as_ref(), &organization_id).await?;
        let members = self.ports.members.as_ref();
        let member = existing_member(members, &organization_id, &pending.member).await?;
        let Redeemed {
            codes,
            hash,
            factor,
            proof,
        } = self.redeemed(&pending.member, &request.raw_code).await?;
        let policy = organization.auth_config().step_up_policy();
        answer(&mut session, &member, proof, policy)?;
        self.spend(&pending.member, &codes, &hash).await?;
        self.raise().keep(&session).await?;
        self.save_factor(&pending.member, &factor).await?;
        auditor
            .dispatch_by(
                &ActorRef::OrgUser(pending.member),
                vec![OrgMfaVerified::observed(&session)],
            )
            .await
            .or_internal()?;
        Ok(session.owed())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::authentication::sessions::mfa_factor::FactorProved;
    use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;
    use ianua_domain::domains::organization::access::session::{
        OrgSession, OrgSessionRow, SessionPlace,
    };
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{CredentialChange, Fact, OrganizationId, SessionId, TenantId};

    use super::*;
    use crate::test_support::authentication::{FakeMfaEnrollmentStore, lockout};
    use crate::test_support::organization::{
        FakeOrgRecoveryCodeStore, RecordingOrgSessionStore, org_store_with, org_user_store_with,
        test_org, test_org_user,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    /// Olivia, a member of Acme halfway through a sign-in, with her
    /// authenticator and recovery codes as the test sets them.
    struct Setup {
        pending: PendingMemberSession,
        codes: Arc<FakeOrgRecoveryCodeStore>,
        enrollments: Arc<FakeMfaEnrollmentStore>,
        audit: Arc<FakeEventDispatcher>,
        use_case: OrgRecoveryCodeSignInUseCase,
    }

    impl Setup {
        /// Olivia holding the codes `hashes` and, when `enrolled` says
        /// so, an authenticator in force.
        fn with(hashes: &[&str], enrolled: Enrolled) -> Self {
            let organization_id = OrganizationId::new();
            let olivia = test_org_user(organization_id, "olivia@acme.test", OrgRole::Member);
            let member = *olivia.id();
            let session = waiting_for_her_factor(&olivia);
            let pending = PendingMemberSession {
                session_id: *session.id(),
                member,
            };
            let codes = Arc::new(FakeOrgRecoveryCodeStore::with_codes(member, hashes));
            let enrollments = Arc::new(enrolled.store_for(member));
            let use_case = OrgRecoveryCodeSignInUseCase::new(
                lockout(),
                OrgRecoveryCodeSignInPorts {
                    sessions: Arc::new(RecordingOrgSessionStore::holding([session])),
                    organizations: org_store_with([test_org(organization_id, "acme")]),
                    members: Arc::new(org_user_store_with([olivia])),
                    enrollment_store: enrollments.clone(),
                    recovery_store: codes.clone(),
                    ..OrgRecoveryCodeSignInPorts::fakes()
                },
            );
            Self {
                pending,
                codes,
                enrollments,
                audit: Arc::new(FakeEventDispatcher::new()),
                use_case,
            }
        }

        /// Offers `code` for the waiting sign-in named by `pending`.
        fn offer_for(
            &self,
            pending: &PendingMemberSession,
            code: &str,
        ) -> Result<SecondFactor, AppError> {
            block_on(self.use_case.execute(
                pending,
                &test_auditor(self.audit.clone()),
                OrgRecoveryCodeSignInRequest {
                    raw_code: Secret::new(code.to_owned()),
                },
            ))
        }

        /// Offers `code` for Olivia's waiting sign-in.
        fn offer(&self, code: &str) -> Result<SecondFactor, AppError> {
            self.offer_for(&self.pending, code)
        }

        /// What the audit trail recorded.
        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// A password sign-in of `member` waiting for the factor they hold.
    fn waiting_for_her_factor(member: &OrgUser) -> OrgSession {
        let now = clock::now();
        OrgSession::reconstitute(OrgSessionRow {
            id: SessionId::new(),
            org_user_id: *member.id(),
            organization_id: *member.organization_id(),
            place: SessionPlace::Tenant(TenantId::new()),
            refresh_token_hash: TokenHash::from_stored("refresh".to_owned()),
            progress: SignInProgressRow {
                method: AuthMethod::Password,
                factor: FactorProved::NoneYet,
                owed: SecondFactor::Verify,
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

    /// Whether Olivia's authenticator is in force.
    #[derive(Clone, Copy)]
    enum Enrolled {
        /// The test member has a confirmed authenticator available.
        InForce,
        /// She never set one up.
        Nothing,
    }

    impl Enrolled {
        /// Stores the member's confirmed factor when the setup requires one.
        fn store_for(self, member: OrgUserId) -> FakeMfaEnrollmentStore {
            match self {
                Self::InForce => FakeMfaEnrollmentStore::active_for(member),
                Self::Nothing => FakeMfaEnrollmentStore::empty(),
            }
        }
    }

    /// Olivia lost her phone and types one of her recovery codes. The code
    /// is spent, her sign-in no longer waits for the factor, and the answer
    /// is recorded.
    #[test]
    fn a_recovery_code_answers_the_sign_in_and_is_spent() {
        let setup = Setup::with(&["hash_1", "hash_2"], Enrolled::InForce);

        let owed = setup.offer("code_1").unwrap();

        assert_ne!(owed, SecondFactor::Verify);
        assert_eq!(setup.codes.remaining(&setup.pending.member), 1);
        assert_eq!(setup.recorded(), vec!["organization.org_mfa_verified"]);
    }

    /// Replaying a spent recovery code is forbidden and produces no
    /// additional verification record.
    #[test]
    fn a_spent_code_is_refused() {
        let setup = Setup::with(&["hash_1", "hash_2"], Enrolled::InForce);
        setup.offer("code_1").unwrap();
        let replay = Setup {
            audit: Arc::new(FakeEventDispatcher::new()),
            ..setup
        };

        let result = replay.offer("code_1");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(replay.recorded().is_empty());
    }

    /// A wrong recovery code increments the factor's failed attempts while
    /// preserving the unused code and producing no audit record.
    #[test]
    fn a_wrong_code_is_refused_and_counted() {
        let setup = Setup::with(&["hash_1"], Enrolled::InForce);

        let result = setup.offer("code_9");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.codes.remaining(&setup.pending.member), 1);
        let factor = setup
            .enrollments
            .enrollment_of(setup.pending.member)
            .unwrap();
        assert_eq!(factor.failed_attempts(), 1);
        assert!(setup.recorded().is_empty());
    }

    /// Olivia never set up an authenticator, so no recovery code stands in
    /// for one. It is not found.
    #[test]
    fn without_a_factor_in_force_there_is_nothing_to_recover() {
        let setup = Setup::with(&["hash_1"], Enrolled::Nothing);

        let result = setup.offer("code_1");

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(setup.codes.remaining(&setup.pending.member), 1);
    }

    /// An unknown sign-in is not found, leaving the offered recovery code unspent.
    #[test]
    fn an_unknown_sign_in_is_not_found() {
        let setup = Setup::with(&["hash_1"], Enrolled::InForce);
        let elsewhere = PendingMemberSession {
            session_id: SessionId::new(),
            member: setup.pending.member,
        };

        let result = setup.offer_for(&elsewhere, "code_1");

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(setup.codes.remaining(&setup.pending.member), 1);
    }
}
