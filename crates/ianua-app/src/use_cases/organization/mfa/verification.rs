//! A member answering their sign-in's second factor with a code from their
//! authenticator.
//!
//! Called after a sign-in reports that it owes a factor. The domain decides
//! whether the code answers what the sign-in owes, and how far it raises
//! it.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::enrollment::{AnsweredCode, LockoutPolicy};
use ianua_domain::domains::authentication::sessions::proved_factor::ProvedFactor;
use ianua_domain::domains::organization::access::session::OrgSession;
use ianua_domain::domains::organization::events::access::OrgMfaVerified;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::types::ActorRef;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgSessionStore, OrgUserStore, OrganizationStore};
use crate::use_case::Command;
use crate::use_cases::organization::lookup::{existing_member, existing_organization};
use crate::use_cases::organization::mfa::codes::{MemberCodePorts, member_enrollment_in_force};
use crate::use_cases::organization::mfa::raise::MemberSessionRaise;
use crate::use_cases::organization::mfa::setter::{PendingMemberSession, waiting_session};

/// The ports [`OrgVerifyUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OrgVerifyPorts {
    /// The sign-in the code is given for.
    pub sessions: Arc<dyn OrgSessionStore>,
    /// The organization, for its step-up policy.
    pub organizations: Arc<dyn OrganizationStore>,
    /// The member signing in, as they stand now.
    pub members: Arc<dyn OrgUserStore>,
    /// The member's second factor, and what checks its codes.
    pub codes: MemberCodePorts,
}

/// A second-factor code offered for a member's sign-in.
pub struct OrgVerifyRequest {
    /// The code as typed.
    pub code: String,
}

/// Answers a member's sign-in second factor with an authenticator code.
pub struct OrgVerifyUseCase {
    lockout: LockoutPolicy,
    ports: OrgVerifyPorts,
}

impl OrgVerifyUseCase {
    /// A use case working through `ports`, locking the factor under
    /// `lockout`.
    #[must_use]
    pub fn new(lockout: LockoutPolicy, ports: OrgVerifyPorts) -> Self {
        Self { lockout, ports }
    }

    /// Records the code `answered` on `session` for its member as they
    /// stand now, under `organization`'s step-up policy, and saves it.
    async fn raise(
        &self,
        session: &mut OrgSession,
        organization: &Organization,
        answered: &AnsweredCode,
    ) -> Result<(), AppError> {
        let members = self.ports.members.as_ref();
        let member = existing_member(members, organization.id(), session.org_user_id()).await?;
        MemberSessionRaise {
            sessions: self.ports.sessions.as_ref(),
        }
        .raise(
            session,
            &member,
            ProvedFactor::by_code(answered),
            organization.auth_config().step_up_policy(),
        )
        .await
    }
}

impl Command for OrgVerifyUseCase {
    type Caller = PendingMemberSession;
    type Input = OrgVerifyRequest;
    type Output = Result<(), AppError>;

    /// Checks `request.code` against the member's authenticator, records
    /// the factor on their sign-in as the domain allows, and records
    /// `organization.org_mfa_verified`.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` for an empty/oversized code; `NotFound` for an unknown/foreign sign-in, missing member/organization or no active authenticator.
    /// - `AppError::Forbidden` for a wrong/spent code or sign-in that cannot accept it; `Conflict` for an equally strong or stronger factor already proved.
    /// - `AppError::AccountLocked` after wrong codes; `Internal` on storage or decryption failure.
    async fn execute(
        &self,
        pending: &PendingMemberSession,
        auditor: &RequestAuditor,
        request: OrgVerifyRequest,
    ) -> Result<(), AppError> {
        crate::input::validate_short_code("totp_code", &request.code)?;
        let mut session = waiting_session(self.ports.sessions.as_ref(), pending).await?;
        let organization_id = *session.organization_id();
        let organization =
            existing_organization(self.ports.organizations.as_ref(), &organization_id).await?;
        let store = self.ports.codes.enrollment_store.as_ref();
        let mut enrollment = member_enrollment_in_force(store, &pending.member).await?;
        let answered = self
            .ports
            .codes
            .checked(self.lockout, organization_id)
            .answered(&pending.member, &mut enrollment, &request.code)
            .await?;
        self.raise(&mut session, &organization, &answered).await?;
        auditor
            .dispatch_by(
                &ActorRef::OrgUser(pending.member),
                vec![OrgMfaVerified::observed(&session)],
            )
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authentication::sessions::mfa_factor::{FactorProved, MfaFactor};
    use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;
    use ianua_domain::domains::organization::access::session::{OrgSessionRow, SessionPlace};
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{
        CredentialChange, Fact, OrgUserId, OrganizationId, SessionId, TenantId, TokenHash,
    };

    use super::*;
    use crate::test_support::authentication::{FakeMfaEnrollmentStore, Holder, lockout};
    use crate::test_support::organization::{
        RecordingOrgSessionStore, org_store_with, org_user_store_with, test_org, test_org_user,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    const RIGHT_CODE: &str = "123456";

    struct Setup {
        olivia: OrgUserId,
        session_id: SessionId,
        sessions: Arc<RecordingOrgSessionStore>,
        enrollments: Arc<FakeMfaEnrollmentStore>,
        audit: Arc<FakeEventDispatcher>,
        use_case: OrgVerifyUseCase,
    }

    impl Setup {
        fn with(
            owed: SecondFactor,
            enrolled: impl FnOnce(Holder) -> FakeMfaEnrollmentStore,
        ) -> Self {
            let organization_id = OrganizationId::new();
            let member = test_org_user(organization_id, "olivia@acme.test", OrgRole::Member);
            let olivia = *member.id();
            let session = session_owing(olivia, organization_id, owed);
            let session_id = *session.id();
            let sessions = Arc::new(RecordingOrgSessionStore::holding([session]));
            let enrollments = Arc::new(enrolled(Holder::member_of(organization_id, olivia)));
            let use_case = OrgVerifyUseCase::new(
                lockout(),
                OrgVerifyPorts {
                    sessions: sessions.clone(),
                    organizations: org_store_with([test_org(organization_id, "acme")]),
                    members: Arc::new(org_user_store_with([member])),
                    codes: MemberCodePorts {
                        enrollment_store: enrollments.clone(),
                        ..MemberCodePorts::fakes()
                    },
                    ..OrgVerifyPorts::fakes()
                },
            );
            Self {
                olivia,
                session_id,
                sessions,
                enrollments,
                audit: Arc::new(FakeEventDispatcher::new()),
                use_case,
            }
        }

        fn enrolled() -> Self {
            Self::with(SecondFactor::Verify, |olivia| {
                FakeMfaEnrollmentStore::active_for(olivia)
            })
        }

        fn verify_as(&self, member: OrgUserId, code: &str) -> Result<(), AppError> {
            let pending = PendingMemberSession {
                session_id: self.session_id,
                member,
            };
            block_on(self.use_case.execute(
                &pending,
                &test_auditor(self.audit.clone()),
                OrgVerifyRequest {
                    code: code.to_owned(),
                },
            ))
        }

        fn verify(&self, code: &str) -> Result<(), AppError> {
            self.verify_as(self.olivia, code)
        }

        fn satisfied(&self) -> bool {
            block_on(self.sessions.find_by_id(&self.session_id))
                .unwrap()
                .unwrap()
                .mfa_satisfied()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// A fresh password sign-in of `member`, owing `owed`.
    fn session_owing(
        member: OrgUserId,
        organization_id: OrganizationId,
        owed: SecondFactor,
    ) -> OrgSession {
        let now = clock::now();
        let factor = match owed {
            SecondFactor::NotOwed => FactorProved::Proved(MfaFactor::Totp),
            _ => FactorProved::NoneYet,
        };
        OrgSession::reconstitute(OrgSessionRow {
            id: SessionId::new(),
            org_user_id: member,
            organization_id,
            place: SessionPlace::Tenant(TenantId::new()),
            refresh_token_hash: TokenHash::from_stored("refresh".to_owned()),
            progress: SignInProgressRow {
                method: AuthMethod::Password,
                factor,
                owed,
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

    /// Olivia, a member, signed in with her password and is asked for her
    /// code. She gives the right one, her sign-in is let in, and the
    /// answer is recorded.
    #[test]
    fn verify_valid_code_satisfies_mfa() {
        let setup = Setup::enrolled();

        setup.verify(RIGHT_CODE).unwrap();

        assert!(setup.satisfied());
        assert_eq!(setup.recorded(), vec!["organization.org_mfa_verified"]);
    }

    /// A wrong authenticator code is forbidden and counted as a failed
    /// attempt while the sign-in still owes its factor.
    #[test]
    fn verify_wrong_code_returns_forbidden_and_increments() {
        let setup = Setup::enrolled();

        let result = setup.verify("000000");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.enrollments.failed_attempts(), 1);
        assert!(!setup.satisfied());
    }

    /// Five wrong codes trigger lockout, so a subsequent correct code
    /// cannot satisfy the sign-in's factor.
    #[test]
    fn verify_locks_after_max_attempts() {
        let setup = Setup::enrolled();
        for _ in 0..5 {
            let _ = setup.verify("000000");
        }

        let result = setup.verify(RIGHT_CODE);

        assert!(matches!(result, Err(AppError::AccountLocked(_))));
        assert!(!setup.satisfied());
    }

    /// A sign-in named under another member is not found and remains
    /// unsatisfied by the offered code.
    #[test]
    fn verify_wrong_user_returns_not_found() {
        let setup = Setup::enrolled();

        let result = setup.verify_as(OrgUserId::new(), RIGHT_CODE);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(!setup.satisfied());
    }

    /// Olivia's sign-in already proved its second factor. Another code is a
    /// conflict.
    #[test]
    fn verify_already_satisfied_returns_conflict() {
        let setup = Setup::with(SecondFactor::NotOwed, |olivia| {
            FakeMfaEnrollmentStore::active_for(olivia)
        });

        let result = setup.verify(RIGHT_CODE);

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Reusing a code that satisfied the same sign-in is forbidden.
    #[test]
    fn a_replayed_code_is_refused() {
        let setup = Setup::enrolled();
        setup.verify(RIGHT_CODE).unwrap();

        let replayed = setup.verify(RIGHT_CODE);

        assert!(matches!(replayed, Err(AppError::Forbidden(_))));
    }

    /// Olivia has no authenticator in force. There is no factor to answer
    /// with.
    #[test]
    fn verify_no_enrollment_returns_not_found() {
        let setup = Setup::with(SecondFactor::Verify, |_| FakeMfaEnrollmentStore::empty());

        let result = setup.verify(RIGHT_CODE);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A code names a sign-in nobody started. It is not found.
    #[test]
    fn verify_nonexistent_session_returns_not_found() {
        let setup = Setup::enrolled();
        let pending = PendingMemberSession {
            session_id: SessionId::new(),
            member: setup.olivia,
        };

        let result = block_on(setup.use_case.execute(
            &pending,
            &test_auditor(setup.audit.clone()),
            OrgVerifyRequest {
                code: RIGHT_CODE.to_owned(),
            },
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
