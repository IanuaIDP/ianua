//! Approver presence: proof that the person approving a risky action is at
//! the keyboard right now.
//!
//! A session proves someone signed in, perhaps hours ago, perhaps on a device
//! left open. For an action that deletes, pays, reconfigures or administers,
//! whether an agent asks to take it or a workflow step does, the approver
//! answers a fresh code from their enrolled second factor. An approver with
//! no second factor cannot approve such actions at all: the check exists to
//! be passed, not skipped.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::enrollment::{AnsweredCode, LockoutPolicy};
use ianua_domain::domains::authentication::mfa::verifier::MfaVerifier;
use ianua_domain::message;
use ianua_domain::types::{OrgUserId, UserId};

use crate::context::{CallerContext, CallerIdentity};
use crate::error::AppError;
use crate::ports::authentication::{
    MfaEnrollmentStore, SecretEncryptor, SentCodeGenerator, SentCodeStore,
};
use crate::ports::organization::OrgMfaEnrollmentStore;
use crate::services::authentication::account_factor::{
    AccountFactor, FactorAnswer, FactorChecks, FactorCode, SentCodes,
};
use crate::services::authentication::member_factor::MemberFactor;
use crate::services::authentication::sign_in_steps::{CodeCheck, SentCodeCheck};

/// Ports the presence check reads enrollments and checks codes through.
#[derive(ianua_macros::Fakes)]
pub struct ApproverPresencePorts {
    /// Tenant users' enrollments.
    pub tenant_mfa: Arc<dyn MfaEnrollmentStore>,
    /// Org users' enrollments.
    pub org_mfa: Arc<dyn OrgMfaEnrollmentStore>,
    /// Opens a stored secret.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Checks a code against a secret.
    pub verifier: Arc<dyn MfaVerifier>,
    /// The codes sent for tenant users' mailed and texted factors.
    pub sent_codes: Arc<dyn SentCodeStore>,
    /// Hashes a typed code the way a sent one was hashed.
    pub sent_code_generator: Arc<dyn SentCodeGenerator>,
}

/// Requires a fresh second-factor code from the approver.
pub struct ApproverPresence {
    lockout: LockoutPolicy,
    ports: ApproverPresencePorts,
}

impl ApproverPresence {
    /// Creates the check, locking a factor under `lockout`.
    #[must_use]
    pub fn new(lockout: LockoutPolicy, ports: ApproverPresencePorts) -> Self {
        Self { lockout, ports }
    }

    /// The caller's answer to `code`, once it is right and its time step
    /// was never used before. The approval takes it as the caller's proof
    /// of presence.
    ///
    /// A tenant user answers the factor their tenant keeps for them, a
    /// member the one their organization keeps; each plane's record stays
    /// its own type.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the caller has no active second factor,
    ///   is a platform operator, or the code is wrong or already used.
    /// - `AppError::StepUpRequired` when no code was given.
    /// - `AppError::AccountLocked` after too many wrong codes.
    /// - `AppError::Internal` when an enrollment cannot be read or saved.
    pub async fn require(
        &self,
        ctx: &CallerContext,
        code: Option<&str>,
    ) -> Result<AnsweredCode, AppError> {
        let answer = match ctx.identity() {
            CallerIdentity::TenantUser(user) => self.tenant_answer(ctx, user, code).await?,
            CallerIdentity::OrgUser(member) => self.member_answer(ctx, member, code).await?,
            CallerIdentity::Operator(_) => {
                return Err(AppError::Forbidden(message!(
                    "authentication-a-platform-operator-cannot-approve-a",
                    "a platform operator cannot approve a high-risk action"
                )));
            }
        };
        present(answer)
    }

    /// What the factor `ctx`'s tenant keeps for `user` says to `code`.
    async fn tenant_answer(
        &self,
        ctx: &CallerContext,
        user: &UserId,
        code: Option<&str>,
    ) -> Result<FactorAnswer, AppError> {
        let factor = AccountFactor {
            enrollments: self.ports.tenant_mfa.as_ref(),
            checks: FactorChecks {
                app: self.check(),
                sent: SentCodes {
                    store: self.ports.sent_codes.as_ref(),
                    check: SentCodeCheck {
                        generator: self.ports.sent_code_generator.as_ref(),
                        lockout: self.lockout,
                    },
                },
            },
        };
        let tenant = ctx.tenant();
        let given = FactorCode {
            tenant: &tenant,
            user_id: user,
            code,
        };
        factor.answer(given).await
    }

    /// What the factor `member`'s organization, the one `ctx` acts in,
    /// keeps for them says to `code`.
    async fn member_answer(
        &self,
        ctx: &CallerContext,
        member: &OrgUserId,
        code: Option<&str>,
    ) -> Result<FactorAnswer, AppError> {
        let factor = MemberFactor {
            enrollments: self.ports.org_mfa.as_ref(),
            check: self.check(),
        };
        factor.answer(&ctx.organization_id(), member, code).await
    }

    fn check(&self) -> CodeCheck<'_> {
        CodeCheck {
            encryptor: self.ports.encryptor.as_ref(),
            verifier: self.ports.verifier.as_ref(),
            lockout: self.lockout,
        }
    }
}

/// The answer as proof of presence. An approver with no factor in use is
/// refused: the check exists to be passed, not skipped.
fn present(answer: FactorAnswer) -> Result<AnsweredCode, AppError> {
    match answer {
        FactorAnswer::Answered(answered) => Ok(answered),
        FactorAnswer::NoneOnFile => Err(AppError::Forbidden(message!(
            "authentication-approving-a-high-risk-action-needs",
            "approving a high-risk action needs a second factor; enrol one first"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::billing::plan::OrganizationPlan;
    use ianua_domain::types::SessionId;

    use super::*;
    use crate::context::Credential;
    use crate::test_support::agents::{PRESENT_CODE, enrolled_presence};
    use crate::test_support::authentication::FakeMfaEnrollmentStore;
    use crate::test_support::{block_on, test_ctx};

    fn member_caller(member: OrgUserId) -> CallerContext {
        CallerContext::new(
            CallerIdentity::OrgUser(member),
            Credential::OrgSession(SessionId::new()),
            test_ctx().organization_id(),
            test_ctx().tenant_id(),
            OrganizationPlan::Free.default_limits(),
        )
        .unwrap()
    }

    /// Olivia, a member of the organization acting in the tenant, answers
    /// the authenticator her organization keeps for her. She is present.
    #[test]
    fn a_member_proves_presence_with_their_organizations_factor() {
        let olivia = OrgUserId::new();
        let presence = enrolled_presence(Arc::new(FakeMfaEnrollmentStore::active_for(olivia)));

        let answered = block_on(presence.require(&member_caller(olivia), Some(PRESENT_CODE)));

        assert!(answered.is_ok());
    }

    /// An organization member without an enrolled factor cannot provide
    /// approval presence, even when a code is supplied.
    #[test]
    fn a_member_without_a_factor_is_refused() {
        let presence = enrolled_presence(Arc::new(FakeMfaEnrollmentStore::empty()));
        let mallory = member_caller(OrgUserId::new());

        let result = block_on(presence.require(&mallory, Some(PRESENT_CODE)));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    fn enrolled(ctx: &CallerContext) -> Arc<FakeMfaEnrollmentStore> {
        let CallerIdentity::TenantUser(user) = ctx.identity() else {
            panic!("the test caller is a tenant user");
        };
        let store = Arc::new(FakeMfaEnrollmentStore::empty());
        store.enroll(*user);
        store
    }

    /// Ann answers her authenticator's current code. She is present, and
    /// the answer comes back as her proof.
    #[test]
    fn a_right_code_proves_presence() {
        let ctx = test_ctx();
        let presence = enrolled_presence(enrolled(&ctx));

        let answered = block_on(presence.require(&ctx, Some(PRESENT_CODE)));

        assert!(answered.is_ok());
    }

    /// Ann gives no code for a delete. She is asked to step up.
    #[test]
    fn no_code_asks_for_a_step_up() {
        let ctx = test_ctx();
        let presence = enrolled_presence(enrolled(&ctx));

        let result = block_on(presence.require(&ctx, None));

        assert!(matches!(result, Err(AppError::StepUpRequired)));
    }

    /// The absence of a tenant user's second factor is a forbidden result,
    /// rather than permission to skip the presence check.
    #[test]
    fn a_caller_without_a_second_factor_is_refused() {
        let presence = enrolled_presence(Arc::new(FakeMfaEnrollmentStore::empty()));

        let result = block_on(presence.require(&test_ctx(), Some(PRESENT_CODE)));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A wrong code for the signed-in tenant user's factor cannot prove
    /// approval presence.
    #[test]
    fn a_wrong_code_is_refused() {
        let ctx = test_ctx();
        let presence = enrolled_presence(enrolled(&ctx));

        let result = block_on(presence.require(&ctx, Some("000000")));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A code that already proved presence is forbidden on its second use.
    #[test]
    fn a_code_used_once_is_refused_the_second_time() {
        let ctx = test_ctx();
        let presence = enrolled_presence(enrolled(&ctx));
        block_on(presence.require(&ctx, Some(PRESENT_CODE))).unwrap();

        let replayed = block_on(presence.require(&ctx, Some(PRESENT_CODE)));

        assert!(matches!(replayed, Err(AppError::Forbidden(_))));
    }

    /// Enrolling a different account does not satisfy the current caller's
    /// presence check; that caller is still forbidden.
    #[test]
    fn another_accounts_enrolment_does_not_count() {
        let ctx = test_ctx();
        let other = Arc::new(FakeMfaEnrollmentStore::empty());
        other.enroll(UserId::new());
        let presence = enrolled_presence(other);

        let result = block_on(presence.require(&ctx, Some(PRESENT_CODE)));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
