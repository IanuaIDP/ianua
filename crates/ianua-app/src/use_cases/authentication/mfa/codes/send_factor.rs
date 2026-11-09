//! Sending a code for a person's mailed or texted factor: for a sign-in
//! that waits for it, for a setup still to be confirmed, or for a person
//! signed in who must prove the factor again before a change.

use std::sync::Arc;

use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::MfaEnrollmentStore;
use crate::ports::identity::UserStore;
use crate::ports::shared::SessionStore;
use crate::services::lookup::owned_session;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::mfa::codes::sent::{
    CodeFor, CodeSent, SentCodePolicy, SentCodePorts,
};
use crate::use_cases::authentication::mfa::enrollment::setup_proof::{
    FactorSetter, SetterAccounts,
};
use crate::use_cases::authentication::mfa::lookup::existing_factor_in_use;
use crate::use_cases::authentication::mfa::sessions::sign_in_parties::PendingSignIn;

/// The ports [`SendFactorCodeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SendFactorCodePorts {
    /// The person's factor.
    pub enrollment_store: Arc<dyn MfaEnrollmentStore>,
    /// Makes, keeps and sends the code.
    pub codes: SentCodePorts,
    /// The account of a sign-in waiting for its factor.
    pub user_store: Arc<dyn UserStore>,
    /// The session of a sign-in waiting for its factor.
    pub session_store: Arc<dyn SessionStore>,
    /// Who is signed in to a caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Sends a code for a person's mailed or texted factor.
pub struct SendFactorCodeUseCase {
    policy: SentCodePolicy,
    ports: SendFactorCodePorts,
}

impl SendFactorCodeUseCase {
    /// A use case sending codes under `policy`, working through `ports`.
    #[must_use]
    pub fn new(policy: SentCodePolicy, ports: SendFactorCodePorts) -> Self {
        Self { policy, ports }
    }

    /// The tenant the setter acts in and their account, once a waiting
    /// sign-in still owes something.
    async fn account(
        &self,
        setter: &FactorSetter,
    ) -> Result<(ScopedTenant, User<ResolvedTenant>), AppError> {
        if let FactorSetter::SigningIn(pending) = setter {
            ensure_still_waiting(self.ports.session_store.as_ref(), pending).await?;
        }
        SetterAccounts {
            authorities: self.ports.tenant_authorities.as_ref(),
            users: self.ports.user_store.as_ref(),
        }
        .account(setter)
        .await
    }
}

impl Command for SendFactorCodeUseCase {
    type Caller = FactorSetter;
    type Input = ();
    type Output = Result<CodeSent, AppError>;

    /// Sends a fresh code for `setter`'s mailed or texted factor, in force
    /// or still to be confirmed, and records `authentication.mfa_code_sent`.
    /// The code replaces any sent before.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when a signed-in setter's session no
    ///   longer counts.
    /// - `AppError::NotFound` when the person has no factor in use, or a
    ///   waiting sign-in's session or account is gone.
    /// - `AppError::Conflict` when the factor is an authenticator app, or the
    ///   waiting sign-in owes nothing.
    /// - `AppError::TooManyRequests` when a code went out moments ago.
    /// - `AppError::Internal` on storage, sending or audit failure.
    async fn execute(
        &self,
        setter: &FactorSetter,
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<CodeSent, AppError> {
        let (tenant, account) = self.account(setter).await?;
        let store = self.ports.enrollment_store.as_ref();
        let factor = existing_factor_in_use(store, &tenant, account.id()).await?;
        let to = CodeFor {
            tenant: &tenant,
            account: &account,
            factor: &factor,
        };
        let (sent, events) = self.ports.codes.send(to, self.policy).await?;
        auditor.dispatch(&events).await.or_internal()?;
        Ok(sent)
    }
}

/// Refuses a code for a sign-in that owes no second factor any more.
///
/// # Errors
///
/// - `AppError::NotFound` when the session is gone or another's.
/// - `AppError::Conflict` when it owes nothing.
/// - `AppError::Internal` on storage failure.
async fn ensure_still_waiting(
    sessions: &dyn SessionStore,
    pending: &PendingSignIn,
) -> Result<(), AppError> {
    let session = owned_session(
        sessions,
        &pending.tenant,
        &pending.session_id,
        &pending.user_id,
    )
    .await?;
    if session.owed().is_satisfied() {
        return Err(AppError::Conflict(message!(
            "authentication-this-sign-in-owes-no-second",
            "this sign-in owes no second factor"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::authentication::mfa::enrollment::EnrolledFactor;
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authentication::sessions::mfa_factor::FactorProved;
    use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
    use ianua_domain::domains::identity::account::profile_values::PhoneNumber;
    use ianua_domain::types::{Lifetime, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{
        FakeMfaEnrollmentStore, FakeSentCodeStore, FakeSessionStore, RecordingCodeSender,
        UnreachableCodeSender, session_signed_in, test_caller_id,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn policy() -> SentCodePolicy {
        SentCodePolicy {
            lifetime: Lifetime::seconds(300).unwrap(),
            resend_after: time::Duration::seconds(30),
        }
    }

    fn texted() -> EnrolledFactor {
        EnrolledFactor::SmsCode(PhoneNumber::new("+4930123456").unwrap())
    }

    struct Fixture {
        sent: Arc<FakeSentCodeStore>,
        sender: Arc<RecordingCodeSender>,
        audit: Arc<FakeEventDispatcher>,
        ports: SendFactorCodePorts,
    }

    impl Fixture {
        fn over(enrollments: FakeMfaEnrollmentStore) -> Self {
            let sent = Arc::new(FakeSentCodeStore::empty());
            let sender = Arc::new(RecordingCodeSender::default());
            Self {
                ports: SendFactorCodePorts {
                    enrollment_store: Arc::new(enrollments),
                    codes: SentCodePorts {
                        sent_codes: sent.clone(),
                        sender: sender.clone(),
                        ..SentCodePorts::fakes()
                    },
                    ..SendFactorCodePorts::fakes()
                },
                sent,
                sender,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn send_as(&self, setter: &FactorSetter) -> Result<CodeSent, AppError> {
            let use_case = SendFactorCodeUseCase::new(
                policy(),
                SendFactorCodePorts {
                    codes: self.ports.codes.clone(),
                    enrollment_store: self.ports.enrollment_store.clone(),
                    user_store: self.ports.user_store.clone(),
                    session_store: self.ports.session_store.clone(),
                    tenant_authorities: self.ports.tenant_authorities.clone(),
                },
            );
            block_on(use_case.execute(setter, &test_auditor(self.audit.clone()), ()))
        }

        fn send(&self) -> Result<CodeSent, AppError> {
            self.send_as(&FactorSetter::SignedIn(Box::new(test_ctx())))
        }
    }

    /// Ann's factor texts her codes. She asks for one before changing her
    /// address; it goes to her number and is recorded.
    #[test]
    fn a_code_goes_to_the_factors_number() {
        let fixture = Fixture::over(FakeMfaEnrollmentStore::active_with_factor(
            test_caller_id(),
            texted(),
        ));

        fixture.send().unwrap();

        assert_eq!(fixture.sender.messages()[0].to, "+4930123456");
        assert!(fixture.sent.latest_of(test_caller_id()).is_some());
        assert_eq!(
            fixture.audit.records.lock().unwrap().as_slice(),
            ["authentication.mfa_code_sent"]
        );
    }

    /// An immediate second code request is rate-limited and leaves exactly
    /// one message sent.
    #[test]
    fn a_second_code_moments_later_is_refused() {
        let fixture = Fixture::over(FakeMfaEnrollmentStore::active_with_factor(
            test_caller_id(),
            texted(),
        ));
        fixture.send().unwrap();

        let again = fixture.send();

        assert!(matches!(again, Err(AppError::TooManyRequests(_))));
        assert_eq!(fixture.sender.messages().len(), 1);
    }

    /// The SMS provider does not answer in time. Ann is told it failed
    /// rather than waiting on a text that never comes, and nothing is
    /// recorded as sent.
    #[test]
    fn a_provider_that_does_not_answer_fails_the_send() {
        let mut fixture = Fixture::over(FakeMfaEnrollmentStore::active_with_factor(
            test_caller_id(),
            texted(),
        ));
        fixture.ports.codes.sender = Arc::new(UnreachableCodeSender);

        let result = fixture.send();

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert!(fixture.audit.records.lock().unwrap().is_empty());
    }

    /// Ann's factor is an authenticator app, which makes its own codes.
    /// Nothing is sent.
    #[test]
    fn an_app_is_sent_nothing() {
        let fixture = Fixture::over(FakeMfaEnrollmentStore::active_for(test_caller_id()));

        let result = fixture.send();

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(fixture.sender.messages().is_empty());
    }

    /// Ann has no second factor. There is nothing to send a code for.
    #[test]
    fn without_a_factor_nothing_is_found() {
        let fixture = Fixture::over(FakeMfaEnrollmentStore::empty());

        let result = fixture.send();

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann's sign-in waits for her mailed code. Her waiting sign-in asks for
    /// one, and it goes to her address.
    #[test]
    fn a_waiting_sign_in_is_sent_its_code() {
        let ann = UserId::new();
        let session = session_signed_in(
            ann,
            SignInProgressRow {
                method: AuthMethod::Password,
                factor: FactorProved::NoneYet,
                owed: SecondFactor::Verify,
            },
        );
        let pending = PendingSignIn {
            tenant: test_ctx().tenant(),
            session_id: *session.id(),
            user_id: ann,
        };
        let mut fixture = Fixture::over(FakeMfaEnrollmentStore::active_with_factor(
            ann,
            EnrolledFactor::EmailCode,
        ));
        fixture.ports.session_store = Arc::new(FakeSessionStore::with_session(session));
        fixture.ports.user_store = Arc::new(FakeUserStore::with_user(ann, "ann@acme.test"));

        fixture.send_as(&FactorSetter::SigningIn(pending)).unwrap();

        assert_eq!(fixture.sender.messages()[0].to, "ann@acme.test");
    }

    /// A signed-out caller is unauthenticated and sends no factor code.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let mut fixture = Fixture::over(FakeMfaEnrollmentStore::active_with_factor(
            test_caller_id(),
            texted(),
        ));
        fixture.ports.tenant_authorities =
            Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = fixture.send();

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(fixture.sender.messages().is_empty());
    }
}
