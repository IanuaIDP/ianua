//! Sending the code a password reset asks for, to a person whose second
//! factor is a code mailed or texted to them.
//!
//! Someone following a reset link is signed out, so there is no session to
//! send the code for. The link stands in for it: it was mailed to the
//! account's address and still works, which proves the reader holds that
//! mailbox. The code is the second proof the reset then asks for, so a
//! mailbox alone still opens nothing.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::enrollment::{CodeDelivery, MfaEnrollment};
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{MfaEnrollmentStore, ResetRequestStore};
use crate::ports::identity::UserStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::mfa::codes::sent::{CodeFor, SentCodePolicy, SentCodePorts};
use crate::use_cases::authentication::password::reset::lookup::{FollowedReset, ResetLinks};

/// The ports [`ResetCodeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResetCodePorts {
    /// Finds the reset the link names.
    pub reset_store: Arc<dyn ResetRequestStore>,
    /// Loads the account the reset was mailed for.
    pub user_store: Arc<dyn UserStore>,
    /// Hashes the link's token the way it was stored.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// The account's second factor.
    pub mfa_store: Arc<dyn MfaEnrollmentStore>,
    /// Makes, keeps and sends the code.
    pub codes: SentCodePorts,
}

/// Sends the code a password reset asks for, from a reset link.
pub struct ResetCodeUseCase {
    policy: SentCodePolicy,
    ports: ResetCodePorts,
}

impl ResetCodeUseCase {
    /// A use case sending codes under `policy`, working through `ports`.
    #[must_use]
    pub fn new(policy: SentCodePolicy, ports: ResetCodePorts) -> Self {
        Self { policy, ports }
    }

    /// The reset `raw_token` names and its account, while the link can
    /// still set a password for that account.
    async fn usable(
        &self,
        tenant: &ScopedTenant,
        raw_token: &str,
    ) -> Result<Option<FollowedReset>, AppError> {
        let links = ResetLinks {
            resets: self.ports.reset_store.as_ref(),
            users: self.ports.user_store.as_ref(),
            hasher: self.ports.token_generator.as_ref(),
        };
        links.usable(tenant, raw_token, clock::now()).await
    }

    /// The account's factor in force, when its codes are sent rather than
    /// made by an app: the only factor a reset sends a code for.
    async fn sent_factor(
        &self,
        tenant: &ScopedTenant,
        followed: &FollowedReset,
    ) -> Result<Option<MfaEnrollment<ResolvedTenant>>, AppError> {
        Ok(self
            .ports
            .mfa_store
            .find_by_user(tenant, followed.holder.id())
            .await
            .or_internal()?
            .filter(MfaEnrollment::is_active)
            .filter(|factor| factor.method().delivery() == CodeDelivery::Sent))
    }
}

impl Command for ResetCodeUseCase {
    type Caller = ScopedTenant;
    type Input = String;
    type Output = Result<(), AppError>;

    /// Sends a fresh code for the second factor of the account the reset
    /// link `raw_token` was mailed for, and records
    /// `authentication.mfa_code_sent`. The code replaces any sent before,
    /// and the reset-confirm step takes it.
    ///
    /// A link that is unknown, expired, spent or mailed to an address the
    /// account has left sends nothing, and neither does an account whose
    /// factor is an app or that has none: each answers the same as a code
    /// sent, so the answer tells nothing about the link or the account.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the token is malformed.
    /// - `AppError::TooManyRequests` when a code went out moments ago.
    /// - `AppError::Internal` on storage, sending or audit failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        raw_token: String,
    ) -> Result<(), AppError> {
        let Some(followed) = self.usable(tenant, &raw_token).await? else {
            return Ok(());
        };
        let Some(factor) = self.sent_factor(tenant, &followed).await? else {
            return Ok(());
        };
        let to = CodeFor {
            tenant,
            account: &followed.holder,
            factor: &factor,
        };
        let (_, events) = self.ports.codes.send(to, self.policy).await?;
        auditor.dispatch(&events).await.or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::credentials::breach::NewPasswordBreach;
    use ianua_domain::domains::authentication::credentials::password::PasswordHasher as _;
    use ianua_domain::domains::authentication::mfa::enrollment::EnrolledFactor;
    use ianua_domain::domains::authentication::recovery::reset::{
        CreateResetParams, PasswordResetRequest, PasswordResetRow, ResetInitiator, ResetState,
    };
    use ianua_domain::domains::identity::account::profile_values::PhoneNumber;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::test_support::fakes::FakeHasher;
    use ianua_domain::types::{Email, Lifetime, PasswordPolicy, PasswordResetId, UserId};

    use super::*;
    use crate::test_support::authentication::{
        FakeMfaEnrollmentStore, FakeResetRequestStore, FakeSentCodeGenerator, FakeSentCodeStore,
        RecordingCodeSender, SENT_CODE, lockout,
    };
    use crate::test_support::identity::{
        FakeUserStore, RecordingCredentialStore, hash_of_link, stored_user,
    };
    use crate::test_support::tenant::tenant_store_with_password_policy;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::authentication::password::{
        ReplacementPorts, ResetConfirmPorts, ResetConfirmRequest, ResetConfirmUseCase,
    };

    const ADDRESS: &str = "ann@acme.test";
    const LINK: &str = "fake_refresh_0";

    fn policy() -> SentCodePolicy {
        SentCodePolicy {
            lifetime: Lifetime::seconds(300).unwrap(),
            resend_after: time::Duration::seconds(30),
        }
    }

    fn pending_for(ann: UserId) -> PasswordResetRequest {
        PasswordResetRequest::create(
            &stored_user(ann, ADDRESS, UserStatus::Active),
            CreateResetParams {
                initiator: ResetInitiator::User,
                token_hash: hash_of_link(LINK),
                lifetime: Lifetime::seconds(3600).unwrap(),
            },
        )
        .unwrap()
    }

    fn expired_for(ann: UserId) -> PasswordResetRequest {
        let now = clock::now();
        PasswordResetRequest::reconstitute(PasswordResetRow {
            id: PasswordResetId::new(),
            user_id: ann,
            email: Email::new(ADDRESS).unwrap(),
            initiator: ResetInitiator::User,
            state: ResetState::Pending,
            token_hash: hash_of_link(LINK),
            created_at: now - time::Duration::hours(2),
            expires_at: now - time::Duration::hours(1),
        })
        .unwrap()
    }

    fn spent_for(ann: UserId) -> PasswordResetRequest {
        let mut reset = pending_for(ann);
        reset
            .complete(&stored_user(ann, ADDRESS, UserStatus::Active), clock::now())
            .unwrap();
        reset
    }

    struct Fixture {
        ann: UserId,
        resets: Arc<FakeResetRequestStore>,
        users: Arc<FakeUserStore>,
        factors: Arc<FakeMfaEnrollmentStore>,
        sent: Arc<FakeSentCodeStore>,
        sender: Arc<RecordingCodeSender>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        /// Ann, whose factor mails her codes, with a reset link pending.
        fn new() -> Self {
            let ann = UserId::new();
            Self::with_factor(ann, EnrolledFactor::EmailCode, &pending_for(ann))
        }

        fn with_factor(ann: UserId, factor: EnrolledFactor, reset: &PasswordResetRequest) -> Self {
            Self {
                ann,
                resets: Arc::new(FakeResetRequestStore::with_request(reset)),
                users: Arc::new(FakeUserStore::with_user(ann, ADDRESS)),
                factors: Arc::new(FakeMfaEnrollmentStore::active_with_factor(ann, factor)),
                sent: Arc::new(FakeSentCodeStore::empty()),
                sender: Arc::new(RecordingCodeSender::default()),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn holding(ann: UserId, reset: &PasswordResetRequest) -> Self {
            Self::with_factor(ann, EnrolledFactor::EmailCode, reset)
        }

        fn send(&self) -> Result<(), AppError> {
            let use_case = ResetCodeUseCase::new(
                policy(),
                ResetCodePorts {
                    reset_store: self.resets.clone(),
                    user_store: self.users.clone(),
                    mfa_store: self.factors.clone(),
                    codes: SentCodePorts {
                        sent_codes: self.sent.clone(),
                        generator: Arc::new(FakeSentCodeGenerator),
                        sender: self.sender.clone(),
                        ..SentCodePorts::fakes()
                    },
                    ..ResetCodePorts::fakes()
                },
            );
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.audit.clone()),
                LINK.to_owned(),
            ))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }

        /// Confirms Ann's reset with `code`, over the same resets, factor
        /// and sent codes the code was sent through.
        fn confirm(&self, code: &str) -> Result<NewPasswordBreach, AppError> {
            let use_case = ResetConfirmUseCase::new(
                lockout(),
                ResetConfirmPorts {
                    reset_store: self.resets.clone(),
                    replacement: ReplacementPorts {
                        user_store: self.users.clone(),
                        credential_store: Arc::new(RecordingCredentialStore::holding(
                            self.ann,
                            &FakeHasher.hash("old").unwrap(),
                        )),
                        tenant_store: tenant_store_with_password_policy(PasswordPolicy::relaxed()),
                        ..ReplacementPorts::fakes()
                    },
                    mfa_store: self.factors.clone(),
                    sent_codes: self.sent.clone(),
                    sent_code_generator: Arc::new(FakeSentCodeGenerator),
                    ..ResetConfirmPorts::fakes()
                },
            );
            let request = ResetConfirmRequest {
                raw_token: LINK.to_owned(),
                new_password: Secret::new("new_pass"),
                mfa_code: Some(code.to_owned()),
            };
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.audit.clone()),
                request,
            ))
        }
    }

    /// Ann forgot her password and her factor mails her codes. From her
    /// reset link she asks for one: it goes to her address, is kept for the
    /// reset to take, and is recorded.
    #[test]
    fn a_usable_link_sends_the_factors_code() {
        let fixture = Fixture::new();

        fixture.send().unwrap();

        assert_eq!(fixture.sender.messages()[0].to, ADDRESS);
        assert!(fixture.sent.latest_of(fixture.ann).is_some());
        assert_eq!(fixture.recorded(), ["authentication.mfa_code_sent"]);
    }

    /// Ann types the code she was sent into the reset form. The reset takes
    /// it and her new password is set.
    #[test]
    fn the_code_sent_is_the_one_the_reset_takes() {
        let fixture = Fixture::new();
        fixture.send().unwrap();

        let reset = fixture.confirm(SENT_CODE);

        assert!(reset.is_ok(), "{reset:?}");
        assert!(
            fixture
                .recorded()
                .contains(&"authentication.password_reset_completed".to_owned())
        );
    }

    /// A reset link with a wrong texted factor code cannot complete the password reset.
    #[test]
    fn a_guessed_code_does_not_reset_the_password() {
        let ann = UserId::new();
        let fixture = Fixture::with_factor(
            ann,
            EnrolledFactor::SmsCode(PhoneNumber::new("+4930123456").unwrap()),
            &pending_for(ann),
        );
        fixture.send().unwrap();

        let reset = fixture.confirm("000000");

        assert!(matches!(reset, Err(AppError::Forbidden(_))), "{reset:?}");
    }

    /// Ann's factor texts her codes. The code goes to her number.
    #[test]
    fn a_texted_factor_gets_its_code_by_text() {
        let ann = UserId::new();
        let fixture = Fixture::with_factor(
            ann,
            EnrolledFactor::SmsCode(PhoneNumber::new("+4930123456").unwrap()),
            &pending_for(ann),
        );

        fixture.send().unwrap();

        assert_eq!(fixture.sender.messages()[0].to, "+4930123456");
    }

    /// An unknown reset link gets the normal successful answer without sending
    /// a code or recording an event.
    #[test]
    fn an_unknown_link_sends_nothing_and_answers_the_same() {
        let fixture = Fixture {
            resets: Arc::new(FakeResetRequestStore::empty()),
            ..Fixture::new()
        };

        let result = fixture.send();

        assert!(result.is_ok());
        assert!(fixture.sender.messages().is_empty());
        assert!(fixture.recorded().is_empty());
    }

    /// A reset link expired for one hour gets the normal answer without sending a code.
    #[test]
    fn an_expired_link_sends_nothing_and_answers_the_same() {
        let ann = UserId::new();
        let fixture = Fixture::holding(ann, &expired_for(ann));

        let result = fixture.send();

        assert!(result.is_ok());
        assert!(fixture.sender.messages().is_empty());
    }

    /// A completed reset gets the normal successful answer without sending another code.
    #[test]
    fn a_spent_link_sends_nothing_and_answers_the_same() {
        let ann = UserId::new();
        let fixture = Fixture::holding(ann, &spent_for(ann));

        let result = fixture.send();

        assert!(result.is_ok());
        assert!(fixture.sender.messages().is_empty());
    }

    /// A reset mailed to Ann's former address sends no factor code while
    /// returning the normal successful answer.
    #[test]
    fn a_link_to_an_address_the_account_left_sends_nothing() {
        let fixture = Fixture::new();
        let fixture = Fixture {
            users: Arc::new(FakeUserStore::with_user(fixture.ann, "ann@new.example")),
            ..fixture
        };

        let result = fixture.send();

        assert!(result.is_ok());
        assert!(fixture.sender.messages().is_empty());
    }

    /// Ann's factor is an authenticator app, which makes its own codes.
    /// Nothing is sent, and the answer is the same.
    #[test]
    fn an_app_factor_is_sent_nothing() {
        let ann = UserId::new();
        let fixture = Fixture {
            factors: Arc::new(FakeMfaEnrollmentStore::active_for(ann)),
            ..Fixture::holding(ann, &pending_for(ann))
        };

        let result = fixture.send();

        assert!(result.is_ok());
        assert!(fixture.sender.messages().is_empty());
    }

    /// Ann has no second factor. The link alone resets her password, so
    /// there is nothing to send.
    #[test]
    fn an_account_without_a_factor_is_sent_nothing() {
        let fixture = Fixture {
            factors: Arc::new(FakeMfaEnrollmentStore::empty()),
            ..Fixture::new()
        };

        let result = fixture.send();

        assert!(result.is_ok());
        assert!(fixture.sender.messages().is_empty());
    }

    /// A second request inside the cooldown is rate limited and leaves only
    /// the first code message sent.
    #[test]
    fn a_second_code_moments_later_is_refused() {
        let fixture = Fixture::new();
        fixture.send().unwrap();

        let again = fixture.send();

        assert!(matches!(again, Err(AppError::TooManyRequests(_))));
        assert_eq!(fixture.sender.messages().len(), 1);
    }
}
