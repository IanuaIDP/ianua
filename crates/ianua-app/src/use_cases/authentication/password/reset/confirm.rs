//! The second half of a password reset: the person follows the mailed link
//! and sets a new password.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::breach::NewPasswordBreach;
use ianua_domain::domains::authentication::mfa::enrollment::LockoutPolicy;
use ianua_domain::domains::authentication::mfa::verifier::MfaVerifier;
use ianua_domain::domains::authentication::recovery::reset::PasswordResetRequest;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::ActorRef;
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::input::validate_password;
use crate::ports::authentication::{
    MfaEnrollmentStore, ResetRequestStore, SecretEncryptor, SentCodeGenerator, SentCodeStore,
};
use crate::services::authentication::account_factor::{
    AccountFactor, FactorChecks, FactorCode, SentCodes,
};
use crate::services::authentication::new_password::NewPassword;
use crate::services::authentication::refused::unusable_reset_link;
use crate::services::authentication::sign_in_steps::{CodeCheck, SentCodeCheck};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::password::new::ReplacementPorts;
use crate::use_cases::authentication::password::reset::lookup::{FollowedReset, ResetLinks};

/// The ports [`ResetConfirmUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResetConfirmPorts {
    /// Finds and saves reset requests.
    pub reset_store: Arc<dyn ResetRequestStore>,
    /// Loads the account the reset is for, checks the new password and puts
    /// it in force.
    pub replacement: ReplacementPorts,
    /// The account's second factor, which a reset must answer.
    pub mfa_store: Arc<dyn MfaEnrollmentStore>,
    /// Opens the factor's stored secret.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Checks a code against the factor's secret.
    pub verifier: Arc<dyn MfaVerifier>,
    /// The codes sent for mailed and texted factors.
    pub sent_codes: Arc<dyn SentCodeStore>,
    /// Hashes a typed code the way a sent one was hashed.
    pub sent_code_generator: Arc<dyn SentCodeGenerator>,
    /// Hashes the link's token the way it was stored.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// The mailed link's token, the new password and, for an account with a
/// second factor, a code from it.
pub struct ResetConfirmRequest {
    /// The token from the reset email.
    pub raw_token: String,
    /// The password to set.
    pub new_password: Secret,
    /// A code from the account's second factor, when it has one.
    pub mfa_code: Option<String>,
}

/// Sets a new password through a reset link.
pub struct ResetConfirmUseCase {
    lockout: LockoutPolicy,
    ports: ResetConfirmPorts,
}

impl ResetConfirmUseCase {
    /// A use case locking a second factor under `lockout`, working through
    /// `ports`.
    #[must_use]
    pub fn new(lockout: LockoutPolicy, ports: ResetConfirmPorts) -> Self {
        Self { lockout, ports }
    }

    /// The reset `raw_token` names and its account, while the link can
    /// still set a password for that account.
    async fn usable(
        &self,
        tenant: &ScopedTenant,
        raw_token: &str,
        now: OffsetDateTime,
    ) -> Result<FollowedReset, AppError> {
        let links = ResetLinks {
            resets: self.ports.reset_store.as_ref(),
            users: self.ports.replacement.user_store.as_ref(),
            hasher: self.ports.token_generator.as_ref(),
        };
        links
            .usable(tenant, raw_token, now)
            .await?
            .or_not_found(message!(
                "authentication-invalid-or-expired-reset-link",
                "invalid or expired reset link"
            ))
    }

    /// Completes `reset` for `holder` at `now` and stores it, refusing it
    /// when it can no longer complete, or when another confirm of the same
    /// link completed it first: a link sets one password.
    async fn complete_here(
        &self,
        tenant: &ScopedTenant,
        reset: &mut PasswordResetRequest,
        holder: &User<ResolvedTenant>,
        now: OffsetDateTime,
    ) -> Result<(), AppError> {
        reset
            .complete(holder, now)
            .map_err(|_| unusable_reset_link())?;
        let store = self.ports.reset_store.as_ref();
        if !store.complete(tenant, reset).await.or_internal()? {
            return Err(unusable_reset_link());
        }
        Ok(())
    }

    fn factor(&self) -> AccountFactor<'_> {
        AccountFactor {
            enrollments: self.ports.mfa_store.as_ref(),
            checks: FactorChecks {
                app: CodeCheck {
                    encryptor: self.ports.encryptor.as_ref(),
                    verifier: self.ports.verifier.as_ref(),
                    lockout: self.lockout,
                },
                sent: SentCodes {
                    store: self.ports.sent_codes.as_ref(),
                    check: SentCodeCheck {
                        generator: self.ports.sent_code_generator.as_ref(),
                        lockout: self.lockout,
                    },
                },
            },
        }
    }
}

impl Command for ResetConfirmUseCase {
    type Caller = ScopedTenant;
    type Input = ResetConfirmRequest;
    type Output = Result<NewPasswordBreach, AppError>;

    /// Sets `request.new_password` on the account the link was mailed for,
    /// and answers what the breach check found of it.
    ///
    /// An account with a second factor must answer it here, whatever the
    /// tenant's policy: someone who set one up expects it to stand between a
    /// mailbox and their account. The link works once. Every session the
    /// account held ends, and `authentication.password_reset_completed` is
    /// recorded.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` for a malformed token or password outside tenant rules, including name/address, common, reused or breached values.
    /// - `AppError::NotFound` for an unknown, expired or spent link, a changed mailbox, or an account unable to sign in.
    /// - `AppError::StepUpRequired` for a missing factor code; `Forbidden` for a wrong/spent code or disabled passwords; `AccountLocked` after wrong codes.
    /// - `AppError::Busy` when hashing cannot start in time; `Internal` on storage, hashing or session-ending failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: ResetConfirmRequest,
    ) -> Result<NewPasswordBreach, AppError> {
        validate_password(request.new_password.expose())?;
        let now = clock::now();
        let FollowedReset {
            mut reset,
            mut holder,
        } = self.usable(tenant, &request.raw_token, now).await?;
        let given = FactorCode {
            tenant,
            user_id: holder.id(),
            code: request.mfa_code.as_deref(),
        };
        self.factor().answer(given).await?;
        let replacement = self.ports.replacement.replacement();
        let chosen = replacement
            .chosen(NewPassword {
                tenant,
                account: &holder,
                chosen: &request.new_password,
            })
            .await?;
        self.complete_here(tenant, &mut reset, &holder, now).await?;
        replacement.install(tenant, &mut holder, &chosen).await?;
        auditor
            .dispatch_by(&ActorRef::User(*holder.id()), reset.take_events(tenant))
            .await
            .or_internal()?;
        Ok(chosen.breach)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::credentials::password::PasswordHasher as _;
    use ianua_domain::domains::authentication::recovery::reset::{
        CreateResetParams, PasswordResetRequest, PasswordResetRow, ResetInitiator, ResetState,
        ResetStatus,
    };
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::test_support::fakes::{FakeHasher, FakeMfaVerifier};
    use ianua_domain::types::{Email, Lifetime, PasswordPolicy, PasswordResetId, UserId};

    use super::*;
    use crate::ports::identity::UserStore;
    use crate::test_support::authentication::{
        FakeEncryptor, FakeMfaEnrollmentStore, FakeResetRequestStore, FakeSessionStore,
        RevocationSwitch, lockout,
    };
    use crate::test_support::identity::{
        FakeUserStore, RecordingCredentialStore, hash_of_link, stored_user,
    };
    use crate::test_support::tenant::tenant_store_with_password_policy;
    use crate::test_support::{
        FakeEventDispatcher, ReadBeforeWrite, block_on, test_auditor, test_ctx,
    };

    const ADDRESS: &str = "alice@acme.com";
    const LINK: &str = "fake_refresh_0";
    const RIGHT_CODE: &str = "123456";

    struct Fixture {
        ann: UserId,
        resets: Arc<FakeResetRequestStore>,
        users: Arc<FakeUserStore>,
        creds: Arc<RecordingCredentialStore>,
        mfa: Arc<FakeMfaEnrollmentStore>,
        sessions: Arc<FakeSessionStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        /// Ann, with a pending reset link mailed to her verified address.
        fn new() -> Self {
            let ann = UserId::new();
            let users = FakeUserStore::with_user(ann, ADDRESS);
            let holder = stored_user(ann, ADDRESS, UserStatus::Active);
            Self {
                resets: Arc::new(FakeResetRequestStore::with_request(&pending_for(&holder))),
                users: Arc::new(users),
                creds: Arc::new(RecordingCredentialStore::holding(
                    ann,
                    &FakeHasher.hash("old").unwrap(),
                )),
                mfa: Arc::new(FakeMfaEnrollmentStore::empty()),
                sessions: Arc::new(FakeSessionStore::empty()),
                audit: Arc::new(FakeEventDispatcher::new()),
                ann,
            }
        }

        fn enrolled() -> Self {
            let fixture = Self::new();
            Self {
                mfa: Arc::new(FakeMfaEnrollmentStore::active_for(fixture.ann)),
                ..fixture
            }
        }

        fn use_case(&self) -> ResetConfirmUseCase {
            self.use_case_over(self.resets.clone())
        }

        fn use_case_over(&self, resets: Arc<dyn ResetRequestStore>) -> ResetConfirmUseCase {
            ResetConfirmUseCase::new(
                lockout(),
                ResetConfirmPorts {
                    reset_store: resets,
                    replacement: ReplacementPorts {
                        user_store: self.users.clone(),
                        credential_store: self.creds.clone(),
                        session_store: self.sessions.clone(),
                        tenant_store: tenant_store_with_password_policy(PasswordPolicy::relaxed()),
                        ..ReplacementPorts::fakes()
                    },
                    mfa_store: self.mfa.clone(),
                    encryptor: Arc::new(FakeEncryptor),
                    verifier: Arc::new(FakeMfaVerifier {
                        valid_code: RIGHT_CODE.to_owned(),
                    }),
                    ..ResetConfirmPorts::fakes()
                },
            )
        }

        fn confirm(&self, code: Option<&str>) -> Result<NewPasswordBreach, AppError> {
            self.confirm_with(&self.use_case(), code)
        }

        fn confirm_with(
            &self,
            use_case: &ResetConfirmUseCase,
            code: Option<&str>,
        ) -> Result<NewPasswordBreach, AppError> {
            let request = ResetConfirmRequest {
                raw_token: LINK.to_owned(),
                new_password: Secret::new("new_pass"),
                mfa_code: code.map(str::to_owned),
            };
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.audit.clone()),
                request,
            ))
        }

        /// The reset store as two confirms racing on Ann's link see it:
        /// both read her pending reset before either completed it.
        fn racing_resets(&self) -> Arc<ReadBeforeWrite<FakeResetRequestStore>> {
            let pending = block_on(
                self.resets
                    .find_by_token_hash(&test_ctx().tenant(), &hash_of_link(LINK)),
            )
            .unwrap()
            .unwrap();
            Arc::new(ReadBeforeWrite::new(
                FakeResetRequestStore::with_request(&pending),
                self.resets.clone(),
            ))
        }

        fn stored_hash(&self) -> String {
            self.creds.hash_of(&self.ann).unwrap().as_str().to_owned()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn pending_for(holder: &User<ResolvedTenant>) -> PasswordResetRequest {
        PasswordResetRequest::create(
            holder,
            CreateResetParams {
                initiator: ResetInitiator::User,
                token_hash: hash_of_link(LINK),
                lifetime: Lifetime::seconds(3600).unwrap(),
            },
        )
        .unwrap()
    }

    fn expired_for(user_id: UserId) -> PasswordResetRequest {
        let now = clock::now();
        PasswordResetRequest::reconstitute(PasswordResetRow {
            id: PasswordResetId::new(),
            user_id,
            email: Email::new(ADDRESS).unwrap(),
            initiator: ResetInitiator::User,
            state: ResetState::Pending,
            token_hash: hash_of_link(LINK),
            created_at: now - time::Duration::hours(2),
            expires_at: now - time::Duration::hours(1),
        })
        .unwrap()
    }

    /// Ann follows her reset link and sets a new password. It is stored, the
    /// link is spent, her sessions end and the reset is recorded.
    #[test]
    fn a_followed_link_sets_the_new_password() {
        let fixture = Fixture::new();

        fixture.confirm(None).unwrap();

        assert_eq!(fixture.stored_hash(), "fake$new_pass");
        assert_eq!(fixture.resets.status(), Some(ResetStatus::Completed));
        assert_eq!(*fixture.sessions.revoke_all_count.lock().unwrap(), 1);
        assert_eq!(
            fixture.recorded(),
            ["authentication.password_reset_completed"]
        );
    }

    /// Ann's reset changes how she signs in, so devices she remembered
    /// before stop skipping her second factor.
    #[test]
    fn a_reset_is_recorded_as_a_change_of_sign_in() {
        let fixture = Fixture::new();

        fixture.confirm(None).unwrap();

        let ann = block_on(fixture.users.find_by_id(&test_ctx().tenant(), &fixture.ann))
            .unwrap()
            .unwrap();
        assert!(
            ann.credentials_changed_at()
                .since(clock::now() - time::Duration::minutes(1))
        );
    }

    /// An unknown reset link returns not found without recording completion.
    #[test]
    fn an_unknown_link_is_not_found() {
        let fixture = Fixture {
            resets: Arc::new(FakeResetRequestStore::empty()),
            ..Fixture::new()
        };

        let result = fixture.confirm(None);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(fixture.recorded().is_empty());
    }

    /// A reset link expired for one hour is refused and preserves the stored password.
    #[test]
    fn an_expired_link_is_refused() {
        let fixture = Fixture::new();
        let fixture = Fixture {
            resets: Arc::new(FakeResetRequestStore::with_request(&expired_for(
                fixture.ann,
            ))),
            ..fixture
        };

        let result = fixture.confirm(None);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.stored_hash(), "fake$old");
    }

    /// A completed reset link returns not found on a second confirmation.
    #[test]
    fn a_used_link_cannot_be_used_again() {
        let fixture = Fixture::new();
        fixture.confirm(None).unwrap();

        let replay = fixture.confirm(None);

        assert!(matches!(replay, Err(AppError::NotFound(_))));
    }

    /// Two confirmations reading the same pending reset allow one completion;
    /// the second is refused, with one session revocation and one audit event.
    #[test]
    fn a_reset_confirmed_twice_at_once_sets_one_password() {
        let fixture = Fixture::new();
        let use_case = fixture.use_case_over(fixture.racing_resets());

        fixture.confirm_with(&use_case, None).unwrap();
        let second = fixture.confirm_with(&use_case, None);

        assert!(matches!(second, Err(AppError::NotFound(_))));
        assert_eq!(*fixture.sessions.revoke_all_count.lock().unwrap(), 1);
        assert_eq!(
            fixture.recorded(),
            ["authentication.password_reset_completed"]
        );
    }

    /// Locking the account after reset issuance makes the link unusable
    /// and preserves the stored password.
    #[test]
    fn a_link_for_a_locked_account_does_nothing() {
        let fixture = Fixture::new();
        let users = FakeUserStore::empty();
        users.add(stored_user(fixture.ann, ADDRESS, UserStatus::Locked));
        let fixture = Fixture {
            users: Arc::new(users),
            ..fixture
        };

        let result = fixture.confirm(None);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.stored_hash(), "fake$old");
    }

    /// An enrolled account's reset asks for a factor code when none is supplied
    /// and records no completion event.
    #[test]
    fn an_enrolled_account_must_answer_its_factor() {
        let fixture = Fixture::enrolled();

        let result = fixture.confirm(None);

        assert!(matches!(result, Err(AppError::StepUpRequired)));
        assert!(fixture.recorded().is_empty());
    }

    /// Ann has a second factor and types its code. Her password is reset.
    #[test]
    fn an_enrolled_account_resets_when_it_answers_its_factor() {
        let fixture = Fixture::enrolled();

        fixture.confirm(Some(RIGHT_CODE)).unwrap();

        assert_eq!(
            fixture.recorded(),
            ["authentication.password_reset_completed"]
        );
    }

    /// A wrong factor code refuses the reset, increments failed attempts
    /// and preserves the stored password.
    #[test]
    fn a_wrong_code_does_not_reset_the_password() {
        let fixture = Fixture::enrolled();

        let result = fixture.confirm(Some("000000"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.mfa.failed_attempts(), 1);
        assert_eq!(fixture.stored_hash(), "fake$old");
    }

    /// A factor code already accepted by the account's factor cannot be reused for a reset.
    #[test]
    fn a_replayed_code_is_refused() {
        let fixture = Fixture::enrolled();
        let use_case = fixture.use_case();
        let factor_answer = block_on(use_case.factor().answer(FactorCode {
            tenant: &test_ctx().tenant(),
            user_id: &fixture.ann,
            code: Some(RIGHT_CODE),
        }));
        assert!(factor_answer.is_ok());

        let result = fixture.confirm_with(&use_case, Some(RIGHT_CODE));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Five wrong reset codes lock the factor against a later valid code.
    #[test]
    fn a_locked_factor_refuses_the_reset() {
        let fixture = Fixture::enrolled();
        for _ in 0..5 {
            let _ = fixture.confirm(Some("000000"));
        }

        let result = fixture.confirm(Some(RIGHT_CODE));

        assert!(matches!(result, Err(AppError::AccountLocked(_))));
    }

    /// Ann has no second factor. The link and the new password are enough.
    #[test]
    fn an_account_without_a_factor_resets_with_the_link_alone() {
        let fixture = Fixture::new();

        let result = fixture.confirm(None);

        assert!(result.is_ok());
    }

    /// The session store cannot be reached when the sessions are to end.
    /// The reset fails rather than leaving the old sessions open.
    #[test]
    fn a_failed_sign_out_fails_the_reset() {
        let fixture = Fixture {
            sessions: Arc::new(FakeSessionStore::empty().failing_revocation()),
            ..Fixture::new()
        };

        let result = fixture.confirm(None);

        assert!(matches!(result, Err(AppError::Internal(_))));
    }
}
