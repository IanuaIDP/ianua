//! A person signed in, or bound to the directory, changes their own
//! password after proving who they are again.
//!
//! The new password ends every other session at once: the domain's session
//! check refuses a session opened before the account last changed how it
//! signs in. The session the change was made from is kept through it, since
//! its holder just proved who they are. A directory bind opens no session,
//! so a change made over LDAP keeps none.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::breach::NewPasswordBreach;
use ianua_domain::domains::authentication::credentials::password::PasswordHasher as _;
use ianua_domain::domains::authentication::operations::password_change::PasswordChange;
use ianua_domain::domains::authentication::sessions::fresh_sign_in::FreshSignIn;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, PasswordHash, UserId};

use crate::acting::TenantAuthorities;
use crate::acting::tenant::{AccountHolder, SignedInAccount};
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authentication::{CredentialStore, PasswordHistory};
use crate::ports::identity::UserStore;
use crate::ports::shared::SessionStore;
use crate::ports::tenant::TenantStore;
use crate::services::authentication::fresh_proof::{FreshProofs, ReenteredProof};
use crate::services::authentication::new_password::{Earlier, NewPassword, NewPasswordPorts};
use crate::services::authentication::password_hashing::PasswordHashing;
use crate::services::lookup::existing_tenant;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::password::new::PasswordSetting;

/// The ports [`ChangeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangePorts {
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Turns what the person typed again into a fresh proof of them.
    pub fresh_proofs: Arc<dyn FreshProofs>,
    /// Reads and replaces the account's password hash.
    pub credential_store: Arc<dyn CredentialStore>,
    /// The account's retired passwords, when the deployment keeps them.
    pub password_history: Option<Arc<dyn PasswordHistory>>,
    /// Hashes the new password and checks it against old ones, under the
    /// node's cap on hashes running at once.
    pub hashing: PasswordHashing,
    /// Saves the account with its change of sign-in recorded.
    pub user_store: Arc<dyn UserStore>,
    /// Saves the session the change was made from.
    pub session_store: Arc<dyn SessionStore>,
    /// The tenant, for its password rules.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Checks the new password against breaches, the common list and the
    /// tenant's reuse limit.
    pub new_password: NewPasswordPorts,
}

/// How often a password may change and how far back reuse is checked.
#[derive(Debug, Clone, Copy)]
pub struct ChangePolicy {
    /// How many retired passwords a new one may not repeat. 0 checks none.
    pub history_check_count: u32,
    /// Seconds before the password can be changed again. 0 or less allows
    /// a change at any time.
    pub min_age_seconds: i64,
}

/// The new password, and what the person gave to prove who they are.
pub struct ChangeRequest {
    /// The current password, with a code from their second factor when they
    /// have one, typed again.
    pub proof: ReenteredProof,
    /// The password to set.
    pub new_password: Secret,
}

/// Changes the password of the person signed in.
pub struct ChangeUseCase {
    policy: ChangePolicy,
    ports: ChangePorts,
}

impl ChangeUseCase {
    /// A use case under `policy`, working through `ports`.
    #[must_use]
    pub fn new(policy: ChangePolicy, ports: ChangePorts) -> Self {
        Self { policy, ports }
    }

    async fn current_hash(
        &self,
        tenant: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<PasswordHash, AppError> {
        self.ports
            .credential_store
            .find_password_hash(tenant, user_id)
            .await
            .or_internal()?
            .or_not_found(message!(
                "authentication-no-password-set",
                "no password set"
            ))
    }

    /// Refuses a change sooner than the policy's minimum age after the last
    /// one. A minimum of zero, or no recorded change, always passes.
    async fn ensure_old_enough(
        &self,
        tenant: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<(), AppError> {
        if self.policy.min_age_seconds <= 0 {
            return Ok(());
        }
        let changed_at = self
            .ports
            .credential_store
            .password_changed_at(tenant, user_id)
            .await
            .or_internal()?;
        let Some(at) = changed_at else {
            return Ok(());
        };
        if (clock::now() - at).whole_seconds() < self.policy.min_age_seconds {
            return Err(AppError::Conflict(message!(
                "authentication-password-was-changed-too-recently",
                "password was changed too recently"
            )));
        }
        Ok(())
    }

    /// The hash of `new.chosen`, once it meets the tenant's rules, with what
    /// the breach check found of it.
    async fn checked_new(
        &self,
        new: NewPassword<'_>,
    ) -> Result<(PasswordHash, NewPasswordBreach), AppError> {
        let hash = PasswordSetting {
            tenants: self.ports.tenant_store.as_ref(),
            hashing: &self.ports.hashing,
        }
        .hashed(new.tenant, new.chosen)
        .await?;
        let workspace = existing_tenant(self.ports.tenant_store.as_ref(), new.tenant).await?;
        let breach = self.ports.new_password.screened(&workspace, new).await?;
        Ok((hash, breach))
    }

    /// Refuses the current password or one of the recent ones: as many as
    /// the tenant's policy counts, and at least as many as the deployment's,
    /// when it keeps a history.
    async fn ensure_not_recently_used(
        &self,
        new: NewPassword<'_>,
        current: &PasswordHash,
    ) -> Result<(), AppError> {
        let workspace = existing_tenant(self.ports.tenant_store.as_ref(), new.tenant).await?;
        let earlier = Earlier {
            current: Some(current),
            hashing: &self.ports.hashing,
        };
        self.ports
            .new_password
            .ensure_not_repeated(&workspace, new, earlier)
            .await?;
        self.ensure_not_in_history(new, current).await
    }

    /// Refuses the current password or one of the deployment's retired
    /// ones, as many as its policy counts, when it keeps a history.
    ///
    /// Each stored hash is verified against the new password: hashes are
    /// salted, so comparing a fresh hash with a stored one never matches.
    /// The checks run one after another under a single permit.
    ///
    /// # Errors
    ///
    /// - `AppError::Conflict` when the new password was used recently.
    /// - `AppError::Busy` when no hash could start on this node in time.
    /// - `AppError::Internal` when the history cannot be read or a hash
    ///   cannot be checked.
    async fn ensure_not_in_history(
        &self,
        new: NewPassword<'_>,
        current: &PasswordHash,
    ) -> Result<(), AppError> {
        let count = self.policy.history_check_count;
        let Some(history) = self.ports.password_history.as_ref().filter(|_| count > 0) else {
            return Ok(());
        };
        let user_id = new.account.id();
        let retired = history
            .recent(new.tenant, user_id, count)
            .await
            .or_internal()?;
        let hasher = self.ports.hashing.permitted().await?;
        for used in std::iter::once(current).chain(&retired) {
            if hasher.verify(new.chosen.expose(), used).or_internal()? {
                return Err(AppError::Conflict(message!(
                    "authentication-password-was-recently-used",
                    "password was recently used"
                )));
            }
        }
        Ok(())
    }

    /// Retires `current` into the history, when one is kept, and stores
    /// `new` in its place. The history is written first, so one that cannot
    /// be written leaves the old password in place.
    async fn replace_hash(
        &self,
        tenant: &ScopedTenant,
        user_id: &UserId,
        current: &PasswordHash,
        new: &PasswordHash,
    ) -> Result<(), AppError> {
        if let Some(history) = &self.ports.password_history {
            history
                .record(tenant, user_id, current)
                .await
                .or_internal()?;
        }
        self.ports
            .credential_store
            .update_password_hash(tenant, user_id, new)
            .await
            .or_internal()
    }

    /// Records the change on the account, which ends every session opened
    /// before it, and keeps the session it was made from, when it was made
    /// from one.
    async fn record_change(
        &self,
        tenant: &ScopedTenant,
        holder: &mut AccountHolder,
        fresh: &FreshSignIn,
    ) -> Result<(), AppError> {
        let account = holder.account_mut();
        account.record_credential_change();
        self.ports
            .user_store
            .save(tenant, account)
            .await
            .or_internal()?;
        let AccountHolder::Session(person) = holder else {
            return Ok(());
        };
        self.keep_this_session(tenant, person, fresh).await
    }

    /// Keeps the session the change was made from through it, since its
    /// holder just proved who they are.
    async fn keep_this_session(
        &self,
        tenant: &ScopedTenant,
        person: &mut SignedInAccount,
        fresh: &FreshSignIn,
    ) -> Result<(), AppError> {
        person
            .session
            .keep_through_own_password_change(&person.account, fresh)
            .map_err(AppError::from_domain)?;
        self.ports
            .session_store
            .save(tenant, &person.session)
            .await
            .or_internal()
    }
}

impl Command for ChangeUseCase {
    type Caller = CallerContext;
    type Input = ChangeRequest;
    type Output = Result<NewPasswordBreach, AppError>;

    /// Changes the password of the person signed in to `ctx`'s session, or
    /// bound to the directory by it, once they proved who they are again.
    /// Every other session they hold ends; the one it was made from stays.
    /// Records `authentication.password_changed`. Answers what the breach
    /// check found, so a person whose tenant only warns is told.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller or one without a tenant session/directory bind; `NotFound` for no password.
    /// - `AppError::Forbidden` for inadequate fresh proof or disabled passwords; `StepUpRequired` for a missing factor code; `AccountLocked` after wrong codes.
    /// - `AppError::Conflict` for a change too soon or password reuse; `Domain` for a password outside tenant rules, including name/address, common, reused or breached values.
    /// - `AppError::Busy` when hashing cannot start in time; `Internal` on persistence or hashing failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ChangeRequest,
    ) -> Result<NewPasswordBreach, AppError> {
        let mut holder = self.ports.tenant_authorities.holder(ctx).await?;
        let tenant = ctx.tenant();
        let user_id = *holder.account().id();
        let new = NewPassword {
            tenant: &tenant,
            account: holder.account(),
            chosen: &request.new_password,
        };
        let (new_hash, breach) = self.checked_new(new).await?;
        let current = self.current_hash(&tenant, &user_id).await?;
        self.ensure_old_enough(&tenant, &user_id).await?;
        let fresh = self
            .ports
            .fresh_proofs
            .prove(&tenant, holder.account(), request.proof, ctx.origin())
            .await?;
        let mut change =
            PasswordChange::by_holder(holder.account(), &fresh).map_err(AppError::from_domain)?;
        self.ensure_not_recently_used(new, &current).await?;
        self.replace_hash(&tenant, &user_id, &current, &new_hash)
            .await?;
        self.record_change(&tenant, &mut holder, &fresh).await?;
        auditor
            .dispatch_by(&ActorRef::User(user_id), change.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(breach)
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ianua_domain::domains::authentication::credentials::password::PasswordHasher;
    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authentication::sessions::account_check::SessionCheck;
    use ianua_domain::domains::authentication::sessions::channel::SessionChannel;
    use ianua_domain::domains::authentication::sessions::mfa_factor::FactorProved;
    use ianua_domain::domains::authentication::sessions::session::{
        Session, SessionOrigin, SessionRow,
    };
    use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;
    use ianua_domain::domains::authentication::sessions::timeout::SessionTimeoutPolicy;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::test_support::fakes::{FakeHasher, SaltedFakeHasher};
    use ianua_domain::types::{
        CharacterRequirements, CredentialChange, Fact, PasswordPolicy, SessionId, TokenHash,
    };

    use super::*;
    use crate::ports::TenantScoped;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{
        FakePasswordHistory, FakeSessionStore, REENTERED_PASSWORD, hashing_with, right_password,
        wrong_password,
    };
    use crate::test_support::identity::{FakeUserStore, RecordingCredentialStore};
    use crate::test_support::tenant::tenant_store_with_password_policy;
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_ctx_with, test_session_id,
    };

    struct UnreachablePasswordHistory;

    impl TenantScoped for UnreachablePasswordHistory {}

    #[async_trait]
    impl PasswordHistory for UnreachablePasswordHistory {
        async fn recent(
            &self,
            _: &ScopedTenant,
            _: &UserId,
            _: u32,
        ) -> Result<Vec<PasswordHash>, DomainError> {
            Ok(Vec::new())
        }

        async fn record(
            &self,
            _: &ScopedTenant,
            _: &UserId,
            _: &PasswordHash,
        ) -> Result<(), DomainError> {
            Err(DomainError::infra_msg("the password history is down"))
        }
    }

    const NEW_PASSWORD: &str = "new_password_here";

    struct Fixture {
        ann: UserId,
        creds: Arc<RecordingCredentialStore>,
        sessions: Arc<FakeSessionStore>,
        users: Arc<FakeUserStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn new() -> Self {
            Self::holding(&FakeHasher)
        }

        fn holding(hasher: &dyn PasswordHasher) -> Self {
            let ann = UserId::new();
            let current = hasher.hash(REENTERED_PASSWORD).unwrap();
            Self {
                ann,
                creds: Arc::new(RecordingCredentialStore::holding(ann, &current)),
                sessions: Arc::new(FakeSessionStore::empty()),
                users: Arc::new(FakeUserStore::empty()),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self) -> ChangePorts {
            ChangePorts {
                credential_store: self.creds.clone(),
                session_store: self.sessions.clone(),
                user_store: self.users.clone(),
                tenant_store: tenant_store_with_password_policy(PasswordPolicy::relaxed()),
                ..ChangePorts::fakes()
            }
        }

        fn use_case(&self) -> ChangeUseCase {
            ChangeUseCase::new(policy(), self.ports())
        }

        fn caller(&self) -> CallerContext {
            let ctx = test_ctx();
            test_ctx_with(ctx.organization_id(), ctx.tenant_id(), self.ann)
        }

        fn change(
            &self,
            use_case: &ChangeUseCase,
            to: &str,
        ) -> Result<NewPasswordBreach, AppError> {
            self.change_proving(use_case, right_password(), to)
        }

        fn change_proving(
            &self,
            use_case: &ChangeUseCase,
            proof: ReenteredProof,
            to: &str,
        ) -> Result<NewPasswordBreach, AppError> {
            let request = ChangeRequest {
                proof,
                new_password: Secret::new(to),
            };
            block_on(use_case.execute(&self.caller(), &test_auditor(self.audit.clone()), request))
        }

        fn stored_hash(&self) -> String {
            self.creds.hash_of(&self.ann).unwrap().as_str().to_owned()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn policy() -> ChangePolicy {
        ChangePolicy {
            history_check_count: 3,
            min_age_seconds: 0,
        }
    }

    fn salted_use_case(fixture: &Fixture, hasher: SaltedFakeHasher) -> ChangeUseCase {
        let retired = hasher.hash("retired_password").unwrap();
        let history: Arc<dyn PasswordHistory> =
            Arc::new(FakePasswordHistory::with_entry(fixture.ann, retired));
        ChangeUseCase::new(
            policy(),
            ChangePorts {
                hashing: hashing_with(Arc::new(hasher)),
                password_history: Some(history),
                ..fixture.ports()
            },
        )
    }

    fn with_history(fixture: &Fixture, history: Arc<dyn PasswordHistory>) -> ChangeUseCase {
        ChangeUseCase::new(
            policy(),
            ChangePorts {
                password_history: Some(history),
                ..fixture.ports()
            },
        )
    }

    fn with_min_age(fixture: &Fixture, min_age_seconds: i64) -> ChangeUseCase {
        ChangeUseCase::new(
            ChangePolicy {
                min_age_seconds,
                ..policy()
            },
            fixture.ports(),
        )
    }

    fn aged(fixture: Fixture, seconds_ago: i64) -> Fixture {
        let current = FakeHasher.hash(REENTERED_PASSWORD).unwrap();
        Fixture {
            creds: Arc::new(
                RecordingCredentialStore::holding(fixture.ann, &current)
                    .changed_seconds_ago(seconds_ago),
            ),
            ..fixture
        }
    }

    /// A session of `user_id` signed in half an hour ago, on another device.
    fn signed_in_earlier(user_id: UserId) -> Session<ResolvedTenant> {
        let now = clock::now();
        let earlier = now - time::Duration::minutes(30);
        Session::reconstitute(SessionRow {
            id: SessionId::new(),
            user_id,
            refresh_token_hash: TokenHash::from_stored("phone".to_owned()),
            parent_id: SessionOrigin::SignIn,
            ip_address: Fact::Unknown,
            user_agent: Fact::Unknown,
            signed_in_from: Fact::Unknown,
            progress: SignInProgressRow {
                method: AuthMethod::Password,
                factor: FactorProved::NoneYet,
                owed: SecondFactor::NotOwed,
            },
            status: SessionStatus::Active,
            channel: SessionChannel::Dashboard,
            signed_in_at: earlier,
            created_at: earlier,
            last_active_at: now,
            expires_at: now + time::Duration::hours(4),
            kept_through: CredentialChange::Never,
            last_use: Fact::Unknown,
        })
        .unwrap()
    }

    fn passes_check(fixture: &Fixture, session: &Session<ResolvedTenant>) -> bool {
        let tenant = test_ctx().tenant();
        let account = block_on(fixture.users.find_by_id(&tenant, &fixture.ann))
            .unwrap()
            .unwrap();
        SessionCheck {
            account: &account,
            timeout: &SessionTimeoutPolicy::STANDARD,
            now: clock::now(),
        }
        .admits(session)
    }

    /// Ann types her password again and chooses a new one. The new hash is
    /// stored and the change recorded.
    #[test]
    fn a_changed_password_is_stored_and_recorded() {
        let fixture = Fixture::new();

        fixture.change(&fixture.use_case(), NEW_PASSWORD).unwrap();

        assert_eq!(fixture.stored_hash(), "fake$new_password_here");
        assert_eq!(fixture.recorded(), ["authentication.password_changed"]);
    }

    /// Ann changes her password from her laptop. The laptop's session keeps
    /// working; the session on the phone she lost, opened before the change,
    /// no longer counts.
    #[test]
    fn the_session_used_is_kept_and_earlier_ones_end() {
        let fixture = Fixture::new();

        fixture.change(&fixture.use_case(), NEW_PASSWORD).unwrap();

        let kept = fixture.sessions.get_session(&test_session_id()).unwrap();
        assert!(passes_check(&fixture, &kept));
        let lost_phone = signed_in_earlier(fixture.ann);
        assert!(!passes_check(&fixture, &lost_phone));
    }

    /// A wrong current password refuses the change, preserves the stored
    /// hash and records no event.
    #[test]
    fn a_wrong_current_password_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.change_proving(&fixture.use_case(), wrong_password(), NEW_PASSWORD);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.stored_hash(), "fake$correct horse battery staple");
        assert!(fixture.recorded().is_empty());
    }

    /// A signed-out caller cannot change a password and records no event.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::new();
        let use_case = ChangeUseCase::new(
            policy(),
            ChangePorts {
                tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
                ..fixture.ports()
            },
        );

        let result = fixture.change(&use_case, NEW_PASSWORD);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(fixture.recorded().is_empty());
    }

    /// Ann signs in only by passkey and never set a password. There is no
    /// password to change.
    #[test]
    fn an_account_without_a_password_has_none_to_change() {
        let fixture = Fixture {
            creds: Arc::new(RecordingCredentialStore::default()),
            ..Fixture::new()
        };

        let result = fixture.change(&fixture.use_case(), NEW_PASSWORD);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A password found in recent history produces a conflict without a change event.
    #[test]
    fn a_recently_used_password_is_refused() {
        let fixture = Fixture::new();
        let reused = FakeHasher.hash("reused_password").unwrap();
        let history = Arc::new(FakePasswordHistory::with_entry(fixture.ann, reused));
        let use_case = with_history(&fixture, history);

        let result = fixture.change(&use_case, "reused_password");

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(fixture.recorded().is_empty());
    }

    /// A real hasher salts every hash, so the same password never hashes the
    /// same way twice. Ann's retired password is still found and refused.
    #[test]
    fn a_retired_password_is_refused_although_its_hash_differs() {
        let hasher = SaltedFakeHasher::default();
        let fixture = Fixture::holding(&hasher);
        let use_case = salted_use_case(&fixture, hasher);

        let result = fixture.change(&use_case, "retired_password");

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Choosing the current password again produces a conflict even with salted hashes.
    #[test]
    fn the_current_password_cannot_be_set_again() {
        let hasher = SaltedFakeHasher::default();
        let fixture = Fixture::holding(&hasher);
        let use_case = salted_use_case(&fixture, hasher);

        let result = fixture.change(&use_case, REENTERED_PASSWORD);

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Ann picks a password she never used. It is accepted.
    #[test]
    fn a_password_never_used_before_is_accepted() {
        let hasher = SaltedFakeHasher::default();
        let fixture = Fixture::holding(&hasher);
        let use_case = salted_use_case(&fixture, hasher);

        let result = fixture.change(&use_case, "brand_new_password");

        assert!(result.is_ok());
    }

    /// Ann changes her password. The one she retired joins her history, so
    /// she cannot switch back to it soon.
    #[test]
    fn the_retired_password_joins_the_history() {
        let fixture = Fixture::new();
        let history = Arc::new(FakePasswordHistory::empty());
        let use_case = with_history(&fixture, history.clone());

        fixture.change(&use_case, NEW_PASSWORD).unwrap();

        assert_eq!(
            history.retired(),
            vec!["fake$correct horse battery staple".to_owned()]
        );
    }

    /// The deployment keeps no password history. Ann's change goes through
    /// without a reuse check.
    #[test]
    fn no_history_check_without_a_history() {
        let fixture = Fixture::new();

        let result = fixture.change(&fixture.use_case(), NEW_PASSWORD);

        assert!(result.is_ok());
    }

    /// A password changed one minute ago cannot change again under a one-hour minimum age.
    #[test]
    fn a_change_too_soon_after_the_last_is_refused() {
        let fixture = aged(Fixture::new(), 60);

        let result = fixture.change(&with_min_age(&fixture, 3600), NEW_PASSWORD);

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Ann changed her password two hours ago, and an hour is asked for. She
    /// may change it again.
    #[test]
    fn a_change_after_the_minimum_age_is_allowed() {
        let fixture = aged(Fixture::new(), 7200);

        let result = fixture.change(&with_min_age(&fixture, 3600), NEW_PASSWORD);

        assert!(result.is_ok());
    }

    /// Ann's password is exactly the minimum age old. She may change it.
    #[test]
    fn a_password_exactly_the_minimum_age_old_can_be_changed() {
        let fixture = aged(Fixture::new(), 3600);

        let result = fixture.change(&with_min_age(&fixture, 3600), NEW_PASSWORD);

        assert!(result.is_ok());
    }

    /// A clock that disagrees between servers stamped Ann's last change a
    /// minute in the future. With no minimum age set, she is not refused as
    /// changing too recently.
    #[test]
    fn no_minimum_age_never_refuses_even_a_change_stamped_in_the_future() {
        let fixture = aged(Fixture::new(), -60);

        let result = fixture.change(&fixture.use_case(), NEW_PASSWORD);

        assert!(result.is_ok());
    }

    /// The deployment checks no history. Ann may pick a password she used
    /// before.
    #[test]
    fn switching_the_history_check_off_allows_a_recently_used_password() {
        let fixture = Fixture::new();
        let reused = FakeHasher.hash("reused_password").unwrap();
        let history: Arc<dyn PasswordHistory> =
            Arc::new(FakePasswordHistory::with_entry(fixture.ann, reused));
        let use_case = ChangeUseCase::new(
            ChangePolicy {
                history_check_count: 0,
                ..policy()
            },
            ChangePorts {
                password_history: Some(history),
                ..fixture.ports()
            },
        );

        let result = fixture.change(&use_case, "reused_password");

        assert!(result.is_ok());
    }

    fn under_strict_rules(fixture: &Fixture) -> ChangeUseCase {
        let strict = PasswordPolicy::new(12, CharacterRequirements::strict()).unwrap();
        ChangeUseCase::new(
            policy(),
            ChangePorts {
                tenant_store: tenant_store_with_password_policy(strict),
                ..fixture.ports()
            },
        )
    }

    /// The tenant's strict length and character rules refuse the password "weak".
    #[test]
    fn a_weak_password_is_refused_by_the_tenants_rules() {
        let fixture = Fixture::new();

        let result = fixture.change(&under_strict_rules(&fixture), "weak");

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Ann picks a password that meets her workspace's strict rules. It is
    /// accepted.
    #[test]
    fn a_strong_password_meets_strict_rules() {
        let fixture = Fixture::new();

        let result = fixture.change(&under_strict_rules(&fixture), "MyStr0ng!Pass");

        assert!(result.is_ok());
    }

    /// The password history cannot be written. The change fails and Ann
    /// keeps her old password, rather than a new one the history never saw.
    #[test]
    fn a_failed_history_record_fails_the_change_and_keeps_the_old_password() {
        let fixture = Fixture::new();
        let use_case = with_history(&fixture, Arc::new(UnreachablePasswordHistory));

        let result = fixture.change(&use_case, NEW_PASSWORD);

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert_eq!(fixture.stored_hash(), "fake$correct horse battery staple");
    }
}
