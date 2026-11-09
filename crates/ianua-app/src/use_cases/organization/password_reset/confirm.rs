//! The second half of a member's password reset: they follow the mailed
//! link and set a new password.
//!
//! Whoever held the old password may be the reason for the reset, so every
//! session the member held ends with it.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::password::PasswordHasher as _;
use ianua_domain::domains::authentication::mfa::enrollment::LockoutPolicy;
use ianua_domain::domains::authentication::mfa::verifier::MfaVerifier;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::tokens::password_reset::PasswordReset;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, OrgUserId, PasswordHash, TokenState};
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{CredentialBreachChecker, SecretEncryptor};
use crate::ports::organization::{
    OrgMfaEnrollmentStore, OrgSessionStore, OrgTokenStore, OrgUserStore, OrganizationStore,
};
use crate::services::authentication::member_factor::MemberFactor;
use crate::services::authentication::password_hashing::PasswordHashing;
use crate::services::authentication::refused::unusable_reset_link;
use crate::services::authentication::sign_in_steps::CodeCheck;
use crate::use_case::Command;
use crate::use_cases::organization::lookup::existing_organization;
use crate::use_cases::organization::password_breach::ensure_password_unbreached;
use crate::use_cases::organization::password_reset::links::{
    FollowedMemberReset, MemberResetLinks,
};
use crate::use_cases::organization::sign_in::sessions::sign_out::sign_out_member;

/// The ports [`ConfirmOrgResetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ConfirmOrgResetPorts {
    /// Loads and saves the member the reset is for.
    pub org_user_store: Arc<dyn OrgUserStore>,
    /// Members' reset links, spent here.
    pub token_store: Arc<dyn OrgTokenStore<PasswordReset>>,
    /// Ends every session the member holds.
    pub org_session_store: Arc<dyn OrgSessionStore>,
    /// The member's organization, for its own password rules.
    pub org_store: Arc<dyn OrganizationStore>,
    /// The member's second factor, which a reset must answer.
    pub mfa_store: Arc<dyn OrgMfaEnrollmentStore>,
    /// Opens the factor's stored secret.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Checks a code against the factor's secret.
    pub verifier: Arc<dyn MfaVerifier>,
    /// Hashes the new password, under the node's cap on hashes running at
    /// once.
    pub hashing: PasswordHashing,
    /// Hashes the link's token the way it was stored.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// Checks the new password against known breaches.
    pub breach_checker: Arc<dyn CredentialBreachChecker>,
}

/// The mailed link's token, the new password and, for a member with a
/// second factor, a code from it. It holds secrets, so it has no `Debug`.
pub struct ConfirmOrgResetRequest {
    /// The raw token from the reset email.
    pub raw_token: String,
    /// The password to set.
    pub new_password: Secret,
    /// A code from the member's second factor, when they have one.
    pub mfa_code: Option<String>,
}

/// Sets a member's new password through a reset link.
pub struct ConfirmOrgResetUseCase {
    lockout: LockoutPolicy,
    ports: ConfirmOrgResetPorts,
}

impl ConfirmOrgResetUseCase {
    /// A use case locking a second factor under `lockout`, working through
    /// `ports`.
    #[must_use]
    pub fn new(lockout: LockoutPolicy, ports: ConfirmOrgResetPorts) -> Self {
        Self { lockout, ports }
    }

    /// The link `raw_token` names and its member, while it can still set a
    /// password for that member.
    async fn usable(
        &self,
        raw_token: &str,
        now: OffsetDateTime,
    ) -> Result<FollowedMemberReset, AppError> {
        let links = MemberResetLinks {
            tokens: self.ports.token_store.as_ref(),
            members: self.ports.org_user_store.as_ref(),
            hasher: self.ports.token_generator.as_ref(),
        };
        links
            .followed(raw_token)
            .await?
            .filter(|followed| followed.link.state_for(&followed.holder, now) == TokenState::Usable)
            .ok_or_else(unusable_reset_link)
    }

    /// The hash of the password chosen, once it meets the rules of
    /// `holder`'s organization and passes its breach check.
    async fn chosen_hash(
        &self,
        holder: &OrgUser,
        chosen: &Secret,
    ) -> Result<PasswordHash, AppError> {
        let organizations = self.ports.org_store.as_ref();
        let organization = existing_organization(organizations, holder.organization_id()).await?;
        let config = organization.auth_config();
        config
            .password_policy()
            .validate(chosen.expose())
            .map_err(|e| AppError::Domain(DomainError::Validation(e)))?;
        let checker = self.ports.breach_checker.as_ref();
        ensure_password_unbreached(checker, config.breached_passwords(), chosen).await?;
        let hasher = self.ports.hashing.permitted().await?;
        hasher.hash(chosen.expose()).or_internal()
    }

    fn factor(&self) -> MemberFactor<'_> {
        MemberFactor {
            enrollments: self.ports.mfa_store.as_ref(),
            check: CodeCheck {
                encryptor: self.ports.encryptor.as_ref(),
                verifier: self.ports.verifier.as_ref(),
                lockout: self.lockout,
            },
        }
    }

    /// Spends the link, then keeps the member's new password and ends every
    /// session the member held. A link another request spent first is
    /// answered as one nobody holds, and nothing is kept.
    async fn keep(&self, followed: &FollowedMemberReset) -> Result<(), AppError> {
        let spent = self
            .ports
            .token_store
            .spend(&followed.link)
            .await
            .or_internal()?;
        if !spent {
            return Err(unusable_reset_link());
        }
        self.ports
            .org_user_store
            .save(&followed.holder)
            .await
            .or_internal()?;
        sign_out_member(self.ports.org_session_store.as_ref(), followed.holder.id()).await
    }
}

impl Command for ConfirmOrgResetUseCase {
    type Caller = ();
    type Input = ConfirmOrgResetRequest;
    type Output = Result<OrgUserId, AppError>;

    /// Sets `request.new_password` on the member the link was mailed for,
    /// and answers who that was.
    ///
    /// A member with a second factor must answer it here: someone who set
    /// one up expects it to stand between a mailbox and their membership.
    /// The link works once. Every session the member held ends, and
    /// `organization.org_user_password_changed` is recorded.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` for a malformed token or password outside organization rules, including blocked breached passwords.
    /// - `AppError::NotFound` for an unknown/expired/spent link, concurrent spend, changed mailbox or missing member/organization.
    /// - `AppError::StepUpRequired` for a missing factor code; `Forbidden` for a wrong/spent code; `AccountLocked` after wrong codes.
    /// - `AppError::Busy` when hashing cannot start in time; `Internal` on storage, hashing or session-ending failure.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        request: ConfirmOrgResetRequest,
    ) -> Result<OrgUserId, AppError> {
        let now = clock::now();
        let mut followed = self.usable(&request.raw_token, now).await?;
        let member = *followed.holder.id();
        self.factor()
            .answer(
                followed.holder.organization_id(),
                &member,
                request.mfa_code.as_deref(),
            )
            .await?;
        let hash = self
            .chosen_hash(&followed.holder, &request.new_password)
            .await?;
        let proof = followed
            .link
            .redeem(&followed.holder, now)
            .map_err(|_| unusable_reset_link())?;
        followed
            .holder
            .reset_password(hash, &proof)
            .map_err(AppError::from_domain)?;
        self.keep(&followed).await?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(member), followed.holder.take_events())
            .await
            .or_internal()?;
        Ok(member)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::credentials::breach::BreachStatus;
    use ianua_domain::domains::organization::access::token::{NewOrgToken, OrgToken, OrgTokenRow};
    use ianua_domain::domains::organization::members::org_user::OrgPassword;
    use ianua_domain::test_support::fakes::{FakeHasher, FakeMfaVerifier};
    use ianua_domain::types::{Email, Lifetime, OrganizationId, Usage};
    use time::Duration;

    use super::*;
    use crate::test_support::authentication::{
        FakeBreachChecker, FakeEncryptor, FakeMfaEnrollmentStore, Holder, hashing_with, lockout,
    };
    use crate::test_support::identity::hash_of_link;
    use crate::test_support::organization::{
        FakeOrgTokenStore, FakeOrgUserStore, RecordingOrgSessionStore,
        org_store_with_strict_password_policy, org_user_store_with, test_org_owner,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    const ADDRESS: &str = "alice@acme.test";
    const LINK: &str = "fake_refresh_0";
    const OLD_PASSWORD: &str = "Old-password-123!-and-long-enough";
    const NEW_PASSWORD: &str = "New-password-456!-and-longer";
    /// Meets the default rules but not the organization's stricter ones.
    const DEFAULT_ONLY_PASSWORD: &str = "Defaultpass123";
    const RIGHT_CODE: &str = "123456";

    struct Fixture {
        alice: OrgUserId,
        users: Arc<FakeOrgUserStore>,
        tokens: Arc<FakeOrgTokenStore<PasswordReset>>,
        sessions: Arc<RecordingOrgSessionStore>,
        enrollments: Arc<FakeMfaEnrollmentStore>,
        organization: OrganizationId,
        breaches: BreachStatus,
    }

    impl Fixture {
        /// Alice, with a password, holding a reset link `link` makes, in an
        /// organization with strict password rules.
        fn holding(link: impl FnOnce(OrgUserId) -> OrgToken<PasswordReset>) -> Self {
            let organization = OrganizationId::new();
            let alice = test_org_owner(organization, ADDRESS, OLD_PASSWORD);
            let id = *alice.id();
            Self {
                alice: id,
                users: Arc::new(org_user_store_with([alice])),
                tokens: Arc::new(FakeOrgTokenStore::holding([link(id)])),
                sessions: Arc::new(RecordingOrgSessionStore::new()),
                enrollments: Arc::new(FakeMfaEnrollmentStore::empty()),
                organization,
                breaches: BreachStatus::Clean,
            }
        }

        /// The same, with every password found in known breaches.
        fn with_every_password_breached(self) -> Self {
            Self {
                breaches: BreachStatus::Breached(5),
                ..self
            }
        }

        fn with_a_factor(self) -> Self {
            Self {
                enrollments: Arc::new(FakeMfaEnrollmentStore::active_for(Holder::member_of(
                    self.organization,
                    self.alice,
                ))),
                ..self
            }
        }

        fn confirm(&self, password: &str, code: Option<&str>) -> Result<OrgUserId, AppError> {
            let use_case = ConfirmOrgResetUseCase::new(
                lockout(),
                ConfirmOrgResetPorts {
                    org_user_store: self.users.clone(),
                    token_store: self.tokens.clone(),
                    org_session_store: self.sessions.clone(),
                    org_store: org_store_with_strict_password_policy(self.organization),
                    mfa_store: self.enrollments.clone(),
                    encryptor: Arc::new(FakeEncryptor),
                    verifier: Arc::new(FakeMfaVerifier {
                        valid_code: RIGHT_CODE.to_owned(),
                    }),
                    hashing: hashing_with(Arc::new(FakeHasher)),
                    breach_checker: Arc::new(FakeBreachChecker {
                        status: self.breaches,
                    }),
                    ..ConfirmOrgResetPorts::fakes()
                },
            );
            block_on(use_case.execute(
                &(),
                &test_auditor(Arc::new(FakeEventDispatcher::new())),
                ConfirmOrgResetRequest {
                    raw_token: LINK.to_owned(),
                    new_password: Secret::new(password),
                    mfa_code: code.map(str::to_owned),
                },
            ))
        }

        fn password_is(&self, password: &str) -> bool {
            let alice = block_on(self.users.find_by_id(&self.alice))
                .unwrap()
                .unwrap();
            let OrgPassword::Set(hash) = alice.password_hash() else {
                return false;
            };
            FakeHasher.verify(password, hash).unwrap()
        }

        fn link_spent(&self) -> bool {
            block_on(self.tokens.find_by_hash(&hash_of_link(LINK)))
                .unwrap()
                .is_some_and(|link| link.consumed_at().is_some())
        }
    }

    fn live_link(alice: OrgUserId) -> OrgToken<PasswordReset> {
        OrgToken::issue(NewOrgToken {
            token_hash: hash_of_link(LINK),
            org_user_id: alice,
            sent_to: Email::new(ADDRESS).unwrap(),
            lifetime: Lifetime::seconds(3600).unwrap(),
        })
        .unwrap()
    }

    fn expired_link(alice: OrgUserId) -> OrgToken<PasswordReset> {
        let expires_at = clock::now() - Duration::seconds(1);
        OrgToken::reconstitute(OrgTokenRow {
            token_hash: hash_of_link(LINK),
            org_user_id: alice,
            sent_to: Email::new(ADDRESS).unwrap(),
            created_at: expires_at - Duration::hours(1),
            expires_at,
            usage: Usage::Unused,
        })
        .unwrap()
    }

    /// Alice follows her live link and sets a new password. It is set, the
    /// link is spent, and every session she held ends.
    #[test]
    fn a_live_link_sets_the_new_password_and_signs_the_member_out() {
        let fixture = Fixture::holding(live_link);

        let who = fixture.confirm(NEW_PASSWORD, None).unwrap();

        assert_eq!(who, fixture.alice);
        assert!(fixture.password_is(NEW_PASSWORD));
        assert!(fixture.link_spent());
        assert!(fixture.sessions.revoked(&fixture.alice));
    }

    /// A password that misses the organization's stricter rules is rejected;
    /// the existing password and unspent reset link remain.
    #[test]
    fn a_password_meeting_only_the_default_rules_is_refused() {
        let fixture = Fixture::holding(live_link);

        let result = fixture.confirm(DEFAULT_ONLY_PASSWORD, None);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(fixture.password_is(OLD_PASSWORD));
        assert!(!fixture.link_spent());
    }

    /// A blocked breached password is rejected without replacing the
    /// existing password or spending the reset link.
    #[test]
    fn a_breached_password_is_refused() {
        let fixture = Fixture::holding(live_link).with_every_password_breached();

        let result = fixture.confirm(NEW_PASSWORD, None);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(fixture.password_is(OLD_PASSWORD));
        assert!(!fixture.link_spent());
    }

    /// An expired reset link is not found; the password stays unchanged
    /// and the member's sessions are not revoked.
    #[test]
    fn an_expired_link_cannot_set_a_password() {
        let fixture = Fixture::holding(expired_link);

        let result = fixture.confirm(NEW_PASSWORD, None);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(fixture.password_is(OLD_PASSWORD));
        assert!(!fixture.sessions.revoked(&fixture.alice));
    }

    /// Replaying a spent reset link is rejected, preserving the password
    /// set by its first use.
    #[test]
    fn a_link_cannot_set_a_password_twice() {
        let fixture = Fixture::holding(live_link);
        fixture.confirm(NEW_PASSWORD, None).unwrap();

        let second = fixture.confirm("Another-password-789!-long", None);

        assert!(matches!(second, Err(AppError::NotFound(_))));
        assert!(fixture.password_is(NEW_PASSWORD));
    }

    /// A reset link spent by a competing request is treated as not found;
    /// the losing request changes no password and revokes no sessions.
    #[test]
    fn a_link_spent_by_another_request_a_moment_before_sets_nothing() {
        let held = Fixture::holding(live_link);
        let fixture = Fixture {
            tokens: Arc::new(FakeOrgTokenStore::raced([live_link(held.alice)])),
            ..held
        };

        let result = fixture.confirm(NEW_PASSWORD, None);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(fixture.password_is(OLD_PASSWORD));
        assert!(!fixture.sessions.revoked(&fixture.alice));
    }

    /// A reset link naming a missing member is not found and cannot change
    /// the existing member's password.
    #[test]
    fn a_link_of_a_member_who_is_gone_is_not_found() {
        let fixture = Fixture::holding(|_| live_link(OrgUserId::new()));

        let result = fixture.confirm(NEW_PASSWORD, None);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(fixture.password_is(OLD_PASSWORD));
    }

    /// Alice set up a second factor. Her mailbox alone does not reset her
    /// password: she is asked for a code.
    #[test]
    fn a_member_with_a_factor_must_give_its_code() {
        let fixture = Fixture::holding(live_link).with_a_factor();

        let result = fixture.confirm(NEW_PASSWORD, None);

        assert!(matches!(result, Err(AppError::StepUpRequired)));
        assert!(fixture.password_is(OLD_PASSWORD));
    }

    /// A wrong second-factor code is refused, preserving both the current
    /// password and the unspent reset link.
    #[test]
    fn a_wrong_code_is_refused() {
        let fixture = Fixture::holding(live_link).with_a_factor();

        let result = fixture.confirm(NEW_PASSWORD, Some("999999"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(fixture.password_is(OLD_PASSWORD));
        assert!(!fixture.link_spent());
    }

    /// Alice gives her link, a new password and her code. The password is
    /// set.
    #[test]
    fn the_link_and_the_code_reset_the_password() {
        let fixture = Fixture::holding(live_link).with_a_factor();

        fixture.confirm(NEW_PASSWORD, Some(RIGHT_CODE)).unwrap();

        assert!(fixture.password_is(NEW_PASSWORD));
    }
}
