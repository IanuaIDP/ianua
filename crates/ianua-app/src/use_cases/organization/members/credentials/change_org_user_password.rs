//! A member changing their own password, proving it is them with the one
//! they have now.
//!
//! Every session the member has ends, the one they asked from included, so
//! whoever else held one is out.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::password::PasswordHasher as _;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, PasswordHash, PasswordPolicy};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::CredentialBreachChecker;
use crate::ports::organization::{OrgSessionStore, OrgUserStore};
use crate::services::authentication::password_hashing::PasswordHashing;
use crate::use_case::Command;
use crate::use_cases::organization::lookup::existing_member;
use crate::use_cases::organization::password_breach::ensure_password_unbreached;
use crate::use_cases::organization::sign_in::sessions::sign_out::sign_out_member;

/// The password the member has now, and the one they want instead. It
/// holds secrets, so it has no `Debug`.
pub struct ChangeOrgUserPasswordRequest {
    /// The current password, proving the caller is the member.
    pub current: Secret,
    /// The password to switch to.
    pub new: Secret,
}

/// The ports [`ChangeOrgUserPasswordUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeOrgUserPasswordPorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// The organization's members.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Checks the current password and hashes the new one, under the
    /// node's cap on hashes running at once.
    pub hashing: PasswordHashing,
    /// Members' sessions, all ended after the change.
    pub org_sessions: Arc<dyn OrgSessionStore>,
    /// Checks the new password against known breaches.
    pub breach_checker: Arc<dyn CredentialBreachChecker>,
}

/// Changes the calling member's own password.
pub struct ChangeOrgUserPasswordUseCase {
    ports: ChangeOrgUserPasswordPorts,
}

impl ChangeOrgUserPasswordUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: ChangeOrgUserPasswordPorts) -> Self {
        Self { ports }
    }

    /// The hash of `new`, once it meets `policy`.
    async fn new_hash(
        &self,
        policy: &PasswordPolicy,
        new: &Secret,
    ) -> Result<PasswordHash, AppError> {
        policy
            .validate(new.expose())
            .map_err(|error| AppError::Domain(DomainError::Validation(error)))?;
        let hasher = self.ports.hashing.permitted().await?;
        hasher.hash(new.expose()).or_internal()
    }
}

impl Command for ChangeOrgUserPasswordUseCase {
    type Caller = OrgCaller;
    type Input = ChangeOrgUserPasswordRequest;
    type Output = Result<(), AppError>;

    /// Replaces the caller's password once their current one checks out,
    /// ends every session they have and records
    /// `organization.org_user_password_changed`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an API key or invalid session; `Forbidden` for a wrong current password or no password.
    /// - `AppError::Domain` for a password outside organization rules, including blocked breached passwords.
    /// - `AppError::NotFound` for a missing member; `Busy` when hashing cannot start in time; `Internal` on hashing, persistence or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: ChangeOrgUserPasswordRequest,
    ) -> Result<(), AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        actor.signed_in()?;
        let users = self.ports.org_users.as_ref();
        let mut member = existing_member(users, organization.id(), actor.member().id()).await?;
        let config = organization.auth_config();
        let hash = self
            .new_hash(config.password_policy(), &request.new)
            .await?;
        let checker = self.ports.breach_checker.as_ref();
        ensure_password_unbreached(checker, config.breached_passwords(), &request.new).await?;
        let hasher = self.ports.hashing.permitted().await?;
        member
            .change_own_password(request.current.expose(), hash, &hasher)
            .map_err(AppError::from_domain)?;
        drop(hasher);
        users.save(&member).await.or_internal()?;
        sign_out_member(self.ports.org_sessions.as_ref(), member.id()).await?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*member.id()), member.take_events())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::credentials::breach::BreachStatus;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::members::org_user::OrgPassword;
    use ianua_domain::test_support::fakes::FakeHasher;
    use ianua_domain::types::Scope;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::authentication::{FakeBreachChecker, hashing_with};
    use crate::test_support::organization::{
        FakeOrgUserStore, RecordingOrgSessionStore, org_user_store_with, stored_caller,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    const OLD: &str = "Old-password-123!";
    const NEW: &str = "New-password-456!";

    struct Setup {
        uc: ChangeOrgUserPasswordUseCase,
        users: Arc<FakeOrgUserStore>,
        sessions: Arc<RecordingOrgSessionStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn as_caller(actors: FakeOrgActors) -> Self {
            Self::checking(actors, FakeBreachChecker::default())
        }

        /// The caller as `actors` say, with new passwords checked by
        /// `breaches`.
        fn checking(actors: FakeOrgActors, breaches: FakeBreachChecker) -> Self {
            let users = Arc::new(org_user_store_with([stored_caller(OrgRole::Member, OLD)]));
            let sessions = Arc::new(RecordingOrgSessionStore::new());
            Self {
                uc: ChangeOrgUserPasswordUseCase::new(ChangeOrgUserPasswordPorts {
                    org_actors: Arc::new(actors),
                    org_users: users.clone(),
                    hashing: hashing_with(Arc::new(FakeHasher)),
                    org_sessions: sessions.clone(),
                    breach_checker: Arc::new(breaches),
                }),
                users,
                sessions,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn new() -> Self {
            Self::as_caller(FakeOrgActors::in_role(OrgRole::Member))
        }

        fn change(&self, current: &str, new: &str) -> Result<(), AppError> {
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                ChangeOrgUserPasswordRequest {
                    current: Secret::new(current),
                    new: Secret::new(new),
                },
            ))
        }

        fn password_is(&self, password: &str) -> bool {
            let sam = block_on(self.users.find_by_id(test_org_caller().member()))
                .unwrap()
                .unwrap();
            let OrgPassword::Set(hash) = sam.password_hash() else {
                return false;
            };
            FakeHasher.verify(password, hash).unwrap()
        }

        fn signed_out(&self) -> bool {
            self.sessions.revoked(test_org_caller().member())
        }
    }

    /// Sam types his current password and a new one. The new one is saved,
    /// every session of his ends, and the change is recorded.
    #[test]
    fn the_right_current_password_changes_it_and_signs_out_every_session() {
        let setup = Setup::new();

        setup.change(OLD, NEW).unwrap();

        assert!(setup.password_is(NEW));
        assert!(setup.signed_out());
        assert_eq!(
            *setup.audit.records.lock().unwrap(),
            ["organization.org_user_password_changed"]
        );
    }

    /// An incorrect current password prevents replacement; the current
    /// password still verifies and sessions remain open.
    #[test]
    fn a_wrong_current_password_is_refused_and_changes_nothing() {
        let setup = Setup::new();

        let result = setup.change("not-the-old-one", NEW);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.password_is(OLD));
        assert!(!setup.signed_out());
    }

    /// Sam picks a new password far too short for the organization's
    /// rules. It is refused and the old one stays.
    #[test]
    fn a_new_password_breaking_the_rules_is_refused() {
        let setup = Setup::new();

        let result = setup.change(OLD, "x");

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(setup.password_is(OLD));
    }

    /// A replacement reported as breached is refused; the current password
    /// still verifies and no change is recorded.
    #[test]
    fn a_breached_new_password_is_refused() {
        let setup = Setup::checking(
            FakeOrgActors::in_role(OrgRole::Member),
            FakeBreachChecker {
                status: BreachStatus::Breached(3),
            },
        );

        let result = setup.change(OLD, NEW);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(setup.password_is(OLD));
        assert!(setup.audit.records.lock().unwrap().is_empty());
    }

    /// An API key cannot change a password even with the correct current
    /// password, which remains usable.
    #[test]
    fn an_api_key_cannot_change_a_password() {
        let setup = Setup::as_caller(FakeOrgActors::through_key(
            OrgRole::Member,
            Vec::<Scope>::new(),
        ));

        let result = setup.change(OLD, NEW);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(setup.password_is(OLD));
    }

    /// A signed-out caller must authenticate before changing their password.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = setup.change(OLD, NEW);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Refused organization authority prevents a password change.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::refusing(Refusal::Forbidden));

        let result = setup.change(OLD, NEW);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
