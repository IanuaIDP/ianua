//! An owner setting another member's password: the one they chose, or one
//! drawn to the organization's rules.
//!
//! Every session the member has ends, so whoever held the old password is
//! out.

use std::sync::Arc;

use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, OrgUserId};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::CredentialBreachChecker;
use crate::ports::organization::{OrgSessionStore, OrgUserStore};
use crate::use_case::Command;
use crate::use_cases::identity::users::credentials::new_password::PasswordMaker;
use crate::use_cases::organization::lookup::existing_member;
use crate::use_cases::organization::password_breach::ensure_password_unbreached;
use crate::use_cases::organization::sign_in::sessions::sign_out::sign_out_member;

/// Whose password to set, and to what. It holds a secret, so it has no
/// `Debug`.
pub struct ResetOrgUserPasswordRequest {
    /// The member whose password changes.
    pub member: OrgUserId,
    /// The password the owner chose, or none to draw one.
    pub new_password: Option<String>,
}

/// The password set. It holds a secret, so it has no `Debug`.
pub struct ResetPasswordResult {
    /// The new password, shown once to the owner and never stored.
    pub new_password: Secret,
}

/// The ports [`ResetOrgUserPasswordUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResetOrgUserPasswordPorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// The organization's members.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Checks a chosen password, or draws one, and hashes it.
    pub passwords: Arc<PasswordMaker>,
    /// Members' sessions, all ended after the reset.
    pub org_sessions: Arc<dyn OrgSessionStore>,
    /// Checks the new password against known breaches.
    pub breach_checker: Arc<dyn CredentialBreachChecker>,
}

/// Sets another member's password.
pub struct ResetOrgUserPasswordUseCase {
    ports: ResetOrgUserPasswordPorts,
}

impl ResetOrgUserPasswordUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: ResetOrgUserPasswordPorts) -> Self {
        Self { ports }
    }
}

impl Command for ResetOrgUserPasswordUseCase {
    type Caller = OrgCaller;
    type Input = ResetOrgUserPasswordRequest;
    type Output = Result<ResetPasswordResult, AppError>;

    /// Sets `request.member`'s password, ends every session they have and
    /// records `organization.org_user_password_reset`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller names themselves, may not
    ///   update members, or acts on an owner without being one.
    /// - `AppError::NotFound` when the organization has no such member.
    /// - `AppError::Domain` when the chosen password breaks the
    ///   organization's rules, or appears in known breaches where the
    ///   organization blocks those.
    /// - `AppError::Internal` on drawing, hashing, persistence or audit
    ///   failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: ResetOrgUserPasswordRequest,
    ) -> Result<ResetPasswordResult, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        let users = self.ports.org_users.as_ref();
        let mut member = existing_member(users, organization.id(), &request.member).await?;
        let config = organization.auth_config();
        let made = self
            .ports
            .passwords
            .made(config.password_policy(), request.new_password)
            .await?;
        let checker = self.ports.breach_checker.as_ref();
        ensure_password_unbreached(checker, config.breached_passwords(), &made.secret).await?;
        member
            .change_password(made.hash, &control)
            .map_err(AppError::from_domain)?;
        users.save(&member).await.or_internal()?;
        sign_out_member(self.ports.org_sessions.as_ref(), member.id()).await?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*caller.member()), member.take_events())
            .await
            .or_internal()?;
        Ok(ResetPasswordResult {
            new_password: made.secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::credentials::breach::BreachStatus;
    use ianua_domain::domains::authentication::credentials::password::PasswordHasher;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::members::org_user::OrgPassword;
    use ianua_domain::test_support::fakes::FakeHasher;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::authentication::FakeBreachChecker;
    use crate::test_support::organization::{
        FakeOrgUserStore, RecordingOrgSessionStore, org_user_store_with, stored_caller,
        test_org_owner, test_org_user,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    const CHOSEN: &str = "Chosen-password-123!";

    struct Setup {
        uc: ResetOrgUserPasswordUseCase,
        users: Arc<FakeOrgUserStore>,
        sessions: Arc<RecordingOrgSessionStore>,
        audit: Arc<FakeEventDispatcher>,
        member: OrgUserId,
        owner: OrgUserId,
    }

    impl Setup {
        fn as_caller(actors: FakeOrgActors) -> Self {
            Self::checking(actors, FakeBreachChecker::default())
        }

        /// The caller as `actors` say, with new passwords checked by
        /// `breaches`.
        fn checking(actors: FakeOrgActors, breaches: FakeBreachChecker) -> Self {
            let organization_id = test_org_caller().organization_id();
            let member = test_org_user(organization_id, "sam@acme.test", OrgRole::Member);
            let owner = test_org_owner(organization_id, "olivia@acme.test", "Olivia-pw-123!");
            let (member_id, owner_id) = (*member.id(), *owner.id());
            let users = Arc::new(org_user_store_with([
                member,
                owner,
                stored_caller(OrgRole::Owner, "Caller-pw-123!"),
            ]));
            let sessions = Arc::new(RecordingOrgSessionStore::new());
            Self {
                uc: ResetOrgUserPasswordUseCase::new(ResetOrgUserPasswordPorts {
                    org_actors: Arc::new(actors),
                    org_users: users.clone(),
                    org_sessions: sessions.clone(),
                    breach_checker: Arc::new(breaches),
                    ..ResetOrgUserPasswordPorts::fakes()
                }),
                users,
                sessions,
                audit: Arc::new(FakeEventDispatcher::new()),
                member: member_id,
                owner: owner_id,
            }
        }

        fn reset(
            &self,
            member: OrgUserId,
            chosen: Option<&str>,
        ) -> Result<ResetPasswordResult, AppError> {
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                ResetOrgUserPasswordRequest {
                    member,
                    new_password: chosen.map(str::to_owned),
                },
            ))
        }

        fn password_is(&self, member: OrgUserId, password: &str) -> bool {
            let stored = block_on(self.users.find_by_id(&member)).unwrap().unwrap();
            let OrgPassword::Set(hash) = stored.password_hash() else {
                return false;
            };
            FakeHasher.verify(password, hash).unwrap()
        }
    }

    /// Olivia, an owner, sets Sam's password to one she chose. It is saved,
    /// Sam is signed out everywhere, and the reset is recorded.
    #[test]
    fn an_owner_sets_a_chosen_password_and_signs_the_member_out() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Owner));

        let result = setup.reset(setup.member, Some(CHOSEN)).unwrap();

        assert_eq!(result.new_password.expose(), CHOSEN);
        assert!(setup.password_is(setup.member, CHOSEN));
        assert!(setup.sessions.revoked(&setup.member));
        assert_eq!(
            *setup.audit.records.lock().unwrap(),
            ["organization.org_user_password_reset"]
        );
    }

    /// Olivia asks for a password to be drawn for Sam. The one shown to her
    /// is the one saved.
    #[test]
    fn a_drawn_password_is_shown_once_and_saved() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Owner));

        let result = setup.reset(setup.member, None).unwrap();

        assert!(setup.password_is(setup.member, result.new_password.expose()));
    }

    /// Olivia chooses a password far too short for the organization's
    /// rules. It is refused and nothing changes.
    #[test]
    fn a_chosen_password_breaking_the_rules_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Owner));

        let result = setup.reset(setup.member, Some("x"));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(!setup.sessions.revoked(&setup.member));
    }

    /// A chosen password reported as breached is refused, leaving Sam's
    /// sessions open and producing no reset record.
    #[test]
    fn a_breached_chosen_password_is_refused() {
        let setup = Setup::checking(
            FakeOrgActors::in_role(OrgRole::Owner),
            FakeBreachChecker {
                status: BreachStatus::Breached(7),
            },
        );

        let result = setup.reset(setup.member, Some(CHOSEN));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(!setup.sessions.revoked(&setup.member));
        assert!(setup.audit.records.lock().unwrap().is_empty());
    }

    /// A plain member cannot reset an owner's password; her current password
    /// still verifies.
    #[test]
    fn a_member_setting_an_owners_password_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Member));

        let result = setup.reset(setup.owner, Some(CHOSEN));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.password_is(setup.owner, "Olivia-pw-123!"));
    }

    /// An owner cannot use the administrative password reset on their own account.
    #[test]
    fn an_owner_setting_their_own_password_here_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Owner));

        let result = setup.reset(*test_org_caller().member(), Some(CHOSEN));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An owner requesting a reset for an unknown member receives not found.
    #[test]
    fn a_member_of_another_organization_is_not_found() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Owner));

        let result = setup.reset(OrgUserId::new(), Some(CHOSEN));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out caller must authenticate before resetting a password.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = setup.reset(setup.member, Some(CHOSEN));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Refused organization authority prevents resetting Sam's password.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::refusing(Refusal::Forbidden));

        let result = setup.reset(setup.member, Some(CHOSEN));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
