//! Accept org invitation: the invitee follows the emailed link, chooses a
//! password and joins the organization.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::password::PasswordHasher as _;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::invitations::route::InvitationRoute;
use ianua_domain::domains::organization::members::invitation::OrgInvitation;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, OrgUserId, OrganizationId, PasswordHash};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::CredentialBreachChecker;
use crate::ports::organization::{OrgInvitationStore, OrgUserStore, OrganizationStore};
use crate::ports::shared::MailSetup;
use crate::services::authentication::password_hashing::PasswordHashing;
use crate::use_case::Command;
use crate::use_cases::organization::invitations::offers::link::InvitationLinks;
use crate::use_cases::organization::invitations::offers::records::InvitationRecords;
use crate::use_cases::organization::lookup::{existing_member, existing_organization};
use crate::use_cases::organization::password_breach::ensure_password_unbreached;

/// The ports [`AcceptOrgUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AcceptOrgPorts {
    /// Loads and saves the invited member, and loads who sent it.
    pub org_user_store: Arc<dyn OrgUserStore>,
    /// Loads and saves invitations.
    pub org_invitation_store: Arc<dyn OrgInvitationStore>,
    /// Reads the organization's own password rules.
    pub organization_store: Arc<dyn OrganizationStore>,
    /// Hashes the link that was followed.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// Hashes the password the invitee chose, under the node's cap on
    /// hashes running at once.
    pub hashing: PasswordHashing,
    /// Checks the chosen password against known breaches.
    pub breach_checker: Arc<dyn CredentialBreachChecker>,
    /// Whether this deployment mails invitations, or hands their links to
    /// the inviter: only a mailed link proves the invitee's mailbox.
    pub mail: Arc<dyn MailSetup>,
}

/// The invitation link's token, and the password the invitee chose. Both
/// are secrets, so it has no `Debug`.
pub struct AcceptOrgRequest {
    /// The organization the invitation link names.
    pub organization_id: OrganizationId,
    /// The token from the invitation link.
    pub raw_token: String,
    /// The password the invitee chose.
    pub password: String,
}

/// Lets an invitee join the organization through the link mailed to them.
pub struct AcceptOrgUseCase {
    ports: AcceptOrgPorts,
}

impl AcceptOrgUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AcceptOrgPorts) -> Self {
        Self { ports }
    }

    /// The hash of `password`, once it meets the organization's own rules
    /// and passes its breach check.
    async fn password_to_store(
        &self,
        organization_id: &OrganizationId,
        password: &str,
    ) -> Result<PasswordHash, AppError> {
        let organizations = self.ports.organization_store.as_ref();
        let organization = existing_organization(organizations, organization_id).await?;
        let config = organization.auth_config();
        config
            .password_policy()
            .validate(password)
            .map_err(|error| AppError::Domain(DomainError::Validation(error)))?;
        let chosen = Secret::new(password);
        let checker = self.ports.breach_checker.as_ref();
        ensure_password_unbreached(checker, config.breached_passwords(), &chosen).await?;
        let hasher = self.ports.hashing.permitted().await?;
        hasher.hash(password).or_internal()
    }

    /// The open invitation of `organization_id` the link `raw_token`
    /// belongs to.
    ///
    /// # Errors
    ///
    /// As [`InvitationLinks::open`].
    async fn opened(
        &self,
        organization_id: &OrganizationId,
        raw_token: &str,
    ) -> Result<OrgInvitation, AppError> {
        let links = InvitationLinks {
            invitations: self.ports.org_invitation_store.as_ref(),
            token_generator: self.ports.token_generator.as_ref(),
        };
        links.open(organization_id, raw_token).await
    }

    /// The member who sent `invitation`, as they stand now.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when they are gone from the organization:
    ///   nobody vouches for the invitation any more.
    /// - `AppError::Internal` on lookup failure.
    async fn inviter_of(&self, invitation: &OrgInvitation) -> Result<OrgUser, AppError> {
        self.ports
            .org_user_store
            .find_by_id_in_org(invitation.organization_id(), invitation.invited_by())
            .await
            .or_internal()?
            .ok_or_else(|| {
                AppError::Forbidden(message!(
                    "organization-whoever-sent-the-invitation-may-no",
                    "whoever sent the invitation may no longer invite"
                ))
            })
    }
}

impl Command for AcceptOrgUseCase {
    type Caller = ();
    type Input = AcceptOrgRequest;
    type Output = Result<OrgUserId, AppError>;

    /// Accepts the invitation of `organization_id` that `request.raw_token`
    /// belongs to, lets the invited member in with the password they chose,
    /// and records `organization.org_user_invitation_accepted` and the
    /// member's `organization.org_user_status_changed`.
    ///
    /// No session is needed. Where invitations are mailed, following the
    /// link shows the reader holds the invited mailbox, so the address
    /// becomes confirmed. On a deployment with no mail server the link was
    /// handed to the inviter to pass on, which proves no mailbox, so the
    /// address stays unconfirmed. The sender is
    /// checked again as they stand now, so an invitation from someone who
    /// lost the right to send it lets nobody in. The password is held to the
    /// organization's own rules before anything is written.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` for a malformed token or password outside organization rules; `NotFound` for an unknown/answered/revoked link or missing member/organization.
    /// - `AppError::LinkExpired` for an unused expired invitation; `Forbidden` for lost sender invitation rights or a changed invited address.
    /// - `AppError::Conflict` for a member no longer joining; `Busy` when hashing cannot start in time.
    /// - `AppError::Internal` on persistence or hashing failure.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        request: AcceptOrgRequest,
    ) -> Result<OrgUserId, AppError> {
        let organization_id = &request.organization_id;
        let mut invitation = self.opened(organization_id, &request.raw_token).await?;
        let members = self.ports.org_user_store.as_ref();
        let mut invitee =
            existing_member(members, organization_id, invitation.org_user_id()).await?;
        let password_hash = self
            .password_to_store(organization_id, &request.password)
            .await?;
        let inviter = self.inviter_of(&invitation).await?;
        let route = InvitationRoute::under(self.ports.mail.reach());
        let accepted = invitation
            .accept(&invitee, &inviter, route)
            .map_err(AppError::from_domain)?;
        invitee
            .accept_invitation(password_hash, accepted)
            .map_err(AppError::from_domain)?;
        let records = InvitationRecords {
            members,
            invitations: self.ports.org_invitation_store.as_ref(),
        };
        records.save(&invitee, &invitation).await?;
        let mut events = invitation.take_events();
        events.extend(invitee.take_events());
        auditor
            .dispatch_by(&ActorRef::OrgUser(*invitee.id()), events)
            .await
            .or_internal()?;
        Ok(*invitee.id())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::credentials::breach::BreachStatus;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;
    use ianua_domain::test_support::fakes::FakeHasher;
    use ianua_domain::types::{ActedBy, TokenHash};

    use super::*;
    use crate::test_support::authentication::{FakeBreachChecker, hashing_with};
    use crate::test_support::organization::{
        FakeOrgInvitationStore, FakeOrgUserStore, expired_org_invitation, invited_org_user,
        org_invitation_from, org_store_with_strict_password_policy, org_user_store_with,
        test_org_user,
    };
    use crate::test_support::{Fake, FakeEventDispatcher, FakeMailSetup, block_on, test_auditor};

    const LINK: &str = "fake_refresh_7";
    const STRONG: &str = "Correct-Horse-Battery-Staple-42";

    fn link_hash() -> TokenHash {
        TokenHash::from_stored("fake_hash_7".to_owned())
    }

    struct Setup {
        uc: AcceptOrgUseCase,
        organization_id: OrganizationId,
        bob: OrgUserId,
        members: Arc<FakeOrgUserStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        /// Bob, invited by Olivia (an owner in `olivia_role` now) through
        /// the invitation `invitation` makes.
        fn with(
            olivia_role: OrgRole,
            invitation: impl FnOnce(&OrgUser, &OrgUser) -> OrgInvitation,
        ) -> Self {
            Self::checking(olivia_role, invitation, BreachStatus::Clean)
        }

        /// The same, with every chosen password found as `breaches` says.
        fn checking(
            olivia_role: OrgRole,
            invitation: impl FnOnce(&OrgUser, &OrgUser) -> OrgInvitation,
            breaches: BreachStatus,
        ) -> Self {
            Self::reaching(olivia_role, invitation, breaches, Fake::fake())
        }

        /// Bob's pending invitation, on a deployment with no mail server,
        /// where its link was handed to Olivia to pass on.
        fn handed_over() -> Self {
            Self::reaching(
                OrgRole::Owner,
                |olivia, bob| org_invitation_from(olivia, bob, link_hash()),
                BreachStatus::Clean,
                FakeMailSetup::not_set_up(),
            )
        }

        /// The same, on a deployment whose mail is set up as `mail` says.
        fn reaching(
            olivia_role: OrgRole,
            invitation: impl FnOnce(&OrgUser, &OrgUser) -> OrgInvitation,
            breaches: BreachStatus,
            mail: Arc<dyn MailSetup>,
        ) -> Self {
            let organization_id = OrganizationId::new();
            let olivia = test_org_user(organization_id, "olivia@acme.test", olivia_role);
            let bob = invited_org_user(organization_id, "bob@acme.test", OrgRole::Member);
            let bob_id = *bob.id();
            let invitations = FakeOrgInvitationStore::holding([invitation(&olivia, &bob)]);
            let members = Arc::new(org_user_store_with([olivia, bob]));
            Self {
                uc: AcceptOrgUseCase::new(AcceptOrgPorts {
                    org_user_store: members.clone(),
                    org_invitation_store: Arc::new(invitations),
                    organization_store: org_store_with_strict_password_policy(organization_id),
                    hashing: hashing_with(Arc::new(FakeHasher)),
                    breach_checker: Arc::new(FakeBreachChecker { status: breaches }),
                    mail,
                    ..AcceptOrgPorts::fakes()
                }),
                organization_id,
                bob: bob_id,
                members,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn pending() -> Self {
            Self::with(OrgRole::Owner, |olivia, bob| {
                org_invitation_from(olivia, bob, link_hash())
            })
        }

        fn accept(&self, password: &str) -> Result<OrgUserId, AppError> {
            let request = AcceptOrgRequest {
                organization_id: self.organization_id,
                raw_token: LINK.to_owned(),
                password: password.to_owned(),
            };
            block_on(
                self.uc
                    .execute(&(), &test_auditor(self.audit.clone()), request),
            )
        }

        fn status_of_bob(&self) -> Option<OrgUserStatus> {
            self.members.get_status(&self.bob)
        }
    }

    /// Bob follows Olivia's invitation and chooses a strong password. He
    /// joins, his address counts as confirmed, and both the acceptance and
    /// his move to active are recorded, once each.
    #[test]
    fn accepting_lets_the_invitee_in() {
        let setup = Setup::pending();

        let joined = setup.accept(STRONG).unwrap();

        assert_eq!(joined, setup.bob);
        assert_eq!(setup.status_of_bob(), Some(OrgUserStatus::Active));
        let bob = block_on(setup.members.find_by_id(&setup.bob))
            .unwrap()
            .unwrap();
        assert!(bob.email_verified());
        assert_eq!(
            setup.audit.records.lock().unwrap().clone(),
            vec![
                "organization.org_user_invitation_accepted",
                "organization.org_user_status_changed"
            ]
        );
    }

    /// Accepting an invitation handed over without mail activates the
    /// member while leaving the mailbox unconfirmed.
    #[test]
    fn a_handed_over_invitation_leaves_the_address_unconfirmed() {
        let setup = Setup::handed_over();

        setup.accept(STRONG).unwrap();

        assert_eq!(setup.status_of_bob(), Some(OrgUserStatus::Active));
        let bob = block_on(setup.members.find_by_id(&setup.bob))
            .unwrap()
            .unwrap();
        assert!(!bob.email_verified());
    }

    /// A blocked breached password prevents invitation acceptance; the
    /// member stays invited and no audit event is recorded.
    #[test]
    fn a_breached_password_is_refused() {
        let setup = Setup::checking(
            OrgRole::Owner,
            |olivia, bob| org_invitation_from(olivia, bob, link_hash()),
            BreachStatus::Breached(40),
        );

        let result = setup.accept(STRONG);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(setup.status_of_bob(), Some(OrgUserStatus::Invited));
        assert!(setup.audit.records.lock().unwrap().is_empty());
    }

    /// An invitation token with no matching link returns not found on acceptance.
    #[test]
    fn an_unknown_link_is_not_found() {
        let setup = Setup::with(OrgRole::Owner, |_, bob| {
            org_invitation_from(bob, bob, TokenHash::from_stored("other".to_owned()))
        });

        let result = setup.accept(STRONG);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Bob follows his invitation after it ran out. He is told it expired,
    /// so he can ask Olivia for another.
    #[test]
    fn an_expired_invitation_is_link_expired() {
        let setup = Setup::with(OrgRole::Owner, |_, bob| {
            expired_org_invitation(
                *bob.organization_id(),
                *bob.id(),
                bob.email().as_str(),
                link_hash(),
            )
        });

        let result = setup.accept(STRONG);

        assert!(matches!(result, Err(AppError::LinkExpired(_))));
        assert_eq!(setup.status_of_bob(), Some(OrgUserStatus::Invited));
    }

    /// A revoked invitation cannot be accepted and returns not found.
    #[test]
    fn a_revoked_invitation_is_not_found() {
        let setup = Setup::with(OrgRole::Owner, |olivia, bob| {
            let mut invitation = org_invitation_from(olivia, bob, link_hash());
            invitation.revoke(ActedBy::Platform).unwrap();
            invitation
        });

        let result = setup.accept(STRONG);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// An accepted invitation cannot be accepted again with the same link.
    #[test]
    fn a_replayed_link_is_not_found() {
        let setup = Setup::pending();
        setup.accept(STRONG).unwrap();

        let replayed = setup.accept(STRONG);

        assert!(matches!(replayed, Err(AppError::NotFound(_))));
    }

    /// Bob chooses a password that meets only the default rules. Acme asks
    /// for more, so it is refused and he still waits to join.
    #[test]
    fn a_password_below_the_organizations_rules_is_refused() {
        let setup = Setup::pending();

        let result = setup.accept("Abcdefgh1");

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(setup.status_of_bob(), Some(OrgUserStatus::Invited));
    }

    /// Acceptance is forbidden when the sender lacks invitation rights,
    /// leaving the recipient's account invited.
    #[test]
    fn an_invitation_whose_sender_may_no_longer_invite_is_refused() {
        let setup = Setup::with(OrgRole::Member, |olivia, bob| {
            org_invitation_from(olivia, bob, link_hash())
        });

        let result = setup.accept(STRONG);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.status_of_bob(), Some(OrgUserStatus::Invited));
    }

    /// An invitation whose sender is absent from the organization cannot
    /// be accepted.
    #[test]
    fn an_invitation_whose_sender_is_gone_is_refused() {
        let setup = Setup::with(OrgRole::Owner, |_, bob| {
            let stranger = test_org_user(OrganizationId::new(), "x@else.test", OrgRole::Owner);
            org_invitation_from(&stranger, bob, link_hash())
        });

        let result = setup.accept(STRONG);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
