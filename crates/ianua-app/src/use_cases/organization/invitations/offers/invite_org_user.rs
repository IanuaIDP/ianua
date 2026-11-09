//! Invite org user: an owner asks someone to join the organization, and an
//! invitation goes to their address.
//!
//! An address whose account in the organization was closed gets that same
//! account back, opened again. The person returns with their history, and
//! with none of the tenant access they held until it is granted again. The
//! address may reach someone else by now, so the account's second factor
//! and passkeys go too: the invitee sets up their own.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::organization::members::control::OrgControl;
use ianua_domain::domains::organization::members::invitation::{
    CreateOrgInvitationParams, OrgInvitation,
};
use ianua_domain::domains::organization::members::membership::OrgRole;
use ianua_domain::domains::organization::members::org_user::{
    CreateOrgUserParams, OrgPassword, OrgUser,
};
use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;
use ianua_domain::domains::organization::members::reopened::{ReopenedAccount, Withdrawn};
use ianua_domain::message;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, DisplayName, Email, OrgUserId, OrganizationId, Text};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::email::{InvitationDelivery, InvitationMailing, LinkScope};
use crate::error::{AppError, OrInternal};
use crate::ports::limits::{MailPurpose, MailThrottle};
use crate::ports::organization::{
    OrgInvitationStore, OrgMfaEnrollmentStore, OrgPasskeyStore, OrgTenantGrantStore, OrgUserStore,
};
use crate::services::limits::mail_cooldown::ensure_mail_admitted;
use crate::use_case::Command;
use crate::use_cases::organization::invitations::offers::mail::{
    OrgInvitationMail, deliver_org_invitation,
};
use crate::use_cases::organization::invitations::offers::records::InvitationRecords;

/// The ports [`InviteOrgUserUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct InviteOrgUserPorts {
    /// Saves the invited member, and finds addresses already taken.
    pub org_user_store: Arc<dyn OrgUserStore>,
    /// The tenants members were let into, withdrawn from a reopened
    /// account.
    pub tenant_grants: Arc<dyn OrgTenantGrantStore>,
    /// Members' second factors, turned off on a reopened account.
    pub enrollments: Arc<dyn OrgMfaEnrollmentStore>,
    /// Members' passkeys, removed from a reopened account.
    pub passkeys: Arc<dyn OrgPasskeyStore>,
    /// Saves invitations, and finds one already waiting.
    pub org_invitation_store: Arc<dyn OrgInvitationStore>,
    /// Who acts on the organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// Mails the invitation under the invitation policy.
    pub mailing: InvitationMailing,
    /// Lets one invitation a minute through to an address.
    pub mail_throttle: Arc<dyn MailThrottle>,
    /// Makes invitation links.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// A member just invited, and how their link went out.
#[derive(Debug)]
pub struct OrgInvited {
    /// The invited account.
    pub org_user_id: OrgUserId,
    /// Mailed, or handed to the inviter to pass on.
    pub delivery: InvitationDelivery,
}

/// Who to invite, in which role.
pub struct InviteOrgUserRequest {
    /// The address to invite.
    pub email: Email,
    /// The name the invited member gets.
    pub display_name: DisplayName,
    /// The role they hold once they accept, any of the five. The domain
    /// decides who may hand it out: only an owner invites an owner or a
    /// billing contact, and an admin invites admins.
    pub role: OrgRole,
    /// A personal message for the invitation, when given.
    pub message: Option<Text>,
    /// Where the invitation link lands.
    pub scope: LinkScope,
}

/// Invites someone into the caller's organization.
pub struct InviteOrgUserUseCase {
    ports: InviteOrgUserPorts,
}

/// The account an invitation goes to.
enum Invitee {
    /// A new account, made for the invitation.
    New(OrgUser),
    /// The organization's closed account on the address, opened again, with
    /// the domain's word that its ways in may be taken away.
    Reopened(OrgUser, ReopenedAccount),
}

impl Invitee {
    /// The invited account.
    fn member(&self) -> &OrgUser {
        match self {
            Self::New(member) | Self::Reopened(member, _) => member,
        }
    }
}

impl InviteOrgUserUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: InviteOrgUserPorts) -> Self {
        Self { ports }
    }

    /// The account the invitation goes to: the organization's closed
    /// account on `fresh`'s address, opened again as `control` invites
    /// `fresh`, or `fresh` itself when no member of the organization has the
    /// address. An account on it in another organization is never looked
    /// at, so the answer says nothing about one.
    async fn invitee(&self, fresh: OrgUser, control: &OrgControl<'_>) -> Result<Invitee, AppError> {
        let found = self
            .ports
            .org_user_store
            .find_by_email(fresh.organization_id(), fresh.email())
            .await
            .or_internal()?;
        let Some(mut closed) = found else {
            return Ok(Invitee::New(fresh));
        };
        ensure_closed(&closed)?;
        let reopened = closed
            .reopen_for_invitation(fresh.display_name().clone(), fresh.role(), control)
            .map_err(AppError::from_domain)?;
        Ok(Invitee::Reopened(closed, reopened))
    }

    /// Refuses mailing `member` an invitation when one went to their address
    /// within the last minute. Asked after every other check, so a refused
    /// request leaves the address's minute unspent.
    async fn ensure_mailable(&self, member: &OrgUser) -> Result<(), AppError> {
        let throttle = self.ports.mail_throttle.as_ref();
        ensure_mail_admitted(throttle, MailPurpose::OrgInvitation, member.email()).await
    }

    /// Refuses an address with an invitation waiting in `organization_id`.
    async fn ensure_not_yet_invited(
        &self,
        organization_id: &OrganizationId,
        email: &Email,
    ) -> Result<(), AppError> {
        let pending = self
            .ports
            .org_invitation_store
            .find_pending_by_email(organization_id, email)
            .await
            .or_internal()?;
        if pending.is_some() {
            return Err(AppError::Conflict(message!(
                "identity-pending-invitation-already-exists",
                "pending invitation already exists"
            )));
        }
        Ok(())
    }

    /// A new invitation for `invitee`, as `control` sends it, with the raw
    /// token its link carries.
    fn invitation(
        &self,
        invitee: &OrgUser,
        control: &OrgControl<'_>,
        message: Option<Text>,
    ) -> Result<(Secret, OrgInvitation), AppError> {
        let generator = self.ports.token_generator.as_ref();
        let (raw_token, token_hash) = generator.generate().or_internal()?.into_parts();
        let params = CreateOrgInvitationParams {
            token_hash,
            message,
            lifetime: self.ports.mailing.policy.lifetime,
        };
        let invitation =
            OrgInvitation::create(params, invitee, control).map_err(AppError::from_domain)?;
        Ok((raw_token, invitation))
    }

    /// Withdraws what a reopened account held, and gives back the record of
    /// its reopening, counting how much it was. A new account held nothing
    /// and has no such record.
    async fn reopening(&self, invitee: &Invitee) -> Result<Option<DomainEvent>, AppError> {
        let Invitee::Reopened(member, reopened) = invitee else {
            return Ok(None);
        };
        let tenants = self.withdrawn_access(member).await?;
        let second_factor = self.withdrawn_second_factor(member, reopened).await?;
        let passkeys = self.withdrawn_passkeys(member, reopened).await?;
        Ok(Some(reopened.recorded(Withdrawn {
            tenants,
            factors: usize::from(second_factor) + passkeys,
        })))
    }

    /// Withdraws every tenant access `member` held, and gives back how many
    /// tenants it reached.
    async fn withdrawn_access(&self, member: &OrgUser) -> Result<usize, AppError> {
        let grants = self.ports.tenant_grants.as_ref();
        let tenants = grants.list_tenant_ids(member.id()).await.or_internal()?;
        for tenant in &tenants {
            grants
                .replace_in_tenant(member.id(), tenant, &[])
                .await
                .or_internal()?;
        }
        Ok(tenants.len())
    }

    /// Turns off `member`'s second factor, in force or still being set up,
    /// and says whether there was one.
    async fn withdrawn_second_factor(
        &self,
        member: &OrgUser,
        reopened: &ReopenedAccount,
    ) -> Result<bool, AppError> {
        let enrollments = self.ports.enrollments.as_ref();
        let found = enrollments.find_by_user(member.id()).await.or_internal()?;
        let Some(mut enrollment) = found.filter(|e| e.is_active() || e.is_pending()) else {
            return Ok(false);
        };
        enrollment.withdraw(reopened).or_internal()?;
        enrollments
            .save(member.id(), &enrollment)
            .await
            .or_internal()?;
        Ok(true)
    }

    /// Removes every passkey `member` registered, and gives back how many.
    async fn withdrawn_passkeys(
        &self,
        member: &OrgUser,
        reopened: &ReopenedAccount,
    ) -> Result<usize, AppError> {
        let passkeys = self.ports.passkeys.as_ref();
        let held = passkeys.list_by_user(member.id()).await.or_internal()?;
        for passkey in &held {
            passkey
                .ensure_withdrawn_by(reopened)
                .map_err(AppError::from_domain)?;
            passkeys.delete(passkey.id()).await.or_internal()?;
        }
        Ok(held.len())
    }

    /// Withdraws what a reopened account held, saves the invited member and
    /// their invitation, then records the invitation as `by`'s, after the
    /// reopening when there was one.
    async fn keep(
        &self,
        auditor: &RequestAuditor,
        invitee: &Invitee,
        invitation: &mut OrgInvitation,
        by: ActorRef,
    ) -> Result<(), AppError> {
        let reopening = self.reopening(invitee).await?;
        let records = InvitationRecords {
            members: self.ports.org_user_store.as_ref(),
            invitations: self.ports.org_invitation_store.as_ref(),
        };
        records.save(invitee.member(), invitation).await?;
        let events = reopening
            .into_iter()
            .chain(invitation.take_events())
            .collect();
        auditor.dispatch_by(&by, events).await.or_internal()
    }

    /// The invited member, once the invitation is mailed under the
    /// invitation policy, or its link handed back where nothing is mailed.
    async fn invited(&self, mail: OrgInvitationMail<'_>) -> Result<OrgInvited, AppError> {
        let org_user_id = *mail.invitee.id();
        let delivery = deliver_org_invitation(&self.ports.mailing, mail).await?;
        Ok(OrgInvited {
            org_user_id,
            delivery,
        })
    }
}

impl Command for InviteOrgUserUseCase {
    type Caller = OrgCaller;
    type Input = InviteOrgUserRequest;
    type Output = Result<OrgInvited, AppError>;

    /// Opens an invited account for `request.email` in the caller's
    /// organization, records `organization.org_user_invited` and mails the
    /// invitation. The account has no password until the invitee accepts.
    /// On a deployment with no mail server nothing is mailed: the answer
    /// hands the caller the link to pass on.
    ///
    /// When the organization's account on the address was closed, that
    /// account is opened again instead, its tenant access, second factor
    /// and passkeys withdrawn, and `organization.org_user_reopened` is
    /// recorded first.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` for missing invitation rights, an ungrantable role or a nonowner reopening an owner.
    /// - `AppError::Conflict` for an open account/pending invitation in this organization; another organization's account is not disclosed.
    /// - `AppError::Domain` for an excessive invitation lifetime; `Upstream` for refused mail after storing the account/invitation.
    /// - `AppError::TooManyRequests` for an invitation sent within a minute; `Internal` on persistence or token failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: InviteOrgUserRequest,
    ) -> Result<OrgInvited, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        let params = CreateOrgUserParams {
            id: OrgUserId::new(),
            organization_id: *organization.id(),
            email: request.email,
            display_name: request.display_name,
            password_hash: OrgPassword::NotSet,
            role: request.role,
        };
        let fresh = OrgUser::invite(params, &control).map_err(AppError::from_domain)?;
        let invitee = self.invitee(fresh, &control).await?;
        let member = invitee.member();
        self.ensure_not_yet_invited(member.organization_id(), member.email())
            .await?;
        let (raw_token, mut invitation) = self.invitation(member, &control, request.message)?;
        self.ensure_mailable(member).await?;

        let by = ActorRef::OrgUser(*actor.member().id());
        self.keep(auditor, &invitee, &mut invitation, by).await?;
        self.invited(OrgInvitationMail {
            invitee: member,
            organization_name: organization.name().as_str(),
            raw_token: &raw_token,
            scope: &request.scope,
        })
        .await
    }
}

/// Refuses inviting the address of `member`, an account of the
/// organization, unless the account was closed.
///
/// # Errors
///
/// Returns `AppError::Conflict` when the account is still waiting, active
/// or locked.
fn ensure_closed(member: &OrgUser) -> Result<(), AppError> {
    if member.status() == OrgUserStatus::Deactivated {
        return Ok(());
    }
    Err(AppError::Conflict(message!(
        "identity-email-already-registered",
        "email already registered"
    )))
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::clock;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::{TenantId, TokenHash};

    use super::*;
    use crate::email::InvitationPolicy;
    use crate::ports::shared::MailSetup;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::authentication::FakeMfaEnrollmentStore;
    use crate::test_support::organization::{
        FakeOrgInvitationStore, FakeOrgPasskeyStore, FakeOrgTenantGrantStore, FakeOrgUserStore,
        org_user_store_with, pending_org_invitation, platform_grant, test_org_member_at,
        test_org_user,
    };
    use crate::test_support::{
        Fake, FakeEventDispatcher, FakeMailSetup, FakeMailer, block_on, test_auditor,
        test_org_caller, test_org_link_scope,
    };

    struct Setup {
        uc: InviteOrgUserUseCase,
        members: Arc<FakeOrgUserStore>,
        invitations: Arc<FakeOrgInvitationStore>,
        grants: Arc<FakeOrgTenantGrantStore>,
        enrollments: Arc<FakeMfaEnrollmentStore>,
        passkeys: Arc<FakeOrgPasskeyStore>,
        mailer: Arc<FakeMailer>,
        audit: Arc<FakeEventDispatcher>,
    }

    /// What members of the organization already hold.
    struct Held {
        grants: FakeOrgTenantGrantStore,
        enrollments: FakeMfaEnrollmentStore,
        passkeys: FakeOrgPasskeyStore,
    }

    impl Held {
        fn nothing() -> Self {
            Self {
                grants: FakeOrgTenantGrantStore::empty(),
                enrollments: FakeMfaEnrollmentStore::empty(),
                passkeys: FakeOrgPasskeyStore::empty(),
            }
        }
    }

    impl Setup {
        fn with(actors: FakeOrgActors, members: FakeOrgUserStore, mailer: FakeMailer) -> Self {
            Self::holding(actors, members, mailer, Held::nothing())
        }

        fn holding(
            actors: FakeOrgActors,
            members: FakeOrgUserStore,
            mailer: FakeMailer,
            held: Held,
        ) -> Self {
            Self::reaching(actors, members, (mailer, Fake::fake()), held)
        }

        /// An owner inviting on a deployment with no mail server.
        fn without_mail() -> Self {
            Self::reaching(
                FakeOrgActors::in_role(OrgRole::Owner),
                FakeOrgUserStore::empty(),
                (FakeMailer::new(), FakeMailSetup::not_set_up()),
                Held::nothing(),
            )
        }

        fn reaching(
            actors: FakeOrgActors,
            members: FakeOrgUserStore,
            (mailer, mail): (FakeMailer, Arc<dyn MailSetup>),
            held: Held,
        ) -> Self {
            let members = Arc::new(members);
            let invitations = Arc::new(FakeOrgInvitationStore::empty());
            let grants = Arc::new(held.grants);
            let enrollments = Arc::new(held.enrollments);
            let passkeys = Arc::new(held.passkeys);
            let mailer = Arc::new(mailer);
            Self {
                uc: InviteOrgUserUseCase::new(InviteOrgUserPorts {
                    org_user_store: members.clone(),
                    org_invitation_store: invitations.clone(),
                    tenant_grants: grants.clone(),
                    enrollments: enrollments.clone(),
                    passkeys: passkeys.clone(),
                    org_actors: Arc::new(actors),
                    mailing: InvitationMailing {
                        mailer: mailer.clone(),
                        mail,
                        ..InvitationMailing::fakes()
                    },
                    ..InviteOrgUserPorts::fakes()
                }),
                members,
                invitations,
                grants,
                enrollments,
                passkeys,
                mailer,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// Bob, whose account in the caller's organization was closed,
        /// with access to two tenants, an authenticator app and a security
        /// key he held before, and the caller acting as `actors` say.
        fn with_closed_bob(actors: FakeOrgActors) -> (Self, OrgUserId) {
            let organization = test_org_caller().organization_id();
            let bob = test_org_member_at(organization, "bob@acme.test", OrgUserStatus::Deactivated);
            let bob_id = *bob.id();
            let held = Held {
                grants: FakeOrgTenantGrantStore::holding([
                    platform_grant(&bob, TenantId::new()),
                    platform_grant(&bob, TenantId::new()),
                ]),
                enrollments: FakeMfaEnrollmentStore::active_for(bob_id),
                passkeys: FakeOrgPasskeyStore::with_passkey(organization, bob_id),
            };
            let setup = Self::holding(actors, org_user_store_with([bob]), FakeMailer::new(), held);
            (setup, bob_id)
        }

        fn access_of(&self, member: &OrgUserId) -> usize {
            block_on(self.grants.list_by_user(member)).unwrap().len()
        }

        fn has_second_factor(&self, member: OrgUserId) -> bool {
            self.enrollments
                .enrollment_of(member)
                .is_some_and(|enrollment| enrollment.is_active())
        }

        fn new() -> Self {
            Self::with(
                FakeOrgActors::in_role(OrgRole::Owner),
                FakeOrgUserStore::empty(),
                FakeMailer::new(),
            )
        }

        fn invite(&self, email: &str) -> Result<OrgUserId, AppError> {
            self.invite_as(email, OrgRole::Member)
        }

        fn invite_as(&self, email: &str, role: OrgRole) -> Result<OrgUserId, AppError> {
            self.invited(email, role).map(|invited| invited.org_user_id)
        }

        fn invited(&self, email: &str, role: OrgRole) -> Result<OrgInvited, AppError> {
            let request = InviteOrgUserRequest {
                email: Email::new(email).unwrap(),
                display_name: DisplayName::new("Bob", &DomainLimits::default().display_name)
                    .unwrap(),
                role,
                message: None,
                scope: test_org_link_scope(),
            };
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                request,
            ))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Olivia, an owner, invites Bob. He gets an account waiting to join,
    /// an invitation, a mail, and the invitation is recorded.
    #[test]
    fn an_invitation_opens_a_waiting_account_and_mails_it() {
        let setup = Setup::new();

        let bob = setup.invite("bob@acme.test").unwrap();

        assert_eq!(setup.members.get_status(&bob), Some(OrgUserStatus::Invited));
        assert_eq!(setup.invitations.count(), 1);
        assert_eq!(setup.mailer.recipients(), vec!["bob@acme.test".to_owned()]);
        assert_eq!(setup.recorded(), vec!["organization.org_user_invited"]);
    }

    /// With a mail server set up, Bob's link is mailed and Olivia is handed
    /// nothing.
    #[test]
    fn a_mailed_invitation_hands_over_no_link() {
        let setup = Setup::new();

        let invited = setup.invited("bob@acme.test", OrgRole::Member).unwrap();

        assert!(matches!(invited.delivery, InvitationDelivery::Mailed));
    }

    /// Olivia invites Bob on a deployment with no mail server. Nothing is
    /// mailed; she is handed Bob's accept link to pass on, and Bob still
    /// waits to join, his invitation recorded.
    #[test]
    fn without_mail_the_link_is_handed_to_the_inviter() {
        let setup = Setup::without_mail();

        let invited = setup.invited("bob@acme.test", OrgRole::Member).unwrap();

        let link = invited.delivery.handed_over().map(Secret::expose);
        assert!(link.is_some_and(|link| link.contains("accept-invite")));
        assert_eq!(setup.mailer.count(), 0);
        assert_eq!(
            setup.members.get_status(&invited.org_user_id),
            Some(OrgUserStatus::Invited)
        );
        assert_eq!(setup.recorded(), vec!["organization.org_user_invited"]);
    }

    /// The mail service refuses Bob's invitation. Olivia learns the mail did
    /// not go out, and the invitation stays, recorded, for her to resend.
    #[test]
    fn a_refused_invitation_mail_is_reported_and_the_invitation_kept() {
        let setup = Setup::with(
            FakeOrgActors::in_role(OrgRole::Owner),
            FakeOrgUserStore::empty(),
            FakeMailer::refusing(),
        );

        let result = setup.invite("bob@acme.test");

        assert!(matches!(result, Err(AppError::Upstream(_))));
        assert_eq!(setup.invitations.count(), 1);
        assert_eq!(setup.recorded(), vec!["organization.org_user_invited"]);
    }

    /// Bob's invitation lasts as long as the invitation policy says, from
    /// when it is sent.
    #[test]
    fn an_invitation_lasts_the_configured_time_from_when_it_is_sent() {
        let setup = Setup::new();
        let before = clock::now();

        setup.invite("bob@acme.test").unwrap();

        let lifetime = InvitationPolicy::fake().lifetime.duration();
        let invitation = block_on(setup.invitations.find_by_token_hash(
            &test_org_caller().organization_id(),
            &TokenHash::from_stored("fake_hash_0".to_owned()),
        ))
        .unwrap()
        .unwrap();
        assert!(invitation.expires_at() >= before + lifetime);
        assert!(invitation.expires_at() <= clock::now() + lifetime);
    }

    /// Bob already has an account. Inviting his address again is refused.
    #[test]
    fn an_address_with_an_account_is_refused() {
        let organization = test_org_caller().organization_id();
        let setup = Setup::with(
            FakeOrgActors::in_role(OrgRole::Owner),
            org_user_store_with([test_org_user(
                organization,
                "bob@acme.test",
                OrgRole::Member,
            )]),
            FakeMailer::new(),
        );

        let result = setup.invite("bob@acme.test");

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// An address already registered in another organization can still
    /// receive an invited account here, with the invitation recorded.
    #[test]
    fn an_address_with_an_account_elsewhere_is_invited_alike() {
        let globex = OrganizationId::new();
        let setup = Setup::with(
            FakeOrgActors::in_role(OrgRole::Owner),
            org_user_store_with([test_org_user(globex, "bob@acme.test", OrgRole::Member)]),
            FakeMailer::new(),
        );

        let bob = setup.invite("bob@acme.test").unwrap();

        assert_eq!(setup.members.get_status(&bob), Some(OrgUserStatus::Invited));
        assert_eq!(setup.recorded(), vec!["organization.org_user_invited"]);
    }

    /// Bob was invited a moment ago. A second invitation is refused.
    #[test]
    fn an_address_already_invited_is_refused() {
        let setup = Setup::new();
        setup.invite("bob@acme.test").unwrap();

        let result = setup.invite("bob@acme.test");

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// A member without invitation rights cannot invite an address, and
    /// no account is created or mail sent.
    #[test]
    fn a_member_without_the_invite_right_is_refused() {
        let setup = Setup::with(
            FakeOrgActors::in_role(OrgRole::Member),
            FakeOrgUserStore::empty(),
            FakeMailer::new(),
        );

        let result = setup.invite("sam.again@acme.test");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.members.count(), 0);
        assert!(setup.mailer.recipients().is_empty());
    }

    /// A caller refused by the organization actor port cannot create an invitation.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let setup = Setup::with(
            FakeOrgActors::refusing(Refusal::Forbidden),
            FakeOrgUserStore::empty(),
            FakeMailer::new(),
        );

        let result = setup.invite("friend@acme.test");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.invitations.count(), 0);
    }

    /// A signed-out session cannot authorize inviting a member.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::with(
            FakeOrgActors::refusing(Refusal::SignedOut),
            FakeOrgUserStore::empty(),
            FakeMailer::new(),
        );

        let result = setup.invite("friend@acme.test");

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Olivia invites Bob as an owner. Only an owner may, and she is one,
    /// so his account waits to join as an owner.
    #[test]
    fn an_owner_invites_an_owner() {
        let setup = Setup::new();

        let bob = setup.invite_as("bob@acme.test", OrgRole::Owner).unwrap();

        let stored = block_on(setup.members.find_by_id(&bob)).unwrap().unwrap();
        assert_eq!(stored.role(), OrgRole::Owner);
    }

    /// Ada, an admin, invites Bob as an admin. His account waits to join
    /// as one.
    #[test]
    fn an_admin_invites_an_admin() {
        let setup = Setup::with(
            FakeOrgActors::in_role(OrgRole::Admin),
            FakeOrgUserStore::empty(),
            FakeMailer::new(),
        );

        let bob = setup.invite_as("bob@acme.test", OrgRole::Admin).unwrap();

        let stored = block_on(setup.members.find_by_id(&bob)).unwrap().unwrap();
        assert_eq!(stored.role(), OrgRole::Admin);
    }

    /// An admin cannot invite an owner, and no account, mail or audit event
    /// is created.
    #[test]
    fn an_admin_inviting_an_owner_is_refused() {
        let setup = Setup::with(
            FakeOrgActors::in_role(OrgRole::Admin),
            FakeOrgUserStore::empty(),
            FakeMailer::new(),
        );

        let result = setup.invite_as("ada.again@acme.test", OrgRole::Owner);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.members.count(), 0);
        assert!(setup.mailer.recipients().is_empty());
        assert!(setup.recorded().is_empty());
    }

    /// An admin cannot invite a billing contact, and no invitation is stored.
    #[test]
    fn an_admin_inviting_a_billing_contact_is_refused() {
        let setup = Setup::with(
            FakeOrgActors::in_role(OrgRole::Admin),
            FakeOrgUserStore::empty(),
            FakeMailer::new(),
        );

        let result = setup.invite_as("friend@acme.test", OrgRole::Billing);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.invitations.count(), 0);
    }

    /// A viewer cannot invite another viewer, and no member account is created.
    #[test]
    fn a_viewer_inviting_is_refused() {
        let setup = Setup::with(
            FakeOrgActors::in_role(OrgRole::Viewer),
            FakeOrgUserStore::empty(),
            FakeMailer::new(),
        );

        let result = setup.invite_as("friend@acme.test", OrgRole::Viewer);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.members.count(), 0);
    }

    /// Bob left Acme and his account was closed. Olivia invites his address
    /// again. His same account waits to join, the two tenants he reached
    /// are withdrawn, he is mailed, and the reopening is recorded before
    /// the invitation.
    #[test]
    fn inviting_a_closed_account_reopens_it_without_its_old_access() {
        let (setup, bob) = Setup::with_closed_bob(FakeOrgActors::in_role(OrgRole::Owner));

        let invited = setup.invite("bob@acme.test").unwrap();

        assert_eq!(invited, bob);
        assert_eq!(setup.members.count(), 1);
        assert_eq!(setup.members.get_status(&bob), Some(OrgUserStatus::Invited));
        assert_eq!(setup.access_of(&bob), 0);
        assert_eq!(setup.invitations.count(), 1);
        assert_eq!(setup.mailer.recipients(), vec!["bob@acme.test".to_owned()]);
        assert_eq!(
            setup.recorded(),
            vec![
                "organization.org_user_reopened",
                "organization.org_user_invited"
            ]
        );
    }

    /// Reinviting a closed account disables its authenticator and removes
    /// its passkey, recording two withdrawn factors and two tenant grants.
    #[test]
    fn a_reopened_account_keeps_none_of_its_old_second_factors() {
        let (setup, bob) = Setup::with_closed_bob(FakeOrgActors::in_role(OrgRole::Owner));

        setup.invite("bob@acme.test").unwrap();

        assert!(!setup.has_second_factor(bob));
        assert_eq!(setup.passkeys.count(), 0);
        let reopened = setup.audit.payload_of("organization.org_user_reopened");
        assert_eq!(reopened.get("factors_withdrawn"), Some("2"));
        assert_eq!(reopened.get("tenants_withdrawn"), Some("2"));
    }

    /// A member without invitation rights cannot reopen a closed account;
    /// its grants, authenticator and passkey remain, with no audit event.
    #[test]
    fn a_member_without_the_invite_right_reopens_nothing() {
        let (setup, bob) = Setup::with_closed_bob(FakeOrgActors::in_role(OrgRole::Member));

        let result = setup.invite("bob@acme.test");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(
            setup.members.get_status(&bob),
            Some(OrgUserStatus::Deactivated)
        );
        assert_eq!(setup.access_of(&bob), 2);
        assert!(setup.has_second_factor(bob));
        assert_eq!(setup.passkeys.count(), 1);
        assert!(setup.recorded().is_empty());
    }

    /// A pending invitation prevents reinviting a closed account, which
    /// stays deactivated with its two tenant grants.
    #[test]
    fn a_closed_account_with_an_invitation_waiting_is_not_reopened() {
        let (setup, bob) = Setup::with_closed_bob(FakeOrgActors::in_role(OrgRole::Owner));
        let old = pending_org_invitation(
            test_org_caller().organization_id(),
            bob,
            "bob@acme.test",
            TokenHash::from_stored("old_link".to_owned()),
        );
        block_on(setup.invitations.save(&old)).unwrap();

        let result = setup.invite("bob@acme.test");

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(
            setup.members.get_status(&bob),
            Some(OrgUserStatus::Deactivated)
        );
        assert_eq!(setup.access_of(&bob), 2);
    }

    /// Bob's account is locked, not closed. Inviting his address is
    /// refused as taken, and nothing about the account changes.
    #[test]
    fn an_account_that_is_not_closed_is_not_reopened() {
        let organization = test_org_caller().organization_id();
        let bob = test_org_member_at(organization, "bob@acme.test", OrgUserStatus::Locked);
        let bob_id = *bob.id();
        let setup = Setup::with(
            FakeOrgActors::in_role(OrgRole::Owner),
            org_user_store_with([bob]),
            FakeMailer::new(),
        );

        let result = setup.invite("bob@acme.test");

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(
            setup.members.get_status(&bob_id),
            Some(OrgUserStatus::Locked)
        );
    }
}
