//! An owner correcting another member's address.
//!
//! The address changes at once and counts as unverified until the member
//! confirms it through the link mailed there: nobody vouches for a mailbox
//! they do not hold. Links mailed to the old address stop working. A member
//! moving their own address goes through the email change flow, which
//! proves them first.

use std::sync::Arc;

use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::domains::organization::members::permission::{MemberAction, OrgPermission};
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, Email, OrgUserId};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::limits::{MailPurpose, MailThrottle};
use crate::ports::organization::OrgUserStore;
use crate::services::identity::address_free::ensure_member_address_free;
use crate::services::limits::mail_cooldown::ensure_mail_admitted;
use crate::use_case::Command;
use crate::use_cases::organization::attributed::attributed;
use crate::use_cases::organization::invitations::verification::mail::OrgVerificationMail;
use crate::use_cases::organization::lookup::existing_member;

/// Whose address changes, and to what.
pub struct ChangeOrgUserEmailRequest {
    /// The member whose address changes.
    pub member: OrgUserId,
    /// The new address.
    pub email: Email,
}

/// The ports [`ChangeOrgUserEmailUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeOrgUserEmailPorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// The organization's members, to keep an address to one account in
    /// it.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Mails the member the link that confirms their new address.
    pub verification: OrgVerificationMail,
    /// Lets one confirmation link a minute through to an address.
    pub mail_throttle: Arc<dyn MailThrottle>,
}

/// Changes another member's address, unverified.
pub struct ChangeOrgUserEmailUseCase {
    ports: ChangeOrgUserEmailPorts,
}

impl ChangeOrgUserEmailUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: ChangeOrgUserEmailPorts) -> Self {
        Self { ports }
    }

    /// Refuses the address `member` moves to when another member of their
    /// organization already holds it, or a confirmation link went to it a
    /// moment ago, unless it is `old`, the member's own. An account on it in
    /// another organization leaves it open.
    async fn ensure_address_open(&self, old: &Email, member: &OrgUser) -> Result<(), AppError> {
        let email = member.email();
        if old == email {
            return Ok(());
        }
        let members = self.ports.org_users.as_ref();
        ensure_member_address_free(members, member.organization_id(), email).await?;
        let throttle = self.ports.mail_throttle.as_ref();
        ensure_mail_admitted(throttle, MailPurpose::OrgAddressConfirmation, email).await
    }
}

impl Command for ChangeOrgUserEmailUseCase {
    type Caller = OrgCaller;
    type Input = ChangeOrgUserEmailRequest;
    type Output = Result<(), AppError>;

    /// Moves `request.member` to `request.email`, unverified, mails a link
    /// to confirm it there, and records `organization.org_user_email_changed`
    /// and, once the mail is accepted,
    /// `organization.org_verification_email_sent`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` for self-change, missing member-update rights or a nonowner changing an owner.
    /// - `AppError::NotFound` for a missing organization member; `Conflict` for another member's address.
    /// - `AppError::TooManyRequests` for confirmation sent within a minute; `Internal` on persistence, link or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: ChangeOrgUserEmailRequest,
    ) -> Result<(), AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        control
            .ensure_may(
                organization.id(),
                OrgPermission::Members(MemberAction::Update),
            )
            .map_err(AppError::from_domain)?;
        let users = self.ports.org_users.as_ref();
        let mut member = existing_member(users, organization.id(), &request.member).await?;
        let old = member.email().clone();
        member
            .change_email(request.email, &control)
            .map_err(AppError::from_domain)?;
        self.ensure_address_open(&old, &member).await?;
        users.save(&member).await.or_internal()?;
        let mailed = self
            .ports
            .verification
            .send_to_member(&member, &organization)
            .await?;
        let by = ActorRef::OrgUser(*caller.member());
        let events = attributed(&by, member.take_events(), mailed);
        auditor.dispatch(&events).await.or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        FakeOrgUserStore, org_user_store_with, stored_caller, test_org_user,
    };
    use crate::test_support::{
        FakeEventDispatcher, FakeMailer, block_on, test_auditor, test_org_caller,
    };

    struct Setup {
        uc: ChangeOrgUserEmailUseCase,
        users: Arc<FakeOrgUserStore>,
        mailer: Arc<FakeMailer>,
        audit: Arc<FakeEventDispatcher>,
        alice: OrgUserId,
        owner: OrgUserId,
    }

    impl Setup {
        /// Alice, whose address is changing, an owner, Carol in the same
        /// organization and Bob in another, who each hold an address Alice
        /// might want.
        fn as_caller(actors: FakeOrgActors) -> Self {
            let organization_id = test_org_caller().organization_id();
            let alice = test_org_user(organization_id, "alice@acme.test", OrgRole::Member);
            let owner = test_org_user(organization_id, "olivia@acme.test", OrgRole::Owner);
            let carol = test_org_user(organization_id, "carol@acme.test", OrgRole::Member);
            let bob = test_org_user(OrganizationId::new(), "bob@other.test", OrgRole::Member);
            let (alice_id, owner_id) = (*alice.id(), *owner.id());
            let users = Arc::new(org_user_store_with([
                alice,
                owner,
                carol,
                bob,
                stored_caller(OrgRole::Owner, "pw"),
            ]));
            let mailer = Arc::new(FakeMailer::new());
            Self {
                uc: ChangeOrgUserEmailUseCase::new(ChangeOrgUserEmailPorts {
                    mail_throttle: Arc::new(crate::test_support::OpenMailThrottle),
                    org_actors: Arc::new(actors),
                    org_users: users.clone(),
                    verification: OrgVerificationMail {
                        mailer: mailer.clone(),
                        ..OrgVerificationMail::fakes()
                    },
                }),
                users,
                mailer,
                audit: Arc::new(FakeEventDispatcher::new()),
                alice: alice_id,
                owner: owner_id,
            }
        }

        fn change(&self, member: OrgUserId, address: &str) -> Result<(), AppError> {
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                ChangeOrgUserEmailRequest {
                    member,
                    email: Email::new(address).unwrap(),
                },
            ))
        }

        fn stored(&self, member: OrgUserId) -> OrgUser {
            block_on(self.users.find_by_id(&member)).unwrap().unwrap()
        }
    }

    /// Olivia, an owner, corrects Alice's address to one nobody holds. It
    /// changes at once, unverified until Alice confirms it, and the change
    /// is recorded.
    #[test]
    fn an_owner_moves_a_member_to_a_free_address_unverified() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Owner));

        setup.change(setup.alice, "alice@new.test").unwrap();

        let alice = setup.stored(setup.alice);
        assert_eq!(alice.email().as_str(), "alice@new.test");
        assert!(!alice.email_verified());
        assert_eq!(
            *setup.audit.records.lock().unwrap(),
            [
                "organization.org_user_email_changed",
                "organization.org_verification_email_sent"
            ]
        );
    }

    /// Olivia corrects Alice's address. A link to confirm it goes to the
    /// new address, not the old one.
    #[test]
    fn the_new_address_is_mailed_a_link_to_confirm_it() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Owner));

        setup.change(setup.alice, "alice@new.test").unwrap();

        assert_eq!(setup.mailer.recipients(), ["alice@new.test"]);
    }

    /// Moving Alice onto Carol's address in the same organization conflicts;
    /// Alice keeps her own address.
    #[test]
    fn an_address_another_member_holds_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Owner));

        let result = setup.change(setup.alice, "carol@acme.test");

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(
            setup.stored(setup.alice).email().as_str(),
            "alice@acme.test"
        );
    }

    /// Bob holds bob@other.test in another organization. Olivia moves Alice
    /// onto it in Acme: an address is unique within an organization only.
    #[test]
    fn an_address_held_in_another_organization_is_open() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Owner));

        setup.change(setup.alice, "bob@other.test").unwrap();

        assert_eq!(setup.stored(setup.alice).email().as_str(), "bob@other.test");
    }

    /// Setting Alice's address to the one she has is no conflict with
    /// herself.
    #[test]
    fn keeping_the_same_address_is_not_a_conflict_with_oneself() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Owner));

        setup.change(setup.alice, "alice@acme.test").unwrap();

        assert_eq!(
            setup.stored(setup.alice).email().as_str(),
            "alice@acme.test"
        );
    }

    /// A plain member cannot replace an owner's address, which stays unchanged.
    #[test]
    fn a_member_moving_an_owners_address_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Member));

        let result = setup.change(setup.owner, "sam@evil.test");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(
            setup.stored(setup.owner).email().as_str(),
            "olivia@acme.test"
        );
    }

    /// A plain member naming a taken address receives a permission refusal
    /// rather than an address conflict.
    #[test]
    fn a_member_who_may_not_move_the_address_learns_nothing_of_a_taken_one() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Member));

        let result = setup.change(setup.owner, "carol@acme.test");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A plain member naming an absent member receives a permission refusal
    /// rather than a not-found response.
    #[test]
    fn a_member_who_may_not_update_members_learns_nothing_of_an_unknown_one() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Member));

        let result = setup.change(OrgUserId::new(), "sam@evil.test");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An owner cannot use the administrative address change on their own account.
    #[test]
    fn moving_ones_own_address_here_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Owner));

        let result = setup.change(*test_org_caller().member(), "mallory@evil.test");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller must authenticate before changing another member's address.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = setup.change(setup.alice, "alice@new.test");

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Refused organization authority prevents changing Alice's address.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::refusing(Refusal::Forbidden));

        let result = setup.change(setup.alice, "alice@new.test");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
