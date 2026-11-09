//! An owner adding a member straight away, with a password they chose,
//! rather than inviting them.
//!
//! The member is active at once, but their address counts as unverified
//! until they confirm it through the link mailed there: nobody adding an
//! account vouches for a mailbox they do not hold.

use std::sync::Arc;

use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::control::OrgControl;
use ianua_domain::domains::organization::members::membership::OrgRole;
use ianua_domain::domains::organization::members::org_user::{
    AddedBy, CreateOrgUserParams, OrgPassword, OrgUser,
};
use ianua_domain::domains::organization::members::permission::{MemberAction, OrgPermission};
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, DisplayName, Email, OrgUserId, PasswordHash};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::limits::{MailPurpose, MailThrottle};
use crate::ports::organization::OrgUserStore;
use crate::services::identity::address_free::ensure_member_address_free;
use crate::services::limits::mail_cooldown::ensure_mail_admitted;
use crate::use_case::Command;
use crate::use_cases::identity::users::credentials::new_password::PasswordMaker;
use crate::use_cases::organization::attributed::attributed;
use crate::use_cases::organization::invitations::verification::mail::OrgVerificationMail;

/// Who to add. It holds a password, so it has no `Debug`.
pub struct CreateOrgUserRequest {
    /// Their address.
    pub email: Email,
    /// The name they are shown by.
    pub display_name: DisplayName,
    /// The password the owner chose for them.
    pub password: String,
    /// Their role, any of the five. The domain decides who may hand it
    /// out: only an owner adds an owner or a billing contact, and an admin
    /// adds admins.
    pub role: OrgRole,
}

/// The member added.
pub struct CreateOrgUserResult {
    /// The new member's id.
    pub id: OrgUserId,
}

/// The ports [`CreateOrgUserUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreateOrgUserPorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// The organization's members, to keep an address to one account in
    /// it.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Checks the chosen password against the organization's rules and
    /// hashes it.
    pub passwords: Arc<PasswordMaker>,
    /// Mails the new member the link that confirms their address.
    pub verification: OrgVerificationMail,
    /// Lets one confirmation link a minute through to an address.
    pub mail_throttle: Arc<dyn MailThrottle>,
}

/// Adds a member with a known password.
pub struct CreateOrgUserUseCase {
    ports: CreateOrgUserPorts,
}

impl CreateOrgUserUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: CreateOrgUserPorts) -> Self {
        Self { ports }
    }

    /// Refuses mailing `member` a confirmation link when one went to their
    /// address a moment ago. Asked after every other check, so a refused
    /// request leaves the address's minute unspent.
    async fn ensure_mailable(&self, member: &OrgUser) -> Result<(), AppError> {
        let throttle = self.ports.mail_throttle.as_ref();
        ensure_mail_admitted(
            throttle,
            MailPurpose::OrgAddressConfirmation,
            member.email(),
        )
        .await
    }
}

impl Command for CreateOrgUserUseCase {
    type Caller = OrgCaller;
    type Input = CreateOrgUserRequest;
    type Output = Result<CreateOrgUserResult, AppError>;

    /// Adds the member `request` describes to the caller's organization,
    /// mails them a link to confirm their address, and records
    /// `organization.org_user_created` and, once the mail is accepted,
    /// `organization.org_verification_email_sent`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without creation rights, owner rights to grant owner/billing, or owner/admin rights to grant admin.
    /// - `AppError::Conflict` for another member's address; `Domain` for a password outside organization rules.
    /// - `AppError::TooManyRequests` for confirmation sent within a minute; `Internal` on hashing, persistence, link or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        mut request: CreateOrgUserRequest,
    ) -> Result<CreateOrgUserResult, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        ensure_may_create_members(&control, &organization)?;
        let members = self.ports.org_users.as_ref();
        ensure_member_address_free(members, organization.id(), &request.email).await?;
        let policy = organization.auth_config().password_policy();
        let password = std::mem::take(&mut request.password);
        let made = self.ports.passwords.made(policy, Some(password)).await?;
        let mut member = new_member(control, &organization, request, made.hash)?;
        self.ensure_mailable(&member).await?;
        members.save(&member).await.or_internal()?;
        let mailed = self
            .ports
            .verification
            .send_to_member(&member, &organization)
            .await?;
        let by = ActorRef::OrgUser(*caller.member());
        let events = attributed(&by, member.take_events(), mailed);
        auditor.dispatch(&events).await.or_internal()?;
        Ok(CreateOrgUserResult { id: *member.id() })
    }
}

/// Refuses a caller who may not create members of `organization`, before
/// anything about the address they named is looked up.
fn ensure_may_create_members(
    control: &OrgControl<'_>,
    organization: &Organization,
) -> Result<(), AppError> {
    control
        .ensure_may(
            organization.id(),
            OrgPermission::Members(MemberAction::Create),
        )
        .map_err(AppError::from_domain)
}

/// The member `request` asks for in `organization`, with the password hash
/// `hash`, added by the member `control` speaks for.
fn new_member(
    control: OrgControl<'_>,
    organization: &Organization,
    request: CreateOrgUserRequest,
    hash: PasswordHash,
) -> Result<OrgUser, AppError> {
    let params = CreateOrgUserParams {
        id: OrgUserId::new(),
        organization_id: *organization.id(),
        email: request.email,
        display_name: request.display_name,
        password_hash: OrgPassword::Set(hash),
        role: request.role,
    };
    OrgUser::create(params, AddedBy::Member(control)).map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{FakeOrgUserStore, org_user_store_with, test_org_user};
    use crate::test_support::{
        FakeEventDispatcher, FakeMailer, OneMailThrottle, OpenMailThrottle, block_on, test_auditor,
        test_org_caller,
    };

    const PASSWORD: &str = "Chosen-password-123!";

    struct Setup {
        uc: CreateOrgUserUseCase,
        users: Arc<FakeOrgUserStore>,
        mailer: Arc<FakeMailer>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn as_caller(actors: FakeOrgActors) -> Self {
            Self::behind(actors, Arc::new(OpenMailThrottle))
        }

        fn behind(actors: FakeOrgActors, mail_throttle: Arc<dyn MailThrottle>) -> Self {
            let bob = test_org_user(OrganizationId::new(), "bob@other.test", OrgRole::Member);
            let acme = test_org_caller().organization_id();
            let carol = test_org_user(acme, "carol@acme.test", OrgRole::Member);
            let users = Arc::new(org_user_store_with([bob, carol]));
            let mailer = Arc::new(FakeMailer::new());
            Self {
                uc: CreateOrgUserUseCase::new(CreateOrgUserPorts {
                    org_actors: Arc::new(actors),
                    org_users: users.clone(),
                    verification: OrgVerificationMail {
                        mailer: mailer.clone(),
                        ..OrgVerificationMail::fakes()
                    },
                    mail_throttle,
                    ..CreateOrgUserPorts::fakes()
                }),
                users,
                mailer,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn add(&self, email: &str, role: OrgRole, password: &str) -> Result<OrgUserId, AppError> {
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                CreateOrgUserRequest {
                    email: Email::new(email).unwrap(),
                    display_name:
                        DisplayName::new("Sam", &DomainLimits::default().display_name).unwrap(),
                    password: password.to_owned(),
                    role,
                },
            ))
            .map(|created| created.id)
        }
    }

    /// Olivia, an owner, adds Sam. He is an active member of Acme with an
    /// unverified address, and the addition is recorded.
    #[test]
    fn an_owner_adds_an_active_member_with_an_unverified_address() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Owner));

        let sam = setup
            .add("sam@acme.test", OrgRole::Member, PASSWORD)
            .unwrap();

        let stored = block_on(setup.users.find_by_id(&sam)).unwrap().unwrap();
        assert_eq!(stored.status(), OrgUserStatus::Active);
        assert_eq!(
            *stored.organization_id(),
            test_org_caller().organization_id()
        );
        assert!(!stored.email_verified());
        assert_eq!(
            *setup.audit.records.lock().unwrap(),
            [
                "organization.org_user_created",
                "organization.org_verification_email_sent"
            ]
        );
    }

    /// Olivia adds Sam. A link to confirm his address goes to it, since
    /// Olivia typing it in vouches for nothing.
    #[test]
    fn the_new_member_is_mailed_a_link_to_confirm_their_address() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Owner));

        setup
            .add("sam@acme.test", OrgRole::Member, PASSWORD)
            .unwrap();

        assert_eq!(setup.mailer.recipients(), ["sam@acme.test"]);
    }

    /// A duplicate address within Acme is refused, leaving the member count unchanged.
    #[test]
    fn an_address_a_member_of_the_organization_holds_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Owner));

        let result = setup.add("carol@acme.test", OrgRole::Member, PASSWORD);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(setup.users.count(), 2);
    }

    /// Bob is a member of another organization. Olivia adds him to Acme on
    /// the same address: an address is unique within an organization only.
    #[test]
    fn an_address_held_in_another_organization_is_added() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Owner));

        let result = setup.add("bob@other.test", OrgRole::Member, PASSWORD);

        assert!(result.is_ok());
        assert_eq!(setup.users.count(), 3);
    }

    /// A password far too short for the organization's rules is refused.
    #[test]
    fn a_password_breaking_the_rules_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Owner));

        let result = setup.add("sam@acme.test", OrgRole::Member, "x");

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(setup.users.count(), 2);
    }

    /// Olivia mistypes Sam's password and is refused. Nothing was mailed, so
    /// her corrected retry goes through at once instead of waiting a minute.
    #[test]
    fn a_refused_addition_leaves_the_address_free_to_mail() {
        let throttle = Arc::new(OneMailThrottle::default());
        let setup = Setup::behind(FakeOrgActors::in_role(OrgRole::Owner), throttle);
        setup
            .add("sam@acme.test", OrgRole::Member, "x")
            .unwrap_err();

        let result = setup.add("sam@acme.test", OrgRole::Member, PASSWORD);

        assert!(result.is_ok());
        assert_eq!(setup.mailer.recipients(), ["sam@acme.test"]);
    }

    /// A plain member cannot create another member; the stored count stays unchanged.
    #[test]
    fn a_member_without_the_create_right_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Member));

        let result = setup.add("eve@acme.test", OrgRole::Member, PASSWORD);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.users.count(), 2);
    }

    /// A plain member naming a taken address receives a permission refusal
    /// rather than an address conflict.
    #[test]
    fn a_member_without_the_create_right_learns_nothing_of_a_taken_address() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Member));

        let result = setup.add("carol@acme.test", OrgRole::Member, PASSWORD);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An owner's key without member-creation scope cannot add an owner.
    #[test]
    fn a_key_without_the_create_scope_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::through_key(OrgRole::Owner, Vec::new()));

        let result = setup.add("eve@acme.test", OrgRole::Owner, PASSWORD);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ada, an admin, adds Sam as an admin. He is stored as one.
    #[test]
    fn an_admin_adds_an_admin() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Admin));

        let sam = setup
            .add("sam@acme.test", OrgRole::Admin, PASSWORD)
            .unwrap();

        let stored = block_on(setup.users.find_by_id(&sam)).unwrap().unwrap();
        assert_eq!(stored.role(), OrgRole::Admin);
    }

    /// An admin cannot create an owner; the member count stays unchanged
    /// and no mail or audit record is produced.
    #[test]
    fn an_admin_adding_an_owner_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Admin));

        let result = setup.add("ada.again@acme.test", OrgRole::Owner, PASSWORD);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.users.count(), 2);
        assert!(setup.mailer.recipients().is_empty());
        assert!(setup.audit.records.lock().unwrap().is_empty());
    }

    /// An admin cannot add a billing contact, leaving the member count unchanged.
    #[test]
    fn an_admin_adding_a_billing_contact_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Admin));

        let result = setup.add("friend@acme.test", OrgRole::Billing, PASSWORD);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.users.count(), 2);
    }

    /// A signed-out caller must authenticate before creating a member.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = setup.add("sam@acme.test", OrgRole::Member, PASSWORD);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Refused organization authority prevents member creation.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::refusing(Refusal::Forbidden));

        let result = setup.add("sam@acme.test", OrgRole::Member, PASSWORD);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
