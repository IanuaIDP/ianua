//! Accept invitation: the invitee follows the link, chooses a password, and
//! their account joins the tenant with the role the invitation offers.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::password::PasswordHasher as _;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::authorization::role::Role;
use ianua_domain::domains::authorization::role_assignment::RoleAssignment;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::identity::invitations::invitation::Invitation;
use ianua_domain::domains::identity::invitations::route::InvitationRoute;
use ianua_domain::domains::identity::invitations::status::InvitationLifecycle;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, EventLabel, PasswordHash, PrincipalRef, UserId};
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authentication::CredentialStore;
use crate::ports::authorization::{RoleAssignmentStore, RoleStore, SeparationRuleStore};
use crate::ports::identity::{InvitationStore, UserStore};
use crate::ports::shared::{AuditLabelResolver, MailSetup};
use crate::ports::tenant::TenantStore;
use crate::services::authentication::new_password::{NewPassword, NewPasswordPorts};
use crate::services::authentication::password_hashing::PasswordHashing;
use crate::services::authorization::duties::{DutySources, Granting, ensure_duties_kept};
use crate::services::lookup::{existing_tenant, existing_user};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::audit_label::resolved_user_label;
use crate::use_cases::identity::invitations::inviter::{InviterPorts, inviter_now};
use crate::use_cases::identity::lookup::invitation_by_link;

/// The ports [`AcceptUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AcceptPorts {
    /// Loads and saves invitations.
    pub invitation_store: Arc<dyn InvitationStore>,
    /// What the invited account is set up through: the users, its password and its first session.
    pub account: AcceptedAccountPorts,
    /// The role the invitation gives, checked against the tenant's separation rules.
    pub roles: AcceptedRolePorts,
    /// Where what the sender holds now is read from.
    pub inviter: InviterPorts,
    /// Names the sender in the audit record.
    pub audit_label_resolver: Arc<dyn AuditLabelResolver>,
    /// Whether this deployment mails invitations, or hands their links to
    /// the inviter: only a mailed link proves the invitee's mailbox.
    pub mail: Arc<dyn MailSetup>,
}

/// What the invited account is set up through: the users, its password and its first session.
#[derive(ianua_macros::Fakes)]
pub struct AcceptedAccountPorts {
    /// Loads and saves the invited account.
    pub user_store: Arc<dyn UserStore>,
    /// Stores the password the invitee chooses.
    pub credential_store: Arc<dyn CredentialStore>,
    /// Reads the tenant's own password rules.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Hashes the link that was followed.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// Hashes the password the invitee chose, under the node's cap on
    /// hashes running at once.
    pub hashing: PasswordHashing,
    /// Checks the password against breaches and the common list.
    pub new_password: NewPasswordPorts,
}

/// The role the invitation gives, checked against the tenant's separation rules.
#[derive(ianua_macros::Fakes)]
pub struct AcceptedRolePorts {
    /// Loads the role the invitation offers.
    pub role_store: Arc<dyn RoleStore>,
    /// Records the role the invitee gets.
    pub assignment_store: Arc<dyn RoleAssignmentStore>,
    /// The tenant's separation-of-duties rules, which the role is checked
    /// against.
    pub separation_rules: Arc<dyn SeparationRuleStore>,
}

/// The invitation link's token, and the password the invitee chose.
pub struct AcceptRequest {
    /// The token from the invitation link.
    pub raw_token: String,
    /// The password chosen, if the tenant signs users in with one.
    pub password: Option<String>,
}

/// Lets an invitee join through the link mailed to them.
pub struct AcceptUseCase {
    ports: AcceptPorts,
}

impl AcceptUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AcceptPorts) -> Self {
        Self { ports }
    }

    /// The still-open invitation `raw_token` belongs to.
    async fn open_invitation(
        &self,
        tenant: &ScopedTenant,
        raw_token: &str,
    ) -> Result<Invitation<ResolvedTenant>, AppError> {
        crate::input::validate_token("token", raw_token)?;
        let token_hash = self.ports.account.token_generator.hash_raw(raw_token);
        let store = self.ports.invitation_store.as_ref();
        let invitation = invitation_by_link(store, tenant, &token_hash).await?;
        ensure_open(&invitation, clock::now())?;
        Ok(invitation)
    }

    /// The hash to store for the password the invitee chose, or `None` for a
    /// tenant without password sign-in, whose invitees choose none. Anything
    /// sent there is dropped rather than kept for the day the method is
    /// switched on.
    ///
    /// The password is held to the tenant's rules for `invitee`: its length
    /// and characters, their name and address, the common list and known
    /// breaches. A warning the tenant gives for a breached password is
    /// logged.
    async fn password_to_store(
        &self,
        tenant: &ScopedTenant,
        invitee: &User<ResolvedTenant>,
        password: Option<&str>,
    ) -> Result<Option<PasswordHash>, AppError> {
        let workspace = existing_tenant(self.ports.account.tenant_store.as_ref(), tenant).await?;
        let Some(policy) = workspace.auth_config().new_password_policy() else {
            return Ok(None);
        };
        let Some(password) = password else {
            return Err(AppError::Domain(DomainError::invalid(message!(
                "identity-password-is-required-this-tenant-signs",
                "password is required: this tenant signs its users in with one"
            ))));
        };
        policy
            .validate(password)
            .map_err(|e| AppError::Domain(DomainError::Validation(e)))?;
        let chosen = Secret::new(password);
        let new = NewPassword {
            tenant,
            account: invitee,
            chosen: &chosen,
        };
        self.ports
            .account
            .new_password
            .screened(&workspace, new)
            .await?;
        let hasher = self.ports.account.hashing.permitted().await?;
        hasher.hash(password).map(Some).or_internal()
    }

    /// The role the invitation offers, as the tenant has it now.
    async fn offered_role(
        &self,
        tenant: &ScopedTenant,
        invitation: &Invitation<ResolvedTenant>,
    ) -> Result<Role<ResolvedTenant>, AppError> {
        self.ports
            .roles
            .role_store
            .find_by_id(tenant, invitation.role_id())
            .await
            .or_internal()?
            .or_not_found(message!(
                "identity-the-role-this-invitation-offers-is",
                "the role this invitation offers is gone"
            ))
    }

    /// Refuses giving `role` to the account `invitation` was sent for when
    /// it would then hold both roles of one of the tenant's separation
    /// rules: an account waiting to join may have been given a role
    /// already.
    async fn ensure_kept_apart(
        &self,
        tenant: &ScopedTenant,
        invitation: &Invitation<ResolvedTenant>,
        role: &Role<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let duties = DutySources::of(
            self.ports.inviter.access_records.as_ref(),
            self.ports.roles.separation_rules.as_ref(),
        );
        let granting = Granting::Role {
            principal: PrincipalRef::User(*invitation.user_id()),
            role: role.id(),
        };
        ensure_duties_kept(duties, tenant, granting).await
    }

    /// The invitation accepted for its account, with the role it gives, once
    /// the sender may still hand it out.
    async fn joined(
        &self,
        tenant: &ScopedTenant,
        joining: Joining,
        role: &Role<ResolvedTenant>,
    ) -> Result<Joined, AppError> {
        let Joining {
            mut invitation,
            mut user,
            password_hash,
        } = joining;
        let inviter = inviter_now(&self.ports.inviter, tenant, invitation.invited_by()).await?;
        let route = InvitationRoute::under(self.ports.mail.reach());
        invitation
            .accept(&mut user, role, &inviter, route)
            .map_err(AppError::from_domain)?;
        let sender_label = self.sender_label(tenant, invitation.invited_by()).await;
        let assignment =
            RoleAssignment::from_accepted_invitation(&invitation, role, &user, sender_label)
                .map_err(AppError::from_domain)?;
        Ok(Joined {
            user,
            invitation,
            assignment,
            password_hash,
        })
    }

    /// Saves the chosen password, the joined account, the accepted
    /// invitation and the role it gives.
    async fn store(&self, tenant: &ScopedTenant, joined: &Joined) -> Result<(), AppError> {
        if let Some(hash) = &joined.password_hash {
            self.ports
                .account
                .credential_store
                .update_password_hash(tenant, joined.user.id(), hash)
                .await
                .or_internal()?;
        }
        self.ports
            .account
            .user_store
            .save(tenant, &joined.user)
            .await
            .or_internal()?;
        self.ports
            .invitation_store
            .save(tenant, &joined.invitation)
            .await
            .or_internal()?;
        self.ports
            .roles
            .assignment_store
            .save(tenant, &joined.assignment)
            .await
            .or_internal()
    }

    /// The label the record names the sender by.
    async fn sender_label(&self, tenant: &ScopedTenant, sender: &ActorRef) -> EventLabel {
        let ActorRef::User(id) = sender else {
            return EventLabel::of(&sender.audit_label());
        };
        resolved_user_label(self.ports.audit_label_resolver.as_ref(), tenant, id).await
    }
}

impl Command for AcceptUseCase {
    type Caller = ScopedTenant;
    type Input = AcceptRequest;
    type Output = Result<UserId, AppError>;

    /// Accepts the invitation `request.raw_token` belongs to, for the account
    /// it was sent for, and stores the password the invitee chose.
    ///
    /// No session is needed. Where invitations are mailed, following the
    /// link shows the reader holds the invited mailbox, so the address
    /// becomes confirmed. On a deployment with no mail server the link was
    /// handed to the inviter to pass on, which proves no mailbox, so the
    /// address stays unconfirmed. The deployment is read as it stands when
    /// the invitation is accepted. The role is checked
    /// again against what the sender holds now, so an invitation from someone
    /// who lost their rights gives nothing. The password is held to the
    /// tenant's own rules and checked before anything is written. Records
    /// `identity.invitation_accepted`, the account's move to active as
    /// `identity.user_status_changed`, and `authorization.role_assigned`,
    /// once everything is saved.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` for a malformed token or a missing/invalid required password; `NotFound` for an unknown/answered/revoked link or missing account/role/tenant.
    /// - `AppError::LinkExpired` for an unused expired invitation; `Forbidden` for lost sender grant rights or a changed invited address.
    /// - `AppError::Conflict` for an account no longer joining or a separation-of-duties violation.
    /// - `AppError::Busy` when hashing cannot start in time; `Internal` on persistence or hashing failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: AcceptRequest,
    ) -> Result<UserId, AppError> {
        let AcceptRequest {
            raw_token,
            password,
        } = request;
        let invitation = self.open_invitation(tenant, &raw_token).await?;
        let users = self.ports.account.user_store.as_ref();
        let user = existing_user(users, tenant, invitation.user_id()).await?;
        let password_hash = self
            .password_to_store(tenant, &user, password.as_deref())
            .await?;
        let role = self.offered_role(tenant, &invitation).await?;
        self.ensure_kept_apart(tenant, &invitation, &role).await?;
        let joining = Joining {
            invitation,
            user,
            password_hash,
        };
        let mut joined = self.joined(tenant, joining, &role).await?;

        self.store(tenant, &joined).await?;
        let mut events = joined.invitation.take_events(tenant);
        events.extend(joined.user.take_events(tenant));
        events.extend(joined.assignment.take_events(tenant));
        let actor = ActorRef::User(*joined.user.id());
        auditor.dispatch_by(&actor, events).await.or_internal()?;
        Ok(*joined.user.id())
    }
}

/// An invitation on its way to being accepted, before the sender is
/// checked.
struct Joining {
    /// The invitation being accepted.
    invitation: Invitation<ResolvedTenant>,
    /// The account it invites.
    user: User<ResolvedTenant>,
    /// The hash of the password chosen, when the tenant takes one.
    password_hash: Option<PasswordHash>,
}

/// What an accepted invitation leaves to store.
struct Joined {
    /// The account, now joined.
    user: User<ResolvedTenant>,
    /// The invitation, now accepted.
    invitation: Invitation<ResolvedTenant>,
    /// The role it gives.
    assignment: RoleAssignment<ResolvedTenant>,
    /// The hash of the password chosen, when the tenant takes one.
    password_hash: Option<PasswordHash>,
}

/// Refuses an invitation whose link ran out or was closed, telling the two
/// apart: one that ran out can be renewed.
fn ensure_open(
    invitation: &Invitation<ResolvedTenant>,
    now: OffsetDateTime,
) -> Result<(), AppError> {
    match invitation.state(now) {
        InvitationLifecycle::Pending => Ok(()),
        InvitationLifecycle::Expired => Err(AppError::LinkExpired(message!(
            "identity-this-invitation-has-expired",
            "this invitation has expired"
        ))),
        InvitationLifecycle::Closed => Err(AppError::NotFound(message!(
            "identity-invitation-already-used",
            "invitation already used"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::identity::invitations::offer::OfferState;
    use ianua_domain::types::RoleId;

    use super::*;
    use crate::ports::authorization::AccessRecords;
    use crate::test_support::authorization::{
        FakeAccessRecordStore, FakeRoleAssignmentStore, FakeRoleStore, FakeSeparationRuleStore,
        separation_between, stored_assignment, stored_role,
    };
    use crate::test_support::identity::{
        FakeInvitationStore, FakeUserStore, InvitationSeed, RecordingCredentialStore,
        access_where_holds, stored_user,
    };
    use crate::test_support::organization::strict_password_policy;
    use crate::test_support::tenant::{
        FakeTenantStore, tenant_store_with_password_policy, tenant_store_without_password_login,
    };
    use crate::test_support::{
        FakeEventDispatcher, FakeMailSetup, block_on, test_auditor, test_ctx,
    };

    const LINK: &str = "bob-invite";
    const STRONG: &str = "Correct-Horse-Battery-9";

    /// Sam, who may add users and view them, invited Bob as an editor, which
    /// lets him view users. The stores watch what accepting does.
    struct Invited {
        bob: UserId,
        users: Arc<FakeUserStore>,
        invitations: Arc<FakeInvitationStore>,
        roles: Arc<FakeRoleStore>,
        assignments: Arc<FakeRoleAssignmentStore>,
        credentials: Arc<RecordingCredentialStore>,
        tenants: Arc<FakeTenantStore>,
        records: Arc<FakeAccessRecordStore>,
        rules: Arc<FakeSeparationRuleStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Invited {
        fn by_sam_holding(sams_rights: &[SystemPermission], link: InvitationSeed) -> Self {
            let sam = UserId::new();
            let viewing = vec![SystemPermission::Users(UserAction::View)];
            let editor = stored_role("editor", viewing, Vec::new());
            let users = Arc::new(FakeUserStore::empty());
            users.add(stored_user(
                link.user_id,
                "bob@acme.com",
                UserStatus::Invited,
            ));
            users.add(stored_user(sam, "sam@acme.com", UserStatus::Active));
            let bob = link.user_id;
            let invitation = InvitationSeed {
                role_id: *editor.id(),
                ..link
            }
            .sent_by(ActorRef::User(sam))
            .stored();
            Self {
                bob,
                users,
                invitations: Arc::new(FakeInvitationStore::holding(invitation)),
                roles: Arc::new(FakeRoleStore::holding(test_ctx().tenant_id(), [editor])),
                assignments: Arc::new(FakeRoleAssignmentStore::empty()),
                credentials: Arc::new(RecordingCredentialStore::default()),
                tenants: tenant_store_with_password_policy(strict_password_policy()),
                records: access_where_holds(sam, sams_rights),
                rules: Arc::new(FakeSeparationRuleStore::empty()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn pending() -> Self {
            Self::by_sam_holding(&inviters_rights(), bobs_link())
        }

        fn ports(&self) -> AcceptPorts {
            AcceptPorts {
                invitation_store: self.invitations.clone(),
                inviter: InviterPorts {
                    access_records: self.records.clone(),
                    user_store: self.users.clone(),
                    ..InviterPorts::fakes()
                },
                account: AcceptedAccountPorts {
                    user_store: self.users.clone(),
                    credential_store: self.credentials.clone(),
                    tenant_store: self.tenants.clone(),
                    ..AcceptedAccountPorts::fakes()
                },
                roles: AcceptedRolePorts {
                    role_store: self.roles.clone(),
                    assignment_store: self.assignments.clone(),
                    separation_rules: self.rules.clone(),
                },
                ..AcceptPorts::fakes()
            }
        }

        fn accept(&self, raw_token: &str, password: Option<&str>) -> Result<UserId, AppError> {
            let use_case = AcceptUseCase::new(self.ports());
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.sink.clone()),
                AcceptRequest {
                    raw_token: raw_token.to_owned(),
                    password: password.map(str::to_owned),
                },
            ))
        }

        fn bobs_status(&self) -> Option<UserStatus> {
            self.users.get_status(&self.bob)
        }
    }

    fn inviters_rights() -> Vec<SystemPermission> {
        vec![
            SystemPermission::Users(UserAction::Create),
            SystemPermission::Users(UserAction::View),
        ]
    }

    fn bobs_link() -> InvitationSeed {
        InvitationSeed::for_user(UserId::new(), "bob@acme.com", RoleId::new(), LINK)
    }

    /// Bob accepts with a strong password. He joins, his address is
    /// confirmed, his password is kept, he holds the editor role, and the
    /// acceptance, his move to active and the role are each recorded once.
    #[test]
    fn accepting_lets_the_invitee_in_with_the_offered_role() {
        let invited = Invited::pending();

        let bob = invited.accept(LINK, Some(STRONG)).unwrap();

        assert_eq!(invited.bobs_status(), Some(UserStatus::Active));
        assert!(invited.credentials.hash_of(&bob).is_some());
        assert_eq!(invited.assignments.count(), 1);
        assert_eq!(
            invited.sink.records.lock().unwrap().as_slice(),
            [
                "identity.invitation_accepted",
                "identity.user_status_changed",
                "authorization.role_assigned"
            ]
        );
    }

    /// Whether Bob's address counts as confirmed now.
    fn bobs_address_confirmed(invited: &Invited) -> bool {
        block_on(invited.users.find_by_id(&test_ctx().tenant(), &invited.bob))
            .unwrap()
            .unwrap()
            .email_verified()
    }

    /// Bob accepts the invitation mailed to him. Following the link proved
    /// his mailbox, so his address is confirmed.
    #[test]
    fn a_mailed_invitation_confirms_the_address() {
        let invited = Invited::pending();

        invited.accept(LINK, Some(STRONG)).unwrap();

        assert!(bobs_address_confirmed(&invited));
    }

    /// Accepting a handed-over invitation without a mail server activates
    /// Bob's account while leaving his address unconfirmed.
    #[test]
    fn a_handed_over_invitation_leaves_the_address_unconfirmed() {
        let invited = Invited::pending();
        let use_case = AcceptUseCase::new(AcceptPorts {
            mail: FakeMailSetup::not_set_up(),
            ..invited.ports()
        });

        block_on(use_case.execute(
            &test_ctx().tenant(),
            &test_auditor(invited.sink.clone()),
            AcceptRequest {
                raw_token: LINK.to_owned(),
                password: Some(STRONG.to_owned()),
            },
        ))
        .unwrap();

        assert_eq!(invited.bobs_status(), Some(UserStatus::Active));
        assert!(!bobs_address_confirmed(&invited));
    }

    /// Bob follows a link nobody sent. It is not found.
    #[test]
    fn an_unknown_link_is_not_found() {
        let invited = Invited::pending();

        let result = invited.accept("nobody-sent-this", Some(STRONG));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(invited.bobs_status(), Some(UserStatus::Invited));
    }

    /// Bob opens his invitation a day late. It has expired, so it can be
    /// renewed, and he stays invited.
    #[test]
    fn an_expired_invitation_is_told_apart() {
        let ran_out = bobs_link().expiring_at(clock::now() - time::Duration::minutes(1));
        let invited = Invited::by_sam_holding(&inviters_rights(), ran_out);

        let result = invited.accept(LINK, Some(STRONG));

        assert!(matches!(result, Err(AppError::LinkExpired(_))));
        assert_eq!(invited.bobs_status(), Some(UserStatus::Invited));
    }

    /// Bob accepts twice. The second time the invitation was already used.
    #[test]
    fn an_invitation_is_accepted_once() {
        let invited = Invited::pending();
        invited.accept(LINK, Some(STRONG)).unwrap();

        let again = invited.accept(LINK, Some(STRONG));

        assert!(matches!(again, Err(AppError::NotFound(_))));
        assert_eq!(invited.assignments.count(), 1);
    }

    /// The tenant asks for 20 characters and Bob picks 15. It is refused,
    /// nothing changes, and the invitation stays open for another try.
    #[test]
    fn a_weak_password_is_refused_and_changes_nothing() {
        let invited = Invited::pending();

        let result = invited.accept(LINK, Some("Fifteen1Chars!!"));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(invited.bobs_status(), Some(UserStatus::Invited));
        let still_open = block_on(
            invited
                .invitations
                .find_pending_by_user_id(&test_ctx().tenant(), &invited.bob),
        );
        assert!(still_open.unwrap().is_some());
    }

    /// The tenant signs people in with a password and Bob sends none. It is
    /// refused.
    #[test]
    fn a_tenant_with_password_sign_in_needs_a_password() {
        let invited = Invited::pending();

        let result = invited.accept(LINK, None);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(invited.bobs_status(), Some(UserStatus::Invited));
    }

    /// The tenant signs people in only with passkeys. Bob joins, and the
    /// password he sent anyway is not kept.
    #[test]
    fn a_tenant_without_password_sign_in_keeps_no_password() {
        let invited = Invited {
            tenants: tenant_store_without_password_login(),
            ..Invited::pending()
        };

        let bob = invited.accept(LINK, Some(STRONG)).unwrap();

        assert_eq!(invited.bobs_status(), Some(UserStatus::Active));
        assert!(invited.credentials.hash_of(&bob).is_none());
    }

    /// Bob cannot accept an invitation whose sender no longer holds the
    /// required rights. He stays invited and receives no role assignment.
    #[test]
    fn an_invitation_from_someone_who_lost_their_rights_gives_nothing() {
        let invited = Invited::by_sam_holding(&[], bobs_link());

        let result = invited.accept(LINK, Some(STRONG));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(invited.bobs_status(), Some(UserStatus::Invited));
        assert_eq!(invited.assignments.count(), 0);
    }

    /// An invitation to Bob's former address cannot activate his account.
    /// Acceptance is refused, and he remains invited.
    #[test]
    fn an_invitation_to_an_address_the_account_left_is_refused() {
        let invited = Invited::pending();
        let moved = stored_user(invited.bob, "elsewhere@acme.com", UserStatus::Invited);
        block_on(invited.users.save(&test_ctx().tenant(), &moved)).unwrap();

        let result = invited.accept(LINK, Some(STRONG));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(invited.bobs_status(), Some(UserStatus::Invited));
    }

    /// Bob's invitation was withdrawn. Following it finds nothing to accept.
    #[test]
    fn a_revoked_invitation_is_not_found() {
        let revoked = bobs_link().stored_as(OfferState::Revoked);
        let invited = Invited {
            invitations: Arc::new(FakeInvitationStore::holding(revoked)),
            ..Invited::pending()
        };

        let result = invited.accept(LINK, Some(STRONG));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Bob already holds a role that a separation rule keeps apart from the
    /// offered editor role. Acceptance conflicts, leaving him invited
    /// without a new role assignment.
    #[test]
    fn an_invitation_that_breaks_a_separation_rule_is_refused() {
        let pending = Invited::pending();
        let tenant = test_ctx().tenant();
        let offered = block_on(
            pending
                .invitations
                .find_pending_by_user_id(&tenant, &pending.bob),
        )
        .unwrap()
        .unwrap();
        let editor = block_on(pending.roles.find_by_id(&tenant, offered.role_id()))
            .unwrap()
            .unwrap();
        let raiser = stored_role("raise payments", Vec::new(), Vec::new());
        let rule = separation_between("raise or edit", &raiser, &editor);
        let bobs_role = stored_assignment(PrincipalRef::User(pending.bob), *raiser.id());
        let records = AccessRecords {
            roles: vec![raiser],
            assignments: vec![bobs_role],
            ..AccessRecords::default()
        };
        let invited = Invited {
            records: Arc::new(FakeAccessRecordStore::holding(*tenant, records)),
            rules: Arc::new(FakeSeparationRuleStore::holding(*tenant, [rule])),
            ..pending
        };

        let result = invited.accept(LINK, Some(STRONG));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(invited.bobs_status(), Some(UserStatus::Invited));
        assert_eq!(invited.assignments.count(), 0);
    }
}
