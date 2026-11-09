//! Invite user: an admin asks someone to join the tenant with a role, and an
//! invitation goes to their address.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::authorization::granter::HeldByGranter;
use ianua_domain::domains::authorization::role::Role;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::identity::invitations::invitation::{
    CreateInvitationParams, Invitation,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{DisplayName, Email, EventLabel, PrincipalRef, RoleId, Text, UserId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::email::{InvitationDelivery, InvitationMailing, LinkScope};
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authorization::RoleStore;
use crate::ports::identity::{InvitationStore, UserStore};
use crate::ports::limits::{LimitEnforcer, MailPurpose, MailThrottle, ResourceKind};
use crate::ports::workflows::ChangeGuard;
use crate::services::guarded::{AdminHolder, ensure_admin_rules_allow};
use crate::services::identity::address_free::ensure_email_free;
use crate::services::limits::mail_cooldown::ensure_mail_admitted;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::invitations::mail::{InvitationMail, deliver_invitation};
use crate::use_cases::identity::renewal::renewed_link;
use crate::use_cases::identity::users::joining::room::ensure_room;

/// The ports [`InviteUserUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct InviteUserPorts {
    /// Saves the invited account, and finds addresses already taken.
    pub user_store: Arc<dyn UserStore>,
    /// Saves invitations, and finds one already waiting.
    pub invitation_store: Arc<dyn InvitationStore>,
    /// Loads the role the invitation offers.
    pub role_store: Arc<dyn RoleStore>,
    /// Holds the tenant to its plan's user limit: an invited user is a user
    /// from the moment they are invited.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Mails the invitation under the invitation policy.
    pub mailing: InvitationMailing,
    /// Lets one invitation a minute through to an address.
    pub mail_throttle: Arc<dyn MailThrottle>,
    /// Makes invitation links.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// The company's "before" rules, asked before an admin role is offered.
    pub guard: Arc<dyn ChangeGuard>,
}

/// Someone just invited, and how their link went out.
#[derive(Debug)]
pub struct Invited {
    /// The invited account.
    pub user_id: UserId,
    /// Mailed, or handed to the inviter to pass on.
    pub delivery: InvitationDelivery,
}

/// Who to invite, with which role.
pub struct InviteUserRequest {
    /// The address to invite.
    pub email: Email,
    /// The name the invited account gets.
    pub display_name: DisplayName,
    /// The role accepting gives.
    pub role_id: RoleId,
    /// A personal message for the invitation, when given.
    pub message: Option<Text>,
    /// Where the invitation link lands.
    pub scope: LinkScope,
}

/// What an invitation offers: an account, the role it gets, and what the
/// person granting it holds.
struct Offer<'a> {
    /// The invited account.
    user: &'a User<ResolvedTenant>,
    /// The role accepting gives.
    role: &'a Role<ResolvedTenant>,
    /// What the inviter holds, which the role may not exceed.
    granter: &'a HeldByGranter<'a>,
}

/// Invites someone into the caller's tenant.
pub struct InviteUserUseCase {
    ports: InviteUserPorts,
}

impl InviteUserUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: InviteUserPorts) -> Self {
        Self { ports }
    }

    /// Stores the invited account and its invitation.
    async fn keep(
        &self,
        tenant: &ScopedTenant,
        user: &User<ResolvedTenant>,
        invitation: &Invitation<ResolvedTenant>,
    ) -> Result<(), AppError> {
        self.ports
            .user_store
            .save(tenant, user)
            .await
            .or_internal()?;
        self.ports
            .invitation_store
            .save(tenant, invitation)
            .await
            .or_internal()
    }

    /// Refuses an invitation that would take the caller's tenant past its
    /// plan's user limit.
    async fn ensure_room_for_one(&self, ctx: &CallerContext) -> Result<(), AppError> {
        let limits = self.ports.limit_enforcer.as_ref();
        ensure_room(
            limits,
            &ctx.tenant(),
            ctx.plan_limits(),
            ResourceKind::Users,
        )
        .await
    }

    /// The role `role_id` names in `tenant`.
    async fn offered_role(
        &self,
        tenant: &ScopedTenant,
        role_id: &RoleId,
    ) -> Result<Role<ResolvedTenant>, AppError> {
        self.ports
            .role_store
            .find_by_id(tenant, role_id)
            .await
            .or_internal()?
            .or_not_found(message!("app-role-not-found", "role not found"))
    }

    /// A new invitation for `offer`'s account to its role, as its granter
    /// may send, with the raw token its link carries.
    fn invitation(
        &self,
        ctx: &CallerContext,
        offer: &Offer<'_>,
        message: Option<Text>,
    ) -> Result<(Secret, Invitation<ResolvedTenant>), AppError> {
        let &Offer {
            user,
            role,
            granter,
        } = offer;
        let generator = self.ports.token_generator.as_ref();
        let (raw_token, link) = renewed_link(generator, self.ports.mailing.policy.lifetime)?;
        let params = CreateInvitationParams {
            user_id: *user.id(),
            email: user.email().clone(),
            invited_by: ctx.actor(),
            token_hash: link.token_hash,
            message,
            lifetime: link.lifetime,
        };
        let invitation =
            Invitation::create(params, role, granter).map_err(AppError::from_domain)?;
        Ok((raw_token, invitation))
    }

    /// Refuses an address that already has an account or an invitation
    /// waiting.
    async fn ensure_not_yet_invited(
        &self,
        tenant: &ScopedTenant,
        email: &Email,
    ) -> Result<(), AppError> {
        ensure_email_free(self.ports.user_store.as_ref(), tenant, email).await?;
        let pending = self
            .ports
            .invitation_store
            .find_pending_by_email(tenant, email)
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

    /// The invitation for `offer`, once its address may be sent one:
    /// refused when the address has an account or an invitation waiting,
    /// when the company's "before admin given" rules refuse its role, or
    /// when the address had an invitation mailed within the last minute.
    /// The throttle is asked after every other check, so a refused request
    /// leaves the address's minute unspent.
    async fn mailable_invitation(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        offer: &Offer<'_>,
        message: Option<Text>,
    ) -> Result<(Secret, Invitation<ResolvedTenant>), AppError> {
        let email = offer.user.email();
        self.ensure_not_yet_invited(&ctx.tenant(), email).await?;
        let invitation = self.invitation(ctx, offer, message)?;
        let invitee = PrincipalRef::User(*offer.user.id());
        let guard = self.ports.guard.as_ref();
        let holder = AdminHolder::Principal(&invitee);
        ensure_admin_rules_allow(guard, &ctx.tenant(), auditor, offer.role, holder).await?;
        let throttle = self.ports.mail_throttle.as_ref();
        ensure_mail_admitted(throttle, MailPurpose::Invitation, email).await?;
        Ok(invitation)
    }

    /// Records what inviting `user` raised, by the caller.
    async fn record(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        user: &mut User<ResolvedTenant>,
    ) -> Result<(), AppError> {
        auditor
            .dispatch_by(&ctx.actor(), user.take_events(&ctx.tenant()))
            .await
            .or_internal()
    }
}

impl Command for InviteUserUseCase {
    type Caller = CallerContext;
    type Input = InviteUserRequest;
    type Output = Result<Invited, AppError>;

    /// Opens an invited account for `request.email` and mails it an
    /// invitation offering `request.role_id`. On a deployment with no mail
    /// server nothing is mailed: the answer hands the caller the link to
    /// pass on.
    ///
    /// Whoever accepts gains everything the role grants, so the caller must
    /// be able to hand all of it out, as well as add people.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` for a full user allowance or missing creation/grant rights.
    /// - `AppError::NotFound` for a missing role; `Conflict` for an existing account or pending invitation at the address.
    /// - `AppError::Upstream` for refused mail, after storing the account and invitation.
    /// - `AppError::TooManyRequests` for an invitation sent within a minute; `Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: InviteUserRequest,
    ) -> Result<Invited, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        self.ensure_room_for_one(ctx).await?;
        let role = self.offered_role(&tenant, &request.role_id).await?;
        let granter = authority.standing();
        let mut user = User::invite(UserId::new(), request.email, request.display_name, &granter)
            .map_err(AppError::from_domain)?;
        let offer = Offer {
            user: &user,
            role: &role,
            granter: &granter,
        };
        let (raw_token, invitation) = self
            .mailable_invitation(ctx, auditor, &offer, request.message)
            .await?;

        self.keep(&tenant, &user, &invitation).await?;
        self.record(ctx, auditor, &mut user).await?;
        let mail = InvitationMail {
            invitee: &user,
            role: Some(&EventLabel::of(role.name().as_str())),
            raw_token: &raw_token,
            scope: &request.scope,
        };
        let delivery = deliver_invitation(&self.ports.mailing, &tenant, mail).await?;
        Ok(Invited {
            user_id: *user.id(),
            delivery,
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::identity::account::user_status::UserStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{FakeRoleStore, stored_role};
    use crate::test_support::identity::{FakeInvitationStore, FakeUserStore, InvitationSeed};
    use crate::test_support::tenant::cfg;
    use crate::test_support::{
        FakeEventDispatcher, FakeMailSetup, FakeMailer, OneMailThrottle, RejectingLimitEnforcer,
        ShutMailThrottle, block_on, test_auditor, test_ctx, test_link_scope,
    };

    /// A tenant with an editor role, which lets people view users, and the
    /// stores that watch an invitation go out.
    struct Tenant {
        editor: RoleId,
        roles: Arc<FakeRoleStore>,
        users: Arc<FakeUserStore>,
        invitations: Arc<FakeInvitationStore>,
        mailer: Arc<FakeMailer>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Tenant {
        fn new() -> Self {
            let viewing = vec![SystemPermission::Users(UserAction::View)];
            let editor = stored_role("editor", viewing, Vec::new());
            Self {
                editor: *editor.id(),
                roles: Arc::new(FakeRoleStore::holding(test_ctx().tenant_id(), [editor])),
                users: Arc::new(FakeUserStore::empty()),
                invitations: Arc::new(FakeInvitationStore::empty()),
                mailer: Arc::new(FakeMailer::new()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self) -> InviteUserPorts {
            InviteUserPorts {
                user_store: self.users.clone(),
                invitation_store: self.invitations.clone(),
                role_store: self.roles.clone(),
                mailing: InvitationMailing {
                    mailer: self.mailer.clone(),
                    ..InvitationMailing::fakes()
                },
                ..InviteUserPorts::fakes()
            }
        }

        fn invite(&self, ports: InviteUserPorts, role_id: RoleId) -> Result<UserId, AppError> {
            self.invited(ports, role_id).map(|invited| invited.user_id)
        }

        fn invited(&self, ports: InviteUserPorts, role_id: RoleId) -> Result<Invited, AppError> {
            let use_case = InviteUserUseCase::new(ports);
            block_on(use_case.execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                InviteUserRequest {
                    email: Email::new("bob@acme.com").unwrap(),
                    display_name: DisplayName::new("Bob", &cfg().display_name).unwrap(),
                    role_id,
                    message: None,
                    scope: test_link_scope(),
                },
            ))
        }

        fn invite_as(&self, rights: &[SystemPermission]) -> Result<UserId, AppError> {
            let ports = InviteUserPorts {
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(rights)),
                ..self.ports()
            };
            self.invite(ports, self.editor)
        }
    }

    /// Ann invites Bob as an editor. Bob waits as invited, his invitation
    /// is stored and mailed to him naming the role, and it is recorded.
    #[test]
    fn an_invitation_opens_an_invited_account_and_goes_out() {
        let tenant = Tenant::new();

        let bob = tenant.invite(tenant.ports(), tenant.editor).unwrap();

        assert_eq!(tenant.users.get_status(&bob), Some(UserStatus::Invited));
        assert_eq!(tenant.invitations.count(), 1);
        assert_eq!(tenant.mailer.recipients(), ["bob@acme.com"]);
        assert_eq!(
            tenant.sink.records.lock().unwrap().as_slice(),
            ["identity.user_invited"]
        );
    }

    /// With a mail server set up, Bob's link is mailed and Ann is handed
    /// nothing.
    #[test]
    fn a_mailed_invitation_hands_over_no_link() {
        let tenant = Tenant::new();

        let invited = tenant.invited(tenant.ports(), tenant.editor).unwrap();

        assert!(matches!(invited.delivery, InvitationDelivery::Mailed));
    }

    /// Ann invites Bob on a deployment with no mail server. Nothing is
    /// mailed; Ann is handed Bob's accept link to pass on, and Bob still
    /// waits as invited.
    #[test]
    fn without_mail_the_link_is_handed_to_the_inviter() {
        let tenant = Tenant::new();
        let mut ports = tenant.ports();
        ports.mailing.mail = FakeMailSetup::not_set_up();

        let invited = tenant.invited(ports, tenant.editor).unwrap();

        let link = invited.delivery.handed_over().map(Secret::expose);
        assert!(link.is_some_and(|link| link.contains("accept-invite")));
        assert_eq!(tenant.mailer.count(), 0);
        assert_eq!(
            tenant.users.get_status(&invited.user_id),
            Some(UserStatus::Invited)
        );
    }

    /// Ann invites Bob with a role the tenant does not have. It is not found
    /// and nobody is invited.
    #[test]
    fn an_unknown_role_is_not_found() {
        let tenant = Tenant::new();

        let result = tenant.invite(tenant.ports(), RoleId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(tenant.users.count(), 0);
    }

    /// Bob already has an account. Inviting him again is a conflict.
    #[test]
    fn an_address_with_an_account_is_a_conflict() {
        let tenant = Tenant::new();
        tenant.users.add_active_user(UserId::new(), "bob@acme.com");

        let result = tenant.invite(tenant.ports(), tenant.editor);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(tenant.invitations.count(), 0);
    }

    /// Bob already has an invitation waiting. Inviting him again is a
    /// conflict.
    #[test]
    fn an_address_with_an_invitation_waiting_is_a_conflict() {
        let tenant = Tenant::new();
        let waiting = InvitationSeed::for_user(UserId::new(), "bob@acme.com", tenant.editor, "bob");
        block_on(
            tenant
                .invitations
                .save(&test_ctx().tenant(), &waiting.stored()),
        )
        .unwrap();

        let result = tenant.invite(tenant.ports(), tenant.editor);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(tenant.users.count(), 0);
    }

    /// The tenant is at its plan's user limit. Ann's invitation is refused
    /// and nobody is invited.
    #[test]
    fn an_invitation_is_refused_at_the_user_limit() {
        let tenant = Tenant::new();
        let ports = InviteUserPorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..tenant.ports()
        };

        let result = tenant.invite(ports, tenant.editor);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.users.count(), 0);
    }

    /// The mail service refuses the invitation. Ann hears of it, and Bob's
    /// invitation is kept so it can be sent again.
    #[test]
    fn a_refused_mail_is_reported_and_the_invitation_kept() {
        let tenant = Tenant::new();
        let mut ports = tenant.ports();
        ports.mailing.mailer = Arc::new(FakeMailer::refusing());

        let result = tenant.invite(ports, tenant.editor);

        assert!(matches!(result, Err(AppError::Upstream(_))));
        assert_eq!(tenant.invitations.count(), 1);
    }

    /// A mail throttle refusal prevents a new invitation to Bob's address.
    /// No invitation is saved and no mail is sent.
    #[test]
    fn an_address_invited_a_moment_ago_waits() {
        let tenant = Tenant::new();
        let ports = InviteUserPorts {
            mail_throttle: Arc::new(ShutMailThrottle),
            ..tenant.ports()
        };

        let result = tenant.invite(ports, tenant.editor);

        assert!(matches!(result, Err(AppError::TooManyRequests(_))));
        assert_eq!(tenant.invitations.count(), 0);
        assert_eq!(tenant.mailer.count(), 0);
    }

    /// User-creation rights alone do not permit offering the editor role's
    /// viewing rights. The refusal creates no account.
    #[test]
    fn a_role_the_caller_cannot_hand_out_is_refused() {
        let tenant = Tenant::new();

        let result = tenant.invite_as(&[SystemPermission::Users(UserAction::Create)]);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.users.count(), 0);
    }

    /// Sam, who cannot hand out the editor role, tries to invite Bob and is
    /// refused. Nothing went to Bob, so Ann's invitation right after still
    /// goes out: Sam cannot hold back her mail to Bob.
    #[test]
    fn a_refused_invitation_leaves_the_address_free_to_mail() {
        let tenant = Tenant::new();
        let throttle: Arc<dyn MailThrottle> = Arc::new(OneMailThrottle::default());
        let as_sam = InviteUserPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Create),
            ])),
            mail_throttle: throttle.clone(),
            ..tenant.ports()
        };
        tenant.invite(as_sam, tenant.editor).unwrap_err();
        let as_ann = InviteUserPorts {
            mail_throttle: throttle,
            ..tenant.ports()
        };

        let result = tenant.invite(as_ann, tenant.editor);

        assert!(result.is_ok());
        assert_eq!(tenant.mailer.count(), 1);
    }

    /// User-viewing rights do not permit inviting Bob, and no account is
    /// created.
    #[test]
    fn a_caller_who_may_not_add_users_is_refused() {
        let tenant = Tenant::new();

        let result = tenant.invite_as(&[SystemPermission::Users(UserAction::View)]);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.users.count(), 0);
    }

    /// A signed-out caller cannot invite Bob into the tenant.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tenant = Tenant::new();
        let ports = InviteUserPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports()
        };

        let result = tenant.invite(ports, tenant.editor);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Ann's company rule refuses every role holding a built-in permission.
    /// Tess invites Bob as an editor, which may view users: it is refused,
    /// no account is opened and nothing is mailed.
    #[test]
    fn a_company_rule_refusing_stops_an_invitation_to_an_admin_role() {
        let tenant = Tenant::new();
        let ports = InviteUserPorts {
            guard: Arc::new(crate::test_support::workflows::RefusingGuard),
            ..tenant.ports()
        };

        let result = tenant.invite(ports, tenant.editor);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.users.count(), 0);
        assert_eq!(tenant.invitations.count(), 0);
        assert_eq!(tenant.mailer.count(), 0);
    }
}
