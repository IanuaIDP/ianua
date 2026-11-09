//! Resend invitation: an admin sends a pending invitation again, with a new
//! link and a fresh expiry.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::identity::invitations::invitation::Invitation;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::UserId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::email::{InvitationDelivery, InvitationMailing, LinkScope};
use crate::error::{AppError, OrInternal};
use crate::ports::identity::{InvitationStore, UserStore};
use crate::ports::limits::{MailPurpose, MailThrottle};
use crate::services::limits::mail_cooldown::ensure_mail_admitted;
use crate::services::lookup::existing_user;
use crate::use_case::Command;
use crate::use_cases::identity::invitations::mail::{InvitationMail, deliver_invitation};
use crate::use_cases::identity::lookup::existing_invitation;
use crate::use_cases::identity::renewal::renewed_link;

/// The ports [`ResendUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResendPorts {
    /// Loads the invited account.
    pub user_store: Arc<dyn UserStore>,
    /// Loads and saves invitations.
    pub invitation_store: Arc<dyn InvitationStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Mails the invitation under the invitation policy.
    pub mailing: InvitationMailing,
    /// Lets one invitation a minute through to an address.
    pub mail_throttle: Arc<dyn MailThrottle>,
    /// Makes invitation links.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// Whose pending invitation to send again, and the pages its link opens.
pub struct ResendRequest {
    /// The invited user.
    pub user_id: UserId,
    /// Where the new link lands.
    pub scope: LinkScope,
}

/// Sends a pending invitation of the caller's tenant again.
pub struct ResendUseCase {
    ports: ResendPorts,
}

impl ResendUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ResendPorts) -> Self {
        Self { ports }
    }

    /// Gives `invitation` a new link and expiry, as `authority` may, and
    /// returns the token the link carries.
    fn rotated(
        &self,
        invitation: &mut Invitation<ResolvedTenant>,
        user: &User<ResolvedTenant>,
        authority: &TenantAuthority,
    ) -> Result<Secret, AppError> {
        let lifetime = self.ports.mailing.policy.lifetime;
        let (raw_token, link) = renewed_link(self.ports.token_generator.as_ref(), lifetime)?;
        invitation
            .rotate_token(user, &authority.standing(), link.token_hash, link.lifetime)
            .map_err(AppError::from_domain)?;
        Ok(raw_token)
    }
}

impl Command for ResendUseCase {
    type Caller = CallerContext;
    type Input = ResendRequest;
    type Output = Result<InvitationDelivery, AppError>;

    /// Gives the pending invitation of `request.user_id` a new link and
    /// expiry, and mails it to the invited address. The old link stops
    /// working. On a deployment with no mail server nothing is mailed: the
    /// answer hands the caller the new link to pass on.
    ///
    /// Sending again is inviting again, so the caller needs what inviting
    /// needs. It is refused once the account has left the invited address,
    /// or the new link would go to the old mailbox.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without invitation rights before lookup, or for a changed invited address.
    /// - `AppError::NotFound` for a missing user/pending invitation; `Upstream` for refused mail.
    /// - `AppError::TooManyRequests` for an invitation sent within a minute; `Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ResendRequest,
    ) -> Result<InvitationDelivery, AppError> {
        let ResendRequest { user_id, scope } = request;
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        ensure_may_invite(&authority)?;
        let user = existing_user(self.ports.user_store.as_ref(), &tenant, &user_id).await?;
        let mut invitation =
            existing_invitation(self.ports.invitation_store.as_ref(), &tenant, &user_id).await?;
        let raw_token = self.rotated(&mut invitation, &user, &authority)?;
        let throttle = self.ports.mail_throttle.as_ref();
        ensure_mail_admitted(throttle, MailPurpose::Invitation, user.email()).await?;

        self.ports
            .invitation_store
            .save(&tenant, &invitation)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), invitation.take_events(&tenant))
            .await
            .or_internal()?;
        let mail = InvitationMail {
            invitee: &user,
            role: None,
            raw_token: &raw_token,
            scope: &scope,
        };
        deliver_invitation(&self.ports.mailing, &tenant, mail).await
    }
}

/// Refuses a caller who may not invite people, before anyone is read.
///
/// # Errors
///
/// Returns `AppError::Forbidden` when `authority` lacks the right to
/// create users.
fn ensure_may_invite(authority: &TenantAuthority) -> Result<(), AppError> {
    authority
        .standing()
        .ensure_holds(SystemPermission::Users(UserAction::Create))
        .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::types::RoleId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::{
        FakeInvitationStore, FakeUserStore, InvitationSeed, hash_of_link, stored_user,
    };
    use crate::test_support::{
        FakeEventDispatcher, FakeMailSetup, FakeMailer, block_on, test_auditor, test_ctx,
        test_link_scope,
    };

    const LINK: &str = "bob-invite";

    /// Bob, invited and waiting, and the stores that watch his invitation.
    struct Invited {
        bob: UserId,
        users: Arc<FakeUserStore>,
        invitations: Arc<FakeInvitationStore>,
        mailer: Arc<FakeMailer>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Invited {
        fn new() -> Self {
            let bob = UserId::new();
            let invitation = InvitationSeed::for_user(bob, "bob@acme.com", RoleId::new(), LINK);
            Self {
                bob,
                users: Arc::new(FakeUserStore::with_invited_user(bob, "bob@acme.com")),
                invitations: Arc::new(FakeInvitationStore::holding(invitation.stored())),
                mailer: Arc::new(FakeMailer::new()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self) -> ResendPorts {
            ResendPorts {
                user_store: self.users.clone(),
                invitation_store: self.invitations.clone(),
                mailing: InvitationMailing {
                    mailer: self.mailer.clone(),
                    ..InvitationMailing::fakes()
                },
                ..ResendPorts::fakes()
            }
        }

        fn resend(&self, ports: ResendPorts) -> Result<InvitationDelivery, AppError> {
            let use_case = ResendUseCase::new(ports);
            block_on(use_case.execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                ResendRequest {
                    user_id: self.bob,
                    scope: test_link_scope(),
                },
            ))
        }

        fn old_link_works(&self) -> bool {
            block_on(
                self.invitations
                    .find_by_token_hash(&test_ctx().tenant(), &hash_of_link(LINK)),
            )
            .unwrap()
            .is_some()
        }
    }

    /// Ann sends Bob's invitation again. It goes to his address with a new
    /// link, the old link stops working, and the resend is recorded.
    #[test]
    fn a_resent_invitation_gets_a_new_link() {
        let invited = Invited::new();

        invited.resend(invited.ports()).unwrap();

        assert_eq!(invited.mailer.recipients(), ["bob@acme.com"]);
        assert!(!invited.old_link_works());
        assert_eq!(
            invited.sink.records.lock().unwrap().as_slice(),
            ["identity.invitation_resent"]
        );
    }

    /// With a mail server set up, the new link is mailed and Ann is handed
    /// nothing.
    #[test]
    fn a_mailed_resend_hands_over_no_link() {
        let invited = Invited::new();

        let delivery = invited.resend(invited.ports()).unwrap();

        assert!(matches!(delivery, InvitationDelivery::Mailed));
    }

    /// Ann sends Bob's invitation again on a deployment with no mail
    /// server. Nothing is mailed; she is handed the new link to pass on,
    /// and the old link stops working.
    #[test]
    fn without_mail_the_new_link_is_handed_to_the_inviter() {
        let invited = Invited::new();
        let mut ports = invited.ports();
        ports.mailing.mail = FakeMailSetup::not_set_up();

        let delivery = invited.resend(ports).unwrap();

        assert!(delivery.handed_over().is_some());
        assert_eq!(invited.mailer.count(), 0);
        assert!(!invited.old_link_works());
    }

    /// Bob has no invitation waiting. There is nothing to send.
    #[test]
    fn a_user_without_an_invitation_is_not_found() {
        let invited = Invited::new();
        let ports = ResendPorts {
            invitation_store: Arc::new(FakeInvitationStore::empty()),
            ..invited.ports()
        };

        let result = invited.resend(ports);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Bob's invitation cannot be resent after his account changes address.
    /// The refusal sends no mail.
    #[test]
    fn an_account_that_left_the_invited_address_gets_nothing() {
        let invited = Invited::new();
        let moved = stored_user(invited.bob, "elsewhere@acme.com", UserStatus::Invited);
        block_on(invited.users.save(&test_ctx().tenant(), &moved)).unwrap();

        let result = invited.resend(invited.ports());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(invited.mailer.count(), 0);
    }

    /// User-viewing rights do not permit resending an invitation. Bob's
    /// existing link remains available after the refusal.
    #[test]
    fn a_caller_who_may_not_invite_is_refused() {
        let invited = Invited::new();
        let ports = ResendPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::View),
            ])),
            ..invited.ports()
        };

        let result = invited.resend(ports);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(invited.old_link_works());
    }

    /// A signed-out caller cannot resend Bob's invitation.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let invited = Invited::new();
        let ports = ResendPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..invited.ports()
        };

        let result = invited.resend(ports);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
