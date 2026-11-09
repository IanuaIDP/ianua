//! Renew invitation: the invitee holding a link that ran out asks for
//! another, sent to the same address.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ActorRef;

use crate::auditor::RequestAuditor;
use crate::email::{InvitationMailing, LinkScope, TokenResent};
use crate::error::{AppError, OrInternal};
use crate::ports::identity::{InvitationStore, UserStore};
use crate::services::authentication::channels::{NO_INVITATION_RENEWALS, ensure_mail_reaches};
use crate::services::lookup::existing_user;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::invitations::mail::{InvitationMail, deliver_invitation};
use crate::use_cases::identity::lookup::invitation_by_link;
use crate::use_cases::identity::renewal::renewed_link;

/// The ports [`RenewUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RenewPorts {
    /// Loads the invited account.
    pub user_store: Arc<dyn UserStore>,
    /// Loads and saves invitations.
    pub invitation_store: Arc<dyn InvitationStore>,
    /// Mails the new link under the invitation policy.
    pub mailing: InvitationMailing,
    /// Makes and hashes invitation links.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// The dead invitation link to renew, by its token, and the pages the new
/// one opens.
pub struct RenewRequest {
    /// The token from the link the invitee still holds.
    pub raw_token: String,
    /// Where the new link lands.
    pub scope: LinkScope,
}

/// Mails a new invitation link to the holder of one that ran out.
pub struct RenewUseCase {
    ports: RenewPorts,
}

impl RenewUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RenewPorts) -> Self {
        Self { ports }
    }
}

impl Command for RenewUseCase {
    type Caller = ScopedTenant;
    type Input = RenewRequest;
    type Output = Result<TokenResent, AppError>;

    /// Renews the invitation `request.raw_token` belongs to with a new link,
    /// mailed to the invited address, never one the caller names.
    ///
    /// Only a link that ran out is renewed, and only while the invitation
    /// stands as it was sent: nobody withdrew it, and the account still
    /// waits to join at the invited address without having changed how it
    /// signs in.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` for a malformed token; `NotFound` for an unknown link or missing account.
    /// - `AppError::Conflict` for a live link or an account no longer joining or with changed sign-in credentials.
    /// - `AppError::Forbidden` for a changed invited address or no mail server, checked before lookup; without mail the inviter must resend.
    /// - `AppError::Upstream` for refused mail; `Internal` on persistence failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: RenewRequest,
    ) -> Result<TokenResent, AppError> {
        let RenewRequest { raw_token, scope } = request;
        let mailing = &self.ports.mailing;
        ensure_mail_reaches(mailing.mail.as_ref(), NO_INVITATION_RENEWALS)?;
        crate::input::validate_token("token", &raw_token)?;
        let invitations = self.ports.invitation_store.as_ref();
        let generator = self.ports.token_generator.as_ref();
        let presented = generator.hash_raw(&raw_token);
        let mut invitation = invitation_by_link(invitations, tenant, &presented).await?;
        let user =
            existing_user(self.ports.user_store.as_ref(), tenant, invitation.user_id()).await?;
        let (raw_link, renewed) = renewed_link(generator, mailing.policy.lifetime)?;
        let renewal = invitation.renew_from_link(&user, &presented, renewed);
        renewal.map_err(AppError::from_domain)?;

        invitations.save(tenant, &invitation).await.or_internal()?;
        let actor = ActorRef::User(*user.id());
        auditor
            .dispatch_by(&actor, invitation.take_events(tenant))
            .await
            .or_internal()?;
        let mail = InvitationMail {
            invitee: &user,
            role: None,
            raw_token: &raw_link,
            scope: &scope,
        };
        deliver_invitation(mailing, tenant, mail).await?;
        Ok(mailing.policy.resend_cooldown.sent())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{RoleId, UserId};
    use time::OffsetDateTime;

    use super::*;
    use crate::ports::shared::MailSetup;
    use crate::test_support::identity::{
        FakeInvitationStore, FakeUserStore, InvitationSeed, stored_user,
    };
    use crate::test_support::{
        Fake, FakeEventDispatcher, FakeMailSetup, FakeMailer, RESEND_COOLDOWN_SECONDS, block_on,
        test_auditor, test_ctx, test_link_scope,
    };

    const LINK: &str = "bob-invite";

    /// Bob, invited, holding a link that runs out at `expires_at`.
    struct Invited {
        bob: UserId,
        users: Arc<FakeUserStore>,
        invitations: Arc<FakeInvitationStore>,
        mailer: Arc<FakeMailer>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Invited {
        fn with_link_until(expires_at: OffsetDateTime) -> Self {
            let bob = UserId::new();
            let invitation = InvitationSeed::for_user(bob, "bob@acme.com", RoleId::new(), LINK)
                .expiring_at(expires_at);
            Self {
                bob,
                users: Arc::new(FakeUserStore::with_invited_user(bob, "bob@acme.com")),
                invitations: Arc::new(FakeInvitationStore::holding(invitation.stored())),
                mailer: Arc::new(FakeMailer::new()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ran_out() -> Self {
            Self::with_link_until(clock::now() - time::Duration::minutes(1))
        }

        fn renew(&self, raw_token: &str) -> Result<TokenResent, AppError> {
            self.renew_reaching(raw_token, Fake::fake())
        }

        fn renew_reaching(
            &self,
            raw_token: &str,
            mail: Arc<dyn MailSetup>,
        ) -> Result<TokenResent, AppError> {
            let use_case = RenewUseCase::new(RenewPorts {
                user_store: self.users.clone(),
                invitation_store: self.invitations.clone(),
                mailing: InvitationMailing {
                    mailer: self.mailer.clone(),
                    mail,
                    ..InvitationMailing::fakes()
                },
                ..RenewPorts::fakes()
            });
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.sink.clone()),
                RenewRequest {
                    raw_token: raw_token.to_owned(),
                    scope: test_link_scope(),
                },
            ))
        }
    }

    /// Bob opens his invitation a week late. A new link goes to his address,
    /// he is told how long to wait before asking again, and it is recorded.
    #[test]
    fn a_link_that_ran_out_is_renewed() {
        let invited = Invited::ran_out();

        let resent = invited.renew(LINK).unwrap();

        assert_eq!(resent.retry_after_seconds, RESEND_COOLDOWN_SECONDS);
        assert_eq!(invited.mailer.recipients(), ["bob@acme.com"]);
        assert_eq!(
            invited.sink.records.lock().unwrap().as_slice(),
            ["identity.invitation_resent"]
        );
    }

    /// Without a mail server, Bob's expired invitation link cannot be
    /// renewed. No mail or audit event is produced.
    #[test]
    fn without_mail_a_dead_link_is_not_renewed() {
        let invited = Invited::ran_out();

        let result = invited.renew_reaching(LINK, FakeMailSetup::not_set_up());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(invited.mailer.count(), 0);
        assert!(invited.sink.records.lock().unwrap().is_empty());
    }

    /// Bob's link still works. There is nothing to renew.
    #[test]
    fn a_link_that_still_works_is_not_renewed() {
        let invited = Invited::with_link_until(clock::now() + time::Duration::hours(1));

        let result = invited.renew(LINK);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(invited.mailer.count(), 0);
    }

    /// Once Bob's account is active, renewing his expired invitation
    /// conflicts and sends no mail.
    #[test]
    fn an_account_that_joined_gets_no_new_link() {
        let invited = Invited::ran_out();
        let joined = stored_user(invited.bob, "bob@acme.com", UserStatus::Active);
        block_on(invited.users.save(&test_ctx().tenant(), &joined)).unwrap();

        let result = invited.renew(LINK);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(invited.mailer.count(), 0);
    }

    /// A link nobody sent is not found.
    #[test]
    fn an_unknown_link_is_not_found() {
        let invited = Invited::ran_out();

        let result = invited.renew("nobody-sent-this");

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
