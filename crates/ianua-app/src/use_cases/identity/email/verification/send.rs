//! Send verification: mail a user a link to confirm their address, asked by
//! the user themselves or by someone who may update users.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::UserId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::{CallerContext, CallerIdentity};
use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserStore;
use crate::services::authentication::channels::NO_CONFIRMATION_LINKS;
use crate::use_case::Command;
use crate::use_cases::identity::email::VerificationLinks;

/// The ports [`SendVerificationUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SendVerificationPorts {
    /// Loads users.
    pub user_store: Arc<dyn UserStore>,
    /// Who the caller is and what they hold in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Mails the link.
    pub verification_links: Arc<VerificationLinks>,
}

/// Who to send a verification link to, and the pages it opens.
pub struct SendVerificationRequest {
    /// The user whose address needs confirming.
    pub user_id: UserId,
    /// Where the link lands.
    pub scope: LinkScope,
}

/// Mails a user of the caller's tenant a link to confirm their address.
pub struct SendVerificationUseCase {
    ports: SendVerificationPorts,
}

impl SendVerificationUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SendVerificationPorts) -> Self {
        Self { ports }
    }

    /// Refuses a caller who is neither the user, signed in now, nor someone
    /// who may update users.
    async fn ensure_may_send(&self, ctx: &CallerContext, user_id: UserId) -> Result<(), AppError> {
        if *ctx.identity() == CallerIdentity::TenantUser(user_id) {
            self.ports.tenant_authorities.signed_in(ctx).await?;
            return Ok(());
        }
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Users(UserAction::Update))
            .map_err(AppError::from_domain)
    }
}

impl Command for SendVerificationUseCase {
    type Caller = CallerContext;
    type Input = SendVerificationRequest;
    type Output = Result<(), AppError>;

    /// Mails `request.user_id` a new link to confirm the address they have
    /// now. Every link sent before stops working.
    ///
    /// A user who is gone, or whose address is already confirmed, is sent
    /// nothing, and the answer is the same. A link goes only to the address
    /// on the account, never one the caller names, so asking proves nothing
    /// about the address and gives nobody else the link.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller is someone else who may not
    ///   update users, or the deployment has no mail server, so the link
    ///   would never arrive.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: SendVerificationRequest,
    ) -> Result<(), AppError> {
        let SendVerificationRequest { user_id, scope } = request;
        self.ensure_may_send(ctx, user_id).await?;
        self.ports
            .verification_links
            .ensure_mailable(NO_CONFIRMATION_LINKS)?;
        let tenant = ctx.tenant();
        let found = self
            .ports
            .user_store
            .find_by_id(&tenant, &user_id)
            .await
            .or_internal()?;
        let Some(mut user) = found.filter(|user| !user.email_verified()) else {
            return Ok(());
        };

        self.ports
            .verification_links
            .send(&tenant, &user, &scope)
            .await?
            .note_on(&mut user);
        auditor
            .dispatch_by(&ctx.actor(), user.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::{
        FakeTokenStore, FakeUserStore, verification_links_over, verification_links_reaching,
    };
    use crate::test_support::{
        FakeEventDispatcher, FakeMailSetup, FakeMailer, block_on, test_auditor, test_ctx,
        test_ctx_with, test_link_scope,
    };

    /// Ann, whose address is not confirmed, and the stores that watch a
    /// link go out.
    struct Mailbox {
        ann: UserId,
        users: Arc<FakeUserStore>,
        tokens: Arc<FakeTokenStore>,
        mailer: Arc<FakeMailer>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Mailbox {
        fn new() -> Self {
            let ann = UserId::new();
            Self {
                ann,
                users: Arc::new(FakeUserStore::with_unverified_user(ann, "ann@acme.com")),
                tokens: Arc::new(FakeTokenStore::empty()),
                mailer: Arc::new(FakeMailer::new()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self) -> SendVerificationPorts {
            SendVerificationPorts {
                user_store: self.users.clone(),
                verification_links: verification_links_over(&self.tokens, &self.mailer),
                ..SendVerificationPorts::fakes()
            }
        }

        fn send(&self, ports: SendVerificationPorts, ctx: &CallerContext) -> Result<(), AppError> {
            block_on(SendVerificationUseCase::new(ports).execute(
                ctx,
                &test_auditor(self.sink.clone()),
                SendVerificationRequest {
                    user_id: self.ann,
                    scope: test_link_scope(),
                },
            ))
        }

        fn as_ann(&self) -> CallerContext {
            let seeded = test_ctx();
            test_ctx_with(seeded.organization_id(), seeded.tenant_id(), self.ann)
        }
    }

    /// Ann, an admin, sends Alice a link. A token is stored, the link goes
    /// to Alice's address, and the mail is recorded.
    #[test]
    fn an_admin_sends_a_link_to_the_users_address() {
        let mailbox = Mailbox::new();

        mailbox.send(mailbox.ports(), &test_ctx()).unwrap();

        assert_eq!(mailbox.tokens.count(), 1);
        assert_eq!(mailbox.mailer.recipients(), ["ann@acme.com"]);
        assert_eq!(
            mailbox.sink.records.lock().unwrap().as_slice(),
            ["identity.verification_email_sent"]
        );
    }

    /// Sending a verification link without a mail server is refused before
    /// creating a token, sending mail or recording an event.
    #[test]
    fn no_link_is_sent_where_nothing_is_mailed() {
        let mailbox = Mailbox::new();
        let ports = SendVerificationPorts {
            verification_links: verification_links_reaching(
                &mailbox.tokens,
                &mailbox.mailer,
                FakeMailSetup::not_set_up(),
            ),
            ..mailbox.ports()
        };

        let result = mailbox.send(ports, &test_ctx());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(mailbox.tokens.count(), 0);
        assert_eq!(mailbox.mailer.count(), 0);
        assert!(mailbox.sink.records.lock().unwrap().is_empty());
    }

    /// The link carries the organization and tenant it belongs to, so the
    /// page it opens knows where it is.
    #[test]
    fn the_link_carries_the_org_and_tenant_it_belongs_to() {
        let mailbox = Mailbox::new();

        mailbox.send(mailbox.ports(), &test_ctx()).unwrap();

        let url = mailbox.mailer.action_url();
        assert!(url.contains("org=acme"));
        assert!(url.contains("tenant=prod"));
    }

    /// Ann asks for a link to her own address. She needs no right for
    /// that, only to be signed in.
    #[test]
    fn a_person_asks_for_their_own_link() {
        let mailbox = Mailbox::new();
        let ports = SendVerificationPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..mailbox.ports()
        };

        mailbox.send(ports, &mailbox.as_ann()).unwrap();

        assert_eq!(mailbox.mailer.count(), 1);
    }

    /// Ann's address is already confirmed. Nothing is sent and the answer
    /// is the same.
    #[test]
    fn a_confirmed_address_is_sent_nothing() {
        let mailbox = Mailbox::new();
        let ports = SendVerificationPorts {
            user_store: Arc::new(FakeUserStore::with_user(mailbox.ann, "ann@acme.com")),
            ..mailbox.ports()
        };

        mailbox.send(ports, &test_ctx()).unwrap();

        assert_eq!(mailbox.mailer.count(), 0);
        assert!(mailbox.sink.records.lock().unwrap().is_empty());
    }

    /// The user is gone. Nothing is sent and the answer is the same.
    #[test]
    fn a_missing_user_is_sent_nothing() {
        let mailbox = Mailbox::new();
        let ports = SendVerificationPorts {
            user_store: Arc::new(FakeUserStore::empty()),
            ..mailbox.ports()
        };

        mailbox.send(ports, &test_ctx()).unwrap();

        assert_eq!(mailbox.mailer.count(), 0);
    }

    /// A caller without user-update rights cannot send Ann a verification
    /// link. No mail is sent.
    #[test]
    fn someone_else_without_the_right_is_refused() {
        let mailbox = Mailbox::new();
        let ports = SendVerificationPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..mailbox.ports()
        };

        let result = mailbox.send(ports, &test_ctx());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(mailbox.mailer.count(), 0);
    }

    /// Ann cannot request her own verification link after signing out.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let mailbox = Mailbox::new();
        let ports = SendVerificationPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..mailbox.ports()
        };

        let result = mailbox.send(ports, &mailbox.as_ann());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
