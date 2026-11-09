//! A person who forgot their password asks for a reset link by address.
//!
//! The answer is the same whether or not an account has the address, so it
//! cannot be used to find accounts.

use std::sync::Arc;

use ianua_domain::domains::authentication::recovery::reset::ResetInitiator;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, Email};

use crate::auditor::RequestAuditor;
use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserStore;
use crate::ports::limits::{MailPurpose, MailThrottle};
use crate::services::authentication::reset_mail::{OutgoingReset, ResetMailPorts};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The ports [`ResetRequestUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResetRequestPorts {
    /// Finds the account with the address.
    pub user_store: Arc<dyn UserStore>,
    /// Lets one reset link a minute through to an address.
    pub mail_throttle: Arc<dyn MailThrottle>,
    /// Keeps, makes and mails the link.
    pub mail: ResetMailPorts,
}

use crate::services::authentication::reset_mail::ResetRequestPolicy;

/// The address to send a reset link to, and the pages the link opens.
pub struct ResetMailRequest {
    /// The address the person typed; nothing is sent if no account has it.
    pub email: Email,
    /// The organization or tenant whose reset page the link opens.
    pub scope: LinkScope,
}

/// Mails a password reset link.
pub struct ResetRequestUseCase {
    policy: ResetRequestPolicy,
    ports: ResetRequestPorts,
}

impl ResetRequestUseCase {
    /// A use case under `policy`, working through `ports`.
    #[must_use]
    pub fn new(policy: ResetRequestPolicy, ports: ResetRequestPorts) -> Self {
        Self { policy, ports }
    }

    /// The account with `email` when a link should go to it now: there is
    /// one, and the address had no reset link in the past minute. A request
    /// held back answers as one that was sent.
    async fn account_to_mail(
        &self,
        tenant: &ScopedTenant,
        email: &Email,
    ) -> Result<Option<User<ResolvedTenant>>, AppError> {
        let Some(holder) = self
            .ports
            .user_store
            .find_by_email(tenant, email)
            .await
            .or_internal()?
        else {
            return Ok(None);
        };
        let admitted = self
            .ports
            .mail_throttle
            .admit(MailPurpose::PasswordReset, email)
            .await
            .or_internal()?;
        Ok(admitted.then_some(holder))
    }
}

impl Command for ResetRequestUseCase {
    type Caller = ScopedTenant;
    type Input = ResetMailRequest;
    type Output = Result<(), AppError>;

    /// Mails a reset link to `request.email` when an account that may get
    /// one has it. Answers `Ok` either way, so it tells nobody which
    /// addresses have accounts.
    ///
    /// A new link supersedes the account's earlier ones and records
    /// `authentication.password_reset_requested`. An unknown address, one
    /// held back by the per-address throttle, or an account the domain gives
    /// no link records nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` on a deployment with no mail server, before
    ///   any account is looked up, so every address is answered alike; the
    ///   refusal says an administrator must reset the password.
    /// - `AppError::Domain` when the configured lifetime is longer than a
    ///   reset link may live.
    /// - `AppError::Internal` on persistence or token failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: ResetMailRequest,
    ) -> Result<(), AppError> {
        let ResetMailRequest { email, scope } = request;
        let mailing = self.ports.mail.mailing(&self.policy)?;
        let Some(holder) = self.account_to_mail(tenant, &email).await? else {
            return Ok(());
        };
        let Some((mut reset, raw)) = mailing.fresh(&holder, ResetInitiator::User)? else {
            return Ok(());
        };
        mailing.replace_links(tenant, &reset).await?;
        let outgoing = OutgoingReset {
            to: reset.email(),
            locale: holder.locale(),
            raw: &raw,
            scope: &scope,
        };
        mailing.mail(tenant, outgoing).await;
        auditor
            .dispatch_by(&ActorRef::User(*holder.id()), reset.take_events(tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::types::{HttpsUrl, Lifetime, UserId};

    use super::*;
    use crate::test_support::authentication::FakeResetRequestStore;
    use crate::test_support::identity::{FakeUserStore, stored_user};
    use crate::test_support::{
        FakeEventDispatcher, FakeMailSetup, FakeMailer, OpenMailThrottle, ShutMailThrottle,
        block_on, test_auditor, test_ctx, test_link_scope,
    };

    const ADDRESS: &str = "alice@acme.com";

    struct Fixture {
        resets: Arc<FakeResetRequestStore>,
        mailer: Arc<FakeMailer>,
        audit: Arc<FakeEventDispatcher>,
        use_case: ResetRequestUseCase,
    }

    impl Fixture {
        fn with_alice() -> Self {
            Self::holding(FakeUserStore::with_user(UserId::new(), ADDRESS))
        }

        fn holding(users: FakeUserStore) -> Self {
            Self::behind(users, Arc::new(OpenMailThrottle))
        }

        fn behind(users: FakeUserStore, mail_throttle: Arc<dyn MailThrottle>) -> Self {
            let resets = Arc::new(FakeResetRequestStore::empty());
            let mailer = Arc::new(FakeMailer::new());
            let use_case = ResetRequestUseCase::new(
                policy(),
                ResetRequestPorts {
                    user_store: Arc::new(users),
                    mail_throttle,
                    mail: ResetMailPorts {
                        reset_store: resets.clone(),
                        mailer: mailer.clone(),
                        ..ResetMailPorts::fakes()
                    },
                },
            );
            Self {
                resets,
                mailer,
                audit: Arc::new(FakeEventDispatcher::new()),
                use_case,
            }
        }

        fn ask(&self, email: &str) {
            let request = ResetMailRequest {
                email: Email::new(email).unwrap(),
                scope: test_link_scope(),
            };
            let auditor = test_auditor(self.audit.clone());
            let answer = block_on(
                self.use_case
                    .execute(&test_ctx().tenant(), &auditor, request),
            );
            assert!(
                answer.is_ok(),
                "a reset request always answers the same way"
            );
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn policy() -> ResetRequestPolicy {
        ResetRequestPolicy {
            lifetime: Lifetime::seconds(3600).unwrap(),
            base_url: HttpsUrl::new("https://test.example.com").unwrap(),
        }
    }

    /// Alice forgot her password and asks for a link. One is kept, mailed to
    /// her and recorded.
    #[test]
    fn a_known_address_gets_a_link_and_the_request_is_recorded() {
        let fixture = Fixture::with_alice();

        fixture.ask(ADDRESS);

        assert_eq!(fixture.resets.count(), 1);
        assert_eq!(fixture.mailer.recipients(), vec![ADDRESS.to_owned()]);
        assert_eq!(
            fixture.recorded(),
            ["authentication.password_reset_requested"]
        );
    }

    /// Alice clicks the link cold, signed out, from her mail app. It names
    /// the organization and tenant, so it lands on their reset page.
    #[test]
    fn the_reset_link_carries_the_org_and_tenant_it_belongs_to() {
        let fixture = Fixture::with_alice();

        fixture.ask(ADDRESS);

        let url = fixture.mailer.action_url();
        assert!(
            url.contains("org=acme") && url.contains("tenant=prod"),
            "{url}"
        );
        assert!(url.contains("/reset-password?"));
        assert!(url.contains("token="));
    }

    /// Alice never got her first link and asks again. The earlier link
    /// stops working, so a lost email cannot be used later.
    #[test]
    fn asking_again_supersedes_the_outstanding_link() {
        let fixture = Fixture::with_alice();

        fixture.ask(ADDRESS);
        fixture.ask(ADDRESS);

        assert_eq!(fixture.resets.superseded().len(), 2);
        assert_eq!(fixture.mailer.count(), 2);
    }

    /// An unknown address gets the normal successful answer without saving
    /// or superseding resets, sending mail or recording an event.
    #[test]
    fn an_unknown_address_answers_the_same_and_does_nothing() {
        let fixture = Fixture::holding(FakeUserStore::empty());

        fixture.ask("nobody@acme.com");

        assert_eq!(fixture.resets.count(), 0);
        assert!(fixture.resets.superseded().is_empty());
        assert_eq!(fixture.mailer.count(), 0);
        assert!(fixture.recorded().is_empty());
    }

    /// A throttled reset request succeeds without sending mail or recording an event.
    #[test]
    fn a_request_held_back_by_the_throttle_answers_as_sent_and_sends_nothing() {
        let users = FakeUserStore::with_user(UserId::new(), ADDRESS);
        let fixture = Fixture::behind(users, Arc::new(ShutMailThrottle));

        fixture.ask(ADDRESS);

        assert_eq!(fixture.mailer.count(), 0);
        assert!(fixture.recorded().is_empty());
    }

    /// An unverified address gets the normal successful answer without a
    /// stored reset or outgoing mail.
    #[test]
    fn an_unverified_address_gets_no_link() {
        let fixture = Fixture::holding(FakeUserStore::with_unverified_user(UserId::new(), ADDRESS));

        fixture.ask(ADDRESS);

        assert_eq!(fixture.resets.count(), 0);
        assert_eq!(fixture.mailer.count(), 0);
    }

    /// A locked account's reset request succeeds without sending mail.
    #[test]
    fn a_locked_account_gets_no_link() {
        let users = FakeUserStore::empty();
        users.add(stored_user(UserId::new(), ADDRESS, UserStatus::Locked));
        let fixture = Fixture::holding(users);

        fixture.ask(ADDRESS);

        assert_eq!(fixture.mailer.count(), 0);
    }

    /// Without mail setup, the refusal directs Alice to an administrator
    /// and creates no reset, mail or audit event.
    #[test]
    fn no_link_is_sent_where_nothing_is_mailed() {
        let resets = Arc::new(FakeResetRequestStore::empty());
        let mailer = Arc::new(FakeMailer::new());
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = ResetRequestUseCase::new(
            policy(),
            ResetRequestPorts {
                user_store: Arc::new(FakeUserStore::with_user(UserId::new(), ADDRESS)),
                mail_throttle: Arc::new(OpenMailThrottle),
                mail: ResetMailPorts {
                    reset_store: resets.clone(),
                    mailer: mailer.clone(),
                    mail: FakeMailSetup::not_set_up(),
                    ..ResetMailPorts::fakes()
                },
            },
        );
        let request = ResetMailRequest {
            email: Email::new(ADDRESS).unwrap(),
            scope: test_link_scope(),
        };

        let answer =
            block_on(use_case.execute(&test_ctx().tenant(), &test_auditor(audit.clone()), request));

        assert!(
            matches!(answer, Err(AppError::Forbidden(why)) if why.as_str().contains("administrator"))
        );
        assert_eq!(resets.count(), 0);
        assert_eq!(mailer.count(), 0);
        assert!(audit.records.lock().unwrap().is_empty());
    }
}
