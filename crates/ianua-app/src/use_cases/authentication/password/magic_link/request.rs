//! Asking for a sign-in link: one is mailed to the address when an account
//! that may sign in has it.
//!
//! The answer is the same whether or not an account has the address, so it
//! cannot be used to find accounts.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::operations::sign_in_link::SignInLinkMailing;
use ianua_domain::domains::authentication::tokens::refresh::{RefreshToken, RefreshTokenGenerator};
use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::identity::tokens::magic_link::MagicLink;
use ianua_domain::domains::identity::tokens::secure::{NewSecureToken, SecureToken};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Email, HttpsUrl, Lifetime};

use crate::auditor::RequestAuditor;
use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::{MagicLinkToken, SignInLinkStore, UserStore};
use crate::ports::limits::{MailPurpose, MailThrottle};
use crate::ports::shared::{MailRecipient, MailSetup, Mailer};
use crate::ports::tenant::TenantStore;
use crate::services::authentication::channels::{NO_MAGIC_LINKS, ensure_mail_reaches};
use crate::services::authentication::sign_in_gate::{ClientOrigin, admit};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// How long a sign-in link works and the address it is built on.
#[derive(Debug, Clone)]
pub struct MagicLinkPolicy {
    /// How long the link works, at most an hour.
    pub lifetime: Lifetime,
    /// The base URL the link is built on: a page that hands the token to
    /// the sign-in.
    pub base_url: HttpsUrl,
}

/// The ports [`RequestMagicLinkUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RequestMagicLinkPorts {
    /// Finds the account with the address.
    pub user_store: Arc<dyn UserStore>,
    /// Keeps the link until it is used.
    pub magic_link_store: Arc<dyn SignInLinkStore<MagicLink>>,
    /// Composes and sends the sign-in email.
    pub mailer: Arc<dyn Mailer>,
    /// The tenant, which must accept sign-in links from where the request
    /// came from.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Lets one sign-in link a minute through to an address.
    pub mail_throttle: Arc<dyn MailThrottle>,
    /// Makes the link's token and its hash.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// Whether anything can be mailed here at all.
    pub mail: Arc<dyn MailSetup>,
}

/// Who asks for a sign-in link, from where, and the pages the link opens.
pub struct RequestMagicLinkRequest {
    /// The address to send the link to, if an account that may sign in has
    /// it.
    pub email: Email,
    /// The organization or tenant whose sign-in page the link opens.
    pub scope: LinkScope,
    /// Where the request came from.
    pub origin: ClientOrigin,
}

/// Mails a sign-in link.
pub struct RequestMagicLinkUseCase {
    policy: MagicLinkPolicy,
    ports: RequestMagicLinkPorts,
}

impl RequestMagicLinkUseCase {
    /// A use case under `policy`, working through `ports`.
    #[must_use]
    pub fn new(policy: MagicLinkPolicy, ports: RequestMagicLinkPorts) -> Self {
        Self { policy, ports }
    }

    /// The account with `email` when a link should go to it now: it may
    /// sign in, and the address had no sign-in link in the past minute. A
    /// request held back answers as one that was sent.
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
            .filter(User::can_authenticate)
        else {
            return Ok(None);
        };
        let admitted = self
            .ports
            .mail_throttle
            .admit(MailPurpose::MagicLink, email)
            .await
            .or_internal()?;
        Ok(admitted.then_some(holder))
    }

    /// Keeps a new single-use link for `holder`, mailed to the address it
    /// has now, and hands back the raw token for the link.
    async fn saved_link(
        &self,
        tenant: &ScopedTenant,
        holder: &User<ResolvedTenant>,
    ) -> Result<Secret, AppError> {
        let (raw, token_hash) = self
            .ports
            .token_generator
            .generate()
            .map(RefreshToken::into_parts)
            .or_internal()?;
        let link: MagicLinkToken = SecureToken::create(NewSecureToken {
            token_hash,
            user_id: *holder.id(),
            sent_to: holder.email().clone(),
            lifetime: self.policy.lifetime,
        })
        .map_err(AppError::from_domain)?;
        self.ports
            .magic_link_store
            .save(tenant, &link)
            .await
            .or_internal()?;
        Ok(raw)
    }

    /// Mails the sign-in link to `holder`.
    async fn mail_link(
        &self,
        tenant: &ScopedTenant,
        holder: &User<ResolvedTenant>,
        raw: &Secret,
        scope: &LinkScope,
    ) -> Result<(), DomainError> {
        let variables = HashMap::from([
            (
                TemplateVariable::UserName,
                holder.display_name().as_str().to_owned(),
            ),
            (
                TemplateVariable::ActionUrl,
                scope.action_url(&self.policy.base_url, "magic-link", raw.expose()),
            ),
            (
                TemplateVariable::ExpiresAt,
                format!("{} minutes", self.policy.lifetime.whole_seconds() / 60),
            ),
        ]);
        let to = MailRecipient {
            email: holder.email(),
            locale: holder.locale(),
        };
        self.ports
            .mailer
            .send_to_person(to, *tenant, EmailTemplateType::MagicLink, &variables)
            .await
    }
}

impl Command for RequestMagicLinkUseCase {
    type Caller = ScopedTenant;
    type Input = RequestMagicLinkRequest;
    type Output = Result<(), AppError>;

    /// Mails a sign-in link to `request.email` when an account that may
    /// sign in has it. Answers `Ok` either way, so it tells nobody which
    /// addresses have accounts.
    ///
    /// Records `authentication.magic_link_requested` once the mail is
    /// accepted. An unknown address, an account that may not sign in, a
    /// request held back by the per-address throttle, or a failed send
    /// records nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::TenantUnavailable` when the workspace is closed.
    /// - `AppError::Forbidden` when the workspace does not accept sign-in
    ///   links, or not from where the request came from, or the deployment
    ///   has no mail server. Every address is answered alike.
    /// - `AppError::NotFound` when the tenant does not exist.
    /// - `AppError::Domain` when the configured lifetime is longer than a
    ///   sign-in link may live.
    /// - `AppError::Internal` on persistence or token failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: RequestMagicLinkRequest,
    ) -> Result<(), AppError> {
        let RequestMagicLinkRequest {
            email,
            scope,
            origin,
        } = request;
        let ip = origin.ip_address.as_ref();
        admit(
            self.ports.tenant_store.as_ref(),
            tenant,
            AuthMethod::MagicLink,
            ip,
        )
        .await?;
        ensure_mail_reaches(self.ports.mail.as_ref(), NO_MAGIC_LINKS)?;
        let Some(holder) = self.account_to_mail(tenant, &email).await? else {
            return Ok(());
        };
        let raw = self.saved_link(tenant, &holder).await?;
        if self.mail_link(tenant, &holder, &raw, &scope).await.is_err() {
            return Ok(());
        }
        let mut mailing = SignInLinkMailing::mailed(&holder).map_err(AppError::from_domain)?;
        auditor
            .dispatch(&mailing.take_events(tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::tenant::access::auth_config::TenantAuthSettings;
    use ianua_domain::domains::tenant::status::TenantStatus;
    use ianua_domain::types::{CidrRange, UserId};

    use super::*;
    use crate::test_support::identity::{FakeSignInLinks, FakeUserStore, stored_user};
    use crate::test_support::tenant::{
        FakeTenantStore, tenant_store_in_status, tenant_store_signing_in_with,
    };
    use crate::test_support::{
        FakeEventDispatcher, FakeMailSetup, FakeMailer, OpenMailThrottle, ShutMailThrottle,
        block_on, test_auditor, test_ctx, test_link_scope,
    };

    const ADDRESS: &str = "ada@acme.com";
    const LINK_MINUTES: i64 = 15;

    fn accepting_links() -> TenantAuthSettings {
        TenantAuthSettings {
            enabled_methods: vec![AuthMethod::Password, AuthMethod::MagicLink],
            ..TenantAuthSettings::default()
        }
    }

    struct Fixture {
        links: Arc<FakeSignInLinks>,
        mailer: Arc<FakeMailer>,
        audit: Arc<FakeEventDispatcher>,
        use_case: RequestMagicLinkUseCase,
    }

    impl Fixture {
        fn with(users: FakeUserStore) -> Self {
            Self::over(RequestMagicLinkPorts {
                user_store: Arc::new(users),
                tenant_store: tenant_store_signing_in_with(accepting_links()),
                mail_throttle: Arc::new(OpenMailThrottle),
                ..RequestMagicLinkPorts::fakes()
            })
        }

        fn with_ada() -> Self {
            Self::with(FakeUserStore::with_user(UserId::new(), ADDRESS))
        }

        fn over(ports: RequestMagicLinkPorts) -> Self {
            let links = Arc::new(FakeSignInLinks::new());
            let mailer = Arc::new(FakeMailer::new());
            let policy = MagicLinkPolicy {
                lifetime: Lifetime::seconds(LINK_MINUTES * 60).unwrap(),
                base_url: HttpsUrl::new("https://app.ianua.test").unwrap(),
            };
            let use_case = RequestMagicLinkUseCase::new(
                policy,
                RequestMagicLinkPorts {
                    magic_link_store: links.clone(),
                    mailer: mailer.clone(),
                    ..ports
                },
            );
            Self {
                links,
                mailer,
                audit: Arc::new(FakeEventDispatcher::new()),
                use_case,
            }
        }

        fn ask(&self) -> Result<(), AppError> {
            let request = RequestMagicLinkRequest {
                email: Email::new(ADDRESS).unwrap(),
                scope: test_link_scope(),
                origin: ClientOrigin::default(),
            };
            let auditor = test_auditor(self.audit.clone());
            block_on(
                self.use_case
                    .execute(&test_ctx().tenant(), &auditor, request),
            )
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn ports_with(tenants: Arc<FakeTenantStore>) -> RequestMagicLinkPorts {
        RequestMagicLinkPorts {
            user_store: Arc::new(FakeUserStore::with_user(UserId::new(), ADDRESS)),
            tenant_store: tenants,
            ..RequestMagicLinkPorts::fakes()
        }
    }

    /// Ada asks for a sign-in link. One is kept, mailed to her for the
    /// configured time, and recorded.
    #[test]
    fn an_account_that_may_sign_in_is_sent_a_link() {
        let fixture = Fixture::with_ada();

        fixture.ask().unwrap();

        assert_eq!(fixture.mailer.recipients(), vec![ADDRESS.to_owned()]);
        assert_eq!(fixture.links.count(), 1);
        let expires = fixture.mailer.sent.lock().unwrap()[0]
            .variables
            .get(&TemplateVariable::ExpiresAt)
            .cloned();
        assert_eq!(expires, Some(format!("{LINK_MINUTES} minutes")));
        assert_eq!(fixture.recorded(), ["authentication.magic_link_requested"]);
    }

    /// A throttled link request succeeds without sending mail to Ada.
    #[test]
    fn a_link_held_back_by_the_throttle_answers_as_sent_and_sends_nothing() {
        let fixture = Fixture::over(RequestMagicLinkPorts {
            mail_throttle: Arc::new(ShutMailThrottle),
            ..ports_with(tenant_store_signing_in_with(accepting_links()))
        });

        let result = fixture.ask();

        assert!(result.is_ok());
        assert!(fixture.mailer.recipients().is_empty());
    }

    /// Missing mail delivery refuses the request without storing a link,
    /// sending mail or recording an event.
    #[test]
    fn no_link_is_sent_where_nothing_is_mailed() {
        let fixture = Fixture::over(RequestMagicLinkPorts {
            user_store: Arc::new(FakeUserStore::with_user(UserId::new(), ADDRESS)),
            tenant_store: tenant_store_signing_in_with(accepting_links()),
            mail_throttle: Arc::new(OpenMailThrottle),
            mail: FakeMailSetup::not_set_up(),
            ..RequestMagicLinkPorts::fakes()
        });

        let result = fixture.ask();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(fixture.mailer.recipients().is_empty());
        assert_eq!(fixture.links.count(), 0);
        assert!(fixture.recorded().is_empty());
    }

    /// A tenant with magic links disabled refuses the request and sends no mail.
    #[test]
    fn no_link_is_sent_when_the_tenant_has_magic_links_off() {
        let fixture = Fixture::over(ports_with(tenant_store_signing_in_with(
            TenantAuthSettings::default(),
        )));

        let result = fixture.ask();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(fixture.mailer.recipients().is_empty());
    }

    /// An unknown client address fails the tenant's office-network restriction
    /// and no sign-in mail is sent.
    #[test]
    fn no_link_is_sent_from_an_address_the_tenant_does_not_allow() {
        let office_only = TenantAuthSettings {
            ip_allowlist: vec![CidrRange::new("10.0.0.0/8").unwrap()],
            ..accepting_links()
        };
        let fixture = Fixture::over(ports_with(tenant_store_signing_in_with(office_only)));

        let result = fixture.ask();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(fixture.mailer.recipients().is_empty());
    }

    /// A suspended tenant returns unavailable for a sign-in link request.
    #[test]
    fn no_link_is_sent_while_the_tenant_is_suspended() {
        let fixture = Fixture::over(ports_with(tenant_store_in_status(TenantStatus::Suspended)));

        let result = fixture.ask();

        assert!(matches!(result, Err(AppError::TenantUnavailable(_))));
    }

    /// A locked account's request succeeds without storing a link or sending mail.
    #[test]
    fn a_locked_account_is_sent_no_link() {
        let users = FakeUserStore::empty();
        users.add(stored_user(UserId::new(), ADDRESS, UserStatus::Locked));
        let fixture = Fixture::with(users);

        let result = fixture.ask();

        assert!(result.is_ok());
        assert!(fixture.mailer.recipients().is_empty());
        assert_eq!(fixture.links.count(), 0);
    }

    /// An unknown address receives the normal successful answer while no
    /// link, mail or event is created.
    #[test]
    fn an_unknown_address_is_sent_nothing() {
        let fixture = Fixture::with(FakeUserStore::empty());

        let result = fixture.ask();

        assert!(result.is_ok());
        assert!(fixture.mailer.recipients().is_empty());
        assert_eq!(fixture.links.count(), 0);
        assert!(fixture.recorded().is_empty());
    }
}
