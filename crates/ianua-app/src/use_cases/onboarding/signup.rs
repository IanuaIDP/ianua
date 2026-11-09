//! Signup: the public form that asks for an organization. Nothing is founded
//! here: the sign-up waits for its link, and
//! [`ConfirmSignupUseCase`](crate::use_cases::onboarding::confirm_signup::ConfirmSignupUseCase)
//! founds it when the link comes back.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
use ianua_domain::domains::organization::signup::{PendingSignup, SignupDetails};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::shared::validation::ValidationError;
use ianua_domain::types::{DisplayName, Email, HttpsUrl, Label, Lifetime, Locale, Timezone};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::limits::{MailPurpose, MailThrottle};
use crate::ports::organization::{OrgUserStore, PendingSignupStore};
use crate::ports::shared::{MailSetup, Mailer};
use crate::services::authentication::channels::{NO_SIGN_UPS, ensure_mail_reaches};
use crate::use_case::Command;
use crate::use_cases::onboarding::founding::{Founder, locale_or_default, timezone_or_utc};

/// What founding an organization on one's own takes: the founder, and
/// whether this deployment lets anyone found one.
pub struct SelfServiceFounding {
    /// Checks names and passwords and founds the organization.
    pub founder: Founder,
    /// Whether this deployment takes new organizations.
    pub enrollment: Enrollment,
}

/// Whether this deployment lets strangers found organizations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enrollment {
    /// Anyone may sign up: the hosted service.
    Open,
    /// Nobody may. An installation has exactly the one organization it
    /// created for itself, and a public form that made a second would hand a
    /// stranger an account on somebody else's server.
    Closed,
}

impl Enrollment {
    /// Refuses founding a new organization on a deployment that takes none.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` if enrollment is closed.
    pub(super) fn ensure_open(self) -> Result<(), AppError> {
        match self {
            Self::Open => Ok(()),
            Self::Closed => Err(AppError::Forbidden(message!(
                "onboarding-this-installation-does-not-accept-new",
                "this installation does not accept new organizations"
            ))),
        }
    }
}

/// Input for the signup flow.
///
/// No primary domain: a tenant proves a domain after it exists, then makes
/// it primary.
pub struct SignupRequest {
    /// Company name (used to derive org slug and display name).
    pub company_name: String,
    /// Tenant name (used to derive tenant slug and display name).
    pub tenant_name: String,
    /// Admin user's email address.
    pub admin_email: Email,
    /// Admin user's full name, shown in the dashboard.
    pub admin_display_name: DisplayName,
    /// Admin user's plaintext password.
    pub admin_password: String,
    /// Timezone for the tenant (defaults to UTC).
    pub timezone: Option<Timezone>,
    /// Locale for the tenant (defaults to en-US).
    pub locale: Option<Locale>,
}

/// How long a sign-up link works and the address it is built on.
#[derive(Debug, Clone)]
pub struct SignupLinks {
    /// How long the link works, at most a day.
    pub lifetime: Lifetime,
    /// The dashboard address the link is built on.
    pub base_url: HttpsUrl,
}

/// The ports [`SignupUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SignupPorts {
    /// Keeps the sign-up until its link comes back.
    pub pending_signups: Arc<dyn PendingSignupStore>,
    /// Every organization's members, to tell whether the address has an
    /// account.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Mails the link, or the notice to an address that has an account.
    pub mailer: Arc<dyn Mailer>,
    /// Lets one sign-up mail a minute through to an address.
    pub mail_throttle: Arc<dyn MailThrottle>,
    /// Makes the link's token.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// How long the link works and where it lands.
    pub links: SignupLinks,
    /// Whether anything can be mailed here at all.
    pub mail: Arc<dyn MailSetup>,
}

/// Who the sign-up link greets: the founder by name, and the company they
/// are signing up.
struct Greeting {
    /// The founder's name.
    name: String,
    /// The company's name.
    company: String,
}

/// Asks for an organization, to be founded once the founder proves their
/// mailbox.
pub struct SignupUseCase {
    founding: SelfServiceFounding,
    ports: SignupPorts,
}

impl SignupUseCase {
    /// A use case founding through `founding` and working through `ports`.
    #[must_use]
    pub fn new(founding: SelfServiceFounding, ports: SignupPorts) -> Self {
        Self { founding, ports }
    }

    /// What `request` asks for, checked: the names, and the password hashed
    /// under the rules a new organization starts with.
    async fn details(&self, request: SignupRequest) -> Result<SignupDetails, AppError> {
        self.founding
            .founder
            .ensure_names_free(&request.company_name, &request.tenant_name)
            .await?;
        Ok(SignupDetails {
            company_name: Label::new("company_name", &request.company_name).map_err(invalid)?,
            tenant_name: Label::new("tenant_name", &request.tenant_name).map_err(invalid)?,
            admin_display_name: request.admin_display_name,
            password_hash: self
                .founding
                .founder
                .checked_password(&request.admin_password)
                .await?,
            timezone: timezone_or_utc(request.timezone.as_ref())?,
            locale: locale_or_default(request.locale.as_ref())?,
        })
    }

    /// Keeps a sign-up for `email` and mails its link.
    async fn pending(&self, email: Email, details: SignupDetails) -> Result<(), AppError> {
        let generator = self.ports.token_generator.as_ref();
        let (raw_token, token_hash) = generator.generate().or_internal()?.into_parts();
        let greeting = Greeting {
            name: details.admin_display_name.as_str().to_owned(),
            company: details.company_name.as_str().to_owned(),
        };
        let signup = PendingSignup::request(email, details, token_hash, self.ports.links.lifetime)
            .map_err(AppError::from_domain)?;
        self.ports
            .pending_signups
            .save(&signup)
            .await
            .or_internal()?;
        let variables = self.link_variables(greeting, &raw_token);
        self.send(
            signup.email(),
            EmailTemplateType::SignupVerification,
            &variables,
        )
        .await;
        Ok(())
    }

    /// Tells the holder of `email`, who has an account already, that
    /// someone asked to sign up with it.
    async fn notify_holder(&self, email: &Email, name: &DisplayName) {
        let base = self.ports.links.base_url.as_str();
        let variables = HashMap::from([
            (TemplateVariable::UserName, name.as_str().to_owned()),
            (TemplateVariable::ActionUrl, format!("{base}/login")),
        ]);
        self.send(email, EmailTemplateType::SignupAccountExists, &variables)
            .await;
    }

    /// What the sign-up link template is filled with: the founder's name
    /// and the company they are signing up, then the link.
    fn link_variables(
        &self,
        greeting: Greeting,
        raw_token: &Secret,
    ) -> HashMap<TemplateVariable, String> {
        let links = &self.ports.links;
        HashMap::from([
            (TemplateVariable::UserName, greeting.name),
            (TemplateVariable::OrganizationName, greeting.company),
            (
                TemplateVariable::ActionUrl,
                format!(
                    "{}/signup/confirm?token={}",
                    links.base_url.as_str(),
                    raw_token.expose()
                ),
            ),
            (
                TemplateVariable::ExpiresAt,
                format!("{} hours", links.lifetime.whole_seconds() / 3600),
            ),
        ])
    }

    /// Mails `template` to `email`. A mail service that refuses fails
    /// nothing: the answer is the same either way, and the person can sign
    /// up again.
    async fn send(
        &self,
        email: &Email,
        template: EmailTemplateType,
        variables: &HashMap<TemplateVariable, String>,
    ) {
        let _ = self
            .ports
            .mailer
            .send(email, None, template, variables)
            .await;
    }

    /// Whether a sign-up mail may go to `email` now.
    async fn admitted(&self, email: &Email) -> Result<bool, AppError> {
        self.ports
            .mail_throttle
            .admit(MailPurpose::Signup, email)
            .await
            .or_internal()
    }
}

impl Command for SignupUseCase {
    type Caller = ();
    type Input = SignupRequest;
    type Output = Result<(), AppError>;

    /// Asks for an organization for a stranger, and mails a link to the
    /// address given. Nothing is founded until the link comes back.
    ///
    /// The answer is the same whether or not the address has an account,
    /// and the password is hashed either way, so the answer and its timing
    /// say nothing about it. An address with an account in any organization
    /// is mailed a notice instead of a link: its holder signs in, and founds
    /// another organization from there under the same address. At most one
    /// mail a minute goes to an address; one held back answers the same.
    ///
    /// Nobody is signed in yet, so it takes no caller, and it records
    /// nothing: nothing exists yet to record it in.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` if this deployment does not take signups, or
    ///   has no mail server, so the link that founds the organization would
    ///   never arrive. Both come before anything is checked or looked up.
    /// - `AppError::Conflict` if the company name is taken. Organization
    ///   names are public, as they are in every sign-in address.
    /// - `AppError::Domain` if a name or the password breaks the rules, or
    ///   the password appears in known breaches or could not be looked up.
    /// - `AppError::Internal` on persistence or hashing failure.
    async fn execute(
        &self,
        (): &(),
        _: &RequestAuditor,
        request: SignupRequest,
    ) -> Result<(), AppError> {
        self.founding.enrollment.ensure_open()?;
        ensure_mail_reaches(self.ports.mail.as_ref(), NO_SIGN_UPS)?;
        let email = request.admin_email.clone();
        let details = self.details(request).await?;
        if !self.admitted(&email).await? {
            return Ok(());
        }
        let taken = self
            .ports
            .org_users
            .email_exists(&email)
            .await
            .or_internal()?;
        if taken {
            self.notify_holder(&email, &details.admin_display_name)
                .await;
            return Ok(());
        }
        self.pending(email, details).await
    }
}

/// A value the founder gave that breaks its rules.
fn invalid(error: ValidationError) -> AppError {
    AppError::from_domain(DomainError::from(error))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::credentials::breach::BreachStatus;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::tenant::compliance_limits::ComplianceLimits;
    use ianua_domain::test_support::fakes::FakeHasher;
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::ports::authentication::CredentialBreachChecker;
    use crate::test_support::authentication::{
        FakeBreachChecker, UnreachableBreachChecker, hashing_with,
    };
    use crate::test_support::organization::{
        FakeOrgUserStore, FakeOrganizationStore, FakePendingSignupStore, org_user_store_with,
        test_org_user,
    };
    use crate::test_support::tenant::cfg;
    use crate::test_support::{
        FakeEventDispatcher, FakeMailSetup, FakeMailer, ShutMailThrottle, block_on, test_auditor,
    };
    use crate::use_cases::onboarding::founding::FoundingPorts;

    /// The deployment and stores a sign-up goes through.
    struct Setup {
        pending: Arc<FakePendingSignupStore>,
        mailer: Arc<FakeMailer>,
        owners: Arc<FakeOrgUserStore>,
        orgs: Arc<FakeOrganizationStore>,
        breaches: Arc<dyn CredentialBreachChecker>,
    }

    impl Setup {
        /// Nothing signed up yet, and no password found in a breach.
        fn new() -> Self {
            Self::checking(Arc::new(FakeBreachChecker::default()))
        }

        /// Nothing signed up yet, passwords looked up in `breaches`.
        fn checking(breaches: Arc<dyn CredentialBreachChecker>) -> Self {
            Self {
                pending: Arc::new(FakePendingSignupStore::empty()),
                mailer: Arc::new(FakeMailer::new()),
                owners: Arc::new(FakeOrgUserStore::empty()),
                orgs: Arc::new(FakeOrganizationStore::empty()),
                breaches,
            }
        }

        /// The ports a sign-up writes through.
        fn ports(&self) -> SignupPorts {
            SignupPorts {
                pending_signups: self.pending.clone(),
                org_users: self.owners.clone(),
                mailer: self.mailer.clone(),
                links: links(),
                ..SignupPorts::fakes()
            }
        }

        /// Signs up through `ports` on a deployment with `enrollment`.
        fn sign_up_with(
            &self,
            enrollment: Enrollment,
            ports: SignupPorts,
            request: SignupRequest,
        ) -> Result<(), AppError> {
            let founder = Founder::new(
                hashing_with(Arc::new(FakeHasher)),
                cfg(),
                ComplianceLimits::default(),
                FoundingPorts {
                    org_store: self.orgs.clone(),
                    org_user_store: self.owners.clone(),
                    breach_checker: self.breaches.clone(),
                    ..FoundingPorts::fakes()
                },
            );
            let use_case = SignupUseCase::new(
                SelfServiceFounding {
                    founder,
                    enrollment,
                },
                ports,
            );
            let audit = Arc::new(FakeEventDispatcher::new());
            block_on(use_case.execute(&(), &test_auditor(audit), request))
        }

        /// Signs up on the hosted service.
        fn sign_up(&self, request: SignupRequest) -> Result<(), AppError> {
            self.sign_up_with(Enrollment::Open, self.ports(), request)
        }
    }

    /// Where sign-up links land, good for a day.
    pub(super) fn links() -> SignupLinks {
        SignupLinks {
            lifetime: Lifetime::seconds(86_400).unwrap(),
            base_url: HttpsUrl::new("https://app.ianua.test").unwrap(),
        }
    }

    /// Alice signs Acme up.
    pub(super) fn signup_req() -> SignupRequest {
        SignupRequest {
            company_name: "Acme Corp".to_owned(),
            tenant_name: "Production".to_owned(),
            admin_email: Email::new("admin@acme.com").unwrap(),
            admin_display_name: DisplayName::new("Alice", &cfg().display_name).unwrap(),
            admin_password: "SecureP@ssw0rd!".to_owned(),
            timezone: None,
            locale: None,
        }
    }

    /// Alice signs Acme up. Nothing is founded yet: the sign-up waits, and
    /// a link to confirm it goes to her address.
    #[test]
    fn a_sign_up_waits_for_its_link() {
        let setup = Setup::new();

        setup.sign_up(signup_req()).unwrap();

        assert_eq!(setup.pending.count(), 1);
        assert_eq!(setup.mailer.recipients(), ["admin@acme.com"]);
        assert_eq!(setup.orgs.count(), 0);
    }

    /// With no mail delivery configured, signup is forbidden and creates
    /// neither a pending signup nor a message.
    #[test]
    fn a_sign_up_is_refused_where_nothing_is_mailed() {
        let setup = Setup::new();
        let ports = SignupPorts {
            mail: FakeMailSetup::not_set_up(),
            ..setup.ports()
        };

        let result = setup.sign_up_with(Enrollment::Open, ports, signup_req());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.pending.count(), 0);
        assert_eq!(setup.mailer.count(), 0);
    }

    /// Signup with an existing account's address still succeeds, mailing
    /// that address while creating no pending signup.
    #[test]
    fn an_address_with_an_account_gets_the_same_answer() {
        let ann = test_org_user(OrganizationId::new(), "admin@acme.com", OrgRole::Owner);
        let setup = Setup {
            owners: Arc::new(org_user_store_with([ann])),
            ..Setup::new()
        };

        let result = setup.sign_up(signup_req());

        assert!(result.is_ok());
        assert_eq!(setup.pending.count(), 0);
        assert_eq!(setup.mailer.recipients(), ["admin@acme.com"]);
    }

    /// When the mail throttle refuses delivery, signup still succeeds but
    /// creates no message or pending signup.
    #[test]
    fn a_sign_up_mailed_a_moment_ago_sends_nothing_more() {
        let setup = Setup::new();
        let ports = SignupPorts {
            mail_throttle: Arc::new(ShutMailThrottle),
            ..setup.ports()
        };

        let result = setup.sign_up_with(Enrollment::Open, ports, signup_req());

        assert!(result.is_ok());
        assert_eq!(setup.mailer.count(), 0);
        assert_eq!(setup.pending.count(), 0);
    }

    /// A password too weak for a new organization's rules is refused and
    /// nothing waits.
    #[test]
    fn a_weak_password_is_refused() {
        let setup = Setup::new();

        let result = setup.sign_up(SignupRequest {
            admin_password: "short".to_owned(),
            ..signup_req()
        });

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(setup.pending.count(), 0);
    }

    /// A breached password is refused before a pending signup is stored or
    /// any recipient is mailed.
    #[test]
    fn a_breached_password_is_refused() {
        let setup = Setup::checking(Arc::new(FakeBreachChecker {
            status: BreachStatus::Breached(42),
        }));

        let result = setup.sign_up(signup_req());

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(setup.pending.count(), 0);
        assert!(setup.mailer.recipients().is_empty());
    }

    /// An unavailable breach checker prevents accepting the password and
    /// leaves no pending signup.
    #[test]
    fn a_password_the_breach_service_cannot_look_up_is_refused() {
        let setup = Setup::checking(Arc::new(UnreachableBreachChecker::default()));

        let result = setup.sign_up(signup_req());

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(setup.pending.count(), 0);
    }

    /// A password no breach holds is taken, and the sign-up waits for its
    /// link.
    #[test]
    fn a_clean_password_is_taken() {
        let setup = Setup::checking(Arc::new(FakeBreachChecker {
            status: BreachStatus::Clean,
        }));

        setup.sign_up(signup_req()).unwrap();

        assert_eq!(setup.pending.count(), 1);
    }

    /// Closed enrollment forbids public signup and creates no pending
    /// signup.
    #[test]
    fn a_closed_installation_refuses_signup() {
        let setup = Setup::new();

        let result = setup.sign_up_with(Enrollment::Closed, setup.ports(), signup_req());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.pending.count(), 0);
    }
}
