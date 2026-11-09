//! The mail provider a tenant's own mail goes out through.
//!
//! By default a tenant's password resets, invitations and sign-in links go
//! out through the platform's mail. A tenant that wants them sent from its
//! own mail account, with its own reputation and logs, names a provider
//! here: an SMTP server, SendGrid, Amazon SES, Postmark or Mailgun. The
//! provider's credentials are sealed before they reach the domain and never
//! print.
//!
//! A newly named provider is unverified until a test send through it
//! worked. Until then mail keeps going out through the platform, so a
//! mistyped password never stops people getting their reset links.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::branding::control::BrandingControl;
use crate::domains::branding::events::{MailProviderChanged, MailProviderTested};
use crate::domains::identity::account::control::RecentProof;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::numeric::validate_range;
use crate::shared::validation::{Charset, TextValue, ValidationError, Validator, text_value};
use crate::types::{DomainName, PublicHost, SealedSecret};

/// The platform's own mail, which a tenant's mail goes through until its
/// own provider is tested.
static PLATFORM_MAIL: MailProvider = MailProvider::Platform;

text_value! {
    /// The user name an SMTP server signs the platform in with.
    pub struct SmtpUsername;
}

impl TextValue for SmtpUsername {
    const FIELD: &'static str = "smtp_username";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.not_blank().length(1..=256).no_control_chars()
    }
}

text_value! {
    /// An AWS region SES runs in, such as `eu-west-1`.
    pub struct SesRegion;
}

impl TextValue for SesRegion {
    const FIELD: &'static str = "ses_region";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.identifier(
            5..=32,
            Charset::LOWERCASE | Charset::DIGIT | Charset::HYPHEN,
        )
    }
}

text_value! {
    /// The id of an AWS access key, such as `AKIAIOSFODNN7EXAMPLE`. Only the
    /// id: the secret half is sealed apart.
    pub struct AwsAccessKeyId;
}

impl TextValue for AwsAccessKeyId {
    const FIELD: &'static str = "aws_access_key_id";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.identifier(16..=128, Charset::UPPERCASE | Charset::DIGIT)
    }
}

/// The port an SMTP server takes mail on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmtpPort(u16);

impl SmtpPort {
    /// Checks that `port` is a port a server can listen on.
    ///
    /// # Errors
    ///
    /// - [`ValidationError::OutOfRange`] for port 0.
    pub fn new(port: u16) -> Result<Self, ValidationError> {
        validate_range("smtp_port", port, 1..=u16::MAX)?;
        Ok(Self(port))
    }

    /// The port number.
    #[must_use]
    pub fn get(self) -> u16 {
        self.0
    }
}

/// How the connection to an SMTP server is encrypted. There is no plain
/// choice: the platform signs in with the tenant's password and sends
/// sign-in links, and neither may cross the network readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpSecurity {
    /// Plain at first, upgraded with `STARTTLS` before signing in. The
    /// upgrade is required, never skipped when the server does not offer it.
    StartTls,
    /// TLS from the first byte, usually on port 465.
    ImplicitTls,
}

/// An SMTP server the tenant runs or rents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpServer {
    host: PublicHost,
    port: SmtpPort,
    security: SmtpSecurity,
    username: SmtpUsername,
    password: SealedSecret,
}

/// What an [`SmtpServer`] is made from.
#[derive(Debug, Clone)]
pub struct SmtpServerParams {
    /// Where the server is. Never an internal host.
    pub host: PublicHost,
    /// The port it takes mail on.
    pub port: SmtpPort,
    /// How the connection is encrypted.
    pub security: SmtpSecurity,
    /// The user name to sign in with.
    pub username: SmtpUsername,
    /// The password, sealed.
    pub password: SealedSecret,
}

impl SmtpServer {
    /// The server `params` describe.
    #[must_use]
    pub fn new(params: SmtpServerParams) -> Self {
        Self {
            host: params.host,
            port: params.port,
            security: params.security,
            username: params.username,
            password: params.password,
        }
    }

    /// Where the server is.
    #[must_use]
    pub fn host(&self) -> &PublicHost {
        &self.host
    }

    /// The port it takes mail on.
    #[must_use]
    pub fn port(&self) -> SmtpPort {
        self.port
    }

    /// How the connection is encrypted.
    #[must_use]
    pub fn security(&self) -> SmtpSecurity {
        self.security
    }

    /// The user name to sign in with.
    #[must_use]
    pub fn username(&self) -> &SmtpUsername {
        &self.username
    }

    /// The password, sealed.
    #[must_use]
    pub fn password(&self) -> &SealedSecret {
        &self.password
    }
}

/// The Mailgun region an account lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailgunRegion {
    /// `api.mailgun.net`.
    Us,
    /// `api.eu.mailgun.net`.
    Eu,
}

/// The provider a tenant's mail goes out through.
///
/// `Debug` prints no credential: each is a [`SealedSecret`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum MailProvider {
    /// The platform's own mail.
    #[default]
    Platform,
    /// An SMTP server.
    Smtp(SmtpServer),
    /// A SendGrid account.
    SendGrid {
        /// The API key, sealed.
        api_key: SealedSecret,
    },
    /// Amazon SES.
    Ses {
        /// The region SES runs in.
        region: SesRegion,
        /// The access key's id.
        access_key_id: AwsAccessKeyId,
        /// The access key's secret, sealed.
        secret_access_key: SealedSecret,
    },
    /// A Postmark server.
    Postmark {
        /// The server token, sealed.
        server_token: SealedSecret,
    },
    /// A Mailgun account.
    Mailgun {
        /// The sending domain set up in Mailgun.
        domain: DomainName,
        /// The region the account lives in.
        region: MailgunRegion,
        /// The API key, sealed.
        api_key: SealedSecret,
    },
}

impl MailProvider {
    /// What kind of provider this is, which records may name.
    #[must_use]
    pub fn kind(&self) -> MailProviderKind {
        match self {
            Self::Platform => MailProviderKind::Platform,
            Self::Smtp(_) => MailProviderKind::Smtp,
            Self::SendGrid { .. } => MailProviderKind::SendGrid,
            Self::Ses { .. } => MailProviderKind::Ses,
            Self::Postmark { .. } => MailProviderKind::Postmark,
            Self::Mailgun { .. } => MailProviderKind::Mailgun,
        }
    }
}

/// The kind of a [`MailProvider`], without its credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailProviderKind {
    /// The platform's own mail.
    Platform,
    /// An SMTP server.
    Smtp,
    /// SendGrid.
    SendGrid,
    /// Amazon SES.
    Ses,
    /// Uses the configured Postmark API credentials to deliver mail.
    Postmark,
    /// Uses the configured Mailgun domain and credentials to deliver mail.
    Mailgun,
}

impl MailProviderKind {
    /// The stable name storage and records use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::Smtp => "smtp",
            Self::SendGrid => "sendgrid",
            Self::Ses => "ses",
            Self::Postmark => "postmark",
            Self::Mailgun => "mailgun",
        }
    }
}

/// What the last test send through the provider showed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderCheck {
    /// No test send has gone through it yet.
    Unverified,
    /// A test send went through it.
    Verified {
        /// When.
        at: OffsetDateTime,
    },
    /// A test send through it failed.
    Failed {
        /// When.
        at: OffsetDateTime,
    },
}

/// How a test send through the provider went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestSendOutcome {
    /// The provider took the mail.
    Delivered,
    /// The provider refused it or could not be reached.
    Refused,
}

/// A [`TenantMailProvider`] as storage holds it, read back through
/// [`TenantMailProvider::reconstitute`].
pub struct TenantMailProviderRow {
    /// The delivery configuration selected for this tenant's outgoing mail.
    pub provider: MailProvider,
    /// What the last test send showed.
    pub check: ProviderCheck,
    /// When the provider was last changed.
    pub updated_at: OffsetDateTime,
}

/// The mail provider one tenant's mail goes out through.
#[derive(Debug, Clone)]
pub struct TenantMailProvider<T: TenantScope> {
    provider: MailProvider,
    check: ProviderCheck,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> TenantMailProvider<T> {
    /// The platform's own mail, which every tenant starts with.
    ///
    /// The platform makes it as it provisions the tenant. It sends through
    /// the platform as before, so nobody decides anything by making it.
    #[must_use]
    pub fn platform_mail() -> Self {
        Self {
            provider: MailProvider::Platform,
            check: ProviderCheck::Unverified,
            updated_at: crate::shared::clock::now(),
            raised: Raised::default(),
            _scope: PhantomData,
        }
    }

    /// Rebuilds a tenant's mail provider from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says a test send was
    ///   made through the platform's own mail, which is never tested, or
    ///   that the test came before the provider was named.
    pub fn reconstitute(row: TenantMailProviderRow) -> Result<Self, DomainError> {
        let tested_at = match row.check {
            ProviderCheck::Unverified => None,
            ProviderCheck::Verified { at } | ProviderCheck::Failed { at } => Some(at),
        };
        RowCheck::of("tenant_mail_provider")
            .holds(
                row.provider != MailProvider::Platform || tested_at.is_none(),
                "a test send through the platform's own mail",
            )
            .in_order_if(row.updated_at, tested_at, "tested before it was named")
            .finish()?;
        Ok(Self {
            provider: row.provider,
            check: row.check,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The provider named, tested or not.
    #[must_use]
    pub fn provider(&self) -> &MailProvider {
        &self.provider
    }

    /// What the last test send showed.
    #[must_use]
    pub fn check(&self) -> ProviderCheck {
        self.check
    }

    /// When the provider was last changed.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// The provider mail goes out through now: the one named once a test
    /// send through it worked, the platform's own until then.
    #[must_use]
    pub fn delivers_through(&self) -> &MailProvider {
        match self.check {
            ProviderCheck::Verified { .. } => &self.provider,
            ProviderCheck::Unverified | ProviderCheck::Failed { .. } => &PLATFORM_MAIL,
        }
    }

    /// Sends the tenant's mail through `provider` once a test send through
    /// it works, or through the platform's own mail again. Raises
    /// `branding.mail_provider_changed`, naming only the kinds.
    ///
    /// Mail carries password reset and sign-in links. Sam may only view
    /// branding. Without this check he points the tenant's mail at a server
    /// of his own, and every reset link passes through it.
    ///
    /// Moving the mail moves those links too, so `by` must also have proved
    /// who they are again just now: Mallory, holding Fay's stolen session,
    /// does not redirect the next reset link to her own server.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change branding.
    /// - [`DomainError::Forbidden`] when `proof` is not a fresh proof of the
    ///   person acting.
    pub fn switch_to(
        &mut self,
        provider: MailProvider,
        by: &BrandingControl<'_>,
        proof: &impl RecentProof,
    ) -> Result<(), DomainError> {
        by.ensure_may_change()?;
        by.ensure_proved_recently(proof)?;
        let old_kind = self.provider.kind();
        self.provider = provider;
        self.check = ProviderCheck::Unverified;
        self.updated_at = crate::shared::clock::now();
        self.raised.raise(MailProviderChanged {
            old_kind,
            new_kind: self.provider.kind(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Records how a test send through the named provider went. Raises
    /// `branding.mail_provider_tested`, naming the kind and the outcome.
    ///
    /// A delivered test moves the tenant's real mail onto the provider, so
    /// when that happened stays on record.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the tenant uses the platform's own
    ///   mail, which is not tested.
    pub fn record_test_send(&mut self, outcome: TestSendOutcome) -> Result<(), DomainError> {
        if self.provider == MailProvider::Platform {
            return Err(DomainError::conflict(message!(
                "branding-the-platform-s-own-mail-is",
                "the platform's own mail is not tested per tenant"
            )));
        }
        let at = crate::shared::clock::now();
        self.check = match outcome {
            TestSendOutcome::Delivered => ProviderCheck::Verified { at },
            TestSendOutcome::Refused => ProviderCheck::Failed { at },
        };
        self.raised.raise(MailProviderTested {
            kind: self.provider.kind(),
            outcome,
            occurred_at: at,
        });
        Ok(())
    }
}

impl<T: TenantScope> Raises for TenantMailProvider<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::{BrandingAction, SystemPermission};
    use crate::domains::tenant::fixtures::{ProvedJustNow, person};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::HostName;

    type Mail = TenantMailProvider<ResolvedTenant>;

    fn editor() -> BrandingControl<'static> {
        BrandingControl::new(anyone_holding(&[SystemPermission::Branding(
            BrandingAction::Update,
        )]))
    }

    fn viewer() -> BrandingControl<'static> {
        BrandingControl::new(anyone_holding(&[SystemPermission::Branding(
            BrandingAction::View,
        )]))
    }

    fn sendgrid() -> MailProvider {
        MailProvider::SendGrid {
            api_key: SealedSecret::new("v1.U0cuc2VjcmV0").unwrap(),
        }
    }

    fn smtp() -> MailProvider {
        MailProvider::Smtp(SmtpServer::new(SmtpServerParams {
            host: PublicHost::new(HostName::new("smtp.acme.com").unwrap()).unwrap(),
            port: SmtpPort::new(587).unwrap(),
            security: SmtpSecurity::StartTls,
            username: SmtpUsername::new("mailer@acme.com").unwrap(),
            password: SealedSecret::new("v1.c210cC1wYXNz").unwrap(),
        }))
    }

    /// Fay, who may change branding, names SendGrid. It is unverified, mail
    /// still goes through the platform, and the change is recorded.
    #[test]
    fn a_new_provider_waits_for_a_test_send() {
        let mut mail = Mail::platform_mail();

        let fay = editor();
        mail.switch_to(sendgrid(), &fay, &fresh(&fay)).unwrap();

        assert_eq!(mail.provider().kind(), MailProviderKind::SendGrid);
        assert_eq!(mail.check(), ProviderCheck::Unverified);
        assert_eq!(mail.delivers_through(), &MailProvider::Platform);
        assert_eq!(
            raised_names(&mut mail),
            vec!["branding.mail_provider_changed"]
        );
    }

    /// A test send through SendGrid works, and mail then goes out through
    /// it. A failed one leaves mail on the platform.
    #[test]
    fn mail_moves_to_the_provider_once_a_test_send_worked() {
        let mut mail = Mail::platform_mail();
        let fay = editor();
        mail.switch_to(sendgrid(), &fay, &fresh(&fay)).unwrap();

        mail.record_test_send(TestSendOutcome::Refused).unwrap();
        assert_eq!(mail.delivers_through(), &MailProvider::Platform);
        mail.record_test_send(TestSendOutcome::Delivered).unwrap();

        assert_eq!(mail.delivers_through(), &sendgrid());
    }

    /// Fay tests the SendGrid account she named. The test is recorded with
    /// the kind of provider and how it went, so when Acme's real mail moved
    /// onto it stays on record.
    #[test]
    fn a_test_send_is_recorded_with_its_outcome() {
        let mut mail = Mail::platform_mail();
        let fay = editor();
        mail.switch_to(sendgrid(), &fay, &fresh(&fay)).unwrap();
        raised_names(&mut mail);

        mail.record_test_send(TestSendOutcome::Delivered).unwrap();

        let events = raised(&mut mail);
        assert_eq!(
            events[0].event_type().as_str(),
            "branding.mail_provider_tested"
        );
        assert_eq!(events[0].payload().get("provider"), Some("sendgrid"));
        assert_eq!(events[0].payload().get("result"), Some("delivered"));
    }

    /// A branding viewer cannot switch to SMTP: the platform remains the
    /// selected provider and no change event is raised.
    #[test]
    fn a_viewer_cannot_move_the_mail() {
        let mut mail = Mail::platform_mail();

        let sam = viewer();
        let refused = mail.switch_to(smtp(), &sam, &fresh(&sam));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(mail.provider(), &MailProvider::Platform);
        assert!(raised_names(&mut mail).is_empty());
    }

    /// A fresh proof for another person cannot authorize a mail-provider
    /// switch, leaving platform mail selected and raising no event.
    #[test]
    fn moving_the_mail_needs_a_fresh_proof() {
        let mut mail = Mail::platform_mail();
        let someone_else = person("mallory@evil.test");

        let refused = mail.switch_to(smtp(), &editor(), &ProvedJustNow::by(&someone_else));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(mail.provider(), &MailProvider::Platform);
        assert!(raised_names(&mut mail).is_empty());
    }

    /// A proof that the person `control` names signed in again just now.
    fn fresh(control: &BrandingControl<'_>) -> ProvedJustNow {
        ProvedJustNow::by(control.by())
    }

    /// A private IP address and a single-label service name are both rejected
    /// as public hosts for SMTP.
    #[test]
    fn an_smtp_server_is_never_internal() {
        for internal in ["10.0.0.5", "postfix"] {
            assert!(PublicHost::new(HostName::new(internal).unwrap()).is_err());
        }
    }

    /// The SMTP password and the SendGrid key never show when the provider
    /// is printed, as a log line would print it.
    #[test]
    fn credentials_never_print() {
        let printed = format!("{:?} {:?}", smtp(), sendgrid());

        assert!(!printed.contains("c210cC1wYXNz"), "{printed}");
        assert!(!printed.contains("U0cuc2VjcmV0"), "{printed}");
    }

    /// The platform's own mail is not tested per tenant, so a test result
    /// for it is refused.
    #[test]
    fn the_platform_mail_takes_no_test_result() {
        let mut mail = Mail::platform_mail();

        let refused = mail.record_test_send(TestSendOutcome::Delivered);

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
    }

    /// Port 0 makes no SMTP port; an SES key id in lower case is refused.
    #[test]
    fn ports_and_key_ids_are_checked() {
        assert!(SmtpPort::new(0).is_err());
        assert!(AwsAccessKeyId::new("akiaiosfodnn7example").is_err());
        assert!(AwsAccessKeyId::new("AKIAIOSFODNN7EXAMPLE").is_ok());
    }

    /// A stored verification result for platform mail is rejected as corrupt,
    /// since platform mail is not tested per tenant.
    #[test]
    fn a_stored_test_of_the_platform_mail_is_refused() {
        let now = crate::shared::clock::now();
        let row = TenantMailProviderRow {
            provider: MailProvider::Platform,
            check: ProviderCheck::Verified { at: now },
            updated_at: now,
        };

        assert!(refused_as_corrupt(&Mail::reconstitute(row)));
    }

    /// A verified SendGrid provider is stored and read back as it was.
    #[test]
    fn a_stored_provider_reads_back() {
        let now = crate::shared::clock::now();
        let row = TenantMailProviderRow {
            provider: sendgrid(),
            check: ProviderCheck::Verified { at: now },
            updated_at: now,
        };

        let mail = Mail::reconstitute(row).unwrap();

        assert_eq!(mail.delivers_through(), &sendgrid());
    }
}
