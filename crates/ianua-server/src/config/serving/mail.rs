//! The platform's own mail: the account it goes out through, the address
//! it comes from, and how long the links it carries last.

use std::time::Duration;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_boot::environment::Environment;
use ianua_domain::domains::branding::mail_provider::{AwsAccessKeyId, MailgunRegion, SesRegion};
use ianua_domain::types::{DomainName, Email, Label};
use ianua_infra::mail::{MailAccount, PlatformMail, SmtpAccount, SmtpLogin, SmtpTls};

const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(3600);
const DAY: Duration = Duration::from_secs(86_400);

/// Which provider `EMAIL_PROVIDER` names, or that there is none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provider {
    Smtp,
    SendGrid,
    Postmark,
    Mailgun,
    Ses,
    NotSetUp,
}

impl Provider {
    /// The settings only this provider reads.
    fn own_settings(self) -> &'static [&'static str] {
        match self {
            Self::NotSetUp => &[],
            Self::Smtp => &[
                "SMTP_HOST",
                "SMTP_PORT",
                "SMTP_TLS",
                "SMTP_USERNAME",
                "SMTP_PASSWORD",
                "SMTP_PASSWORD_FILE",
            ],
            Self::SendGrid => &["SENDGRID_API_KEY", "SENDGRID_API_KEY_FILE"],
            Self::Postmark => &["POSTMARK_SERVER_TOKEN", "POSTMARK_SERVER_TOKEN_FILE"],
            Self::Mailgun => &[
                "MAILGUN_DOMAIN",
                "MAILGUN_REGION",
                "MAILGUN_API_KEY",
                "MAILGUN_API_KEY_FILE",
            ],
            Self::Ses => &[
                "SES_REGION",
                "SES_ACCESS_KEY_ID",
                "SES_SECRET_ACCESS_KEY",
                "SES_SECRET_ACCESS_KEY_FILE",
            ],
        }
    }
}

/// Every provider, for refusing another's settings.
const PROVIDERS: [Provider; 5] = [
    Provider::Smtp,
    Provider::SendGrid,
    Provider::Postmark,
    Provider::Mailgun,
    Provider::Ses,
];

/// How long each emailed link lasts.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LinkLifetimes {
    /// `EMAIL_PASSWORD_RESET_TTL_SECONDS` (3600).
    pub password_reset: Duration,
    /// `EMAIL_MAGIC_LINK_TTL_SECONDS` (900).
    pub magic_link: Duration,
    /// `EMAIL_VERIFICATION_TTL_SECONDS` (3600).
    pub verification: Duration,
    /// `EMAIL_ORG_VERIFICATION_TTL_SECONDS` (86400).
    pub org_verification: Duration,
    /// `INVITATION_TTL_SECONDS` (86400), at most thirty days.
    pub invitation: Duration,
    /// `ORG_INVITATION_TTL_SECONDS` (86400), at most thirty days.
    pub org_invitation: Duration,
    /// `EMAIL_CHANGE_TTL_SECONDS` (86400).
    pub email_change: Duration,
}

/// The platform's own mail.
#[derive(Debug, Clone)]
pub(crate) struct MailConfig {
    /// `EMAIL_PROVIDER` (`smtp`) with its settings, `EMAIL_FROM` and
    /// `EMAIL_FROM_NAME`. `EMAIL_PROVIDER=none` sets up no mail server:
    /// the platform's own mail then fails to send, and a sign-in that would
    /// wait for a mailed link asks for a second factor instead.
    pub platform: PlatformMail,
    /// `EMAIL_SEND_TIMEOUT_SECONDS` (10): one delivery.
    pub send_timeout: Duration,
    /// How long each emailed link lasts.
    pub links: LinkLifetimes,
    /// `MAIL_COOLDOWN_SECONDS` (60): the least time between two links of
    /// one kind to one address; `0` mails every request.
    pub cooldown: Duration,
    /// `MAIL_RESEND_COOLDOWN_SECONDS` (60): the least time before a dead
    /// link may be swapped for a new one again.
    pub resend_cooldown: Duration,
    /// `MAIL_DELIVERY_ATTEMPTS` (5): tries a mail gets before it is
    /// recorded as undelivered.
    pub delivery_attempts: u32,
}

impl MailConfig {
    /// The platform's mail as `vars` sets it up, in `environment`.
    ///
    /// # Errors
    ///
    /// A provider's setting missing, another provider's set (any of them
    /// with `none`), an SMTP user without a password, or unencrypted SMTP in
    /// production.
    pub(crate) fn read(vars: &Env, environment: Environment) -> Read<Self> {
        let provider = vars.choice(
            "EMAIL_PROVIDER",
            Provider::Smtp,
            &[
                ("smtp", Provider::Smtp),
                ("sendgrid", Provider::SendGrid),
                ("postmark", Provider::Postmark),
                ("mailgun", Provider::Mailgun),
                ("ses", Provider::Ses),
                ("none", Provider::NotSetUp),
            ],
        )?;
        refuse_other_providers(vars, provider)?;
        let from_name = vars.parsed("EMAIL_FROM_NAME", |name| {
            Label::new("EMAIL_FROM_NAME", name)
        })?;
        Ok(Self {
            platform: PlatformMail {
                account: account(vars, provider, environment)?,
                from: vars.required_parsed("EMAIL_FROM", Email::new)?,
                from_name,
            },
            send_timeout: vars.seconds("EMAIL_SEND_TIMEOUT_SECONDS", Duration::from_secs(10))?,
            links: links(vars)?,
            cooldown: vars.seconds("MAIL_COOLDOWN_SECONDS", MINUTE)?,
            resend_cooldown: vars.seconds("MAIL_RESEND_COOLDOWN_SECONDS", MINUTE)?,
            delivery_attempts: vars.number_in("MAIL_DELIVERY_ATTEMPTS", 5, 1..=50)?,
        })
    }
}

/// Refuses settings of a provider other than `chosen`, which nothing
/// reads and which leave an operator believing mail goes out through it.
fn refuse_other_providers(vars: &Env, chosen: Provider) -> Read<()> {
    for provider in PROVIDERS.into_iter().filter(|provider| *provider != chosen) {
        for name in provider.own_settings() {
            if vars.optional(name)?.is_some() {
                return Err(ConfigError::contradicts(
                    name,
                    "belongs to another mail provider than EMAIL_PROVIDER names",
                ));
            }
        }
    }
    Ok(())
}

/// The account `provider` sends through, or none when no mail server is
/// set up.
fn account(vars: &Env, provider: Provider, environment: Environment) -> Read<Option<MailAccount>> {
    let account = match provider {
        Provider::NotSetUp => return Ok(None),
        Provider::Smtp => MailAccount::Smtp(smtp(vars, environment)?),
        Provider::SendGrid => MailAccount::SendGrid {
            api_key: vars.required_secret("SENDGRID_API_KEY")?,
        },
        Provider::Postmark => MailAccount::Postmark {
            server_token: vars.required_secret("POSTMARK_SERVER_TOKEN")?,
        },
        Provider::Mailgun => MailAccount::Mailgun {
            domain: vars.required_parsed("MAILGUN_DOMAIN", DomainName::new)?,
            region: vars.choice(
                "MAILGUN_REGION",
                MailgunRegion::Us,
                &[("us", MailgunRegion::Us), ("eu", MailgunRegion::Eu)],
            )?,
            api_key: vars.required_secret("MAILGUN_API_KEY")?,
        },
        Provider::Ses => MailAccount::Ses {
            region: vars.required_parsed("SES_REGION", SesRegion::new)?,
            access_key_id: vars.required_parsed("SES_ACCESS_KEY_ID", AwsAccessKeyId::new)?,
            secret_access_key: vars.required_secret("SES_SECRET_ACCESS_KEY")?,
        },
    };
    Ok(Some(account))
}

/// The SMTP server: `SMTP_HOST`, `SMTP_PORT` (587), `SMTP_TLS`
/// (`starttls`, `implicit`, or `none` in development only), and
/// `SMTP_USERNAME` with `SMTP_PASSWORD` together or neither.
fn smtp(vars: &Env, environment: Environment) -> Read<SmtpAccount> {
    let tls = vars.choice(
        "SMTP_TLS",
        SmtpTls::StartTls,
        &[
            ("starttls", SmtpTls::StartTls),
            ("implicit", SmtpTls::Implicit),
            ("none", SmtpTls::Unencrypted),
        ],
    )?;
    if tls == SmtpTls::Unencrypted && environment.is_production() {
        return Err(ConfigError::contradicts(
            "SMTP_TLS",
            "is none in production, which sends sign-in links unencrypted",
        ));
    }
    let login = smtp_login(vars)?;
    Ok(SmtpAccount {
        host: vars.required("SMTP_HOST")?,
        port: vars.number_in("SMTP_PORT", 587, 1..=u16::MAX)?,
        tls,
        login,
    })
}

/// Requires SMTP credentials to include both the username and password or neither.
fn smtp_login(vars: &Env) -> Read<Option<SmtpLogin>> {
    let username = vars.optional("SMTP_USERNAME")?;
    let password = vars.secret("SMTP_PASSWORD")?;
    let login = match (username, password) {
        (Some(username), Some(password)) => Some(SmtpLogin { username, password }),
        (None, None) => None,
        (Some(_), None) => {
            return Err(ConfigError::contradicts(
                "SMTP_USERNAME",
                "is set without SMTP_PASSWORD",
            ));
        }
        (None, Some(_)) => {
            return Err(ConfigError::contradicts(
                "SMTP_PASSWORD",
                "is set without SMTP_USERNAME",
            ));
        }
    };
    Ok(login)
}

fn links(vars: &Env) -> Read<LinkLifetimes> {
    let thirty_days = 1..=(30 * DAY).as_secs();
    Ok(LinkLifetimes {
        password_reset: vars.seconds("EMAIL_PASSWORD_RESET_TTL_SECONDS", HOUR)?,
        magic_link: vars.seconds("EMAIL_MAGIC_LINK_TTL_SECONDS", 15 * MINUTE)?,
        verification: vars.seconds("EMAIL_VERIFICATION_TTL_SECONDS", HOUR)?,
        org_verification: vars.seconds("EMAIL_ORG_VERIFICATION_TTL_SECONDS", DAY)?,
        invitation: vars.seconds_in("INVITATION_TTL_SECONDS", DAY, thirty_days.clone())?,
        org_invitation: vars.seconds_in("ORG_INVITATION_TTL_SECONDS", DAY, thirty_days)?,
        email_change: vars.seconds("EMAIL_CHANGE_TTL_SECONDS", DAY)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn smtp_server() -> Vec<(&'static str, &'static str)> {
        vec![
            ("EMAIL_FROM", "noreply@example.com"),
            ("SMTP_HOST", "smtp.example.com"),
            ("SMTP_USERNAME", "mailer"),
            ("SMTP_PASSWORD", "smtp-pw"),
        ]
    }

    /// An SMTP server is read with STARTTLS on 587 by default.
    #[test]
    fn an_smtp_server_is_read_with_starttls_on_587() {
        let config = MailConfig::read(&Env::of(smtp_server()), Environment::Production).unwrap();

        let Some(MailAccount::Smtp(account)) = config.platform.account else {
            panic!("an SMTP account");
        };
        assert_eq!(account.port, 587);
        assert_eq!(account.tls, SmtpTls::StartTls);
    }

    /// Mail configuration debug output omits the SMTP password.
    #[test]
    fn the_smtp_password_never_prints() {
        let config = MailConfig::read(&Env::of(smtp_server()), Environment::Production).unwrap();

        assert!(!format!("{config:?}").contains("smtp-pw"));
    }

    /// SMTP configuration without a sender address is refused, naming the
    /// missing sender setting.
    #[test]
    fn the_sender_address_must_be_set() {
        let pairs: Vec<_> = smtp_server()
            .into_iter()
            .filter(|(name, _)| *name != "EMAIL_FROM")
            .collect();

        let read = MailConfig::read(&Env::of(pairs), Environment::Production);

        assert!(matches!(read, Err(ConfigError::Missing { name }) if name == "EMAIL_FROM"));
    }

    /// An SMTP username without a password is refused as contradictory
    /// configuration.
    #[test]
    fn an_smtp_user_without_a_password_is_refused() {
        let pairs: Vec<_> = smtp_server()
            .into_iter()
            .filter(|(name, _)| *name != "SMTP_PASSWORD")
            .collect();

        let read = MailConfig::read(&Env::of(pairs), Environment::Production);

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "SMTP_USERNAME")
        );
    }

    /// Unencrypted SMTP configuration is refused in production and
    /// accepted in development.
    #[test]
    fn unencrypted_smtp_is_refused_in_production() {
        let mut pairs = smtp_server();
        pairs.push(("SMTP_TLS", "none"));

        let production = MailConfig::read(&Env::of(pairs.clone()), Environment::Production);
        let development = MailConfig::read(&Env::of(pairs), Environment::Development);

        assert!(production.is_err());
        assert!(development.is_ok());
    }

    /// A Mailgun key conflicts with SMTP configuration, and the refusal
    /// names the Mailgun setting.
    #[test]
    fn another_providers_setting_is_refused() {
        let mut pairs = smtp_server();
        pairs.push(("MAILGUN_API_KEY", "key-123"));

        let read = MailConfig::read(&Env::of(pairs), Environment::Production);

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "MAILGUN_API_KEY")
        );
    }

    /// Mailgun is read with its domain, region and key.
    #[test]
    fn mailgun_is_read_with_its_domain_region_and_key() {
        let vars = Env::of([
            ("EMAIL_PROVIDER", "mailgun"),
            ("EMAIL_FROM", "noreply@example.com"),
            ("MAILGUN_DOMAIN", "mg.example.com"),
            ("MAILGUN_REGION", "eu"),
            ("MAILGUN_API_KEY", "key-123"),
        ]);

        let config = MailConfig::read(&vars, Environment::Production).unwrap();

        assert!(matches!(
            config.platform.account,
            Some(MailAccount::Mailgun {
                region: MailgunRegion::Eu,
                ..
            })
        ));
    }

    /// A deployment with no mail server is read as one: no account, so the
    /// platform's mail fails to send and sign-ins never wait for a link.
    #[test]
    fn no_mail_server_is_read_as_none() {
        let vars = Env::of([
            ("EMAIL_PROVIDER", "none"),
            ("EMAIL_FROM", "noreply@example.com"),
        ]);

        let config = MailConfig::read(&vars, Environment::Production).unwrap();

        assert!(config.platform.account.is_none());
    }

    /// An SMTP host conflicts with a disabled mail provider, and the
    /// refusal names the SMTP host setting.
    #[test]
    fn a_providers_setting_beside_none_is_refused() {
        let vars = Env::of([
            ("EMAIL_PROVIDER", "none"),
            ("EMAIL_FROM", "noreply@example.com"),
            ("SMTP_HOST", "smtp.example.com"),
        ]);

        let read = MailConfig::read(&vars, Environment::Production);

        assert!(matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "SMTP_HOST"));
    }

    /// Configuration refuses a year-long invitation lifetime because it
    /// exceeds the thirty-day maximum.
    #[test]
    fn an_invitation_past_thirty_days_is_refused() {
        let mut pairs = smtp_server();
        pairs.push(("INVITATION_TTL_SECONDS", "31536000"));

        assert!(MailConfig::read(&Env::of(pairs), Environment::Production).is_err());
    }
}
