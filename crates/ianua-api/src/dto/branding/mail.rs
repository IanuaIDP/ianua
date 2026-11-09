//! Mail provider bodies: the provider a tenant's mail is to go out
//! through, with its credential as typed, and the provider as read back
//! without it.

use ianua_app::use_cases::branding::{
    NamedMailProvider, NamedSmtpServer, SwitchMailProviderRequest,
};
use ianua_domain::domains::branding::mail_provider::{
    AwsAccessKeyId, MailProvider, MailgunRegion, ProviderCheck, SesRegion, SmtpPort, SmtpSecurity,
    SmtpUsername, TenantMailProvider, TestSendOutcome,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{DomainName, HostName, PublicHost};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::dto::tenant::proof::FreshProofBody;
use crate::error::ApiError;

/// The provider to send the tenant's mail through, with a fresh proof of
/// the person. Holds credentials, so it has no `Debug`.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct SwitchMailProviderBody {
    /// The provider, by `kind`.
    pub provider: MailProviderBody,
    /// The person making the change, proved again.
    pub proof: FreshProofBody,
}

/// A mail provider by `kind`, with its credential as typed. Holds
/// credentials, so it has no `Debug`.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum MailProviderBody {
    /// The platform's own mail again.
    Platform,
    /// An SMTP server.
    Smtp {
        /// The server's public host name.
        host: String,
        /// The port it takes mail on.
        port: u16,
        /// `starttls` or `implicit_tls`.
        security: SmtpSecurityBody,
        /// The user name to sign in with.
        username: String,
        /// The secret used to authenticate the SMTP user.
        password: String,
    },
    /// A SendGrid account.
    Sendgrid {
        /// The credential authorizing sends through the SendGrid account.
        api_key: String,
    },
    /// Amazon SES.
    Ses {
        /// The region SES runs in, such as `eu-west-1`.
        region: String,
        /// The access key's id.
        access_key_id: String,
        /// The access key's secret.
        secret_access_key: String,
    },
    /// A Postmark server.
    Postmark {
        /// The credential authorizing sends through this Postmark server.
        server_token: String,
    },
    /// A Mailgun account.
    Mailgun {
        /// The sending domain set up in Mailgun.
        domain: String,
        /// `us` or `eu`.
        region: MailgunRegionBody,
        /// The credential authorizing sends from the Mailgun domain.
        api_key: String,
    },
}

/// How the connection to an SMTP server is encrypted.
#[derive(Deserialize, Serialize, Clone, Copy, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SmtpSecurityBody {
    /// Plain at first, upgraded with `STARTTLS` before signing in.
    Starttls,
    /// TLS from the first byte, usually on port 465.
    ImplicitTls,
}

/// The region a Mailgun account lives in.
#[derive(Deserialize, Serialize, Clone, Copy, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MailgunRegionBody {
    /// `api.mailgun.net`.
    Us,
    /// `api.eu.mailgun.net`.
    Eu,
}

impl From<SmtpSecurityBody> for SmtpSecurity {
    fn from(security: SmtpSecurityBody) -> Self {
        match security {
            SmtpSecurityBody::Starttls => Self::StartTls,
            SmtpSecurityBody::ImplicitTls => Self::ImplicitTls,
        }
    }
}

impl From<SmtpSecurity> for SmtpSecurityBody {
    fn from(security: SmtpSecurity) -> Self {
        match security {
            SmtpSecurity::StartTls => Self::Starttls,
            SmtpSecurity::ImplicitTls => Self::ImplicitTls,
        }
    }
}

impl From<MailgunRegionBody> for MailgunRegion {
    fn from(region: MailgunRegionBody) -> Self {
        match region {
            MailgunRegionBody::Us => Self::Us,
            MailgunRegionBody::Eu => Self::Eu,
        }
    }
}

impl From<MailgunRegion> for MailgunRegionBody {
    fn from(region: MailgunRegion) -> Self {
        match region {
            MailgunRegion::Us => Self::Us,
            MailgunRegion::Eu => Self::Eu,
        }
    }
}

impl TryFrom<SwitchMailProviderBody> for SwitchMailProviderRequest {
    type Error = ApiError;

    fn try_from(body: SwitchMailProviderBody) -> Result<Self, Self::Error> {
        Ok(Self {
            provider: body.provider.try_into()?,
            proof: body.proof.try_into()?,
        })
    }
}

impl TryFrom<MailProviderBody> for NamedMailProvider {
    type Error = ApiError;

    /// Keeps the exhaustive provider mapping and each provider's field validation order together.
    #[allow(clippy::too_many_lines)]
    fn try_from(body: MailProviderBody) -> Result<Self, Self::Error> {
        match body {
            MailProviderBody::Platform => Ok(Self::Platform),
            MailProviderBody::Smtp {
                host,
                port,
                security,
                username,
                password,
            } => Ok(Self::Smtp(NamedSmtpServer {
                host: public_host(host)?,
                port: SmtpPort::new(port).map_err(ApiError::validation)?,
                security: security.into(),
                username: SmtpUsername::new(username).map_err(ApiError::validation)?,
                password: Secret::new(password),
            })),
            MailProviderBody::Sendgrid { api_key } => Ok(Self::SendGrid {
                api_key: Secret::new(api_key),
            }),
            MailProviderBody::Ses {
                region,
                access_key_id,
                secret_access_key,
            } => Ok(Self::Ses {
                region: SesRegion::new(region).map_err(ApiError::validation)?,
                access_key_id: AwsAccessKeyId::new(access_key_id).map_err(ApiError::validation)?,
                secret_access_key: Secret::new(secret_access_key),
            }),
            MailProviderBody::Postmark { server_token } => Ok(Self::Postmark {
                server_token: Secret::new(server_token),
            }),
            MailProviderBody::Mailgun {
                domain,
                region,
                api_key,
            } => Ok(Self::Mailgun {
                domain: DomainName::new(domain).map_err(ApiError::validation)?,
                region: region.into(),
                api_key: Secret::new(api_key),
            }),
        }
    }
}

/// `host` as a public host name, never an internal one.
fn public_host(host: String) -> Result<PublicHost, ApiError> {
    HostName::new(host)
        .and_then(PublicHost::new)
        .map_err(ApiError::validation)
}

/// The tenant's mail provider as read back. No credential is ever shown.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct MailProviderResponse {
    /// The provider named: `platform`, `smtp`, `sendgrid`, `ses`,
    /// `postmark` or `mailgun`.
    pub kind: &'static str,
    /// The SMTP server's host.
    pub host: Option<String>,
    /// The SMTP server's port.
    pub port: Option<u16>,
    /// How the SMTP connection is encrypted.
    pub security: Option<SmtpSecurityBody>,
    /// The SMTP user name.
    pub username: Option<String>,
    /// The SES region.
    pub region: Option<String>,
    /// The SES access key's id.
    pub access_key_id: Option<String>,
    /// The Mailgun sending domain.
    pub domain: Option<String>,
    /// The API location serving the domain, `us` or `eu`, when using Mailgun.
    pub mailgun_region: Option<MailgunRegionBody>,
    /// How the last test send through it went: `unverified` (none yet),
    /// `verified` or `failed`.
    pub check: &'static str,
    /// When that test send was made.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub checked_at: Option<OffsetDateTime>,
    /// The provider the tenant's mail goes out through now: the one named
    /// once a test send through it worked, the platform's until then.
    pub delivers_through: &'static str,
    /// When the provider was last named or tested.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<&TenantMailProvider<ResolvedTenant>> for MailProviderResponse {
    fn from(named: &TenantMailProvider<ResolvedTenant>) -> Self {
        let (check, checked_at) = match named.check() {
            ProviderCheck::Unverified => ("unverified", None),
            ProviderCheck::Verified { at } => ("verified", Some(at)),
            ProviderCheck::Failed { at } => ("failed", Some(at)),
        };
        let shown = ProviderParts::from(named.provider());
        Self {
            kind: named.provider().kind().as_str(),
            host: shown.host,
            port: shown.port,
            security: shown.security,
            username: shown.username,
            region: shown.region,
            access_key_id: shown.access_key_id,
            domain: shown.domain,
            mailgun_region: shown.mailgun_region,
            check,
            checked_at,
            delivers_through: named.delivers_through().kind().as_str(),
            updated_at: named.updated_at(),
        }
    }
}

/// What of a provider may be shown: everything but its credential.
#[derive(Default)]
struct ProviderParts {
    host: Option<String>,
    port: Option<u16>,
    security: Option<SmtpSecurityBody>,
    username: Option<String>,
    region: Option<String>,
    access_key_id: Option<String>,
    domain: Option<String>,
    mailgun_region: Option<MailgunRegionBody>,
}

impl From<&MailProvider> for ProviderParts {
    fn from(provider: &MailProvider) -> Self {
        match provider {
            MailProvider::Platform
            | MailProvider::SendGrid { .. }
            | MailProvider::Postmark { .. } => Self::default(),
            MailProvider::Smtp(server) => Self {
                host: Some(server.host().as_str().to_owned()),
                port: Some(server.port().get()),
                security: Some(server.security().into()),
                username: Some(server.username().as_str().to_owned()),
                ..Self::default()
            },
            MailProvider::Ses {
                region,
                access_key_id,
                ..
            } => Self {
                region: Some(region.as_str().to_owned()),
                access_key_id: Some(access_key_id.as_str().to_owned()),
                ..Self::default()
            },
            MailProvider::Mailgun { domain, region, .. } => Self {
                domain: Some(domain.as_str().to_owned()),
                mailgun_region: Some((*region).into()),
                ..Self::default()
            },
        }
    }
}

/// How a test send through the tenant's provider went.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct MailProviderTestResponse {
    /// `delivered`, after which the tenant's mail goes out through the
    /// provider, or `refused`, after which it stays with the platform's.
    pub outcome: &'static str,
}

impl From<TestSendOutcome> for MailProviderTestResponse {
    fn from(outcome: TestSendOutcome) -> Self {
        Self {
            outcome: match outcome {
                TestSendOutcome::Delivered => "delivered",
                TestSendOutcome::Refused => "refused",
            },
        }
    }
}
