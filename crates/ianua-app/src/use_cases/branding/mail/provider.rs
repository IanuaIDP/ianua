//! A mail provider as the caller typed it, and the same provider with its
//! credential sealed before the tenant keeps it.
//!
//! An SMTP password or a provider's API key sends mail as the tenant, with
//! its sign-in links in it. So it is sealed through the crypto port as soon
//! as it arrives, and only its sealed form reaches the domain and storage.

use ianua_domain::domains::branding::mail_provider::{
    AwsAccessKeyId, MailProvider, MailgunRegion, SesRegion, SmtpPort, SmtpSecurity, SmtpServer,
    SmtpServerParams, SmtpUsername,
};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{DomainName, PublicHost, SealedSecret};

use crate::error::AppError;
use crate::ports::authentication::SecretEncryptor;
use crate::ports::branding::mail_credential_place;
use crate::services::sealing::sealed_text;
use crate::tenancy::ScopedTenant;

/// An SMTP server as the caller typed it. Holds the password, so it has no
/// `Debug`.
pub struct NamedSmtpServer {
    /// Where the server is. Never an internal host.
    pub host: PublicHost,
    /// The port it takes mail on.
    pub port: SmtpPort,
    /// How the connection is encrypted.
    pub security: SmtpSecurity,
    /// The user name to sign in with.
    pub username: SmtpUsername,
    /// The credential used to authenticate to the SMTP server.
    pub password: Secret,
}

/// The provider a tenant's mail is to go out through, with its credential
/// as typed. Holds credentials, so it has no `Debug`.
pub enum NamedMailProvider {
    /// The platform's own mail.
    Platform,
    /// An SMTP server.
    Smtp(NamedSmtpServer),
    /// A SendGrid account.
    SendGrid {
        /// The credential authorizing mail delivery through SendGrid.
        api_key: Secret,
    },
    /// Amazon SES.
    Ses {
        /// The region SES runs in.
        region: SesRegion,
        /// The access key's id.
        access_key_id: AwsAccessKeyId,
        /// The access key's secret.
        secret_access_key: Secret,
    },
    /// A Postmark server.
    Postmark {
        /// The credential authorizing mail delivery through Postmark.
        server_token: Secret,
    },
    /// A Mailgun account.
    Mailgun {
        /// The sending domain set up in Mailgun.
        domain: DomainName,
        /// The region the account lives in.
        region: MailgunRegion,
        /// The credential authorizing mail delivery through Mailgun.
        api_key: Secret,
    },
}

impl NamedMailProvider {
    /// The one credential the provider signs in with, or `None` for the
    /// platform's own mail.
    fn credential(&self) -> Option<&Secret> {
        match self {
            Self::Platform => None,
            Self::Smtp(server) => Some(&server.password),
            Self::SendGrid { api_key } | Self::Mailgun { api_key, .. } => Some(api_key),
            Self::Ses {
                secret_access_key, ..
            } => Some(secret_access_key),
            Self::Postmark { server_token } => Some(server_token),
        }
    }

    /// The provider, keeping `sealed` in place of its credential.
    fn sealed_with(self, sealed: SealedSecret) -> MailProvider {
        match self {
            Self::Platform => MailProvider::Platform,
            Self::Smtp(server) => MailProvider::Smtp(SmtpServer::new(SmtpServerParams {
                host: server.host,
                port: server.port,
                security: server.security,
                username: server.username,
                password: sealed,
            })),
            Self::SendGrid { .. } => MailProvider::SendGrid { api_key: sealed },
            Self::Ses {
                region,
                access_key_id,
                ..
            } => MailProvider::Ses {
                region,
                access_key_id,
                secret_access_key: sealed,
            },
            Self::Postmark { .. } => MailProvider::Postmark {
                server_token: sealed,
            },
            Self::Mailgun { domain, region, .. } => MailProvider::Mailgun {
                domain,
                region,
                api_key: sealed,
            },
        }
    }
}

/// `named`, the provider `tenant` names, with its credential sealed
/// through `encryptor` for the tenant's provider.
///
/// # Errors
///
/// `AppError::Internal` when the credential cannot be sealed.
pub(in crate::use_cases::branding) async fn sealed_provider(
    encryptor: &dyn SecretEncryptor,
    tenant: &ScopedTenant,
    named: NamedMailProvider,
) -> Result<MailProvider, AppError> {
    let Some(credential) = named.credential() else {
        return Ok(MailProvider::Platform);
    };
    let place = mail_credential_place(Some(**tenant));
    let sealed = sealed_text(encryptor, credential.expose(), &place).await?;
    Ok(named.sealed_with(sealed))
}
