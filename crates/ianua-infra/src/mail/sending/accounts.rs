//! The accounts mail goes out through, with their credentials open: the
//! platform's own, read from configuration, and a tenant's, opened from
//! its sealed form for one delivery and dropped after it.

use std::fmt;

use ianua_app::ports::authentication::{SealedFor, SecretEncryptor};
use ianua_app::ports::shared::MailSetup;
use ianua_domain::domains::branding::mail_provider::{
    AwsAccessKeyId, MailProvider, MailgunRegion, SesRegion, SmtpSecurity, SmtpServer,
};
use ianua_domain::domains::identity::account::address::MailReach;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{DomainName, Email, Label, SealedSecret};

use crate::mail::sending::delivery::MailFailure;

/// How the connection to an SMTP server is encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpTls {
    /// Plain at first, upgraded with `STARTTLS` before signing in. Nothing
    /// is sent when the server does not offer the upgrade.
    StartTls,
    /// TLS from the first byte, usually on port 465.
    Implicit,
    /// No encryption at all, for a mail catcher on the same host while
    /// developing. Only the platform's own account can be set up this way:
    /// a tenant's server is always reached over TLS.
    Unencrypted,
}

/// The user name and password an SMTP server signs the platform in with.
#[derive(Clone)]
pub struct SmtpLogin {
    /// The user name.
    pub username: String,
    /// Authenticates the configured SMTP user; omitted from debug output.
    pub password: Secret,
}

impl fmt::Debug for SmtpLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpLogin")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

/// An SMTP server, and how the platform signs in to it.
#[derive(Debug, Clone)]
pub struct SmtpAccount {
    /// The server's host name or address.
    pub host: String,
    /// The port it takes mail on.
    pub port: u16,
    /// How the connection is encrypted.
    pub tls: SmtpTls,
    /// How to sign in, or none for a server that takes mail without it.
    pub login: Option<SmtpLogin>,
}

/// An account mail is sent through, its credentials open.
///
/// `Debug` shows which kind of account it is and nothing of its secrets.
#[derive(Clone)]
pub enum MailAccount {
    /// An SMTP server.
    Smtp(SmtpAccount),
    /// A SendGrid account.
    SendGrid {
        /// Authorizes delivery through the SendGrid account.
        api_key: Secret,
    },
    /// A Postmark server.
    Postmark {
        /// Authorizes delivery through the selected Postmark server.
        server_token: Secret,
    },
    /// A Mailgun account.
    Mailgun {
        /// The sending domain set up in Mailgun.
        domain: DomainName,
        /// The region the account lives in.
        region: MailgunRegion,
        /// Authenticates requests to the sending domain's Mailgun endpoint.
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
}

impl MailAccount {
    /// The name records and errors give this kind of account.
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Smtp(_) => "smtp",
            Self::SendGrid { .. } => "sendgrid",
            Self::Postmark { .. } => "postmark",
            Self::Mailgun { .. } => "mailgun",
            Self::Ses { .. } => "ses",
        }
    }
}

impl fmt::Debug for MailAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailAccount")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

/// The platform's own mail: the account it goes out through, and the
/// address and name it is sent from.
#[derive(Debug, Clone)]
pub struct PlatformMail {
    /// The account, or none on a deployment with no mail server. Then every
    /// mail of the platform's own fails to send, and a sign-in never waits
    /// for one.
    pub account: Option<MailAccount>,
    /// The address the platform's mail is sent from.
    pub from: Email,
    /// The name it is sent under.
    pub from_name: Option<Label>,
}

impl PlatformMail {
    /// The account the platform's own mail goes out through.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when no mail server is set up.
    pub(crate) fn sending_account(&self) -> Result<&MailAccount, DomainError> {
        self.account
            .as_ref()
            .ok_or_else(|| DomainError::infra(MailFailure::NotSetUp))
    }

    /// Whether the platform's own mail goes out at all, for the sign-in
    /// that must not wait for a mail that never arrives.
    #[must_use]
    pub fn mail_setup(&self) -> ConfiguredMailSetup {
        let reach = match self.account {
            Some(_) => MailReach::Available,
            None => MailReach::NotSetUp,
        };
        ConfiguredMailSetup(reach)
    }
}

/// Whether the platform's own mail has an account to go out through, fixed
/// when the configuration was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfiguredMailSetup(MailReach);

impl MailSetup for ConfiguredMailSetup {
    fn reach(&self) -> MailReach {
        self.0
    }
}

/// A credential that did not open to text.
#[derive(Debug, thiserror::Error)]
#[error("a sealed mail credential does not open to text")]
struct NotText;

/// How a provider's sealed credentials are opened: through `secrets`, for
/// the place they were sealed for.
#[derive(Clone, Copy)]
pub(crate) struct Opening<'a> {
    /// Opens a sealed credential.
    pub(crate) secrets: &'a dyn SecretEncryptor,
    /// Where the credentials were sealed for.
    pub(crate) place: &'a SealedFor,
}

impl Opening<'_> {
    /// The account `provider` names, its credentials opened, or none for
    /// the platform's own mail.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a credential does not
    /// open for the place.
    pub(crate) async fn opened(
        self,
        provider: &MailProvider,
    ) -> Result<Option<MailAccount>, DomainError> {
        Ok(Some(match provider {
            MailProvider::Platform => return Ok(None),
            MailProvider::Smtp(server) => MailAccount::Smtp(self.smtp_account(server).await?),
            MailProvider::SendGrid { api_key } => MailAccount::SendGrid {
                api_key: self.open(api_key).await?,
            },
            MailProvider::Postmark { server_token } => MailAccount::Postmark {
                server_token: self.open(server_token).await?,
            },
            MailProvider::Mailgun {
                domain,
                region,
                api_key,
            } => MailAccount::Mailgun {
                domain: domain.clone(),
                region: *region,
                api_key: self.open(api_key).await?,
            },
            MailProvider::Ses {
                region,
                access_key_id,
                secret_access_key,
            } => MailAccount::Ses {
                region: region.clone(),
                access_key_id: access_key_id.clone(),
                secret_access_key: self.open(secret_access_key).await?,
            },
        }))
    }

    /// A tenant's SMTP server as an account, always over TLS.
    async fn smtp_account(self, server: &SmtpServer) -> Result<SmtpAccount, DomainError> {
        let tls = match server.security() {
            SmtpSecurity::StartTls => SmtpTls::StartTls,
            SmtpSecurity::ImplicitTls => SmtpTls::Implicit,
        };
        Ok(SmtpAccount {
            host: server.host().as_str().to_owned(),
            port: server.port().get(),
            tls,
            login: Some(SmtpLogin {
                username: server.username().as_str().to_owned(),
                password: self.open(server.password()).await?,
            }),
        })
    }

    /// The secret `sealed` holds.
    async fn open(self, sealed: &SealedSecret) -> Result<Secret, DomainError> {
        let bytes = self.secrets.decrypt(sealed, self.place).await?;
        let text = String::from_utf8(bytes).map_err(|_| DomainError::infra(NotText))?;
        Ok(Secret::new(text))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_app::ports::branding::mail_credential_place;
    use ianua_domain::domains::branding::mail_provider::{
        SmtpPort, SmtpServerParams, SmtpUsername,
    };
    use ianua_domain::types::{HostName, PublicHost, TenantId};

    use super::*;
    use crate::crypto::keys::KEY_BYTES;
    use crate::crypto::{AesGcmSecretEncryptor, SealingKey};

    fn secrets() -> Arc<dyn SecretEncryptor> {
        Arc::new(AesGcmSecretEncryptor::new(
            SealingKey::new("k1", [7; KEY_BYTES]).unwrap(),
            Vec::new(),
        ))
    }

    /// Where Acme's provider keeps its credential.
    fn acme() -> SealedFor {
        mail_credential_place(Some(TenantId::from_uuid(uuid::Uuid::nil())))
    }

    async fn sealed(secrets: &dyn SecretEncryptor, value: &str) -> SealedSecret {
        secrets.encrypt(value.as_bytes(), &acme()).await.unwrap()
    }

    fn opening<'a>(secrets: &'a dyn SecretEncryptor, place: &'a SealedFor) -> Opening<'a> {
        Opening { secrets, place }
    }

    /// Acme's own SMTP server opens to an account reached over the TLS it
    /// named, signed in with the password it sealed.
    #[tokio::test]
    async fn a_tenant_smtp_server_opens_with_its_password() {
        let secrets = secrets();
        let server = SmtpServer::new(SmtpServerParams {
            host: PublicHost::new(HostName::new("smtp.acme.com").unwrap()).unwrap(),
            port: SmtpPort::new(587).unwrap(),
            security: SmtpSecurity::StartTls,
            username: SmtpUsername::new("mailer").unwrap(),
            password: sealed(secrets.as_ref(), "hunter2").await,
        });

        let opened = opening(secrets.as_ref(), &acme())
            .opened(&MailProvider::Smtp(server))
            .await
            .unwrap();

        let Some(MailAccount::Smtp(account)) = opened else {
            panic!("an SMTP account");
        };
        assert_eq!(account.tls, SmtpTls::StartTls);
        assert_eq!(account.port, 587);
        assert_eq!(account.login.unwrap().password.expose(), "hunter2");
    }

    /// The platform's own mail has no account of the tenant's to open.
    #[tokio::test]
    async fn the_platforms_mail_opens_to_no_account() {
        let secrets = secrets();
        let opened = opening(secrets.as_ref(), &mail_credential_place(None))
            .opened(&MailProvider::Platform)
            .await
            .unwrap();

        assert!(opened.is_none());
    }

    /// A SendGrid credential sealed for Globex fails to open for Acme.
    #[tokio::test]
    async fn a_credential_sealed_for_another_tenant_does_not_open() {
        let secrets = secrets();
        let globex = mail_credential_place(Some(TenantId::new()));
        let provider = MailProvider::SendGrid {
            api_key: secrets.encrypt(b"SG.globex", &globex).await.unwrap(),
        };

        let opened = opening(secrets.as_ref(), &acme()).opened(&provider).await;

        assert!(matches!(opened, Err(DomainError::Infrastructure(_))));
    }

    /// Debug output for an opened SendGrid account names the provider and omits
    /// its API key.
    #[tokio::test]
    async fn an_opened_account_never_prints_its_secret() {
        let secrets = secrets();
        let provider = MailProvider::SendGrid {
            api_key: sealed(secrets.as_ref(), "SG.live-key").await,
        };

        let account = opening(secrets.as_ref(), &acme())
            .opened(&provider)
            .await
            .unwrap()
            .unwrap();

        let shown = format!("{account:?}");
        assert!(!shown.contains("live-key"));
        assert!(shown.contains("sendgrid"));
    }
}
