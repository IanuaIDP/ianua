//! A tenant's mail provider as its row holds it: read back into the
//! aggregate, and written out from it. Each kind of provider fills the
//! columns it needs; the credential is kept sealed, as it came.

use ianua_domain::domains::branding::mail_provider::{
    AwsAccessKeyId, MailProvider, MailProviderKind, ProviderCheck, SesRegion, SmtpPort, SmtpServer,
    SmtpServerParams, SmtpUsername, TenantMailProvider, TenantMailProviderRow,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DomainName, HostName, PublicHost, SealedSecret};
use time::OffsetDateTime;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const PROVIDER: Stored = Stored("tenant mail provider");

/// The word a provider never tested is stored with.
const UNVERIFIED: &str = "unverified";

/// The word a provider whose test send went through is stored with.
const VERIFIED: &str = "verified";

/// The word a provider whose test send failed is stored with.
const FAILED: &str = "failed";

/// A mail provider as it is read. The store's checked queries fill it.
pub(super) struct ProviderRecord {
    pub(super) kind: String,
    pub(super) smtp_host: Option<String>,
    pub(super) smtp_port: Option<i32>,
    pub(super) smtp_security: Option<String>,
    pub(super) smtp_username: Option<String>,
    pub(super) ses_region: Option<String>,
    pub(super) ses_access_key_id: Option<String>,
    pub(super) mailgun_domain: Option<String>,
    pub(super) mailgun_region: Option<String>,
    pub(super) credential: Option<String>,
    pub(super) check_state: String,
    pub(super) checked_at: Option<OffsetDateTime>,
    pub(super) updated_at: OffsetDateTime,
}

impl ProviderRecord {
    /// The mail provider the record holds, rebuilt through the domain's
    /// checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, a column the kind needs is empty, or
    /// the row breaks a rule the provider keeps.
    pub(super) fn into_provider(self) -> Result<TenantMailProvider<ResolvedTenant>, DomainError> {
        let check = check_from(&self.check_state, self.checked_at)?;
        let updated_at = self.updated_at;
        TenantMailProvider::reconstitute(TenantMailProviderRow {
            provider: self.provider()?,
            check,
            updated_at,
        })
    }

    /// The provider the kind and its columns name.
    fn provider(self) -> Result<MailProvider, DomainError> {
        let kind: MailProviderKind = PROVIDER.choice(&self.kind)?;
        match kind {
            MailProviderKind::Platform => Ok(MailProvider::Platform),
            MailProviderKind::Smtp => self.smtp().map(MailProvider::Smtp),
            MailProviderKind::SendGrid => Ok(MailProvider::SendGrid {
                api_key: sealed(self.credential)?,
            }),
            MailProviderKind::Ses => self.ses(),
            MailProviderKind::Postmark => Ok(MailProvider::Postmark {
                server_token: sealed(self.credential)?,
            }),
            MailProviderKind::Mailgun => self.mailgun(),
        }
    }

    /// The SMTP server the record names.
    fn smtp(self) -> Result<SmtpServer, DomainError> {
        let host = present(self.smtp_host, "an SMTP server without its host")?;
        let port = present(self.smtp_port, "an SMTP server without its port")?;
        let port = u16::try_from(port)
            .map_err(|_| DomainError::corrupt_row(PROVIDER.0, "an SMTP port out of range"))?;
        let security = present(self.smtp_security, "an SMTP server without its encryption")?;
        let username = present(self.smtp_username, "an SMTP server without its user name")?;
        Ok(SmtpServer::new(SmtpServerParams {
            host: PROVIDER.value("host", HostName::new(host).and_then(PublicHost::new))?,
            port: PROVIDER.value("port", SmtpPort::new(port))?,
            security: PROVIDER.choice(&security)?,
            username: PROVIDER.value("user name", SmtpUsername::new(username))?,
            password: sealed(self.credential)?,
        }))
    }

    /// The SES account the record names.
    fn ses(self) -> Result<MailProvider, DomainError> {
        let region = present(self.ses_region, "SES without its region")?;
        let key_id = present(self.ses_access_key_id, "SES without its access key")?;
        Ok(MailProvider::Ses {
            region: PROVIDER.value("SES region", SesRegion::new(region))?,
            access_key_id: PROVIDER.value("access key", AwsAccessKeyId::new(key_id))?,
            secret_access_key: sealed(self.credential)?,
        })
    }

    /// The Mailgun account the record names.
    fn mailgun(self) -> Result<MailProvider, DomainError> {
        let domain = present(self.mailgun_domain, "Mailgun without its domain")?;
        let region = present(self.mailgun_region, "Mailgun without its region")?;
        Ok(MailProvider::Mailgun {
            domain: PROVIDER.value("Mailgun domain", DomainName::new(domain))?,
            region: PROVIDER.choice(&region)?,
            api_key: sealed(self.credential)?,
        })
    }
}

/// A column the kind needs, refusing the row when it is empty.
fn present<T>(stored: Option<T>, missing: &'static str) -> Result<T, DomainError> {
    stored.ok_or_else(|| DomainError::corrupt_row(PROVIDER.0, missing))
}

/// The sealed credential a provider holds.
fn sealed(stored: Option<String>) -> Result<SealedSecret, DomainError> {
    let credential = present(stored, "a provider without its credential")?;
    PROVIDER.value("credential", SealedSecret::new(credential))
}

/// What the last test send showed, from its two columns.
fn check_from(
    state: &str,
    checked_at: Option<OffsetDateTime>,
) -> Result<ProviderCheck, DomainError> {
    match (state, checked_at) {
        (UNVERIFIED, None) => Ok(ProviderCheck::Unverified),
        (VERIFIED, Some(at)) => Ok(ProviderCheck::Verified { at }),
        (FAILED, Some(at)) => Ok(ProviderCheck::Failed { at }),
        _ => Err(DomainError::corrupt_row(
            PROVIDER.0,
            "a test send state that does not fit its time",
        )),
    }
}

/// A mail provider's columns, as they are written.
pub(super) struct ProviderColumns<'a> {
    pub(super) kind: &'static str,
    pub(super) smtp_host: Option<&'a str>,
    pub(super) smtp_port: Option<i32>,
    pub(super) smtp_security: Option<&'static str>,
    pub(super) smtp_username: Option<&'a str>,
    pub(super) ses_region: Option<&'a str>,
    pub(super) ses_access_key_id: Option<&'a str>,
    pub(super) mailgun_domain: Option<&'a str>,
    pub(super) mailgun_region: Option<&'static str>,
    pub(super) credential: Option<&'a str>,
    pub(super) check_state: &'static str,
    pub(super) checked_at: Option<OffsetDateTime>,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> ProviderColumns<'a> {
    /// The columns `provider` is written to.
    pub(super) fn of(provider: &'a TenantMailProvider<ResolvedTenant>) -> Self {
        let (check_state, checked_at) = match provider.check() {
            ProviderCheck::Unverified => (UNVERIFIED, None),
            ProviderCheck::Verified { at } => (VERIFIED, Some(at)),
            ProviderCheck::Failed { at } => (FAILED, Some(at)),
        };
        let blank = Self {
            kind: provider.provider().kind().word(),
            smtp_host: None,
            smtp_port: None,
            smtp_security: None,
            smtp_username: None,
            ses_region: None,
            ses_access_key_id: None,
            mailgun_domain: None,
            mailgun_region: None,
            credential: None,
            check_state,
            checked_at,
            updated_at: provider.updated_at(),
        };
        blank.filled_for(provider.provider())
    }

    /// These columns with the ones `provider`'s kind needs filled in.
    fn filled_for(self, provider: &'a MailProvider) -> Self {
        match provider {
            MailProvider::Platform => self,
            MailProvider::Smtp(server) => self.smtp_columns(server),
            MailProvider::SendGrid { api_key }
            | MailProvider::Postmark {
                server_token: api_key,
            } => self.credential_columns(api_key),
            MailProvider::Ses {
                region,
                access_key_id,
                secret_access_key,
            } => Self {
                ses_region: Some(region.as_str()),
                ses_access_key_id: Some(access_key_id.as_str()),
                credential: Some(secret_access_key.as_str()),
                ..self
            },
            MailProvider::Mailgun {
                domain,
                region,
                api_key,
            } => Self {
                mailgun_domain: Some(domain.as_str()),
                mailgun_region: Some(region.word()),
                credential: Some(api_key.as_str()),
                ..self
            },
        }
    }

    /// Fills the connection and authentication columns required by SMTP.
    fn smtp_columns(self, server: &'a SmtpServer) -> Self {
        Self {
            smtp_host: Some(server.host().as_str()),
            smtp_port: Some(i32::from(server.port().get())),
            smtp_security: Some(server.security().word()),
            smtp_username: Some(server.username().as_str()),
            credential: Some(server.password().as_str()),
            ..self
        }
    }

    /// Adds the sealed credential for providers needing no other account columns.
    fn credential_columns(self, credential: &'a SealedSecret) -> Self {
        Self {
            credential: Some(credential.as_str()),
            ..self
        }
    }
}
