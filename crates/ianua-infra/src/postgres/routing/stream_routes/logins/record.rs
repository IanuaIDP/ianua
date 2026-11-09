//! A stream route's workflow login as its row holds it, read back into the
//! domain's value, and the columns its protection is written as.

use ianua_domain::domains::routing::stream::{
    LoginTls, LoginUser, TlsAuthority, TlsCheck, WorkflowLogin,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{CertificatePem, HostName, SealedSecret};

use crate::postgres::foundation::stored::Stored;

const LOGIN: Stored = Stored("stream route login");

/// A login as it is read. The store's checked query fills it.
pub(super) struct LoginRecord {
    pub(super) login_user: String,
    pub(super) login_password: String,
    pub(super) tls: String,
    pub(super) tls_authority: Option<String>,
    pub(super) tls_server_name: Option<String>,
}

impl LoginRecord {
    /// The login the record holds, its values checked again.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, or the protection is one the store does not know.
    pub(super) fn into_login(self) -> Result<WorkflowLogin, DomainError> {
        let tls = self.read_tls()?;
        Ok(WorkflowLogin::new(
            LOGIN.value("user", LoginUser::new(self.login_user))?,
            LOGIN.value("password", SealedSecret::new(self.login_password))?,
            tls,
        ))
    }

    /// The protection the record holds: `off` with no check, or `required`
    /// with the name the certificate is checked for.
    fn read_tls(&self) -> Result<LoginTls, DomainError> {
        match (self.tls.as_str(), &self.tls_server_name) {
            ("off", None) if self.tls_authority.is_none() => Ok(LoginTls::Off),
            ("required", Some(server_name)) => Ok(LoginTls::Required(TlsCheck::new(
                self.tls_authority
                    .clone()
                    .map(|pem| LOGIN.value("tls authority", CertificatePem::new(pem)))
                    .transpose()?
                    .map_or(TlsAuthority::PublicRoots, TlsAuthority::Own),
                LOGIN.value("tls server name", HostName::new(server_name.clone()))?,
            ))),
            _ => Err(DomainError::corrupt_row(
                "stream route login",
                "an unknown or incomplete tls setting",
            )),
        }
    }
}

/// The columns `tls` is written as: its word, the authority and the name.
pub(super) struct TlsColumns<'a> {
    pub(super) word: &'static str,
    pub(super) authority: Option<&'a str>,
    pub(super) server_name: Option<&'a str>,
}

impl<'a> From<&'a LoginTls> for TlsColumns<'a> {
    fn from(tls: &'a LoginTls) -> Self {
        match tls {
            LoginTls::Required(check) => Self {
                word: tls.as_str(),
                authority: match check.authority() {
                    TlsAuthority::Own(pem) => Some(pem.as_str()),
                    TlsAuthority::PublicRoots => None,
                },
                server_name: Some(check.server_name().as_str()),
            },
            LoginTls::Off => Self {
                word: tls.as_str(),
                authority: None,
                server_name: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(tls: &str, server_name: Option<&str>) -> LoginRecord {
        LoginRecord {
            login_user: "workflows_reader".to_owned(),
            login_password: "v1.AAECAwQF".to_owned(),
            tls: tls.to_owned(),
            tls_authority: None,
            tls_server_name: server_name.map(str::to_owned),
        }
    }

    /// A login held to TLS reads back with the name it is checked for.
    #[test]
    fn a_required_login_reads_back_with_its_name() {
        let login = record("required", Some("db.internal"))
            .into_login()
            .unwrap();

        assert!(matches!(
            login.tls(),
            LoginTls::Required(check) if check.server_name().as_str() == "db.internal"
        ));
    }

    /// A row asking for TLS with no name is refused as corrupt, never read
    /// as a login without TLS.
    #[test]
    fn a_required_login_without_a_name_is_corrupt() {
        let login = record("required", None).into_login();

        assert!(
            matches!(login, Err(DomainError::Infrastructure(_))),
            "{login:?}"
        );
    }

    /// An unknown word is refused as corrupt.
    #[test]
    fn an_unknown_tls_word_is_corrupt() {
        let login = record("maybe", None).into_login();

        assert!(
            matches!(login, Err(DomainError::Infrastructure(_))),
            "{login:?}"
        );
    }
}
