//! `ianua connector-pki`: issues the connector authority and the
//! certificate of the gateway's connector listener, and writes them to a
//! folder.
//!
//! Run once, on a workstation. The authority's key goes to the API alone,
//! which signs every connector's certificate with it; the gateway gets the
//! authority's certificate and its listener's certificate and key. A
//! connector is handed the authority's certificate when it enrolls, so no
//! file goes to the tenants' networks. Nothing is written over.

use std::path::Path;

use ianua_domain::shared::errors::DomainError;
use ianua_infra::crypto::{ConnectorPki, ConnectorPkiValidity, issue_connector_pki};

use crate::command::ConnectorPkiRequest;
use crate::error::ServerError;
use crate::pki_files::{PkiFileError, Planned, certificate, key, write_all};

/// Why the connector authority's files were not written.
#[derive(Debug, thiserror::Error)]
pub enum ConnectorPkiError {
    /// The certificates could not be issued.
    #[error("the connector authority could not be issued")]
    Issue(#[source] DomainError),
    /// The files could not be written.
    #[error(transparent)]
    Files(#[from] PkiFileError),
}

/// Issues the authority and the listener's certificate `request` asks for,
/// writes them to its folder, then prints the settings each side takes.
///
/// # Errors
///
/// [`ServerError::ConnectorPki`] when a file is there already, the
/// certificates cannot be issued, or a file cannot be written.
pub fn run(request: &ConnectorPkiRequest) -> Result<(), ServerError> {
    let pki = issue_connector_pki(&request.listener_names, ConnectorPkiValidity::default())
        .map_err(ConnectorPkiError::Issue)?;
    write_all(&request.out, &files_of(&request.out, &pki)).map_err(ConnectorPkiError::from)?;
    println!("{}", settings_of(&request.out));
    Ok(())
}

/// Every file `pki` is written to under `out`.
fn files_of(out: &Path, pki: &ConnectorPki) -> Vec<Planned> {
    vec![
        certificate(out, "connector-ca-cert.pem", &pki.authority.certificate_pem),
        key(
            out,
            "connector-ca-key.pem",
            pki.authority.private_key_pem.expose(),
        ),
        certificate(
            out,
            "connector-listener-cert.pem",
            &pki.listener.certificate_pem,
        ),
        key(
            out,
            "connector-listener-key.pem",
            pki.listener.private_key_pem.expose(),
        ),
    ]
}

/// The settings each side takes, naming the files written.
fn settings_of(out: &Path) -> String {
    let out = out.display();
    [
        format!("The connector authority's files are in {out}."),
        String::new(),
        "The API, which signs connectors' certificates:".to_owned(),
        format!("  CONNECTOR_CA_CERT_FILE={out}/connector-ca-cert.pem"),
        format!("  CONNECTOR_CA_KEY_FILE={out}/connector-ca-key.pem"),
        String::new(),
        "The gateway, which takes connectors' links:".to_owned(),
        "  GATEWAY_CONNECTOR_LISTEN=0.0.0.0:8444".to_owned(),
        format!("  GATEWAY_CONNECTOR_CA_FILE={out}/connector-ca-cert.pem"),
        format!("  GATEWAY_CONNECTOR_TLS_CERT_FILE={out}/connector-listener-cert.pem"),
        format!("  GATEWAY_CONNECTOR_TLS_KEY_FILE={out}/connector-listener-key.pem"),
        String::new(),
        "connector-ca-key.pem signs every connector's certificate: keep it on the API alone."
            .to_owned(),
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(out: &Path) -> ConnectorPkiRequest {
        ConnectorPkiRequest {
            listener_names: vec!["connect.ianua.test".to_owned()],
            out: out.to_path_buf(),
        }
    }

    /// The authority and the listener each get a certificate and a key in
    /// the folder.
    #[test]
    fn every_file_is_written() {
        let folder = tempfile::tempdir().unwrap();
        let out = folder.path().join("connectors");

        run(&request(&out)).unwrap();

        for name in [
            "connector-ca-cert.pem",
            "connector-ca-key.pem",
            "connector-listener-cert.pem",
            "connector-listener-key.pem",
        ] {
            assert!(out.join(name).exists(), "{name} is missing");
        }
    }

    /// Issuing connector PKI twice into the same folder refuses the
    /// second write and preserves the authority certificate.
    #[test]
    fn a_second_run_writes_over_nothing() {
        let folder = tempfile::tempdir().unwrap();
        let out = folder.path().to_path_buf();
        run(&request(&out)).unwrap();
        let authority = std::fs::read_to_string(out.join("connector-ca-cert.pem")).unwrap();

        let again = run(&request(&out));

        assert!(matches!(
            again,
            Err(ServerError::ConnectorPki(ConnectorPkiError::Files(
                PkiFileError::Exists { .. }
            )))
        ));
        assert_eq!(
            std::fs::read_to_string(out.join("connector-ca-cert.pem")).unwrap(),
            authority
        );
    }
}
