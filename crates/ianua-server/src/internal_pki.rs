//! `ianua internal-pki`: issues the internal authority, the certificates
//! of the gateway's workflow and runner listeners and the API's relay
//! listener, and those of the worker and the gateway calling them, and
//! writes them to a folder. Runners hold none of their own: they check the
//! runner listener against the authority, and prove themselves with their
//! agent's key.
//!
//! Run once, on a workstation. It refuses to write over any file it would
//! make, and writes private keys readable by their owner alone (see
//! [`crate::pki_files`]).

use std::path::Path;

use ianua_domain::shared::errors::DomainError;
use ianua_infra::crypto::{
    InternalLeaf, InternalListener, InternalPki, LinkValidity, issue_internal_pki,
};

use crate::command::InternalPkiRequest;
use crate::error::ServerError;
use crate::pki_files::{PkiFileError, Planned, certificate, key, write_all};

/// What the gateway's workflow listener's files are called.
const WORKFLOW_LISTENER: &str = "workflow-listener";

/// What the API's relay listener's files are called.
const RELAY_LISTENER: &str = "relay-listener";

/// What the gateway's runner listener's files are called.
const RUNNER_LISTENER: &str = "runner-listener";

/// The name the worker's certificate is issued to.
const WORKER: &str = "worker";

/// The name the gateway's certificate for the relay is issued to.
const GATEWAY: &str = "gateway";

/// Why the internal links' certificates were not written.
#[derive(Debug, thiserror::Error)]
pub enum InternalPkiError {
    /// The certificates could not be issued.
    #[error("the internal links' certificates could not be issued")]
    Issue(#[source] DomainError),
    /// The files could not be written.
    #[error(transparent)]
    Files(#[from] PkiFileError),
}

/// Issues the certificates `request` asks for and writes them to its
/// folder, then prints the settings each end takes.
///
/// # Errors
///
/// [`ServerError::InternalPki`] when a file is there already, the
/// certificates cannot be issued, or a file cannot be written.
pub fn run(request: &InternalPkiRequest) -> Result<(), ServerError> {
    let listeners = [
        InternalListener {
            name: WORKFLOW_LISTENER,
            host: &request.gateway_name,
        },
        InternalListener {
            name: RELAY_LISTENER,
            host: &request.api_name,
        },
        InternalListener {
            name: RUNNER_LISTENER,
            host: &request.gateway_name,
        },
    ];
    let pki = issue_internal_pki(&listeners, &[WORKER, GATEWAY], LinkValidity::default())
        .map_err(InternalPkiError::Issue)?;
    write_all(&request.out, &files_of(&request.out, &pki)).map_err(InternalPkiError::from)?;
    println!("{}", settings_of(request));
    Ok(())
}

/// Every file `pki` is written to under `out`.
fn files_of(out: &Path, pki: &InternalPki) -> Vec<Planned> {
    let mut planned = vec![
        certificate(out, "ca-cert.pem", &pki.authority.certificate_pem),
        key(out, "ca-key.pem", pki.authority.private_key_pem.expose()),
    ];
    planned.extend(
        pki.servers
            .iter()
            .chain(&pki.clients)
            .flat_map(|leaf| leaf_files(out, leaf)),
    );
    planned
}

/// The certificate and key files of `leaf` under `out`.
fn leaf_files(out: &Path, leaf: &InternalLeaf) -> [Planned; 2] {
    [
        certificate(
            out,
            &format!("{}-cert.pem", leaf.name),
            &leaf.keyed.certificate_pem,
        ),
        key(
            out,
            &format!("{}-key.pem", leaf.name),
            leaf.keyed.private_key_pem.expose(),
        ),
    ]
}

/// The settings each end takes, naming the files written.
fn settings_of(request: &InternalPkiRequest) -> String {
    let out = request.out.display();
    let gateway_name = &request.gateway_name;
    [
        format!("The internal links' certificates are in {out}."),
        String::new(),
        gateway_settings(request),
        String::new(),
        "The API:".to_owned(),
        format!("  RELAY_CA_FILE={out}/ca-cert.pem"),
        format!("  RELAY_TLS_CERT_FILE={out}/{RELAY_LISTENER}-cert.pem"),
        format!("  RELAY_TLS_KEY_FILE={out}/{RELAY_LISTENER}-key.pem"),
        String::new(),
        "The worker:".to_owned(),
        format!("  GATEWAY_WORKFLOW_URL=https://{gateway_name}:<port>"),
        format!("  GATEWAY_WORKFLOW_CA_FILE={out}/ca-cert.pem"),
        format!("  GATEWAY_WORKFLOW_CLIENT_CERT_FILE={out}/{WORKER}-cert.pem"),
        format!("  GATEWAY_WORKFLOW_CLIENT_KEY_FILE={out}/{WORKER}-key.pem"),
        String::new(),
        "Each agent's runner:".to_owned(),
        format!("  RUNNER_GATEWAY_URL=https://{gateway_name}:<port>"),
        format!("  RUNNER_GATEWAY_CA_FILE={out}/ca-cert.pem"),
        String::new(),
        "ca-key.pem signs every certificate here: keep it off the gateway, the API and the worker."
            .to_owned(),
    ]
    .join("\n")
}

/// The gateway's listener certificates and authenticated connection to the API.
fn gateway_settings(request: &InternalPkiRequest) -> String {
    let out = request.out.display();
    let api_name = &request.api_name;
    [
        "The gateway:".to_owned(),
        format!("  GATEWAY_WORKFLOW_CA_FILE={out}/ca-cert.pem"),
        format!("  GATEWAY_WORKFLOW_TLS_CERT_FILE={out}/{WORKFLOW_LISTENER}-cert.pem"),
        format!("  GATEWAY_WORKFLOW_TLS_KEY_FILE={out}/{WORKFLOW_LISTENER}-key.pem"),
        format!("  GATEWAY_RUNNER_TLS_CERT_FILE={out}/{RUNNER_LISTENER}-cert.pem"),
        format!("  GATEWAY_RUNNER_TLS_KEY_FILE={out}/{RUNNER_LISTENER}-key.pem"),
        format!("  API_INTERNAL_URL=https://{api_name}:3002"),
        format!("  API_INTERNAL_CA_FILE={out}/ca-cert.pem"),
        format!("  API_INTERNAL_CLIENT_CERT_FILE={out}/{GATEWAY}-cert.pem"),
        format!("  API_INTERNAL_CLIENT_KEY_FILE={out}/{GATEWAY}-key.pem"),
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn request(out: &Path) -> InternalPkiRequest {
        InternalPkiRequest {
            gateway_name: "gateway.ianua.test".to_owned(),
            api_name: "api.ianua.test".to_owned(),
            out: out.to_path_buf(),
        }
    }

    /// The authority, both listeners, the worker and the gateway each get
    /// a certificate and a key in the folder.
    #[test]
    fn every_file_is_written() {
        let folder = tempfile::tempdir().unwrap();
        let out = folder.path().join("pki");

        run(&request(&out)).unwrap();

        for name in [
            "ca-cert.pem",
            "ca-key.pem",
            "workflow-listener-cert.pem",
            "workflow-listener-key.pem",
            "worker-cert.pem",
            "worker-key.pem",
            "relay-listener-cert.pem",
            "relay-listener-key.pem",
            "gateway-cert.pem",
            "gateway-key.pem",
            "runner-listener-cert.pem",
            "runner-listener-key.pem",
        ] {
            assert!(out.join(name).exists(), "{name} is missing");
        }
    }

    /// Issuing internal PKI twice into the same folder refuses the second
    /// write and preserves the authority certificate.
    #[test]
    fn a_second_run_writes_over_nothing() {
        let folder = tempfile::tempdir().unwrap();
        let out: PathBuf = folder.path().to_path_buf();
        run(&request(&out)).unwrap();
        let authority = std::fs::read_to_string(out.join("ca-cert.pem")).unwrap();

        let again = run(&request(&out));

        assert!(matches!(
            again,
            Err(ServerError::InternalPki(InternalPkiError::Files(
                PkiFileError::Exists { .. }
            )))
        ));
        assert_eq!(
            std::fs::read_to_string(out.join("ca-cert.pem")).unwrap(),
            authority
        );
    }
}
