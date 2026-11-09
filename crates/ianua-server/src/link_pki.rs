//! `ianua link-pki`: issues the private authority, the listener's
//! certificate and one client certificate per nameserver for the link the
//! nameservers outside the cluster follow the zones on, and writes them to
//! a folder.
//!
//! Run once, on a workstation. It refuses to write over any file it would
//! make, and writes private keys readable by their owner alone (see
//! [`crate::pki_files`]).

use std::path::Path;

use ianua_domain::shared::errors::DomainError;
use ianua_infra::crypto::{LinkPki, LinkValidity, issue_link_pki};

use crate::command::LinkPkiRequest;
use crate::error::ServerError;
use crate::pki_files::{PkiFileError, Planned, certificate, key, write_all};

/// Why the link's certificates were not written.
#[derive(Debug, thiserror::Error)]
pub enum LinkPkiError {
    /// The certificates could not be issued.
    #[error("the link's certificates could not be issued")]
    Issue(#[source] DomainError),
    /// The files could not be written.
    #[error(transparent)]
    Files(#[from] PkiFileError),
}

/// Issues the link's certificates `request` asks for and writes them to
/// its folder, then prints the settings each end takes.
///
/// # Errors
///
/// [`ServerError::LinkPki`] when a file is there already, the
/// certificates cannot be issued, or a file cannot be written.
pub fn run(request: &LinkPkiRequest) -> Result<(), ServerError> {
    let pki = issue_link_pki(
        &request.server_name,
        &request.nameservers,
        LinkValidity::default(),
    )
    .map_err(LinkPkiError::Issue)?;
    write_all(&request.out, &files_of(&request.out, &pki)).map_err(LinkPkiError::from)?;
    println!("{}", settings_of(&request.out, &pki));
    Ok(())
}

/// Every file `pki` is written to under `out`.
fn files_of(out: &Path, pki: &LinkPki) -> Vec<Planned> {
    let mut planned = vec![
        certificate(out, "ca-cert.pem", &pki.authority.certificate_pem),
        key(out, "ca-key.pem", pki.authority.private_key_pem.expose()),
        certificate(out, "server-cert.pem", &pki.server.certificate_pem),
        key(out, "server-key.pem", pki.server.private_key_pem.expose()),
    ];
    for client in &pki.clients {
        let name = &client.name;
        planned.push(certificate(
            out,
            &format!("{name}-cert.pem"),
            &client.keyed.certificate_pem,
        ));
        planned.push(key(
            out,
            &format!("{name}-key.pem"),
            client.keyed.private_key_pem.expose(),
        ));
    }
    planned
}

/// The settings each end of the link takes, naming the files written.
fn settings_of(out: &Path, pki: &LinkPki) -> String {
    let out = out.display();
    let mut lines = vec![
        format!("The link's certificates are in {out}."),
        String::new(),
        "The control plane (the API nodes):".to_owned(),
        format!("  GRPC_TLS_CERT_PATH={out}/server-cert.pem"),
        format!("  GRPC_TLS_KEY_PATH={out}/server-key.pem"),
        format!("  GRPC_CLIENT_CA_PATH={out}/ca-cert.pem"),
    ];
    for client in &pki.clients {
        let name = &client.name;
        lines.push(String::new());
        lines.push(format!("{name}:"));
        lines.push(format!("  CONTROL_PLANE_CLIENT_CERT={out}/{name}-cert.pem"));
        lines.push(format!("  CONTROL_PLANE_CLIENT_KEY={out}/{name}-key.pem"));
        lines.push(format!("  CONTROL_PLANE_CA_CERT={out}/ca-cert.pem"));
    }
    lines.push(String::new());
    lines.push(
        "ca-key.pem signs every certificate here: keep it off both ends of the link.".to_owned(),
    );
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(out: &Path) -> LinkPkiRequest {
        LinkPkiRequest {
            server_name: "grpc.ianua.test".to_owned(),
            nameservers: vec!["ns1".to_owned(), "ns2".to_owned()],
            out: out.to_path_buf(),
        }
    }

    /// The authority, the listener and each nameserver get a certificate
    /// and a key in the folder.
    #[test]
    fn every_file_is_written() {
        let folder = tempfile::tempdir().unwrap();
        let out = folder.path().join("pki");

        run(&request(&out)).unwrap();

        for name in [
            "ca-cert.pem",
            "ca-key.pem",
            "server-cert.pem",
            "server-key.pem",
            "ns1-cert.pem",
            "ns1-key.pem",
            "ns2-cert.pem",
            "ns2-key.pem",
        ] {
            assert!(out.join(name).exists(), "{name} is missing");
        }
    }

    /// Issuing link PKI twice into the same folder refuses the second
    /// write and preserves the authority certificate.
    #[test]
    fn a_second_run_writes_over_nothing() {
        let folder = tempfile::tempdir().unwrap();
        let out = folder.path().to_path_buf();
        run(&request(&out)).unwrap();
        let authority = std::fs::read_to_string(out.join("ca-cert.pem")).unwrap();

        let again = run(&request(&out));

        assert!(matches!(
            again,
            Err(ServerError::LinkPki(LinkPkiError::Files(
                PkiFileError::Exists { .. }
            )))
        ));
        assert_eq!(
            std::fs::read_to_string(out.join("ca-cert.pem")).unwrap(),
            authority
        );
    }

    /// The nameserver private key grants no permissions to group or other users.
    #[cfg(unix)]
    #[test]
    fn a_private_key_is_readable_by_its_owner_alone() {
        use std::os::unix::fs::PermissionsExt as _;
        let folder = tempfile::tempdir().unwrap();
        let out = folder.path().to_path_buf();

        run(&request(&out)).unwrap();

        let mode = std::fs::metadata(out.join("ns1-key.pem"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
    }
}
