//! The LDAP directory's TLS in a stack that asks for it: the directory
//! serves a certificate the stack's authority issued for its name, and
//! signs the client certificates people bind with under an authority of
//! its own, made fresh for the stack. Both are written as files the
//! platform reads, as a deployment's are.

use std::path::Path;

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};

use super::StackError;
use super::authority::Authority;
use super::settings::Settings;

/// The name the directory serves under, below the stack's domain.
pub(crate) fn server_name(base_domain: &str) -> String {
    format!("ldap.{base_domain}")
}

/// Writes the directory's certificate and the authority for its clients'
/// certificates under `files`, and points `settings` at them.
///
/// # Errors
///
/// [`StackError::Certificate`] when a certificate cannot be made, and
/// [`StackError::Io`] when a file cannot be written.
pub(crate) fn configure_tls(
    settings: &mut Settings,
    authority: &Authority,
    files: &Path,
    base_domain: &str,
) -> Result<(), StackError> {
    let served = authority.issue(&[server_name(base_domain)])?;
    let clients_key = KeyPair::generate()?;
    let clients = clients_authority()?.self_signed(&clients_key)?;
    let written = [
        (
            "LDAP_TLS_CERT_PATH",
            "ldap.crt",
            served.chain_pem().to_owned(),
        ),
        ("LDAP_TLS_KEY_PATH", "ldap.key", served.key_pem().to_owned()),
        (
            "LDAP_CLIENT_CA_CERT_PATH",
            "ldap-clients.crt",
            clients.pem(),
        ),
        (
            "LDAP_CLIENT_CA_KEY_PATH",
            "ldap-clients.key",
            clients_key.serialize_pem(),
        ),
    ];
    for (setting, file, pem) in written {
        let path = files.join(file);
        std::fs::write(&path, pem).map_err(|cause| StackError::Io {
            what: "the directory's certificate files",
            cause,
        })?;
        settings.set(setting, &path.to_string_lossy());
    }
    Ok(())
}

/// What the authority signing the directory's client certificates says of
/// itself.
fn clients_authority() -> Result<CertificateParams, StackError> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params
        .distinguished_name
        .push(DnType::CommonName, "ianua scenarios directory clients");
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    Ok(params)
}
