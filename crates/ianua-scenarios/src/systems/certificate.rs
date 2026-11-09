//! A certificate a company's system serves, from an authority made for that
//! one system, written to a folder the system's container reads.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use tempfile::TempDir;

/// The certificate, its key and its authority, and the folder holding
/// them as `ca.pem`, `server.crt`, `server.key` and `combined.pem` (the key
/// followed by the certificate).
#[derive(Debug)]
pub struct SystemCertificate {
    authority: String,
    folder: TempDir,
}

impl SystemCertificate {
    /// A certificate for `name`, from a new authority, written out.
    ///
    /// # Panics
    ///
    /// When a certificate cannot be made or written, which is a mistake in
    /// the scenario's machine.
    /// Generating and writing this fixture is required before its container can start.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn for_name(name: &str) -> Self {
        let authority_key = KeyPair::generate().expect("a key is made");
        let mut authority = CertificateParams::new(Vec::new()).expect("an authority's params");
        authority.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        authority.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let authority_pem = authority
            .self_signed(&authority_key)
            .expect("the authority signs itself")
            .pem();
        let issuer = Issuer::new(authority, authority_key);
        let key = KeyPair::generate().expect("a key is made");
        let certificate = CertificateParams::new(vec![name.to_owned()])
            .expect("a certificate's params")
            .signed_by(&key, &issuer)
            .expect("the authority signs the certificate")
            .pem();
        let folder = TempDir::new().expect("a folder for the certificate");
        write(folder.path(), "ca.pem", &authority_pem);
        write(folder.path(), "server.crt", &certificate);
        write(folder.path(), "server.key", &key.serialize_pem());
        write(
            folder.path(),
            "combined.pem",
            &format!("{}{certificate}", key.serialize_pem()),
        );
        fs::set_permissions(folder.path(), fs::Permissions::from_mode(0o755))
            .expect("the folder opens to the container");
        Self {
            authority: authority_pem,
            folder,
        }
    }

    /// The authority's certificate, as PEM.
    #[must_use]
    pub fn authority_pem(&self) -> &str {
        &self.authority
    }

    /// The folder holding the files.
    #[must_use]
    pub fn folder(&self) -> &Path {
        self.folder.path()
    }
}

/// Writes `text` to `name` in `folder`, readable by a container's own user.
/// Failed fixture writes must abort setup rather than start a container with missing TLS files.
#[allow(clippy::expect_used)]
fn write(folder: &Path, name: &str, text: &str) {
    let path = folder.join(name);
    fs::write(&path, text).expect("the certificate is written");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
        .expect("the container's user reads it");
}
