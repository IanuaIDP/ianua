//! A tenant's own domains: registering one, the record that proves it, its
//! verification, and the certificate the tenant brings for it.

use serde::{Deserialize, Serialize};

/// `POST …/domains`.
#[derive(Debug, Clone, Serialize)]
pub struct NewDomain {
    /// The name, such as `shop.acme.example`.
    pub domain: String,
}

/// A registered domain.
#[derive(Debug, Clone, Deserialize)]
pub struct Domain {
    /// Handle used for ownership checks and certificate uploads.
    pub id: String,
    /// Its name.
    pub domain: String,
    /// `Pending`, `Verified` or `Failed`.
    pub verification_status: String,
    /// The name the proving `TXT` record goes at.
    #[serde(default)]
    pub dns_record_name: Option<String>,
    /// The value it must hold.
    #[serde(default)]
    pub dns_record_value: Option<String>,
}

/// What a verification found.
#[derive(Debug, Clone, Deserialize)]
pub struct Verification {
    /// `Pending`, `Verified` or `Failed`.
    pub status: String,
}

/// `PUT …/domains/{id}/certificate`. `Debug` shows no key.
#[derive(Clone, Serialize)]
pub struct UploadCertificate {
    /// The certificate and its chain, as PEM.
    pub certificate_pem: String,
    /// Secret matching the uploaded leaf certificate, encoded as PEM.
    pub private_key_pem: String,
}

impl std::fmt::Debug for UploadCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UploadCertificate").finish_non_exhaustive()
    }
}

/// The certificate a domain now serves.
#[derive(Debug, Clone, Deserialize)]
pub struct ServedCertificate {
    /// The names it covers.
    pub subject_names: Vec<String>,
}
