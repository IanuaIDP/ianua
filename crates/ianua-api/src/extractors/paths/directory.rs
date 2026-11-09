//! The LDAP client certificate or service account a request names.

use ianua_domain::types::{DirectoryServiceAccountId, LdapCertificateId};
use serde::Deserialize;
use uuid::Uuid;

/// `.../auth/ldap-certificates/{certificate_id}`.
#[derive(Deserialize)]
pub(crate) struct LdapCertificatePath {
    certificate_id: Uuid,
}

impl LdapCertificatePath {
    /// The certificate named.
    #[must_use]
    pub(crate) fn certificate(&self) -> LdapCertificateId {
        LdapCertificateId::from_uuid(self.certificate_id)
    }
}

/// `.../auth/ldap-service-accounts/{account_id}/...`.
#[derive(Deserialize)]
pub(crate) struct ServiceAccountPath {
    account_id: Uuid,
}

impl ServiceAccountPath {
    /// The service account named.
    #[must_use]
    pub(crate) fn account(&self) -> DirectoryServiceAccountId {
        DirectoryServiceAccountId::from_uuid(self.account_id)
    }
}
