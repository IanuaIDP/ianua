//! A person bound to the directory over LDAP, as the credential their
//! connection's later requests come with.

use std::sync::Arc;

use ianua_domain::domains::authentication::ldap_certificate::DirectoryBind;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::LdapCertificateId;

/// A bind the directory admitted: the person's password, checked over the
/// client certificate the connection presented, and that certificate's
/// record.
///
/// LDAP has no sessions, so a connection's writes come with the bind
/// itself. Only a bind makes one, so no request can name a certificate and
/// write as its holder without their password. The bind names its
/// certificate and when it was made, so that every request checks them
/// again: a certificate revoked or run out since, an account shut since, or
/// a password reset since, stops the very next write.
#[derive(Debug, Clone)]
pub struct DirectoryBound {
    bind: Arc<DirectoryBind<ResolvedTenant>>,
}

impl DirectoryBound {
    /// The credential `bind` gives the connection's later requests.
    pub(crate) fn new(bind: DirectoryBind<ResolvedTenant>) -> Self {
        Self {
            bind: Arc::new(bind),
        }
    }

    /// The record of the certificate the bind was made over.
    #[must_use]
    pub fn certificate(&self) -> &LdapCertificateId {
        self.bind.certificate()
    }

    /// The domain's proof that the person bound.
    #[must_use]
    pub fn bind(&self) -> &DirectoryBind<ResolvedTenant> {
        &self.bind
    }
}

impl PartialEq for DirectoryBound {
    fn eq(&self, other: &Self) -> bool {
        self.bind.certificate() == other.bind.certificate()
            && self.bind.account() == other.bind.account()
            && self.bind.bound_at() == other.bind.bound_at()
    }
}

impl Eq for DirectoryBound {}
