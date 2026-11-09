//! The client certificates a directory bind needs: issuing one to a person
//! who proves who they are again, listing theirs, and revoking one.
//!
//! A certificate is the possession factor an LDAP simple bind cannot carry
//! on its own. Its private key never leaves the person's device: they send
//! a signing request, and only the fingerprint of what was signed is kept.

pub(crate) mod issue_ldap;
pub(crate) mod list_ldap;
pub(crate) mod revoke_ldap;

pub use issue_ldap::{IssueLdapPorts, IssueLdapRequest, IssueLdapUseCase, IssuedCertificate};
pub use list_ldap::{ListLdapPorts, ListLdapUseCase};
pub use revoke_ldap::{RevokeLdapPorts, RevokeLdapUseCase};
