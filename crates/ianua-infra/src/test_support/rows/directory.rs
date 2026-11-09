//! Rows of the directory context.

use ianua_domain::domains::authentication::directory_service::account::{
    DirectoryServiceAccountRow, ServiceAccountStatus,
};
use ianua_domain::domains::authentication::directory_service::scope::{
    BaseDn, DirectoryAccess, ServiceAccountName, ServiceAccountScope,
};
use ianua_domain::domains::authentication::ldap_certificate::LdapClientCertificateRow;
use ianua_domain::types::{
    CertificateFingerprint, DirectoryServiceAccountId, Label, LdapCertificateId, Revocation,
    TokenHash, UserId,
};
use time::Duration;

use crate::test_support::rows::at;

/// A certificate of `user` on their laptop whose digest is 32 bytes of
/// `byte`, issued at the fixed moment for 90 days, and not revoked.
///
/// # Panics
///
/// Never: the label is a valid one.
#[must_use]
pub fn certificate_row(user: UserId, byte: u8) -> LdapClientCertificateRow {
    LdapClientCertificateRow {
        id: LdapCertificateId::new(),
        user_id: user,
        fingerprint: CertificateFingerprint::from_digest([byte; 32]),
        device_label: Label::new("device_label", "Laptop").expect("a valid label"),
        issued_at: at(0),
        expires_at: at(0).saturating_add(Duration::days(90)),
        revocation: Revocation::InForce,
    }
}

/// An active, read-only account named `name` under one base DN, made at the
/// fixed moment.
///
/// # Panics
///
/// When `name` is not a valid account name, which is a mistake in the
/// test.
#[must_use]
pub fn service_account_row(name: &str) -> DirectoryServiceAccountRow {
    let base = BaseDn::new("ou=people,dc=acme,dc=example").expect("a valid base DN");
    DirectoryServiceAccountRow {
        id: DirectoryServiceAccountId::new(),
        name: ServiceAccountName::new(name).expect("a valid account name"),
        secret_hash: TokenHash::from_stored(format!("hash of {name}")),
        scope: ServiceAccountScope::new(DirectoryAccess::ReadOnly, vec![base])
            .expect("a valid scope"),
        status: ServiceAccountStatus::Active,
        created_at: at(0),
        secret_changed_at: at(0),
    }
}
