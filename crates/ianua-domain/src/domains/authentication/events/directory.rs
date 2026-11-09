//! Directory events: binds and searches through the LDAP interface, and the
//! client certificates it signs in with.

use time::OffsetDateTime;

use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::{EventLabel, LdapCertificateId, UserId};

/// A directory client authenticated with an LDAP simple bind.
///
/// This is not a [`LoginSucceeded`](crate::domains::authentication::events::login::LoginSucceeded). A bind
/// checks credentials without opening a session. So there is no session to
/// name and nothing to revoke afterwards.
#[derive(Debug)]
pub struct DirectoryBindSucceeded {
    /// The user who bound.
    pub(crate) user_id: UserId,
    /// How the bound user is named in the audit entry. It is the address the
    /// bind DN carried.
    pub(crate) user_label: EventLabel,
    /// When the bind completed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    DirectoryBindSucceeded => crate::types::event_type::AuthenticationEvent::DirectoryBindSucceeded,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "user",
                Reference::new(
                    RefKind::USER,
                    self.user_id.to_string(),
                    self.user_label.as_str(),
                ),
            )
            .field("protocol", "ldap")
    }
}

/// A bound directory client read the directory with an LDAP search.
///
/// Ordinary API list endpoints are not audited. LDAP search is, because it
/// is a separate path that fewer people watch. A common attack on directory
/// protocols guesses a password with a bind, then exports the whole
/// directory with a search. The event records counts, not the entries, so
/// the audit log tracks access to personal data without copying it.
#[derive(Debug)]
pub struct DirectorySearchPerformed {
    /// The bound principal who searched.
    pub(crate) user_id: UserId,
    /// How the principal is named in the audit entry. It is the address
    /// they bound with.
    pub(crate) user_label: EventLabel,
    /// User entries the search returned.
    pub(crate) users_returned: u32,
    /// Group entries the search returned.
    pub(crate) groups_returned: u32,
    /// When the search completed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    DirectorySearchPerformed => crate::types::event_type::AuthenticationEvent::DirectorySearchPerformed,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "user",
                Reference::new(
                    RefKind::USER,
                    self.user_id.to_string(),
                    self.user_label.as_str(),
                ),
            )
            .field("protocol", "ldap")
            .field("users_returned", self.users_returned.to_string())
            .field("groups_returned", self.groups_returned.to_string())
    }
}

/// A bound directory client attempted an LDAP search without permission to
/// read the directory.
#[derive(Debug)]
pub struct DirectorySearchDenied {
    /// The bound principal who was denied.
    pub(crate) user_id: UserId,
    /// How the principal is named in the audit entry. It is the address
    /// they bound with.
    pub(crate) user_label: EventLabel,
    /// When the attempt was denied.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    DirectorySearchDenied => crate::types::event_type::AuthenticationEvent::DirectorySearchDenied,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "user",
                Reference::new(
                    RefKind::USER,
                    self.user_id.to_string(),
                    self.user_label.as_str(),
                ),
            )
            .field("protocol", "ldap")
    }
}

/// A client certificate was issued for LDAP write access.
#[derive(Debug)]
pub struct LdapCertificateIssued {
    /// The user the certificate authenticates as.
    pub(crate) user_id: UserId,
    /// How the user is named in the audit entry.
    pub(crate) user_label: EventLabel,
    /// The issued certificate's record id.
    pub(crate) certificate_id: LdapCertificateId,
    /// The label the user gave the device, such as "MacBook VPN client".
    pub(crate) device_label: EventLabel,
    /// When the certificate stops being valid.
    pub(crate) expires_at: OffsetDateTime,
    /// When the certificate was issued.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    LdapCertificateIssued => crate::types::event_type::AuthenticationEvent::LdapCertificateIssued,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "user",
                Reference::new(
                    RefKind::USER,
                    self.user_id.to_string(),
                    self.user_label.as_str(),
                ),
            )
            .field("certificate_id", self.certificate_id.to_string())
            .field("device_label", self.device_label.as_str())
            .field("expires_at", self.expires_at.to_string())
    }
}

/// A client certificate was revoked, ending its LDAP write access.
#[derive(Debug)]
pub struct LdapCertificateRevoked {
    /// The user the certificate authenticated as.
    pub(crate) user_id: UserId,
    /// How the user is named in the audit entry.
    pub(crate) user_label: EventLabel,
    /// The revoked certificate's record id.
    pub(crate) certificate_id: LdapCertificateId,
    /// When the revocation happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    LdapCertificateRevoked => crate::types::event_type::AuthenticationEvent::LdapCertificateRevoked,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "user",
                Reference::new(
                    RefKind::USER,
                    self.user_id.to_string(),
                    self.user_label.as_str(),
                ),
            )
            .field("certificate_id", self.certificate_id.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;

    /// Alice's LDAP search returns 12 users and 3 groups. The event records
    /// the two counts and links to Alice, but copies none of the entries.
    #[test]
    fn directory_search_performed_records_counts_not_entries() {
        let user_id = UserId::new();
        let event = DirectorySearchPerformed {
            user_id,
            user_label: EventLabel::of("alice@example.com"),
            users_returned: 12,
            groups_returned: 3,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        assert_eq!(payload.get("users_returned"), Some("12"));
        assert_eq!(payload.get("groups_returned"), Some("3"));
        let Some(FieldValue::Reference(user)) = payload.value("user") else {
            panic!("expected a user reference");
        };
        assert_eq!(user.id(), user_id.to_string());
    }

    /// Bob binds and tries a search he has no right to. The event links to
    /// Bob by id and by "bob@acme.com".
    #[test]
    fn directory_search_denied_references_the_denied_principal() {
        let user_id = UserId::new();
        let event = DirectorySearchDenied {
            user_id,
            user_label: EventLabel::of("bob@acme.com"),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        let Some(FieldValue::Reference(user)) = payload.value("user") else {
            panic!("expected a user reference");
        };
        assert_eq!(user.id(), user_id.to_string());
        assert_eq!(user.label(), "bob@acme.com");
    }

    /// Alice gets a certificate for her laptop's VPN client. The event links
    /// to Alice and carries the certificate id and the device label as given.
    #[test]
    fn ldap_certificate_issued_references_the_user_and_carries_the_cert_id() {
        let user_id = UserId::new();
        let certificate_id = LdapCertificateId::new();
        let event = LdapCertificateIssued {
            user_id,
            user_label: EventLabel::of("alice@example.com"),
            certificate_id,
            device_label: EventLabel::of("MacBook — VPN client"),
            expires_at: crate::shared::clock::now(),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        assert_eq!(
            payload.get("certificate_id"),
            Some(certificate_id.to_string().as_str())
        );
        assert_eq!(payload.get("device_label"), Some("MacBook — VPN client"));
        let Some(FieldValue::Reference(user)) = payload.value("user") else {
            panic!("expected a user reference");
        };
        assert_eq!(user.id(), user_id.to_string());
    }

    /// Bob's certificate is revoked. The event carries its id, so the audit
    /// log shows which certificate lost write access.
    #[test]
    fn ldap_certificate_revoked_carries_the_cert_id() {
        let certificate_id = LdapCertificateId::new();
        let event = LdapCertificateRevoked {
            user_id: UserId::new(),
            user_label: EventLabel::of("bob@acme.com"),
            certificate_id,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        assert_eq!(
            payload.get("certificate_id"),
            Some(certificate_id.to_string().as_str())
        );
    }
}
