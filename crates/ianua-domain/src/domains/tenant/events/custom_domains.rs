//! Events about a tenant's own domains, their certificates and DNS records.

use time::OffsetDateTime;

use crate::domains::tenant::custom_domains::dns_zone::{RecordName, RecordValue};
use crate::domains::tenant::custom_domains::uploaded_certificate::CertificateIssuer;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::{DomainName, EventLabel, TenantId};

/// A custom domain was registered for a tenant.
///
/// The domain still needs DNS verification before it can be used.
#[derive(Debug)]
pub(crate) struct TenantDomainRegistered {
    /// The domain that was registered.
    pub(crate) domain: DomainName,
    /// When the registration occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantDomainRegistered => crate::types::event_type::TenantEvent::DomainRegistered,
    fn payload(&self) -> EventData {
        EventData::new().field("domain", self.domain.to_string())
    }
}

/// A custom domain's DNS verification succeeded.
///
/// The tenant has proved it controls the domain, so the domain can now be
/// used.
#[derive(Debug)]
pub(crate) struct TenantDomainVerified {
    /// The domain that was verified.
    pub(crate) domain: DomainName,
    /// When the verification succeeded.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantDomainVerified => crate::types::event_type::TenantEvent::DomainVerified,
    fn payload(&self) -> EventData {
        EventData::new().field("domain", self.domain.to_string())
    }
}

/// A verified custom domain stopped resolving.
///
/// The proof was in place and is gone. Only the tenant can put it back.
#[derive(Debug)]
pub(crate) struct TenantDomainVerificationLost {
    /// The domain that stopped resolving.
    pub(crate) domain: DomainName,
    /// When the loss was noticed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantDomainVerificationLost => crate::types::event_type::TenantEvent::DomainVerificationLost,
    fn payload(&self) -> EventData {
        EventData::new().field("domain", self.domain.to_string())
    }
}

/// A custom domain's TLS certificate was provisioned.
///
/// The domain now has an active TLS certificate and can serve HTTPS. The
/// proxy must reload its certificate store.
#[derive(Debug)]
pub(crate) struct TenantDomainTlsProvisioned {
    /// The domain that was provisioned.
    pub(crate) domain: DomainName,
    /// When the certificate expires.
    pub(crate) expires_at: OffsetDateTime,
    /// When the provisioning completed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantDomainTlsProvisioned => crate::types::event_type::TenantEvent::DomainTlsProvisioned,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("domain", self.domain.to_string())
            .field("expires_at", self.expires_at.to_string())
    }
}

/// A tenant offered one of its custom domains to another tenant of the same
/// organization. Nothing moves until an admin of the receiving tenant
/// accepts; the record shows who was offered what, so an offer nobody
/// expected is seen before it is taken.
///
/// The event is filed under the giving tenant. The receiving tenant is named
/// in the payload.
#[derive(Debug)]
pub(crate) struct TenantDomainHandoverOffered {
    /// The tenant the domain is offered to.
    pub(crate) target_tenant_id: TenantId,
    /// The receiving tenant's display name when the offer was made.
    pub(crate) target_tenant_label: EventLabel,
    /// The domain offered.
    pub(crate) domain: DomainName,
    /// When the offer was made.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantDomainHandoverOffered => crate::types::event_type::TenantEvent::DomainHandoverOffered,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("domain", self.domain.to_string())
            .reference(
                "target_tenant",
                Reference::new(
                    RefKind::TENANT,
                    self.target_tenant_id.to_string(),
                    self.target_tenant_label.as_str(),
                ),
            )
    }
}

/// A custom domain was transferred from one tenant to another.
///
/// The domain keeps its verification status and TLS state. Both tenants
/// belong to the same organization.
///
/// The event is filed under the target tenant, which raises it as it
/// accepts the offer. Both tenants are named in the payload.
#[derive(Debug)]
pub(crate) struct TenantDomainTransferred {
    /// The tenant the domain was transferred from.
    pub(crate) source_tenant_id: TenantId,
    /// The source tenant's display name at the time of transfer.
    pub(crate) source_tenant_label: EventLabel,
    /// The tenant the domain was transferred to.
    pub(crate) target_tenant_id: TenantId,
    /// The target tenant's display name at the time of transfer.
    pub(crate) target_tenant_label: EventLabel,
    /// The domain that was transferred.
    pub(crate) domain: DomainName,
    /// When the transfer occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantDomainTransferred => crate::types::event_type::TenantEvent::DomainTransferred,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("domain", self.domain.to_string())
            .reference(
                "source_tenant",
                Reference::new(
                    RefKind::TENANT,
                    self.source_tenant_id.to_string(),
                    self.source_tenant_label.as_str(),
                ),
            )
            .reference(
                "target_tenant",
                Reference::new(
                    RefKind::TENANT,
                    self.target_tenant_id.to_string(),
                    self.target_tenant_label.as_str(),
                ),
            )
    }
}

/// A custom domain was removed from a tenant.
///
/// The adapters should remove its DNS records and TLS certificates.
#[derive(Debug)]
pub(crate) struct TenantDomainRemoved {
    /// The domain that was removed.
    pub(crate) domain: DomainName,
    /// When the removal occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantDomainRemoved => crate::types::event_type::TenantEvent::DomainRemoved,
    fn payload(&self) -> EventData {
        EventData::new().field("domain", self.domain.to_string())
    }
}

/// A tenant's primary domain was changed.
///
/// The proxy resolver, DNS and TLS setup must be updated to the new domain.
#[derive(Debug)]
pub struct TenantPrimaryDomainChanged {
    /// The previous primary domain, or `None` when there was none.
    pub(crate) old_domain: Option<DomainName>,
    /// The new primary domain, or `None` when it was cleared.
    pub(crate) new_domain: Option<DomainName>,
    /// When the change occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantPrimaryDomainChanged => crate::types::event_type::TenantEvent::PrimaryDomainChanged,
    fn payload(&self) -> EventData {
        EventData::new().change_between(
            "domain",
            self.old_domain.as_ref().map(ToString::to_string),
            self.new_domain.as_ref().map(ToString::to_string),
        )
    }
}

/// A record set in a delegated zone was written or replaced.
///
/// A DNS change can take a tenant's service down without any error showing
/// anywhere. When a hostname stops resolving, the first question is "what
/// was it before?". So each change records the old and new values, and the
/// audit log alone can answer it.
#[derive(Debug)]
pub(crate) struct TenantDnsRecordSetChanged {
    /// The delegated hostname whose zone holds the set.
    pub(crate) zone: DomainName,
    /// The name the set answers for.
    pub(crate) name: RecordName,
    /// The record type, as a zone file spells it.
    pub(crate) kind: &'static str,
    /// How the set reads now, one value per entry.
    pub(crate) values: Vec<RecordValue>,
    /// How the set read before, empty when it is new.
    pub(crate) previous_values: Vec<RecordValue>,
    /// When the change was made.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantDnsRecordSetChanged => crate::types::event_type::TenantEvent::DnsRecordSetChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("zone", self.zone.to_string())
            .field("name", self.name.as_str())
            .field("kind", self.kind.to_owned())
            .field("values", presentation(&self.values))
            .field("previous_values", presentation(&self.previous_values))
    }
}

/// A record set in a delegated zone was removed.
///
/// It carries the values the set held. After the removal nothing else holds
/// them, and someone restoring the set needs exactly those.
#[derive(Debug)]
pub(crate) struct TenantDnsRecordSetRemoved {
    /// The delegated hostname whose zone held the set.
    pub(crate) zone: DomainName,
    /// The name the set answered for.
    pub(crate) name: RecordName,
    /// The record type, as a zone file spells it.
    pub(crate) kind: &'static str,
    /// How the set read before it was removed.
    pub(crate) previous_values: Vec<RecordValue>,
    /// When the removal was made.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantDnsRecordSetRemoved => crate::types::event_type::TenantEvent::DnsRecordSetRemoved,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("zone", self.zone.to_string())
            .field("name", self.name.as_str())
            .field("kind", self.kind.to_owned())
            .field("previous_values", presentation(&self.previous_values))
    }
}

/// A TLS certificate was requested for a verified domain. The worker issues
/// it.
#[derive(Debug)]
pub(crate) struct TenantDomainTlsRequested {
    /// The domain the certificate is for.
    pub(crate) domain: DomainName,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantDomainTlsRequested => crate::types::event_type::TenantEvent::DomainTlsRequested,
    fn payload(&self) -> EventData {
        EventData::new().field("domain", self.domain.to_string())
    }
}

/// A tenant uploaded its own certificate for one of its domains, and it now
/// serves the name.
///
/// The record names the issuer and when it runs out, never the key.
#[derive(Debug)]
pub(crate) struct TenantDomainCertificateUploaded {
    /// The domain it serves.
    pub(crate) domain: DomainName,
    /// Who issued it, as the certificate says.
    pub(crate) issuer: CertificateIssuer,
    /// When it runs out.
    pub(crate) expires_at: OffsetDateTime,
    /// When it was uploaded.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantDomainCertificateUploaded => crate::types::event_type::TenantEvent::DomainCertificateUploaded,
    fn payload(&self) -> EventData {
        uploaded_payload(&self.domain, &self.issuer, self.expires_at)
    }
}

/// A tenant replaced the certificate serving one of its domains with
/// another it uploaded.
#[derive(Debug)]
pub(crate) struct TenantDomainCertificateReplaced {
    /// The domain it serves.
    pub(crate) domain: DomainName,
    /// Who issued the new one.
    pub(crate) issuer: CertificateIssuer,
    /// When the new one runs out.
    pub(crate) expires_at: OffsetDateTime,
    /// When it was replaced.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantDomainCertificateReplaced => crate::types::event_type::TenantEvent::DomainCertificateReplaced,
    fn payload(&self) -> EventData {
        uploaded_payload(&self.domain, &self.issuer, self.expires_at)
    }
}

/// A tenant removed the certificate it uploaded for one of its domains. The
/// name serves no certificate until another is uploaded or issued.
#[derive(Debug)]
pub(crate) struct TenantDomainCertificateRemoved {
    /// The domain it served.
    pub(crate) domain: DomainName,
    /// When it was removed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantDomainCertificateRemoved => crate::types::event_type::TenantEvent::DomainCertificateRemoved,
    fn payload(&self) -> EventData {
        EventData::new().field("domain", self.domain.to_string())
    }
}

/// A certificate the tenant uploaded runs out soon. Nobody renews it for
/// the tenant, so this is its warning to upload another.
#[derive(Debug)]
pub(crate) struct TenantDomainCertificateExpiring {
    /// The domain it serves.
    pub(crate) domain: DomainName,
    /// When it runs out.
    pub(crate) expires_at: OffsetDateTime,
    /// When this was noticed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantDomainCertificateExpiring => crate::types::event_type::TenantEvent::DomainCertificateExpiring,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("domain", self.domain.to_string())
            .field("expires_at", self.expires_at.to_string())
    }
}

/// What an uploaded certificate's records carry: the domain, its issuer and
/// when it runs out.
fn uploaded_payload(
    domain: &DomainName,
    issuer: &CertificateIssuer,
    expires_at: OffsetDateTime,
) -> EventData {
    EventData::new()
        .field("domain", domain.to_string())
        .field("issuer", issuer.as_str())
        .field("expires_at", expires_at.to_string())
}

/// DNS values as one comma-separated list, each in zone-file form.
fn presentation(values: &[RecordValue]) -> String {
    values
        .iter()
        .map(RecordValue::as_presentation)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::tenant::custom_domains::dns_zone::RecordKind;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;

    fn address(value: &str) -> RecordValue {
        RecordValue::parse(RecordKind::A, value).unwrap()
    }

    fn domain() -> DomainName {
        DomainName::new("auth.acme.com").unwrap()
    }

    /// The two halves of a recorded change: what it was, and what it became.
    fn expect_change(payload: &EventData, key: &str) -> (Option<String>, Option<String>) {
        let Some(FieldValue::Change(change)) = payload.value(key) else {
            panic!("expected a change at {key}");
        };
        (
            change.from().map(str::to_owned),
            change.to().map(str::to_owned),
        )
    }

    /// A domain moves from Acme EU to Acme US. The payload links both
    /// tenants by id and name.
    #[test]
    fn domain_transfer_references_both_tenants() {
        let source = TenantId::new();
        let target = TenantId::new();
        let event = TenantDomainTransferred {
            source_tenant_id: source,
            source_tenant_label: EventLabel::of("Acme EU"),
            target_tenant_id: target,
            target_tenant_label: EventLabel::of("Acme US"),
            domain: DomainName::new("acme.example").unwrap(),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        let Some(FieldValue::Reference(from)) = payload.value("source_tenant") else {
            panic!("source tenant must be a reference");
        };
        let Some(FieldValue::Reference(to)) = payload.value("target_tenant") else {
            panic!("target tenant must be a reference");
        };
        assert_eq!(from.kind(), RefKind::TENANT);
        assert_eq!(from.id(), source.to_string());
        assert_eq!(from.label(), "Acme EU");
        assert_eq!(to.id(), target.to_string());
        assert_eq!(to.label(), "Acme US");
    }

    /// A tenant with no primary domain sets `acme.example`. The change
    /// records no old value and the new domain.
    #[test]
    fn primary_domain_change_records_an_absent_previous_domain() {
        let event = TenantPrimaryDomainChanged {
            old_domain: None,
            new_domain: Some(DomainName::new("acme.example").unwrap()),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        let Some(FieldValue::Change(change)) = payload.value("domain") else {
            panic!("domain must be recorded as a change");
        };
        assert_eq!(change.from(), None);
        assert_eq!(change.to(), Some("acme.example"));
    }

    /// Acme's production tenant offers `auth.acme.com` to its staging
    /// tenant. The record names staging, so both sides can see the offer
    /// before it is taken.
    #[test]
    fn a_handover_offer_names_the_receiver() {
        let staging = TenantId::new();

        let event = TenantDomainHandoverOffered {
            target_tenant_id: staging,
            target_tenant_label: EventLabel::of("Staging"),
            domain: domain(),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        assert_eq!(payload.get("domain"), Some("auth.acme.com"));
        let Some(FieldValue::Reference(target)) = payload.value("target_tenant") else {
            panic!("the receiving tenant is not referenced");
        };
        assert_eq!(target.id(), staging.to_string());
    }

    /// `auth.acme.com` is registered, verified, loses its proof and is
    /// removed. Each event names the hostname.
    #[test]
    fn every_domain_event_names_the_hostname() {
        let now = crate::shared::clock::now();

        let events: Vec<Box<dyn DomainEventCore>> = vec![
            Box::new(TenantDomainRegistered {
                domain: domain(),
                occurred_at: now,
            }),
            Box::new(TenantDomainVerified {
                domain: domain(),
                occurred_at: now,
            }),
            Box::new(TenantDomainVerificationLost {
                domain: domain(),
                occurred_at: now,
            }),
            Box::new(TenantDomainRemoved {
                domain: domain(),
                occurred_at: now,
            }),
        ];

        for event in events {
            let kind = event.event_type();
            assert_eq!(
                event.payload().get("domain"),
                Some("auth.acme.com"),
                "{kind}"
            );
        }
    }

    /// A 90-day certificate is issued for `auth.acme.com`. The event carries
    /// the domain and the expiry, which the renewal job reads.
    #[test]
    fn provisioning_a_certificate_records_the_domain_and_its_expiry() {
        let expires_at = crate::shared::clock::now() + time::Duration::days(90);

        let event = TenantDomainTlsProvisioned {
            domain: domain(),
            expires_at,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        assert_eq!(payload.get("domain"), Some("auth.acme.com"));
        assert_eq!(
            payload.get("expires_at"),
            Some(expires_at.to_string().as_str())
        );
    }

    /// `www` moves from one address to two, and is then removed. Both events
    /// carry the old values, since the zone itself does not keep them.
    #[test]
    fn the_dns_record_events_carry_the_values_before_and_after() {
        let now = crate::shared::clock::now();

        let changed = TenantDnsRecordSetChanged {
            zone: domain(),
            name: RecordName::new("www").unwrap(),
            kind: "A",
            values: vec![address("203.0.113.10"), address("203.0.113.11")],
            previous_values: vec![address("203.0.113.1")],
            occurred_at: now,
        };
        let removed = TenantDnsRecordSetRemoved {
            zone: domain(),
            name: RecordName::new("www").unwrap(),
            kind: "A",
            previous_values: vec![address("203.0.113.1")],
            occurred_at: now,
        };

        let payload = changed.payload();
        assert_eq!(payload.get("zone"), Some("auth.acme.com"));
        assert_eq!(payload.get("name"), Some("www"));
        assert_eq!(payload.get("kind"), Some("A"));
        assert_eq!(payload.get("values"), Some("203.0.113.10, 203.0.113.11"));
        assert_eq!(payload.get("previous_values"), Some("203.0.113.1"));

        let payload = removed.payload();
        assert_eq!(payload.get("zone"), Some("auth.acme.com"));
        assert_eq!(payload.get("name"), Some("www"));
        assert_eq!(payload.get("kind"), Some("A"));
        assert_eq!(payload.get("previous_values"), Some("203.0.113.1"));
    }

    /// A tenant clears its primary domain `auth.acme.com`. The event
    /// records a change from that domain to nothing.
    #[test]
    fn a_cleared_primary_domain_records_a_change_to_nothing() {
        let event = TenantPrimaryDomainChanged {
            old_domain: Some(domain()),
            new_domain: None,
            occurred_at: crate::shared::clock::now(),
        };

        assert_eq!(
            expect_change(&event.payload(), "domain"),
            (Some("auth.acme.com".to_owned()), None)
        );
    }
}
