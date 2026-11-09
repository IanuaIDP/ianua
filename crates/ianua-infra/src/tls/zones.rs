//! DNS-01 proofs written into the zones tenants delegated to us, through
//! the zone writer the control plane writes them with.
//!
//! The proof for a hostname goes into the zone of the tenant that
//! registered that hostname, and nowhere else: the tenant is read from the
//! registration, and the zone writer writes only into a zone that tenant
//! holds. A wildcard's proof goes into its parent's zone, which the same
//! tenant must hold.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::domain::{CrossTenantDomainStore, DnsZoneWriter};
use ianua_domain::domains::tenant::custom_domains::dns_zone::{
    RecordName, RecordSet, RecordValue, Ttl, TxtValue,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DomainName, TenantId};

use crate::tls::seams::AcmeDnsChallengeStore;

/// The label a certificate authority reads a DNS-01 proof under.
const CHALLENGE_LABEL: &str = "_acme-challenge";

/// The DNS-01 proofs, kept in our delegated zones.
pub struct ZoneAcmeDnsChallengeStore {
    registrations: Arc<dyn CrossTenantDomainStore>,
    zones: Arc<dyn DnsZoneWriter>,
}

impl ZoneAcmeDnsChallengeStore {
    /// Proofs written through `zones`, into the zone of the tenant
    /// `registrations` names for each hostname.
    #[must_use]
    pub fn new(
        registrations: Arc<dyn CrossTenantDomainStore>,
        zones: Arc<dyn DnsZoneWriter>,
    ) -> Self {
        Self {
            registrations,
            zones,
        }
    }

    /// The tenant that registered exactly `hostname`, if one did.
    async fn registrant(&self, hostname: &DomainName) -> Result<Option<TenantId>, DomainError> {
        let overlapping = self.registrations.find_overlapping(hostname).await?;
        Ok(overlapping
            .into_iter()
            .find(|(_, registration)| registration.domain() == hostname)
            .map(|(tenant, _)| tenant))
    }
}

/// The zone the proof for `hostname` is written into: a wildcard's parent,
/// or the hostname itself.
pub(crate) fn zone_of(hostname: &DomainName) -> DomainName {
    hostname
        .wildcard_parent()
        .unwrap_or_else(|| hostname.clone())
}

/// The name a certificate authority reads the proof for `zone` from.
///
/// # Errors
///
/// Returns `DomainError::Validation` when the name would be too long.
pub(crate) fn challenge_name(zone: &DomainName) -> Result<RecordName, DomainError> {
    RecordName::new(format!("{CHALLENGE_LABEL}.{}", zone.as_str())).map_err(DomainError::from)
}

/// The set holding the one proof `value` in `zone`, at the shortest time to
/// live so a withdrawn proof leaves caches soon.
///
/// # Errors
///
/// Returns `DomainError::Validation` when the challenge name would be too
/// long.
fn proof_in(zone: &DomainName, value: &TxtValue) -> Result<RecordSet, DomainError> {
    RecordSet::new(
        challenge_name(zone)?,
        Ttl::shortest(),
        vec![RecordValue::Text(value.clone())],
    )
}

#[async_trait]
impl AcmeDnsChallengeStore for ZoneAcmeDnsChallengeStore {
    async fn publish(&self, hostname: &DomainName, value: &TxtValue) -> Result<(), DomainError> {
        let Some(tenant) = self.registrant(hostname).await? else {
            return Err(DomainError::NotFound);
        };
        let zone = zone_of(hostname);
        self.zones
            .add_to_record_set(&tenant, &zone, &proof_in(&zone, value)?)
            .await
    }

    async fn withdraw(&self, hostname: &DomainName, value: &TxtValue) -> Result<(), DomainError> {
        let Some(tenant) = self.registrant(hostname).await? else {
            return Ok(());
        };
        let zone = zone_of(hostname);
        self.zones
            .remove_from_record_set(&tenant, &zone, &proof_in(&zone, value)?)
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::test_support::domain::{DomainSeed, FakeDnsZoneWriter, FakeDomainStore};
    use ianua_domain::domains::tenant::custom_domains::dns_zone::DelegationLabel;
    use ianua_domain::types::DomainId;

    use super::*;

    struct Fixture {
        zones: Arc<FakeDnsZoneWriter>,
        store: ZoneAcmeDnsChallengeStore,
    }

    fn name(text: &str) -> DomainName {
        DomainName::new(text).unwrap()
    }

    fn proof(text: &str) -> TxtValue {
        TxtValue::new(text).unwrap()
    }

    /// Acme registered `registered` names; the zone of `zone` is held by
    /// `holder`.
    async fn fixture(registered: &[&str], zone: &str, holder: Option<TenantId>) -> Fixture {
        let acme = TenantId::new();
        let domains = FakeDomainStore::holding(
            acme,
            registered
                .iter()
                .map(|domain| DomainSeed::verified(domain).delegated().build()),
        );
        let zones = Arc::new(FakeDnsZoneWriter::with_nameservers(vec![name(
            "ns1.ianua.test",
        )]));
        zones
            .create_zone(
                &holder.unwrap_or(acme),
                &name(zone),
                &DelegationLabel::for_registration(&DomainId::new()),
            )
            .await
            .unwrap();
        Fixture {
            store: ZoneAcmeDnsChallengeStore::new(Arc::new(domains), zones.clone()),
            zones,
        }
    }

    /// A proof for `auth.acme.com` lands at `_acme-challenge.auth.acme.com`
    /// in Acme's zone, with the shortest time to live.
    #[tokio::test]
    async fn a_proof_lands_under_the_challenge_label_of_its_zone() {
        let fx = fixture(&["auth.acme.com"], "auth.acme.com", None).await;

        fx.store
            .publish(&name("auth.acme.com"), &proof("digest"))
            .await
            .unwrap();

        let written = fx.zones.written();
        assert_eq!(written.len(), 1);
        assert_eq!(written[0].0, name("auth.acme.com"));
        assert_eq!(
            written[0].1.name().as_str(),
            "_acme-challenge.auth.acme.com"
        );
        assert_eq!(written[0].1.ttl(), Ttl::shortest());
    }

    /// A wildcard's proof goes into its parent's zone, where the authority
    /// reads it.
    #[tokio::test]
    async fn a_wildcard_proof_goes_into_its_parents_zone() {
        let fx = fixture(&["auth.acme.com", "*.auth.acme.com"], "auth.acme.com", None).await;

        fx.store
            .publish(&name("*.auth.acme.com"), &proof("digest"))
            .await
            .unwrap();

        assert_eq!(
            fx.zones.written()[0].1.name().as_str(),
            "_acme-challenge.auth.acme.com"
        );
    }

    /// A wildcard registration cannot write a proof into another tenant's zone;
    /// publication returns not found and leaves the zone untouched.
    #[tokio::test]
    async fn a_zone_another_tenant_holds_is_not_written() {
        let fx = fixture(&["*.auth.acme.com"], "auth.acme.com", Some(TenantId::new())).await;

        let result = fx
            .store
            .publish(&name("*.auth.acme.com"), &proof("digest"))
            .await;

        assert!(matches!(result, Err(DomainError::NotFound)));
        assert!(fx.zones.written().is_empty());
    }

    /// Publishing a proof for an unregistered hostname returns not found.
    #[tokio::test]
    async fn a_name_nobody_registered_is_not_found() {
        let fx = fixture(&["auth.acme.com"], "auth.acme.com", None).await;

        let result = fx
            .store
            .publish(&name("api.acme.com"), &proof("digest"))
            .await;

        assert!(matches!(result, Err(DomainError::NotFound)));
    }

    /// A withdrawn proof is gone, and withdrawing again, or for a name
    /// nobody registered, is not an error.
    #[tokio::test]
    async fn a_withdrawn_proof_is_gone_and_withdrawing_twice_is_fine() {
        let fx = fixture(&["auth.acme.com"], "auth.acme.com", None).await;
        fx.store
            .publish(&name("auth.acme.com"), &proof("digest"))
            .await
            .unwrap();

        fx.store
            .withdraw(&name("auth.acme.com"), &proof("digest"))
            .await
            .unwrap();

        assert!(fx.zones.written().is_empty());
        assert!(
            fx.store
                .withdraw(&name("auth.acme.com"), &proof("digest"))
                .await
                .is_ok()
        );
        assert!(
            fx.store
                .withdraw(&name("api.acme.com"), &proof("digest"))
                .await
                .is_ok()
        );
    }

    /// Apex and wildcard proofs coexist in one record set; withdrawing the
    /// apex proof leaves the wildcard value intact.
    #[tokio::test]
    async fn two_orders_proving_one_name_keep_each_others_proof() {
        let fx = fixture(&["auth.acme.com", "*.auth.acme.com"], "auth.acme.com", None).await;

        fx.store
            .publish(&name("auth.acme.com"), &proof("apex"))
            .await
            .unwrap();
        fx.store
            .publish(&name("*.auth.acme.com"), &proof("wildcard"))
            .await
            .unwrap();
        let both = fx.zones.written();
        fx.store
            .withdraw(&name("auth.acme.com"), &proof("apex"))
            .await
            .unwrap();

        let left = fx.zones.written();
        assert_eq!(both.len(), 1);
        assert_eq!(both[0].1.values().len(), 2);
        assert_eq!(left[0].1.values(), [RecordValue::Text(proof("wildcard"))]);
    }
}
