//! List the record sets in a delegated zone.

use ianua_domain::domains::authorization::permission::{DomainAction, SystemPermission};
use ianua_domain::domains::tenant::custom_domains::dns_zone::RecordSet;
use ianua_domain::types::DomainId;

use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::use_case::Query;
use crate::use_cases::domain::dns_records::zone::{DelegatedZone, ZonePorts};

/// One record set, and whether the tenant may change it.
///
/// A listing that hid our records would make the zone look wrong, and one
/// that offered them as editable would invite a write that gets refused.
/// Saying which is which is the honest middle.
pub struct ManagedRecordSet {
    /// The set itself.
    pub set: RecordSet,
    /// Whether we maintain this set rather than the tenant: the apex address
    /// or a certificate challenge.
    pub is_reserved: bool,
}

/// Lists the records in a delegated zone.
pub struct ListUseCase {
    ports: ZonePorts,
}

impl ListUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ZonePorts) -> Self {
        Self { ports }
    }
}

impl Query for ListUseCase {
    type Caller = CallerContext;
    type Input = DomainId;
    type Output = Result<Vec<ManagedRecordSet>, AppError>;

    /// Every set the zone answers with, ordered by name and then type.
    ///
    /// Not paginated. A zone is bounded by the plan limit and is read whole:
    /// a resolver's view of a name depends on every set around it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view domains.
    /// - `AppError::NotFound` if the tenant has no such domain.
    /// - `AppError::Conflict` if the domain is not delegated.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        domain_id: DomainId,
    ) -> Result<Vec<ManagedRecordSet>, AppError> {
        self.ports
            .tenant_authorities
            .authority(caller)
            .await?
            .ensure_holds(SystemPermission::Domains(DomainAction::View))
            .map_err(AppError::from_domain)?;
        let zone = DelegatedZone::resolve(&self.ports, caller, &domain_id).await?;
        let sets = self
            .ports
            .dns_zones
            .record_sets(zone.tenant(), zone.hostname())
            .await
            .or_internal()?;
        Ok(sets
            .into_iter()
            .map(|set| ManagedRecordSet {
                is_reserved: zone.policy().is_reserved(set.name(), set.kind()),
                set,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::custom_domains::dns_zone::RecordKind;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::{block_on, test_ctx};
    use crate::use_cases::domain::dns_records::tests::{
        DELEGATED_HOST, ZoneFixture, address_set, delegated_zone, self_managed, text_set,
    };

    fn list(zone: &ZoneFixture, id: DomainId) -> Result<Vec<ManagedRecordSet>, AppError> {
        block_on(ListUseCase::new(zone.ports()).execute(&test_ctx(), id))
    }

    /// Ann lists Acme's zone. She sees the one record it holds.
    #[test]
    fn listing_returns_the_zones_sets() {
        let zone = delegated_zone().holding(&text_set("api.auth.acme.test", "v=spf1 -all"));

        let listed = list(&zone, zone.id).unwrap();

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].set.kind(), RecordKind::Txt);
    }

    /// Ann lists Acme's zone. The apex address we keep is shown, marked as
    /// ours, beside her own record.
    #[test]
    fn our_own_records_are_listed_and_marked_as_ours() {
        let zone = delegated_zone()
            .holding(&address_set(DELEGATED_HOST, "203.0.113.10"))
            .holding(&address_set("api.auth.acme.test", "198.51.100.1"));

        let listed = list(&zone, zone.id).unwrap();

        let reserved = |name: &str| {
            listed
                .iter()
                .find(|m| m.set.name().as_str() == name)
                .map(|m| m.is_reserved)
        };
        assert_eq!(reserved(DELEGATED_HOST), Some(true));
        assert_eq!(reserved("api.auth.acme.test"), Some(false));
    }

    /// Acme's zone holds nothing yet. The listing is empty.
    #[test]
    fn an_empty_zone_lists_nothing() {
        let zone = delegated_zone();

        assert!(list(&zone, zone.id).unwrap().is_empty());
    }

    /// Acme runs this domain at its own provider. An empty list would read
    /// as "you have no records", which is false, so it is refused.
    #[test]
    fn a_self_managed_domain_has_no_zone_to_list() {
        let zone = self_managed();

        assert!(matches!(list(&zone, zone.id), Err(AppError::Conflict(_))));
    }

    /// Ann names a domain Acme does not have. It is not found.
    #[test]
    fn an_unknown_domain_is_not_found() {
        let zone = delegated_zone();

        assert!(matches!(
            list(&zone, DomainId::new()),
            Err(AppError::NotFound(_))
        ));
    }

    /// Listing a delegated zone requires the domain-viewing right; a
    /// caller with no tenant rights receives forbidden.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let zone = delegated_zone().with_authorities(FakeTenantAuthorities::holding(&[]));

        assert!(matches!(list(&zone, zone.id), Err(AppError::Forbidden(_))));
    }

    /// A signed-out session receives an authentication error instead of
    /// the delegated zone's records.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let zone =
            delegated_zone().with_authorities(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(
            list(&zone, zone.id),
            Err(AppError::Unauthenticated)
        ));
    }
}
