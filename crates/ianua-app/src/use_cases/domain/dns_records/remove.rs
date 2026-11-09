//! Remove a record set from a delegated zone.

use ianua_domain::domains::tenant::control::TenantControl;
use ianua_domain::domains::tenant::custom_domains::dns_zone::{
    RecordKind, RecordName, RecordSetRemoval, RemovedRecordSet,
};
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::DomainId;

use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::use_case::Command;
use crate::use_cases::domain::dns_records::zone::{DelegatedZone, ZonePorts};

/// One record set in a domain's zone to remove, by name and type.
pub struct RemoveRequest {
    /// The domain whose zone holds it.
    pub domain_id: DomainId,
    /// The record's name.
    pub name: RecordName,
    /// The record's type.
    pub kind: RecordKind,
}

/// Removes a record set from a delegated zone.
pub struct RemoveUseCase {
    ports: ZonePorts,
}

impl RemoveUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ZonePorts) -> Self {
        Self { ports }
    }
}

impl Command for RemoveUseCase {
    type Caller = CallerContext;
    type Input = RemoveRequest;
    type Output = Result<(), AppError>;

    /// Stops the zone answering for the request's name and type, and records
    /// `tenant.dns_record_set_removed` with what the set used to answer.
    ///
    /// Removing a set that is not there succeeds and records nothing. The
    /// caller wanted the zone to stop answering, and it does not.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without domain-change rights or for a platform-kept apex/challenge set.
    /// - `AppError::NotFound` for a missing tenant domain; `Conflict` for an undelegated/unverified domain.
    /// - `AppError::Domain` for a name outside the zone; `Internal` on zone read/write or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: RemoveRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let zone =
            DelegatedZone::resolve_for_change(&self.ports, caller, &request.domain_id).await?;
        let removal = zone
            .policy()
            .permits_removal(&request.name, request.kind, TenantControl::new(&authority))
            .map_err(AppError::from_domain)?;
        let Some(mut removed) = held_set(&self.ports, &zone, removal).await? else {
            return Ok(());
        };

        self.ports
            .dns_zones
            .remove_record_set(zone.tenant(), zone.hostname(), &request.name, request.kind)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&caller.actor(), removed.take_events())
            .await
            .or_internal()
    }
}

/// The set `zone` holds that `removal` takes out, if it holds one.
async fn held_set(
    ports: &ZonePorts,
    zone: &DelegatedZone,
    removal: RecordSetRemoval,
) -> Result<Option<RemovedRecordSet>, AppError> {
    let existing = ports
        .dns_zones
        .record_sets(zone.tenant(), zone.hostname())
        .await
        .or_internal()?;
    Ok(removal.of_held(&existing))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{DomainAction, SystemPermission};
    use ianua_domain::shared::events::data::FieldValue;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::{block_on, test_auditor, test_ctx};
    use crate::use_cases::domain::dns_records::tests::{
        DELEGATED_HOST, ZoneFixture, address_set, delegated_zone, record_name, self_managed,
    };

    fn remove(zone: &ZoneFixture, name: &str, kind: RecordKind) -> Result<(), AppError> {
        block_on(RemoveUseCase::new(zone.ports()).execute(
            &test_ctx(),
            &test_auditor(zone.audit.clone()),
            RemoveRequest {
                domain_id: zone.id,
                name: record_name(name),
                kind,
            },
        ))
    }

    fn with_api_record() -> ZoneFixture {
        delegated_zone().holding(&address_set("api.auth.acme.test", "198.51.100.1"))
    }

    /// Ann removes `api.auth.acme.test`. The zone stops answering for it and
    /// the removal is recorded.
    #[test]
    fn a_removed_set_stops_being_answered() {
        let zone = with_api_record();

        remove(&zone, "api.auth.acme.test", RecordKind::A).unwrap();

        assert!(zone.held().is_empty());
        assert_eq!(
            zone.audit.records.lock().unwrap()[0],
            "tenant.dns_record_set_removed"
        );
    }

    /// The removal keeps what the set answered, which is exactly what
    /// someone restoring the record needs.
    #[test]
    fn the_removal_records_what_the_set_used_to_answer() {
        let zone = with_api_record();

        remove(&zone, "api.auth.acme.test", RecordKind::A).unwrap();

        let payload = zone.audit.payload_of("tenant.dns_record_set_removed");
        assert_eq!(
            payload
                .value("previous_values")
                .and_then(FieldValue::as_str),
            Some("198.51.100.1")
        );
    }

    /// Ann removes a set the zone does not hold. It succeeds quietly, so a
    /// retried delete does not look broken.
    #[test]
    fn removing_a_set_that_is_not_there_succeeds_quietly() {
        let zone = delegated_zone();

        let result = remove(&zone, "absent.auth.acme.test", RecordKind::A);

        assert!(result.is_ok(), "{result:?}");
        assert!(zone.audit.records.lock().unwrap().is_empty());
    }

    /// Ann removes the apex address. It is refused; it would take Acme's own
    /// login page off the air.
    #[test]
    fn the_apex_address_cannot_be_removed() {
        let zone = delegated_zone().holding(&address_set(DELEGATED_HOST, "203.0.113.10"));

        let result = remove(&zone, DELEGATED_HOST, RecordKind::A);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(zone.held().len(), 1);
    }

    /// Ann removes a certificate challenge. It is refused; those names come
    /// and go while a certificate is issued.
    #[test]
    fn a_certificate_challenge_record_cannot_be_removed() {
        let zone = delegated_zone();

        let result = remove(&zone, "_acme-challenge.auth.acme.test", RecordKind::Txt);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann removes a name outside the zone. It is refused.
    #[test]
    fn a_name_outside_the_zone_cannot_be_removed() {
        let zone = delegated_zone();

        let result = remove(&zone, "elsewhere.example.com", RecordKind::A);

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Acme runs this domain at its own DNS provider. There is no zone here
    /// to remove from.
    #[test]
    fn a_self_managed_domain_has_no_zone_to_remove_from() {
        let zone = self_managed();

        let result = remove(&zone, "api.auth.acme.test", RecordKind::A);

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Viewing domains does not authorize removing an address record;
    /// the attempted removal is forbidden and the set remains stored.
    #[test]
    fn a_caller_who_may_only_view_domains_is_refused() {
        let zone = with_api_record().with_authorities(FakeTenantAuthorities::holding(&[
            SystemPermission::Domains(DomainAction::View),
        ]));

        let result = remove(&zone, "api.auth.acme.test", RecordKind::A);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(zone.held().len(), 1);
    }

    /// A signed-out session cannot remove a delegated zone's address record.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let zone =
            with_api_record().with_authorities(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = remove(&zone, "api.auth.acme.test", RecordKind::A);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
