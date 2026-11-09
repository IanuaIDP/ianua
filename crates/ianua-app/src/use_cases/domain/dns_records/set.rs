//! Write or replace a record set in a delegated zone.

use std::sync::Arc;

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::tenant::control::TenantControl;
use ianua_domain::domains::tenant::custom_domains::dns_zone::{
    RecordSet, RecordSetWrite, WriteEffect,
};
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::DomainId;

use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::use_case::Command;
use crate::use_cases::domain::dns_records::zone::{DelegatedZone, ZonePorts};
use crate::use_cases::domain::limits::ensure_within_limit;

/// The ports [`SetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SetPorts {
    /// The zone and the registration behind it.
    pub zone: ZonePorts,
    /// Checks the plan's ceiling on record sets.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
}

/// Which domain's zone to write, and the record set to write into it.
pub struct SetRequest {
    /// The delegated domain whose zone receives the set.
    pub domain_id: DomainId,
    /// The set to write, replacing any set with the same name and type.
    pub set: RecordSet,
}

/// Writes a record set into a delegated zone.
pub struct SetUseCase {
    ports: SetPorts,
}

impl SetUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SetPorts) -> Self {
        Self { ports }
    }
}

impl Command for SetUseCase {
    type Caller = CallerContext;
    type Input = SetRequest;
    type Output = Result<(), AppError>;

    /// Writes the set, replacing whatever the zone answered for that name
    /// and type before, and records `tenant.dns_record_set_changed` with
    /// both.
    ///
    /// The plan limit is checked only when the set is new. Editing a set the
    /// zone already holds does not grow the zone, and a tenant at their limit
    /// must still be able to correct a record.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without domain-change rights, for a platform-kept apex/challenge set or a full record-set allowance.
    /// - `AppError::NotFound` for a missing tenant domain; `Conflict` for an undelegated/unverified domain.
    /// - `AppError::Domain` for a name outside the zone or a CNAME alongside other records.
    /// - `AppError::Internal` on zone read/write or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: SetRequest,
    ) -> Result<(), AppError> {
        let SetRequest { domain_id, set } = request;
        let zone_ports = &self.ports.zone;
        let authority = zone_ports.tenant_authorities.authority(caller).await?;
        let zone = DelegatedZone::resolve_for_change(zone_ports, caller, &domain_id).await?;
        let mut write = permitted_write(zone_ports, &zone, &set, &authority).await?;
        if write.effect() == WriteEffect::AddsASet {
            ensure_within_limit(
                self.ports.limit_enforcer.as_ref(),
                caller,
                ResourceKind::DnsRecordSets,
            )
            .await?;
        }

        zone_ports
            .dns_zones
            .replace_record_set(zone.tenant(), zone.hostname(), &set)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&caller.actor(), write.take_events())
            .await
            .or_internal()
    }
}

/// The write of `set` into `zone`, once its policy lets `by` write it
/// beside the sets the zone holds.
async fn permitted_write(
    ports: &ZonePorts,
    zone: &DelegatedZone,
    set: &RecordSet,
    by: &TenantAuthority,
) -> Result<RecordSetWrite, AppError> {
    let existing = ports
        .dns_zones
        .record_sets(zone.tenant(), zone.hostname())
        .await
        .or_internal()?;
    zone.policy()
        .permits_write(set, &existing, TenantControl::new(by))
        .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{DomainAction, SystemPermission};
    use ianua_domain::shared::events::data::FieldValue;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::{
        FakeLimitEnforcer, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };
    use crate::use_cases::domain::dns_records::tests::{
        DELEGATED_HOST, ZoneFixture, address_set, alias_set, delegated_zone, self_managed,
        text_set, unverified_zone,
    };

    fn use_case_over(zone: &ZoneFixture, limits: Arc<dyn LimitEnforcer>) -> SetUseCase {
        SetUseCase::new(SetPorts {
            zone: zone.ports(),
            limit_enforcer: limits,
        })
    }

    fn write(use_case: &SetUseCase, zone: &ZoneFixture, set: RecordSet) -> Result<(), AppError> {
        block_on(use_case.execute(
            &test_ctx(),
            &test_auditor(zone.audit.clone()),
            SetRequest {
                domain_id: zone.id,
                set,
            },
        ))
    }

    fn written(zone: &ZoneFixture, set: RecordSet) -> Result<(), AppError> {
        write(&use_case_over(zone, Arc::new(FakeLimitEnforcer)), zone, set)
    }

    /// Ann adds `api.auth.acme.test` to Acme's delegated zone. The zone
    /// answers with it, and the change is recorded.
    #[test]
    fn a_record_beneath_the_apex_is_written() {
        let zone = delegated_zone();
        let set = address_set("api.auth.acme.test", "198.51.100.1");

        written(&zone, set.clone()).unwrap();

        assert_eq!(zone.held(), vec![set]);
        assert_eq!(
            zone.audit.records.lock().unwrap()[0],
            "tenant.dns_record_set_changed"
        );
    }

    /// Acme has not proved it holds the name yet. Ann's record is refused,
    /// so nothing waits in the zone to be served once it is.
    #[test]
    fn a_record_in_an_unverified_zone_is_refused() {
        let zone = unverified_zone();

        let result = written(&zone, address_set("api.auth.acme.test", "198.51.100.1"));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(zone.held().is_empty());
    }

    /// Ann writes the same name and type twice. The second set replaces the
    /// first rather than sitting beside it.
    #[test]
    fn writing_a_set_replaces_the_one_it_answers_for() {
        let zone = delegated_zone();
        let second = address_set("api.auth.acme.test", "198.51.100.2");

        written(&zone, address_set("api.auth.acme.test", "198.51.100.1")).unwrap();
        written(&zone, second.clone()).unwrap();

        assert_eq!(zone.held(), vec![second]);
    }

    /// Ann changes an address. The record keeps what it answered before, for
    /// whoever has to explain why the hostname stopped resolving.
    #[test]
    fn replacing_a_set_records_what_it_used_to_answer() {
        let zone = delegated_zone();
        written(&zone, address_set("api.auth.acme.test", "198.51.100.1")).unwrap();
        let replacing = ZoneFixture::sharing(&zone);

        written(
            &replacing,
            address_set("api.auth.acme.test", "198.51.100.2"),
        )
        .unwrap();

        let payload = replacing.audit.payload_of("tenant.dns_record_set_changed");
        assert_eq!(
            payload
                .value("previous_values")
                .and_then(FieldValue::as_str),
            Some("198.51.100.1")
        );
        assert_eq!(
            payload.value("values").and_then(FieldValue::as_str),
            Some("198.51.100.2")
        );
    }

    /// Ann writes a record for a name outside the zone. No resolver would
    /// ask us for it, so it is refused.
    #[test]
    fn a_record_outside_the_zone_is_refused() {
        let zone = delegated_zone();

        let result = written(&zone, address_set("elsewhere.example.com", "198.51.100.1"));

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Ann overwrites the apex address, which routes Acme's hostname to the
    /// proxy. It is refused; it would take the login page off the air.
    #[test]
    fn the_apex_address_cannot_be_overwritten() {
        let zone = delegated_zone();

        let result = written(&zone, address_set(DELEGATED_HOST, "198.51.100.1"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Even a tenant administrator cannot write an ACME challenge through
    /// the DNS record editor; the reserved name is forbidden.
    #[test]
    fn a_certificate_challenge_record_cannot_be_written() {
        let zone = delegated_zone();

        let result = written(&zone, text_set("_acme-challenge.auth.acme.test", "forged"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann adds an alias where an address already answers. A `CNAME` may not
    /// sit beside another record, so it is refused.
    #[test]
    fn an_alias_beside_an_existing_record_is_refused() {
        let zone = delegated_zone();
        written(&zone, address_set("www.auth.acme.test", "198.51.100.1")).unwrap();

        let result = written(
            &zone,
            alias_set("www.auth.acme.test", "elsewhere.example.com"),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Acme runs this domain at its own DNS provider. There is no zone here
    /// to write into.
    #[test]
    fn a_self_managed_domain_has_no_zone_to_write_into() {
        let zone = self_managed();

        let result = written(&zone, address_set("api.auth.acme.test", "198.51.100.1"));

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Acme is at its plan's limit and Ann adds a new set. It is refused and
    /// nothing is written.
    #[test]
    fn a_new_set_beyond_the_plan_limit_is_refused() {
        let zone = delegated_zone();
        let use_case = use_case_over(&zone, Arc::new(RejectingLimitEnforcer));

        let result = write(
            &use_case,
            &zone,
            address_set("api.auth.acme.test", "198.51.100.1"),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(zone.held().is_empty());
    }

    /// Acme is at its plan's limit and Ann corrects a record it already
    /// has. Editing does not grow the zone, so it is allowed.
    #[test]
    fn an_existing_set_can_be_corrected_at_the_plan_limit() {
        let zone = delegated_zone().holding(&address_set("api.auth.acme.test", "198.51.100.1"));
        let use_case = use_case_over(&zone, Arc::new(RejectingLimitEnforcer));

        let result = write(
            &use_case,
            &zone,
            address_set("api.auth.acme.test", "198.51.100.2"),
        );

        assert!(result.is_ok(), "{result:?}");
    }

    /// Viewing domains does not authorize adding an address record; the
    /// attempt is forbidden and the zone remains empty.
    #[test]
    fn a_caller_who_may_only_view_domains_is_refused() {
        let zone = delegated_zone().with_authorities(FakeTenantAuthorities::holding(&[
            SystemPermission::Domains(DomainAction::View),
        ]));

        let result = written(&zone, address_set("api.auth.acme.test", "198.51.100.1"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(zone.held().is_empty());
    }

    /// A signed-out session cannot add an address record to a delegated zone.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let zone =
            delegated_zone().with_authorities(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = written(&zone, address_set("api.auth.acme.test", "198.51.100.1"));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
