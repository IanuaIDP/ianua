//! The sweeps the app defines: each one's name, how often it runs, and the
//! use case it runs. The worker reads this list, claims each round of each
//! sweep through [`ClaimDueUseCase`](crate::use_cases::scheduling::ClaimDueUseCase)
//! so one worker runs it, and runs the use case named.
//!
//! A sweep that takes the time runs with the start of the round's claim.
//! Running a round late, or twice after a crash, is safe: every sweep
//! looks at what is due now, not at what changed since the last round.

use std::any::type_name;

use ianua_domain::domains::scheduling::sweep::{SweepName, SweepPeriod};
use ianua_domain::shared::errors::DomainError;
use time::Duration;

use crate::use_cases::audit::{PurgeExpiredRecordsUseCase, SweepChainsUseCase, exports};
use crate::use_cases::authentication::sessions::PurgeEndedUseCase;
use crate::use_cases::authorization::{access_requests, access_reviews, holdings};
use crate::use_cases::crypto::assertions;
use crate::use_cases::crypto::keys::{RevokeAfterGraceUseCase, RotateByAgeUseCase};
use crate::use_cases::domain::certificates::{ProvisionPendingTlsUseCase, RenewUseCase};
use crate::use_cases::domain::verification::{DomainHealthCheckUseCase, RetryUseCase};
use crate::use_cases::federation::connections::RefreshMetadataUseCase;
use crate::use_cases::identity::invitations;
use crate::use_cases::identity::privacy::{
    BuildExportsUseCase, ExpireExportsUseCase, ProcessErasuresUseCase,
};
use crate::use_cases::metrics::CaptureSnapshotsUseCase;
use crate::use_cases::notifications::PurgeOldUseCase;
use crate::use_cases::oauth::api_keys;
use crate::use_cases::oauth::flows::ExpireDeviceAuthorizationsUseCase;
use crate::use_cases::organization::billing::{
    EndLapsedTrialsUseCase, SuspendOverdueOrganizationsUseCase,
};
use crate::use_cases::organization::invitations::LapseOrgUseCase;
use crate::use_cases::organization::privacy::ProcessOrgErasuresUseCase;
use crate::use_cases::proxy::ForgetOldRecordsUseCase;
use crate::use_cases::scheduling::{ReconcileUseCase, RemoveEndedJobsUseCase};
use crate::use_cases::tenant::certificates::MaintainPlatformCertificatesUseCase;
use crate::use_cases::tenant::lifecycle::DeleteArchivedUseCase;
use crate::use_cases::workflows::accounts::connections;
use crate::use_cases::workflows::executions::{FireSchedulesUseCase, PurgeEndedRunsUseCase};
use crate::use_cases::workflows::published::{channels, registrations};
use crate::use_cases::workflows::sandboxes::trying::PurgeEndedTrialsUseCase;
use crate::use_cases::workflows::{evaluations, memories};

/// Five minutes.
const FIVE_MINUTES: Duration = Duration::minutes(5);

/// Fifteen minutes.
const FIFTEEN_MINUTES: Duration = Duration::minutes(15);

/// Six hours.
const SIX_HOURS: Duration = Duration::hours(6);

/// One sweep: its name, how often it runs, and the use case it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sweep {
    name: SweepName,
    period: SweepPeriod,
    runs: &'static str,
}

impl Sweep {
    /// The sweep `name`, running `U` every `every`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when the name is not a sweep's,
    /// or the period is not one a sweep may run on.
    fn of<U: 'static>(name: &str, every: Duration) -> Result<Self, DomainError> {
        Ok(Self {
            name: SweepName::new(name)?,
            period: SweepPeriod::new(every)?,
            runs: type_name::<U>(),
        })
    }

    /// The sweep's name, which its rounds are claimed under.
    #[must_use]
    pub fn name(&self) -> &SweepName {
        &self.name
    }

    /// How often it runs.
    #[must_use]
    pub fn period(&self) -> SweepPeriod {
        self.period
    }

    /// The full path of the use case it runs.
    #[must_use]
    pub fn runs(&self) -> &'static str {
        self.runs
    }
}

/// Every sweep the app defines.
///
/// # Errors
///
/// Returns [`DomainError::Validation`] when a sweep is written wrong, which
/// a test rules out.
pub fn sweeps() -> Result<Vec<Sweep>, DomainError> {
    Ok([upkeep()?, lifecycles()?, expiries()?, platform()?].concat())
}

/// Sweeps that keep records in shape: retention of the audit trail, of
/// notifications, of sandbox trials and of ended workflow runs, of the gateway's request and stream
/// records and of sessions long over, the audit chain, signing keys,
/// certificates and domains.
fn upkeep() -> Result<Vec<Sweep>, DomainError> {
    Ok(vec![
        Sweep::of::<PurgeExpiredRecordsUseCase>("audit.purge_expired_records", Duration::DAY)?,
        Sweep::of::<SweepChainsUseCase>("audit.sweep_chains", Duration::HOUR)?,
        Sweep::of::<PurgeOldUseCase>("notifications.purge_old", Duration::DAY)?,
        Sweep::of::<PurgeEndedTrialsUseCase>("workflows.purge_ended_trials", Duration::HOUR)?,
        Sweep::of::<PurgeEndedRunsUseCase>("workflows.purge_ended_runs", Duration::HOUR)?,
        Sweep::of::<evaluations::PurgeEndedUseCase>(
            "workflows.purge_ended_evaluations",
            Duration::DAY,
        )?,
        Sweep::of::<ForgetOldRecordsUseCase>("proxy.forget_old_records", Duration::HOUR)?,
        Sweep::of::<PurgeEndedUseCase>("authentication.purge_ended_sessions", Duration::DAY)?,
        Sweep::of::<exports::ExpireUseCase>("audit.expire_exports", Duration::HOUR)?,
        Sweep::of::<RotateByAgeUseCase>("crypto.rotate_keys_by_age", Duration::DAY)?,
        Sweep::of::<RevokeAfterGraceUseCase>("crypto.revoke_keys_after_grace", Duration::HOUR)?,
        Sweep::of::<assertions::RotateByAgeUseCase>(
            "crypto.rotate_assertion_keys_by_age",
            Duration::HOUR,
        )?,
        Sweep::of::<assertions::RetireAfterOverlapUseCase>(
            "crypto.retire_assertion_keys_after_overlap",
            Duration::HOUR,
        )?,
        Sweep::of::<ProvisionPendingTlsUseCase>("domain.provision_pending_tls", FIVE_MINUTES)?,
        Sweep::of::<RenewUseCase>("domain.renew_certificates", Duration::DAY)?,
        Sweep::of::<DomainHealthCheckUseCase>("domain.health_check", Duration::HOUR)?,
        Sweep::of::<RetryUseCase>("domain.retry_verification", FIVE_MINUTES)?,
        Sweep::of::<RefreshMetadataUseCase>("federation.refresh_saml_metadata", SIX_HOURS)?,
    ])
}

/// Sweeps that move an account, organization or tenant on when its time
/// comes: erasures, exports, trials, overdue bills, archived tenants and
/// evaluations past their deadline.
fn lifecycles() -> Result<Vec<Sweep>, DomainError> {
    Ok(vec![
        Sweep::of::<ProcessErasuresUseCase>("identity.process_erasures", Duration::HOUR)?,
        Sweep::of::<ProcessOrgErasuresUseCase>("organization.process_erasures", Duration::HOUR)?,
        Sweep::of::<BuildExportsUseCase>("identity.build_exports", FIVE_MINUTES)?,
        Sweep::of::<ExpireExportsUseCase>("identity.expire_exports", Duration::HOUR)?,
        Sweep::of::<EndLapsedTrialsUseCase>("organization.end_lapsed_trials", Duration::HOUR)?,
        Sweep::of::<SuspendOverdueOrganizationsUseCase>(
            "organization.suspend_overdue",
            Duration::HOUR,
        )?,
        Sweep::of::<DeleteArchivedUseCase>("tenant.delete_archived", Duration::HOUR)?,
        Sweep::of::<memories::PurgeUseCase>("workflows.purge_memories", Duration::HOUR)?,
        Sweep::of::<evaluations::EndOverdueUseCase>(
            "workflows.end_overdue_evaluations",
            FIFTEEN_MINUTES,
        )?,
    ])
}

/// Sweeps that end what was only ever given for a while: access, holdings,
/// requests, invitations, offers, device codes and API keys.
fn expiries() -> Result<Vec<Sweep>, DomainError> {
    Ok(vec![
        Sweep::of::<access_reviews::CompleteOverdueUseCase>(
            "authorization.complete_overdue_reviews",
            Duration::HOUR,
        )?,
        Sweep::of::<access_requests::ExpireUseCase>(
            "authorization.expire_access_requests",
            FIFTEEN_MINUTES,
        )?,
        Sweep::of::<holdings::ExpireUseCase>("authorization.expire_holdings", Duration::MINUTE)?,
        Sweep::of::<invitations::ExpireUseCase>("identity.expire_invitations", Duration::HOUR)?,
        Sweep::of::<LapseOrgUseCase>("organization.lapse_invitations", Duration::HOUR)?,
        Sweep::of::<ExpireDeviceAuthorizationsUseCase>(
            "oauth.expire_device_authorizations",
            FIVE_MINUTES,
        )?,
        Sweep::of::<api_keys::ExpireUseCase>("oauth.expire_api_keys", Duration::HOUR)?,
    ])
}

/// Sweeps of the platform's own: usage snapshots, workflow schedules, the
/// reconciliation of work left half-done and the removal of ended jobs.
fn platform() -> Result<Vec<Sweep>, DomainError> {
    Ok(vec![
        Sweep::of::<MaintainPlatformCertificatesUseCase>(
            "tenant.platform_certificates",
            Duration::minutes(6),
        )?,
        Sweep::of::<CaptureSnapshotsUseCase>("metrics.capture_snapshots", Duration::HOUR)?,
        Sweep::of::<FireSchedulesUseCase>("workflows.fire_schedules", Duration::MINUTE)?,
        Sweep::of::<connections::SweepUseCase>("workflows.sweep_connections", FIVE_MINUTES)?,
        Sweep::of::<registrations::RenewUseCase>("workflows.renew_registrations", FIFTEEN_MINUTES)?,
        Sweep::of::<registrations::ForgetUseCase>("workflows.forget_deliveries", Duration::HOUR)?,
        Sweep::of::<registrations::AbandonUseCase>(
            "workflows.abandon_registrations",
            FIFTEEN_MINUTES,
        )?,
        Sweep::of::<channels::RenewUseCase>("workflows.renew_channels", FIFTEEN_MINUTES)?,
        Sweep::of::<channels::CloseIdleUseCase>("workflows.close_idle_channels", Duration::HOUR)?,
        Sweep::of::<ReconcileUseCase>("scheduling.reconcile", FIVE_MINUTES)?,
        Sweep::of::<RemoveEndedJobsUseCase>("scheduling.remove_ended_jobs", Duration::HOUR)?,
    ])
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    /// Every sweep reads: a bad name or period would stop the worker at
    /// startup.
    #[test]
    fn every_sweep_is_written_right() {
        assert!(sweeps().is_ok());
    }

    /// Each sweep runs a use case of the app, by its full path, so the
    /// worker cannot be handed a name that runs nothing.
    #[test]
    fn every_sweep_names_a_use_case() {
        for sweep in sweeps().unwrap() {
            assert!(
                sweep.runs().contains("::use_cases::") && sweep.runs().ends_with("UseCase"),
                "{} runs {}",
                sweep.name(),
                sweep.runs()
            );
        }
    }

    /// No two sweeps share a name or a use case: a shared name would let
    /// one claim the other's rounds.
    #[test]
    fn no_two_sweeps_share_a_name_or_a_use_case() {
        let all = sweeps().unwrap();
        let names: HashSet<&str> = all.iter().map(|sweep| sweep.name().as_str()).collect();
        let use_cases: HashSet<&str> = all.iter().map(Sweep::runs).collect();

        assert_eq!(names.len(), all.len());
        assert_eq!(use_cases.len(), all.len());
    }

    /// Time-bound access ends within a minute of its time, so a sweep
    /// ending it runs every minute; nothing runs less than daily.
    #[test]
    fn every_period_is_sane() {
        let all = sweeps().unwrap();
        let holdings = all
            .iter()
            .find(|sweep| sweep.name().as_str() == "authorization.expire_holdings")
            .unwrap();

        assert_eq!(holdings.period().get(), Duration::MINUTE);
        assert!(
            all.iter()
                .all(|sweep| sweep.period().get() <= Duration::DAY)
        );
    }

    /// The sweeps the platform cannot do without.
    const NEEDED_SWEEPS: &[&str] = &[
        "audit.purge_expired_records",
        "authentication.purge_ended_sessions",
        "authorization.complete_overdue_reviews",
        "crypto.rotate_keys_by_age",
        "crypto.revoke_keys_after_grace",
        "organization.process_erasures",
        "identity.build_exports",
        "identity.expire_exports",
        "organization.end_lapsed_trials",
        "organization.suspend_overdue",
        "oauth.expire_device_authorizations",
        "organization.lapse_invitations",
        "authorization.expire_access_requests",
        "authorization.expire_holdings",
        "identity.expire_invitations",
        "tenant.delete_archived",
        "workflows.purge_memories",
        "workflows.end_overdue_evaluations",
        "workflows.purge_ended_evaluations",
        "federation.refresh_saml_metadata",
        "workflows.fire_schedules",
        "scheduling.reconcile",
    ];

    /// The sweeps the platform needs are all there, among them the archived
    /// tenant deletion and the SAML metadata refresh.
    #[test]
    fn the_needed_sweeps_are_registered() {
        let names: Vec<String> = sweeps()
            .unwrap()
            .iter()
            .map(|sweep| sweep.name().to_string())
            .collect();

        for needed in NEEDED_SWEEPS {
            assert!(names.iter().any(|name| name == *needed), "{needed} missing");
        }
    }
}
