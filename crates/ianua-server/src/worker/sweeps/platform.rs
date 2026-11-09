//! The platform's own sweeps: usage snapshots, workflow schedules, account
//! connections nobody finished, registrations at services due for renewal,
//! deliveries no service would send again, the reconciliation of work
//! left half-done, and the removal of ended jobs.

use std::sync::Arc;

use ianua_app::use_cases::agents::runs::RunDrives;
use ianua_app::use_cases::metrics::{CaptureSnapshotsPorts, CaptureSnapshotsUseCase};
use ianua_app::use_cases::scheduling::{
    ReconcilePorts, ReconcileSettings, ReconcileUseCase, RemoveEndedJobsPorts,
    RemoveEndedJobsUseCase,
};
use ianua_app::use_cases::tenant::clones::CloneRuns;
use ianua_app::use_cases::tenant::setup::{SETUP_STEP_JOB, SetupSteps};
use ianua_app::use_cases::tenant::teardown::{TEARDOWN_STEP_JOB, TeardownSteps};
use ianua_app::use_cases::workflows::accounts::connections;
use ianua_app::use_cases::workflows::executions::{
    FireSchedulesPorts, FireSchedulesUseCase, ScheduledStarts,
};
use ianua_app::use_cases::workflows::published::{channels, registrations};
use ianua_infra::postgres::metrics::PgMetricSnapshotWriter;
use ianua_infra::postgres::scheduling::PgStalledWork;
use ianua_infra::postgres::tenant::{PgTenantSetupStore, PgTenantTeardownStore};
use ianua_infra::postgres::workflows::{
    PgChannelDirectory, PgConnectionStates, PgDeliveryRetention, PgScheduledWorkflows,
    PgServiceSubscriptionStore, PgSubscriptionDirectory,
};
use ianua_infra::runtime::LocalTimeZones;

use crate::error::{PlatformError, ServerError};
use crate::worker::handlers::workflows::registrations as workflow_registrations;
use crate::worker::parts::Parts;
use crate::worker::sweeps::{SweepRun, Swept};

/// The platform sweeps' runners.
///
/// # Errors
///
/// [`ServerError`] when a use case cannot be built.
pub(super) fn runners(parts: &Parts<'_>) -> Result<Vec<Arc<dyn SweepRun>>, ServerError> {
    Ok(vec![
        snapshots(parts),
        schedules(parts),
        connections_left(parts),
        registrations_due(parts),
        expired_deliveries(parts),
        registrations_left_waiting(parts),
        channels_due(parts),
        channels_idle(parts),
        reconcile(parts)?,
        ended_jobs(parts),
    ])
}

/// The ended jobs whose keys need holding no longer, removed.
fn ended_jobs(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    Swept::of(RemoveEndedJobsUseCase::new(RemoveEndedJobsPorts {
        jobs: Arc::clone(&parts.jobs),
    }))
}

/// The account connections nobody finished in time, removed.
fn connections_left(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    Swept::of(connections::SweepUseCase::new(connections::SweepPorts {
        states: Arc::new(PgConnectionStates::new(Arc::clone(
            &parts.platform.databases,
        ))),
    }))
}

/// The workflows' registrations at services about to lapse, renewed.
fn registrations_due(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    Swept::of(registrations::RenewUseCase::new(
        registrations::RenewPorts {
            directory: Arc::new(PgSubscriptionDirectory::new(Arc::clone(
                &parts.platform.databases,
            ))),
            registrations: workflow_registrations(parts),
            unit_of_work: Arc::clone(&parts.platform.unit_of_work),
        },
    ))
}

/// The registrations left waiting after their publish ended, given up on.
fn registrations_left_waiting(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    let databases = &parts.platform.databases;
    Swept::of(registrations::AbandonUseCase::new(
        registrations::AbandonPorts {
            directory: Arc::new(PgSubscriptionDirectory::new(Arc::clone(databases))),
            subscriptions: Arc::new(PgServiceSubscriptionStore::new(Arc::clone(databases))),
        },
    ))
}

/// The accounts' channels about to lapse, renewed.
fn channels_due(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    Swept::of(channels::RenewUseCase::new(channels::RenewPorts {
        directory: Arc::new(PgChannelDirectory::new(Arc::clone(
            &parts.platform.databases,
        ))),
        registrations: workflow_registrations(parts),
    }))
}

/// The accounts' channels no workflow waits on, closed.
fn channels_idle(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    Swept::of(channels::CloseIdleUseCase::new(channels::CloseIdlePorts {
        directory: Arc::new(PgChannelDirectory::new(Arc::clone(
            &parts.platform.databases,
        ))),
        registrations: workflow_registrations(parts),
    }))
}

/// The deliveries no service would send again, forgotten.
fn expired_deliveries(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    Swept::of(registrations::ForgetUseCase::new(
        registrations::ForgetPorts {
            retention: Arc::new(PgDeliveryRetention::new(Arc::clone(
                &parts.platform.databases,
            ))),
        },
    ))
}

/// The snapshots of every organization's and live tenant's counts.
fn snapshots(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    Swept::of(CaptureSnapshotsUseCase::new(CaptureSnapshotsPorts {
        writer: Arc::new(PgMetricSnapshotWriter::new(Arc::clone(
            &parts.platform.databases,
        ))),
    }))
}

/// The workflow versions whose schedule fires this minute, started.
fn schedules(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    Swept::of(FireSchedulesUseCase::new(FireSchedulesPorts {
        scheduled: Arc::new(PgScheduledWorkflows::new(Arc::clone(
            &parts.platform.databases,
        ))),
        time_zones: Arc::new(LocalTimeZones),
        jobs: ScheduledStarts {
            queue: Arc::clone(&parts.jobs),
            attempts: parts.attempts,
        },
    }))
}

/// The work left half-done, handed out again.
///
/// # Errors
///
/// [`ServerError`] when the time work may stand does not fit a duration.
fn reconcile(parts: &Parts<'_>) -> Result<Arc<dyn SweepRun>, ServerError> {
    let databases = &parts.platform.databases;
    Ok(Swept::of(ReconcileUseCase::new(
        ReconcilePorts {
            stalled: Arc::new(PgStalledWork::new(Arc::clone(databases))),
            tenants: Arc::clone(&parts.tenants),
            setups: Arc::new(PgTenantSetupStore::new(Arc::clone(databases))),
            teardowns: Arc::new(PgTenantTeardownStore::new(Arc::clone(databases))),
            run_drives: RunDrives {
                queue: Arc::clone(&parts.jobs),
                attempts: parts.attempts,
            },
            clone_runs: CloneRuns {
                queue: Arc::clone(&parts.jobs),
                attempts: parts.attempts,
            },
            setup_steps: SetupSteps::new(SETUP_STEP_JOB, Arc::clone(&parts.jobs), parts.attempts),
            teardown_steps: TeardownSteps::new(
                TEARDOWN_STEP_JOB,
                Arc::clone(&parts.jobs),
                parts.attempts,
            ),
        },
        settings(parts)?,
    )))
}

/// How long work may stand before it is handed out again, and how much of
/// each kind a round takes, as the configuration says.
///
/// # Errors
///
/// [`ServerError`] when the time does not fit a duration.
fn settings(parts: &Parts<'_>) -> Result<ReconcileSettings, ServerError> {
    let reconcile = &parts.config.worker.reconcile;
    let stale_after = time::Duration::try_from(reconcile.stale_after)
        .map_err(PlatformError::of("the reconcile sweep's settings"))?;
    Ok(ReconcileSettings {
        stale_after,
        batch: reconcile.batch,
    })
}
