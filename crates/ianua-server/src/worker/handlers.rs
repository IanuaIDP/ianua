//! Every job handler the worker runs, one for each job type the app and
//! its adapters queue, and the check that none is missing or doubled.

pub(super) mod agents;
mod audit;
mod deliveries;
mod domain;
mod identity;
mod tenant;
pub(super) mod workflows;

use std::collections::BTreeSet;
use std::sync::Arc;

use ianua_app::use_cases::agents::runs::DRIVE_RUN_JOB;
use ianua_app::use_cases::audit::STREAM_RECORD_JOB;
use ianua_app::use_cases::audit::exports::WRITE_EXPORT_JOB;
use ianua_app::use_cases::domain::verification::verified::PROVISION_TLS_JOB;
use ianua_app::use_cases::identity::imports::IMPORT_JOB;
use ianua_app::use_cases::messaging::broker::PUSH_MESSAGES_JOB;
use ianua_app::use_cases::notifications::DESTINATION_POST_JOB;
use ianua_app::use_cases::oauth::flows::BACK_CHANNEL_LOGOUT_JOB;
use ianua_app::use_cases::scheduling::JobHandler;
use ianua_app::use_cases::signals::delivery::DISPATCH_SIGNAL_JOB;
use ianua_app::use_cases::tenant::clones::RUN_CLONE_JOB;
use ianua_app::use_cases::tenant::setup::SETUP_STEP_JOB;
use ianua_app::use_cases::tenant::teardown::TEARDOWN_STEP_JOB;
use ianua_app::use_cases::webhooks::delivery::DELIVER_WEBHOOK_JOB;
use ianua_app::use_cases::workflows::executions::{
    DRIVE_WORKFLOW_JOB, RUN_CODE_JOB, SETTLE_PASS_JOB, START_ON_EVENT_JOB, START_SCHEDULED_JOB,
    STOP_PASS_JOB,
};
use ianua_app::use_cases::workflows::sandboxes::BUILD_SANDBOX_JOB;
use ianua_infra::mail::MAIL_JOB;

use crate::error::{PlatformError, ServerError};
use crate::worker::parts::Parts;

/// Every job type something queues: the app's, and the mail outbox's.
/// A job of a type no handler runs would wait, failing, until it died.
pub(super) const QUEUED_JOB_TYPES: [&str; 21] = [
    MAIL_JOB,
    PROVISION_TLS_JOB,
    SETUP_STEP_JOB,
    TEARDOWN_STEP_JOB,
    RUN_CLONE_JOB,
    IMPORT_JOB,
    STREAM_RECORD_JOB,
    WRITE_EXPORT_JOB,
    DELIVER_WEBHOOK_JOB,
    DISPATCH_SIGNAL_JOB,
    BACK_CHANNEL_LOGOUT_JOB,
    PUSH_MESSAGES_JOB,
    DESTINATION_POST_JOB,
    DRIVE_WORKFLOW_JOB,
    SETTLE_PASS_JOB,
    STOP_PASS_JOB,
    START_ON_EVENT_JOB,
    START_SCHEDULED_JOB,
    DRIVE_RUN_JOB,
    BUILD_SANDBOX_JOB,
    RUN_CODE_JOB,
];

/// Why the handlers cannot run.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(super) enum HandlersError {
    /// A job type something queues has no handler.
    #[error("no handler runs the {0} jobs that are queued")]
    Missing(String),
    /// Two handlers claim one job type, and one would silently win.
    #[error("two handlers run the {0} jobs")]
    Doubled(String),
}

/// Every handler, one for each queued job type.
///
/// # Errors
///
/// [`ServerError`] when a handler cannot be built, or one is missing or
/// doubled.
pub(super) fn handlers(parts: &Parts<'_>) -> Result<Vec<Arc<dyn JobHandler>>, ServerError> {
    let runner = workflows::code_runner(parts);
    let built = [
        vec![Arc::clone(&parts.mail.handler)],
        domain::handlers(parts)?,
        tenant::handlers(parts)?,
        identity::handlers(parts)?,
        audit::handlers(parts)?,
        deliveries::handlers(parts)?,
        workflows::handlers(parts, Arc::clone(&runner))?,
        agents::handlers(parts, runner)?,
    ]
    .concat();
    checked(built).map_err(|error| PlatformError::of("the job handlers")(error).into())
}

/// `handlers`, when each queued job type has exactly one.
///
/// # Errors
///
/// [`HandlersError`] naming the first type missing or doubled.
fn checked(handlers: Vec<Arc<dyn JobHandler>>) -> Result<Vec<Arc<dyn JobHandler>>, HandlersError> {
    let mut run = BTreeSet::new();
    for handler in &handlers {
        let job_type = handler.job_type().as_str().to_owned();
        if !run.insert(job_type.clone()) {
            return Err(HandlersError::Doubled(job_type));
        }
    }
    let missing = QUEUED_JOB_TYPES
        .iter()
        .find(|queued| !run.contains(**queued));
    if let Some(missing) = missing {
        return Err(HandlersError::Missing((*missing).to_owned()));
    }
    Ok(handlers)
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ianua_app::auditor::RequestAuditor;
    use ianua_app::error::AppError;
    use ianua_app::use_cases::scheduling::Handled;
    use ianua_domain::domains::scheduling::job::ScheduledJob;
    use ianua_domain::domains::scheduling::job_type::JobType;

    use super::*;

    struct Runs(JobType);

    #[async_trait]
    impl JobHandler for Runs {
        fn job_type(&self) -> &JobType {
            &self.0
        }

        async fn handle(
            &self,
            _job: &ScheduledJob,
            _auditor: &RequestAuditor,
        ) -> Result<Handled, AppError> {
            Ok(Handled::Done)
        }
    }

    fn runs(job_type: &str) -> Arc<dyn JobHandler> {
        Arc::new(Runs(JobType::new(job_type).unwrap()))
    }

    fn every_queued_type() -> Vec<Arc<dyn JobHandler>> {
        let types: BTreeSet<&str> = QUEUED_JOB_TYPES.into_iter().collect();
        types.into_iter().map(runs).collect()
    }

    /// A handler for each queued job type passes the check.
    #[test]
    fn one_handler_for_each_queued_type_passes() {
        assert!(checked(every_queued_type()).is_ok());
    }

    /// A handler registry missing certificate provisioning is refused,
    /// identifying that job type as missing.
    #[test]
    fn a_missing_handler_refuses_the_start() {
        let without_tls = every_queued_type()
            .into_iter()
            .filter(|handler| handler.job_type().as_str() != PROVISION_TLS_JOB)
            .collect();

        assert_eq!(
            checked(without_tls).err(),
            Some(HandlersError::Missing(PROVISION_TLS_JOB.to_owned()))
        );
    }

    /// A handler registry containing two mail handlers is refused,
    /// identifying mail as the duplicated job type.
    #[test]
    fn a_doubled_handler_refuses_the_start() {
        let mut handlers = every_queued_type();
        handlers.push(runs(MAIL_JOB));

        assert_eq!(
            checked(handlers).err(),
            Some(HandlersError::Doubled(MAIL_JOB.to_owned()))
        );
    }
}
