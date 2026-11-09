//! The job that tells one app's server of a sign-out: queued by the
//! planning of the sign-out, and tried again on the queue's backoff while
//! the server does not take its token.

use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::oauth::grants::logout_notice::SignedOut;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_key::KeyHold;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AuditRecordId, OAuthClientId, TenantId};

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::scheduling::{Enqueued, JobQueue};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command as _;
use crate::use_cases::oauth::flows::logout::{
    LogoutDeliveries, NotifyBackChannelLogoutUseCase, SignOutNotice,
};
use crate::use_cases::scheduling::{
    Handled, JobHandler, NewJob, RetryWhen, key_of, payload_of, unless_gone,
};

/// The job type that tells an app's server of a sign-out.
pub const BACK_CHANNEL_LOGOUT_JOB: &str = "oauth.back_channel_logout";

/// Why a logout job runs again.
const NOT_TAKEN: &str = "the app's server did not take the logout token";

/// What a logout job carries: which app of which tenant, and who signed
/// out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct LogoutJob {
    tenant_id: TenantId,
    client_id: OAuthClientId,
    signed_out: SignedOut,
}

/// Where logout jobs are queued, and how many tries each gets.
#[derive(Clone)]
pub struct LogoutJobs {
    /// Persists deliveries notifying applications of session termination.
    pub queue: Arc<dyn JobQueue>,
    /// Tries a logout job gets before it is given up.
    pub attempts: NonZeroU32,
}

impl LogoutJobs {
    /// Queues the job telling the app `client_id` of `tenant_id` that
    /// `signed_out` signed out, once for the event `event_id` and the app.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the job cannot be built or queued.
    pub(crate) async fn queue(
        &self,
        event_id: AuditRecordId,
        tenant_id: TenantId,
        client_id: OAuthClientId,
        signed_out: SignedOut,
    ) -> Result<Enqueued, AppError> {
        NewJob {
            job_type: BACK_CHANNEL_LOGOUT_JOB,
            payload: &LogoutJob {
                tenant_id,
                client_id,
                signed_out,
            },
            tenant_id,
            key: key_of(event_id, client_id)?,
            hold: KeyHold::WhileKept,
            run_at: clock::now(),
            attempts: self.attempts,
        }
        .queue(self.queue.as_ref())
        .await
    }
}

/// Runs logout jobs through [`NotifyBackChannelLogoutUseCase`].
pub struct BackChannelLogoutHandler {
    job_type: JobType,
    notify: Arc<NotifyBackChannelLogoutUseCase>,
}

impl BackChannelLogoutHandler {
    /// A handler telling apps through `notify`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when the job type is not one,
    /// which it always is.
    pub fn new(notify: Arc<NotifyBackChannelLogoutUseCase>) -> Result<Self, DomainError> {
        let job_type = JobType::new(BACK_CHANNEL_LOGOUT_JOB)?;
        Ok(Self { job_type, notify })
    }
}

#[async_trait]
impl JobHandler for BackChannelLogoutHandler {
    fn job_type(&self) -> &JobType {
        &self.job_type
    }

    /// Tells the app. A server that did not take a token is tried again on
    /// the queue's backoff; an app or a tenant that is gone, or one with no
    /// key to sign with, is done with.
    async fn handle(
        &self,
        job: &ScheduledJob,
        auditor: &RequestAuditor,
    ) -> Result<Handled, AppError> {
        let payload: LogoutJob = payload_of(job)?;
        let tenant = ScopedTenant::for_background(payload.tenant_id);
        let auditor = auditor.with_tenant(payload.tenant_id);
        let notice = SignOutNotice {
            client_id: payload.client_id,
            signed_out: payload.signed_out,
        };
        let told = unless_gone(self.notify.execute(&tenant, &auditor, notice).await)?;
        Ok(after_telling(told))
    }
}

/// What telling an app that went as `told` leaves to do.
fn after_telling(told: Option<LogoutDeliveries>) -> Handled {
    let Some(deliveries) = told.filter(|deliveries| deliveries.unreachable > 0) else {
        return Handled::Done;
    };
    tracing::debug!(
        unreachable = deliveries.unreachable,
        "back-channel logout tried again"
    );
    Handled::Retry {
        reason: NOT_TAKEN,
        when: RetryWhen::OnBackoff,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The portal's server missed its token. The job runs again on the
    /// backoff.
    #[test]
    fn an_unreachable_server_is_tried_again() {
        let told = LogoutDeliveries {
            told: 0,
            unreachable: 1,
        };

        assert!(matches!(
            after_telling(Some(told)),
            Handled::Retry {
                when: RetryWhen::OnBackoff,
                ..
            }
        ));
    }

    /// Every token was taken, or there was nothing to tell. The job is
    /// done.
    #[test]
    fn a_told_app_is_done() {
        let told = LogoutDeliveries {
            told: 2,
            unreachable: 0,
        };

        assert_eq!(after_telling(Some(told)), Handled::Done);
        assert_eq!(after_telling(None), Handled::Done);
    }
}
