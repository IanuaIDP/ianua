//! Report a signal: say something of a person of the tenant that every
//! signal stream taking it should hear, such as "Lee's risk is high".
//!
//! The report is recorded, and the signals planner sends it to each stream
//! that takes it, as it sends every signal from what was recorded.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{SignalsAction, SystemPermission};
use ianua_domain::domains::signals::report::{ReportedSignal, SignalReport};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{EventLabel, UserId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserStore;
use crate::services::lookup::existing_user;
use crate::use_case::Command;

/// What is reported, and about whom.
pub struct SendRequest {
    /// The person it is about.
    pub person: UserId,
    /// What is said of them.
    pub signal: ReportedSignal,
}

/// The ports [`SendUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SendPorts {
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// The tenant's people, to find the one reported.
    pub users: Arc<dyn UserStore>,
}

/// Reports a signal about a person of the tenant.
pub struct SendUseCase {
    ports: SendPorts,
}

impl SendUseCase {
    /// A use case reporting through `ports`.
    #[must_use]
    pub fn new(ports: SendPorts) -> Self {
        Self { ports }
    }
}

impl Command for SendUseCase {
    type Caller = CallerContext;
    type Input = SendRequest;
    type Output = Result<(), AppError>;

    /// Records `signals.signal_reported` about `request.person`, for a
    /// caller who may update signal streams.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update signal
    ///   streams.
    /// - `AppError::NotFound` when the tenant has no such person.
    /// - `AppError::Internal` when the person cannot be read, or the
    ///   report cannot be recorded.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: SendRequest,
    ) -> Result<(), AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Signals(SignalsAction::Update))
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let person = existing_user(self.ports.users.as_ref(), &tenant, &request.person).await?;
        let mut report = SignalReport::<ResolvedTenant>::of(
            request.person,
            EventLabel::of(person.email().as_str()),
            request.signal,
        );
        auditor
            .dispatch(&report.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::signals::signal::SignalRiskLevel;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn reporting(authorities: FakeTenantAuthorities) -> (Result<(), AppError>, Vec<String>) {
        let lee = UserId::new();
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = SendUseCase::new(SendPorts {
            tenant_authorities: Arc::new(authorities),
            users: Arc::new(FakeUserStore::with_user(lee, "lee@acme.com")),
        });
        let result = block_on(use_case.execute(
            &test_ctx(),
            &test_auditor(audit.clone()),
            SendRequest {
                person: lee,
                signal: ReportedSignal::RiskLevel(SignalRiskLevel::High),
            },
        ));
        let recorded = audit.records.lock().unwrap().clone();
        (result, recorded)
    }

    /// Pat reports Lee's risk as high. The report is recorded, for the
    /// planner to send on.
    #[test]
    fn a_report_is_recorded() {
        let (result, recorded) = reporting(FakeTenantAuthorities::holding(&[
            SystemPermission::Signals(SignalsAction::Update),
        ]));

        result.unwrap();
        assert_eq!(recorded, ["signals.signal_reported"]);
    }

    /// Reporting a person's risk level without signal update rights is
    /// forbidden and records no report.
    #[test]
    fn a_caller_who_may_not_update_streams_reports_nothing() {
        let (result, recorded) = reporting(FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(recorded.is_empty());
    }
}
