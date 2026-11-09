//! Submit review verdict: a reviewer agent records an advisory verdict on
//! the agent it reviews, once
//! [admitted](crate::use_cases::agents::reviews::desk) by every check
//! that made its assignment acceptable.
//!
//! The verdict comes from the standing assignment, so it names the agent
//! that assignment reviews, never one the reviewer picks. It must cite
//! evidence records of that agent. It is recorded for a person to act on;
//! the reviewer acts on nothing.

use ianua_domain::domains::agents::oversight::review::{ReviewVerdict, VerdictParams};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActingFor, ActorRef, Audience};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::audit::EvidenceStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::reviews::desk::{
    DeskPorts, DeskVisit, ReviewRequest, admitted_reviewer,
};

/// Who gives the verdict, about whom, and what it concluded.
pub struct SubmitVerdictRequest {
    /// The reviewer and the agent it reviews.
    pub review: ReviewRequest,
    /// The verdict itself.
    pub verdict: VerdictParams,
}

/// Records reviewer agents' verdicts.
pub struct SubmitVerdictUseCase {
    ports: DeskPorts,
    audience: Audience,
}

impl SubmitVerdictUseCase {
    /// A use case working through `ports`, taking assertions addressed to
    /// `audience`, the tenant's token endpoint.
    #[must_use]
    pub fn new(ports: DeskPorts, audience: Audience) -> Self {
        Self { ports, audience }
    }
}

impl Command for SubmitVerdictUseCase {
    type Caller = ScopedTenant;
    type Input = SubmitVerdictRequest;
    type Output = Result<(), AppError>;

    /// Records the reviewer's verdict in the tenant the request was addressed
    /// to.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the assertion does not sign the reviewer
    ///   in, or the reviewer may not review that agent now.
    /// - `AppError::Domain(Validation)` when a cited record is not the
    ///   reviewed agent's.
    /// - `AppError::Internal` when a check cannot be read, or the verdict or
    ///   an attack on the reviewer's sign-in cannot be recorded.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: SubmitVerdictRequest,
    ) -> Result<(), AppError> {
        let visit = DeskVisit {
            tenant,
            audience: &self.audience,
            auditor,
        };
        let mut admitted = admitted_reviewer(&self.ports, visit, &request.review).await?;
        let verdict = admitted
            .assignment
            .verdict(&admitted.acting, request.verdict)
            .map_err(AppError::from_domain)?;
        ensure_cites_reviewed_evidence(self.ports.evidence_store.as_ref(), tenant, &verdict)
            .await?;
        auditor
            .dispatch_by(
                &reviewer_itself(&verdict),
                admitted.assignment.take_events(tenant),
            )
            .await
            .or_internal()
    }
}

/// Refuses a verdict citing any record that is not the reviewed agent's.
async fn ensure_cites_reviewed_evidence(
    store: &dyn EvidenceStore,
    tenant: &ScopedTenant,
    verdict: &ReviewVerdict,
) -> Result<(), AppError> {
    let cited = verdict.cited().seqs();
    let found = store
        .records_of(tenant, verdict.reviewed(), cited)
        .await
        .or_internal()?;
    if found.len() == cited.len() {
        return Ok(());
    }
    Err(AppError::from_domain(DomainError::invalid(message!(
        "agents-a-verdict-may-cite-only-evidence",
        "a verdict may cite only evidence records of the agent it reviews"
    ))))
}

/// The reviewer agent itself, rather than anyone it acts for: who a verdict
/// is recorded as given by.
fn reviewer_itself(verdict: &ReviewVerdict) -> ActorRef {
    ActorRef::Agent {
        id: *verdict.reviewer(),
        on_behalf_of: ActingFor::Itself,
    }
}
