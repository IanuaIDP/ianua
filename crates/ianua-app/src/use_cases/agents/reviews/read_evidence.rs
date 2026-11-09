//! Read review evidence: a reviewer agent reads the evidence of the agent it
//! reviews, once
//! [admitted](crate::use_cases::agents::reviews::desk) by every check
//! that made its assignment acceptable.

use ianua_domain::types::Audience;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::agents::evidence::get::{
    EvidenceCursor, EvidencePage, EvidenceSources, evidence_page,
};
use crate::use_cases::agents::reviews::desk::{
    DeskPorts, DeskVisit, ReviewRequest, admitted_reviewer,
};

/// Who asks about whom, and which page of the evidence.
pub struct ReadEvidenceRequest {
    /// The reviewer and the agent it reviews.
    pub review: ReviewRequest,
    /// The last sequence number already seen.
    pub after_seq: i64,
    /// How many records to return at most.
    pub limit: u32,
}

/// Serves evidence to reviewer agents.
pub struct ReadEvidenceUseCase {
    ports: DeskPorts,
    audience: Audience,
}

impl ReadEvidenceUseCase {
    /// A use case reading through `ports`, taking assertions addressed to
    /// `audience`, the tenant's token endpoint.
    #[must_use]
    pub fn new(ports: DeskPorts, audience: Audience) -> Self {
        Self { ports, audience }
    }
}

impl Query for ReadEvidenceUseCase {
    type Caller = ScopedTenant;
    type Input = ReadEvidenceRequest;
    type Output = Result<EvidencePage, AppError>;

    /// One page of the reviewed agent's evidence, read in the tenant the
    /// request was addressed to, as its host or path resolved it. Reading
    /// records nothing, but a sign-in refused as an attack is recorded, by
    /// the platform, as the desk records it.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the assertion does not sign the reviewer
    ///   in, or the reviewer may not review that agent now.
    /// - `AppError::Internal` when a check or the evidence cannot be read,
    ///   or an attack cannot be recorded.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        request: ReadEvidenceRequest,
    ) -> Result<EvidencePage, AppError> {
        let auditor = RequestAuditor::system(self.ports.event_dispatcher.clone());
        let visit = DeskVisit {
            tenant,
            audience: &self.audience,
            auditor: &auditor,
        };
        admitted_reviewer(&self.ports, visit, &request.review).await?;
        evidence_page(
            EvidenceSources {
                store: self.ports.evidence_store.as_ref(),
                verdicts: self.ports.chain_verdicts.as_ref(),
            },
            tenant,
            &request.review.reviewed,
            EvidenceCursor {
                after_seq: request.after_seq,
                limit: request.limit,
            },
        )
        .await
    }
}
