//! Workload tokens as tests need them: a verifier that answers with fixed
//! claims, and a policy trusting one GitHub Actions workflow.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::agents::identity::attestation::{
    AttestationMethod, AttestationPolicy, WorkloadIssuer, WorkloadKind, WorkloadSubject,
    WorkloadTrust,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::Seconds;

use crate::ports::agents::{
    EnrolledKey, PresentedWorkloadToken, VerifiedWorkloadClaims, WorkloadTokenVerifier,
};
use crate::test_support::Fake;

/// The issuer GitHub Actions tokens come from.
pub const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// The reports repository's main branch, as GitHub Actions names it.
pub const REPORTS_MAIN: &str = "repo:corp/reports:ref:refs/heads/main";

/// Workload token verifier that verifies every token as the same claims,
/// or none, and when the token was made for one key, refuses every other.
///
/// Like a real adapter, it refuses a token from an issuer the agent's
/// policy does not trust for its kind.
pub struct FakeWorkloadTokenVerifier {
    claims: Option<VerifiedWorkloadClaims>,
    audience_key: Option<EnrolledKey>,
}

impl FakeWorkloadTokenVerifier {
    /// A verifier finding every token to carry `claims`, for any key.
    #[must_use]
    pub fn verifying(claims: VerifiedWorkloadClaims) -> Self {
        Self {
            claims: Some(claims),
            audience_key: None,
        }
    }

    /// The same verifier, refusing a token for any key but `key`, as a
    /// token whose audience binds that key is.
    #[must_use]
    pub fn bound_to(self, key: EnrolledKey) -> Self {
        Self {
            audience_key: Some(key),
            ..self
        }
    }

    /// A verifier refusing every token.
    #[must_use]
    pub fn rejecting() -> Self {
        Self {
            claims: None,
            audience_key: None,
        }
    }
}

#[async_trait]
impl WorkloadTokenVerifier for FakeWorkloadTokenVerifier {
    async fn verify(
        &self,
        presented: &PresentedWorkloadToken<'_>,
    ) -> Result<VerifiedWorkloadClaims, DomainError> {
        let Some(claims) = &self.claims else {
            return Err(DomainError::unauthorized("the token does not verify"));
        };
        if self
            .audience_key
            .as_ref()
            .is_some_and(|bound| bound != presented.key)
        {
            return Err(DomainError::unauthorized(
                "the token was made for another key",
            ));
        }
        if !presented.trusted_issuers.contains(&claims.issuer) {
            return Err(DomainError::unauthorized("the issuer is not trusted"));
        }
        Ok(claims.clone())
    }
}

impl Fake for Arc<dyn WorkloadTokenVerifier> {
    fn fake() -> Self {
        Arc::new(FakeWorkloadTokenVerifier::rejecting())
    }
}

/// The claims of a GitHub Actions token for `subject`.
///
/// # Panics
///
/// - When `subject` is not a valid workload subject.
#[must_use]
pub fn github_claims(subject: &str) -> VerifiedWorkloadClaims {
    VerifiedWorkloadClaims {
        issuer: WorkloadIssuer::new(GITHUB_ISSUER).expect("GitHub's issuer is valid"),
        subject: WorkloadSubject::new(subject).expect("the test subject is valid"),
    }
}

/// A policy trusting GitHub Actions tokens for the reports repository's
/// main branch, re-attesting hourly.
///
/// # Panics
///
/// - Never: the trust and policy are well formed.
#[must_use]
pub fn reports_workflow_policy() -> AttestationPolicy {
    let claims = github_claims(REPORTS_MAIN);
    let trust = WorkloadTrust::new(WorkloadKind::GithubActions, claims.issuer, claims.subject)
        .expect("a GitHub trust names GitHub's issuer and a repository");
    AttestationPolicy::with_workloads(
        vec![AttestationMethod::GithubActions],
        Seconds::new(3600),
        Vec::new(),
        vec![trust],
    )
    .expect("the policy is well formed")
}
