//! An agent's attestation trust policy on the wire: which platform
//! attestations and workload tokens it accepts, from where, and how often
//! it must re-attest.

use ianua_app::input::FieldUpdate;
use ianua_domain::domains::agents::identity::attestation::{
    AttestationMethod, AttestationPolicy, AttestedOrigin, WorkloadIssuer, WorkloadSubject,
    WorkloadTrust,
};
use ianua_domain::message;
use ianua_domain::types::Seconds;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// The policy fields given without a policy to belong to.
const PARTS_NEED_A_POLICY: &str = "allowed_origins and workload_trusts are given only with \
     trusted_methods and re_attest_every";

/// The wire names a method is accepted under, for error messages.
const METHODS: &str = "spiffe, aws, gcp, tpm, kubernetes, github_actions, oidc, azure";

/// An attestation method's wire name.
#[must_use]
pub fn method_name(method: AttestationMethod) -> &'static str {
    match method {
        AttestationMethod::Spiffe => "spiffe",
        AttestationMethod::AwsIam => "aws",
        AttestationMethod::GcpInstanceIdentity => "gcp",
        AttestationMethod::Tpm => "tpm",
        AttestationMethod::KubernetesServiceAccount => "kubernetes",
        AttestationMethod::GithubActions => "github_actions",
        AttestationMethod::OidcToken => "oidc",
        AttestationMethod::AzureManagedIdentity => "azure",
    }
}

/// The attestation method a wire name names, in any case.
///
/// # Errors
///
/// - A validation error naming the value when it names no method.
pub(crate) fn method_named(value: &str) -> Result<AttestationMethod, ApiError> {
    match value.to_ascii_lowercase().as_str() {
        "spiffe" => Ok(AttestationMethod::Spiffe),
        "aws" | "aws_iam" => Ok(AttestationMethod::AwsIam),
        "gcp" | "gcp_instance_identity" => Ok(AttestationMethod::GcpInstanceIdentity),
        "tpm" => Ok(AttestationMethod::Tpm),
        "kubernetes" | "kubernetes_service_account" => {
            Ok(AttestationMethod::KubernetesServiceAccount)
        }
        "github_actions" => Ok(AttestationMethod::GithubActions),
        "oidc" | "oidc_token" => Ok(AttestationMethod::OidcToken),
        "azure" | "azure_managed_identity" => Ok(AttestationMethod::AzureManagedIdentity),
        _ => Err(ApiError::validation(message!(
            "api-unknown-attestation-method-expected-one-of",
            format!("unknown attestation method: {value} (expected one of: {METHODS})")
        ))),
    }
}

/// One issuer and subject whose workload token proves the agent: a
/// federated credential, each part matched exactly. The token's audience
/// is not set here: it must be the binding of the bootstrap's challenge
/// and the key it enrols, which the workload asks its platform for.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkloadTrustDto {
    /// The token method: `kubernetes`, `github_actions` or `oidc`.
    pub method: String,
    /// The token's issuer (`iss`), an `https` URL, such as
    /// `https://token.actions.githubusercontent.com`.
    pub issuer: String,
    /// The workload the token must name (`sub`), such as
    /// `repo:corp/reports:ref:refs/heads/main` or
    /// `system:serviceaccount:agents:runner`.
    pub subject: String,
}

impl WorkloadTrustDto {
    /// The trust named.
    ///
    /// # Errors
    ///
    /// - A validation error for a method that proves no workload with a
    ///   token, or an issuer or subject that is not valid or not one that
    ///   method's platform writes.
    pub(crate) fn to_domain(&self) -> Result<WorkloadTrust, ApiError> {
        let method = method_named(&self.method)?;
        let kind = method.workload_kind().ok_or_else(|| {
            ApiError::validation(message!(
                "api-proves-no-workload-with-a-token",
                format!("{} proves no workload with a token", self.method)
            ))
        })?;
        WorkloadTrust::new(
            kind,
            WorkloadIssuer::new(self.issuer.as_str()).map_err(ApiError::validation)?,
            WorkloadSubject::new(self.subject.as_str()).map_err(ApiError::validation)?,
        )
        .map_err(ApiError::validation)
    }
}

impl From<&WorkloadTrust> for WorkloadTrustDto {
    fn from(trust: &WorkloadTrust) -> Self {
        Self {
            method: method_name(trust.kind().method()).to_owned(),
            issuer: trust.issuer().as_str().to_owned(),
            subject: trust.subject().as_str().to_owned(),
        }
    }
}

/// What a policy trusts beyond its methods and interval: the origins a
/// platform vouches for, and the workload tokens that prove the agent.
#[derive(Default)]
pub(crate) struct TrustedSources<'a> {
    /// The accounts, projects or workloads a platform vouches for.
    pub origins: &'a [String],
    /// The issuers and subjects whose tokens prove the agent.
    pub workloads: &'a [WorkloadTrustDto],
}

/// The policy its wire parts name.
///
/// # Errors
///
/// - A validation error for an unknown method, an invalid origin or trust,
///   no methods, neither an origin nor a trust, a token method without its
///   trust, or a zero interval.
pub(crate) fn policy_of(
    methods: &[String],
    interval: u32,
    sources: &TrustedSources<'_>,
) -> Result<AttestationPolicy, ApiError> {
    let methods = methods
        .iter()
        .map(|method| method_named(method))
        .collect::<Result<Vec<_>, _>>()?;
    let origins = sources
        .origins
        .iter()
        .map(|origin| AttestedOrigin::new(origin.as_str()).map_err(ApiError::validation))
        .collect::<Result<Vec<_>, _>>()?;
    let workloads = sources
        .workloads
        .iter()
        .map(WorkloadTrustDto::to_domain)
        .collect::<Result<Vec<_>, _>>()?;
    AttestationPolicy::with_workloads(methods, Seconds::new(interval), origins, workloads)
        .map_err(ApiError::validation)
}

/// The policy a create request's paired fields name, if any.
///
/// # Errors
///
/// - A validation error when only one of `trusted_methods` and
///   `re_attest_every` is given, origins or trusts come without a policy,
///   or the policy is invalid.
pub(crate) fn policy_from_fields(
    trusted_methods: Option<&[String]>,
    re_attest_every: Option<u32>,
    sources: Option<TrustedSources<'_>>,
) -> Result<Option<AttestationPolicy>, ApiError> {
    match (trusted_methods, re_attest_every) {
        (None, None) if sources.is_some() => Err(ApiError::validation(message!(
            "api-allowed-origins-and-workload-trusts-are",
            PARTS_NEED_A_POLICY
        ))),
        (None, None) => Ok(None),
        (Some(methods), Some(interval)) => {
            policy_of(methods, interval, &sources.unwrap_or_default()).map(Some)
        }
        _ => Err(ApiError::validation(message!(
            "api-trusted-methods-and-re-attest-every-2",
            "trusted_methods and re_attest_every must be given together"
        ))),
    }
}

/// What an update request's paired, clearable fields ask of the policy.
///
/// The two fields name one policy together, so they agree on what they
/// ask: both absent keeps it, both `null` clears it, both given replaces
/// it.
///
/// # Errors
///
/// - A validation error when the two fields disagree, origins or trusts
///   come without a policy, or the policy is invalid.
pub(crate) fn policy_update_from_fields(
    trusted_methods: Option<Option<Vec<String>>>,
    re_attest_every: Option<Option<u32>>,
    sources: Option<TrustedSources<'_>>,
) -> Result<FieldUpdate<AttestationPolicy>, ApiError> {
    match (trusted_methods, re_attest_every) {
        (Some(Some(methods)), Some(Some(interval))) => {
            policy_of(&methods, interval, &sources.unwrap_or_default()).map(FieldUpdate::Set)
        }
        _ if sources.is_some() => Err(ApiError::validation(message!(
            "api-allowed-origins-and-workload-trusts-are",
            PARTS_NEED_A_POLICY
        ))),
        (None, None) => Ok(FieldUpdate::Keep),
        (Some(None), Some(None)) => Ok(FieldUpdate::Clear),
        _ => Err(ApiError::validation(message!(
            "api-trusted-methods-and-re-attest-every",
            "trusted_methods and re_attest_every must both be omitted, both null, or both given"
        ))),
    }
}

/// The trusted sources a body's optional lists name, or `None` when it
/// names neither.
#[must_use]
pub(crate) fn sources_of<'a>(
    origins: Option<&'a [String]>,
    workloads: Option<&'a [WorkloadTrustDto]>,
) -> Option<TrustedSources<'a>> {
    if origins.is_none() && workloads.is_none() {
        return None;
    }
    Some(TrustedSources {
        origins: origins.unwrap_or_default(),
        workloads: workloads.unwrap_or_default(),
    })
}

/// An agent's attestation trust policy.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct AttestationPolicyResponse {
    /// Trusted attestation methods (`spiffe`, `aws`, `gcp`, `tpm`,
    /// `kubernetes`, `github_actions`, `oidc`).
    pub methods: Vec<String>,
    /// Maximum interval between re-attestations, in seconds.
    pub reattest_interval_seconds: u32,
    /// The accounts, projects or workloads the agent may attest from.
    pub allowed_origins: Vec<String>,
    /// The workload tokens that prove the agent, for the token methods.
    pub workload_trusts: Vec<WorkloadTrustDto>,
}

impl From<&AttestationPolicy> for AttestationPolicyResponse {
    fn from(policy: &AttestationPolicy) -> Self {
        Self {
            methods: method_names(policy),
            reattest_interval_seconds: policy.reattest_interval_seconds().get(),
            allowed_origins: policy
                .allowed_origins()
                .iter()
                .map(|origin| origin.as_str().to_owned())
                .collect(),
            workload_trusts: policy
                .workload_trusts()
                .iter()
                .map(WorkloadTrustDto::from)
                .collect(),
        }
    }
}

/// The wire names of the methods `policy` trusts.
#[must_use]
pub fn method_names(policy: &AttestationPolicy) -> Vec<String> {
    policy
        .trusted_methods()
        .iter()
        .map(|method| method_name(*method).to_owned())
        .collect()
}

/// Request body for configuring an agent's attestation policy.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct SetAttestationPolicyBody {
    /// Trusted attestation methods (`spiffe`, `aws`, `gcp`, `tpm`,
    /// `kubernetes`, `github_actions`, `oidc`). `azure` is refused: an
    /// Azure managed identity cannot bind its token to the enrolled key.
    pub methods: Vec<String>,
    /// Maximum interval between re-attestations, in seconds.
    pub reattest_interval_seconds: u32,
    /// The accounts, projects or workloads a platform vouches for that the
    /// agent may attest from.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// The workload tokens that prove the agent, one for each token method
    /// trusted. Between them, the origins and the trusts name at least one
    /// source: any VM in any account can attest.
    #[serde(default)]
    pub workload_trusts: Vec<WorkloadTrustDto>,
}

impl SetAttestationPolicyBody {
    /// The policy named.
    ///
    /// # Errors
    ///
    /// - A validation error for an unknown method, an invalid origin or
    ///   trust, no methods, no source, or a zero interval.
    pub(crate) fn policy(&self) -> Result<AttestationPolicy, ApiError> {
        policy_of(
            &self.methods,
            self.reattest_interval_seconds,
            &TrustedSources {
                origins: &self.allowed_origins,
                workloads: &self.workload_trusts,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A GitHub Actions trust for the reports repository's main branch.
    fn github_trust() -> WorkloadTrustDto {
        WorkloadTrustDto {
            method: "github_actions".to_owned(),
            issuer: "https://token.actions.githubusercontent.com".to_owned(),
            subject: "repo:corp/reports:ref:refs/heads/main".to_owned(),
        }
    }

    /// Every method's wire name reads back as the same method.
    #[test]
    fn every_method_name_reads_back() {
        for method in [
            AttestationMethod::Spiffe,
            AttestationMethod::AwsIam,
            AttestationMethod::GcpInstanceIdentity,
            AttestationMethod::Tpm,
            AttestationMethod::KubernetesServiceAccount,
            AttestationMethod::GithubActions,
            AttestationMethod::OidcToken,
            AttestationMethod::AzureManagedIdentity,
        ] {
            assert_eq!(method_named(method_name(method)).ok(), Some(method));
        }
    }

    /// A policy trusting GitHub Actions through one repository's workflow
    /// is read, with no origin needed.
    #[test]
    fn a_workload_trust_alone_makes_a_policy() {
        let workloads = [github_trust()];
        let sources = TrustedSources {
            origins: &[],
            workloads: &workloads,
        };

        let policy = policy_of(&["github_actions".to_owned()], 3600, &sources);

        assert!(policy.is_ok_and(|p| p.workload_trusts().len() == 1));
    }

    /// An AWS platform method cannot be converted into a token trust.
    #[test]
    fn a_trust_for_a_platform_method_is_refused() {
        let trust = WorkloadTrustDto {
            method: "aws".to_owned(),
            ..github_trust()
        };

        assert!(trust.to_domain().is_err());
    }

    /// A GitHub Actions trust rejects an issuer outside GitHub.
    #[test]
    fn a_github_trust_with_another_issuer_is_refused() {
        let trust = WorkloadTrustDto {
            issuer: "https://mallory.example".to_owned(),
            ..github_trust()
        };

        assert!(trust.to_domain().is_err());
    }

    /// Azure and SPIFFE token trusts are rejected by the enrollment policy.
    #[test]
    fn a_policy_trusting_azure_is_refused() {
        let policy = policy_of(
            &["azure".to_owned(), "spiffe".to_owned()],
            3600,
            &TrustedSources {
                origins: &["spiffe://ianua/ns/agents".to_owned()],
                workloads: &[],
            },
        );

        assert!(policy.is_err());
    }

    /// The removed audience field causes deserialization to fail.
    #[test]
    fn a_trust_naming_an_audience_is_refused() {
        let body = r#"{"method":"github_actions","issuer":"https://token.actions.githubusercontent.com","audience":"https://ianua.test","subject":"repo:corp/reports:ref:refs/heads/main"}"#;

        assert!(serde_json::from_str::<WorkloadTrustDto>(body).is_err());
    }

    /// Trusts given with no policy to belong to are refused.
    #[test]
    fn trusts_without_a_policy_are_refused() {
        let workloads = [github_trust()];

        let policy = policy_from_fields(None, None, sources_of(None, Some(&workloads)));

        assert!(policy.is_err());
    }
}
