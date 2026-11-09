//! The types an agent uses to bootstrap without a stored secret.
//!
//! An agent that runs on its own should not hold a long-lived secret. It
//! proves to the platform where it runs, and trades that proof for a
//! short-lived credential.
//!
//! - [`AttestationPolicy`] says which methods and origins an agent trusts.
//! - [`AttestedIdentity`] is what the app layer's `AgentAttestor` port
//!   verified.
//! - [`AttestationRef`] records how a credential was attested, for audit.
//! - [`WorkloadTrust`] says which token issuer and subject prove an agent
//!   that runs on Kubernetes, GitHub Actions or an OIDC issuer.

mod workload;

pub use workload::*;

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::{validate_count, validate_range};
use crate::shared::validation::{Rule, TextValue, ValidationError, Validator, text_value};
use crate::types::Seconds;

/// A way an agent can prove to the platform where it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AttestationMethod {
    /// A SPIFFE or SPIRE SVID, the workload identity used for mTLS.
    Spiffe,
    /// An AWS IAM role, proven by an `sts:GetCallerIdentity` request the
    /// workload signed with the role's credentials and AWS answered.
    AwsIam,
    /// A GCP instance identity JWT.
    GcpInstanceIdentity,
    /// A TPM or PKCS#11 hardware attestation, for machines on site.
    Tpm,
    /// A Kubernetes service account token from the cluster's issuer.
    KubernetesServiceAccount,
    /// A GitHub Actions OIDC token naming the repository and ref.
    GithubActions,
    /// A token from an OIDC issuer the tenant trusts.
    OidcToken,
    /// An Azure managed identity, which no policy may trust.
    ///
    /// Its tokens are only for an audience registered in Entra ID, its App
    /// ID URI or client id, never a value the workload picks per request,
    /// and Azure caches one per audience for about a day. The only signed
    /// document Azure lets a VM put a value of its own in, the attested
    /// document, takes a ten-digit nonce and names the VM, not the
    /// identity. So nothing Azure signs can carry the binding of a
    /// challenge and the key being enrolled, and a token seen in passing
    /// would enrol anyone's key. The method is kept so it is refused by
    /// name; see [`AttestationPolicy::with_workloads`].
    AzureManagedIdentity,
}

impl AttestationMethod {
    /// The prefix of every origin this method vouches for, or `None` for a
    /// method that proves a workload with a token.
    ///
    /// An origin counts only for the method its prefix names. A subject a TPM
    /// vouched for is not an AWS account, even if its name reads like one. A
    /// token method is trusted only through a [`WorkloadTrust`] naming its
    /// issuer and subject, never through an origin.
    #[must_use]
    pub fn origin_scheme(self) -> Option<&'static str> {
        match self {
            Self::Spiffe => Some("spiffe://"),
            Self::AwsIam => Some("aws:"),
            Self::GcpInstanceIdentity => Some("gcp:"),
            Self::Tpm => Some("tpm:"),
            Self::KubernetesServiceAccount
            | Self::GithubActions
            | Self::OidcToken
            | Self::AzureManagedIdentity => None,
        }
    }

    /// The kind of workload token this method proves an agent with, or
    /// `None` for a method a platform vouches with. An Azure managed
    /// identity is neither: no policy trusts it and no attestor checks it.
    #[must_use]
    pub fn workload_kind(self) -> Option<WorkloadKind> {
        match self {
            Self::KubernetesServiceAccount => Some(WorkloadKind::Kubernetes),
            Self::GithubActions => Some(WorkloadKind::GithubActions),
            Self::OidcToken => Some(WorkloadKind::Oidc),
            Self::Spiffe
            | Self::AwsIam
            | Self::GcpInstanceIdentity
            | Self::Tpm
            | Self::AzureManagedIdentity => None,
        }
    }
}

/// The most workload trusts one policy may hold.
pub(crate) const MAX_WORKLOAD_TRUSTS: usize = 20;

text_value! {
    /// Where an attested workload may run: a cloud account or project, or a
    /// workload identity.
    ///
    /// A subject is under an origin when it equals the origin, or continues
    /// it after a `:` or `/`. So `aws:123456789012` covers every role in
    /// that account, and `aws:123456789012:role/runner` that one role.
    /// `spiffe://ianua/ns/agents/sa/runner` covers that runner
    /// and nothing beside it. Wildcards are refused.
    pub struct AttestedOrigin;
}

impl TextValue for AttestedOrigin {
    const FIELD: &'static str = "allowed_origin";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_empty()
            .char_length(1..=512)
            .no_control_chars()
            .no_whitespace()
            .rule(&UnderAKnownScheme)
    }
}

impl AttestedOrigin {
    /// The prefixes an origin may start with, one per attestation method.
    const SCHEMES: [&'static str; 4] = ["aws:", "gcp:", "spiffe://", "tpm:"];

    /// Whether `subject` runs under this origin.
    #[must_use]
    pub fn covers(&self, subject: &str) -> bool {
        let Some(rest) = subject.strip_prefix(&self.0) else {
            return false;
        };
        rest.is_empty() || rest.starts_with(':') || rest.starts_with('/')
    }
}

/// Which attestation methods an agent trusts, where it may run, and how
/// often it must re-attest.
///
/// A credential is issued only after an attestation by a trusted method,
/// from an allowed origin. The agent must re-attest at least every
/// [`reattest_interval_seconds`](Self::reattest_interval_seconds).
///
/// A trusted method alone is not enough. Any VM or role in any cloud
/// account can show a valid platform identity. So the policy also names the accounts,
/// projects or workloads it trusts: origins for the methods a platform
/// vouches for, and [`WorkloadTrust`] entries for the methods that prove a
/// workload with a token.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "AttestationPolicyWire"))]
pub struct AttestationPolicy {
    trusted_methods: Vec<AttestationMethod>,
    reattest_interval_seconds: Seconds,
    allowed_origins: Vec<AttestedOrigin>,
    workload_trusts: Vec<WorkloadTrust>,
}

/// A policy as it arrives, before [`AttestationPolicy::with_workloads`] has
/// checked it.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct AttestationPolicyWire {
    trusted_methods: Vec<AttestationMethod>,
    reattest_interval_seconds: Seconds,
    #[serde(default)]
    allowed_origins: Vec<AttestedOrigin>,
    #[serde(default)]
    workload_trusts: Vec<WorkloadTrust>,
}

#[cfg(feature = "serde")]
impl TryFrom<AttestationPolicyWire> for AttestationPolicy {
    type Error = DomainError;

    /// A stored policy keeps the same rules as one built in code. One that
    /// trusts no method, or names neither an origin nor a workload, cannot
    /// be read back.
    fn try_from(wire: AttestationPolicyWire) -> Result<Self, Self::Error> {
        Self::with_workloads(
            wire.trusted_methods,
            wire.reattest_interval_seconds,
            wire.allowed_origins,
            wire.workload_trusts,
        )
    }
}

impl AttestationPolicy {
    /// Creates a policy trusting `trusted_methods` from `allowed_origins`,
    /// re-attesting every `reattest_interval_seconds`. It trusts no workload
    /// token.
    ///
    /// # Errors
    ///
    /// - The errors of [`with_workloads`](Self::with_workloads), with no
    ///   workload trusts.
    pub fn new(
        trusted_methods: Vec<AttestationMethod>,
        reattest_interval_seconds: Seconds,
        allowed_origins: Vec<AttestedOrigin>,
    ) -> Result<Self, DomainError> {
        Self::with_workloads(
            trusted_methods,
            reattest_interval_seconds,
            allowed_origins,
            Vec::new(),
        )
    }

    /// Creates a policy trusting `trusted_methods` from `allowed_origins`
    /// and the workload tokens `workload_trusts` name, re-attesting every
    /// `reattest_interval_seconds`.
    ///
    /// Each token method trusted needs a trust naming its issuer and
    /// subject, and each trust needs its method trusted. A policy trusting
    /// GitHub Actions with no trust would accept any repository's workflow.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] for no trusted methods, unsupported
    /// `AzureManagedIdentity` key binding, no origin or workload trust, more than
    /// `MAX_WORKLOAD_TRUSTS` trusts, a trusted token method without a matching trust,
    /// a trust whose method is not allowed, or a zero re-attestation interval.
    pub fn with_workloads(
        trusted_methods: Vec<AttestationMethod>,
        reattest_interval_seconds: Seconds,
        allowed_origins: Vec<AttestedOrigin>,
        workload_trusts: Vec<WorkloadTrust>,
    ) -> Result<Self, DomainError> {
        validate_count("trusted_methods", trusted_methods.len(), 1..=usize::MAX)?;
        ensure_bindable(&trusted_methods)?;
        validate_count(
            "allowed_origins",
            allowed_origins.len().saturating_add(workload_trusts.len()),
            1..=usize::MAX,
        )?;
        validate_count(
            "workload_trusts",
            workload_trusts.len(),
            0..=MAX_WORKLOAD_TRUSTS,
        )?;
        ensure_trusts_match_methods(&trusted_methods, &workload_trusts)?;
        validate_range(
            "reattest_interval_seconds",
            reattest_interval_seconds.get(),
            1..=u32::MAX,
        )?;
        Ok(Self {
            trusted_methods,
            reattest_interval_seconds,
            allowed_origins,
            workload_trusts,
        })
    }

    /// The issuers and subjects whose tokens prove the agent.
    #[must_use]
    pub fn workload_trusts(&self) -> &[WorkloadTrust] {
        &self.workload_trusts
    }

    /// Whether a trust of this policy accepts `token`, whose method the
    /// policy trusts.
    #[must_use]
    pub fn accepts_token(&self, token: &WorkloadToken) -> bool {
        self.permits(token.kind().method())
            && self
                .workload_trusts
                .iter()
                .any(|trust| trust.accepts(token))
    }

    /// The trusted attestation methods.
    #[must_use]
    pub fn trusted_methods(&self) -> &[AttestationMethod] {
        &self.trusted_methods
    }

    /// The longest time allowed between two attestations, in seconds.
    #[must_use]
    pub fn reattest_interval_seconds(&self) -> Seconds {
        self.reattest_interval_seconds
    }

    /// The accounts, projects or workloads an attested subject must run under.
    #[must_use]
    pub fn allowed_origins(&self) -> &[AttestedOrigin] {
        &self.allowed_origins
    }

    /// Whether `method` is in the trusted list. Any method not listed is
    /// refused.
    #[must_use]
    pub fn permits(&self, method: AttestationMethod) -> bool {
        self.trusted_methods.contains(&method)
    }

    /// Whether `subject`, vouched for by `method`, runs under an allowed
    /// origin of that method's scheme.
    #[must_use]
    pub fn allows_origin(&self, method: AttestationMethod, subject: &str) -> bool {
        let Some(scheme) = method.origin_scheme() else {
            return false;
        };
        self.allowed_origins
            .iter()
            .filter(|o| o.as_str().starts_with(scheme))
            .any(|o| o.covers(subject))
    }

    /// Whether this policy trusts `subject` as vouched for by `method`.
    ///
    /// The method must be trusted. A subject a platform vouched for must
    /// run under an allowed origin. A subject bound to a workload token must
    /// name the issuer and subject of one of the policy's trusts for that
    /// method. This is the rule for the record a credential was issued
    /// against, and for a fresh token, see
    /// [`AttestedIdentity::is_trusted_by`].
    #[must_use]
    pub fn trusts(&self, method: AttestationMethod, subject: &AttestedSubject) -> bool {
        self.permits(method)
            && (self.allows_origin(method, subject.as_str()) || self.binds(method, subject))
    }

    /// Whether a trust for `method` names the issuer and subject `bound`
    /// records.
    fn binds(&self, method: AttestationMethod, bound: &AttestedSubject) -> bool {
        self.workload_trusts
            .iter()
            .any(|trust| trust.kind().method() == method && trust.binds(bound))
    }
}

/// Refuses a policy trusting Azure managed identities, which cannot bind
/// what they sign to the key a bootstrap enrols.
fn ensure_bindable(methods: &[AttestationMethod]) -> Result<(), DomainError> {
    if !methods.contains(&AttestationMethod::AzureManagedIdentity) {
        return Ok(());
    }
    Err(DomainError::invalid(message!(
        "agents-an-azure-managed-identity-cannot-attest",
        "an Azure managed identity cannot attest: its tokens are only for audiences registered \
         in Entra ID, so they cannot carry the binding of the challenge and the enrolled key"
    )))
}

/// Refuses a token method trusted with no trust naming its workloads, and
/// a trust whose method is not trusted.
fn ensure_trusts_match_methods(
    methods: &[AttestationMethod],
    trusts: &[WorkloadTrust],
) -> Result<(), DomainError> {
    let unbacked = methods.iter().any(|method| {
        method.origin_scheme().is_none()
            && !trusts.iter().any(|trust| trust.kind().method() == *method)
    });
    let untrusted = trusts
        .iter()
        .any(|trust| !methods.contains(&trust.kind().method()));
    if unbacked || untrusted {
        return Err(DomainError::invalid(message!(
            "agents-each-token-method-needs-a-workload",
            "each token method needs a workload trust, and each workload trust its method"
        )));
    }
    Ok(())
}

/// An identity the `AgentAttestor` port verified with the platform.
///
/// It is not yet tied to an [`AgentId`](crate::types::AgentId) or traded for
/// a credential. [`AttestationRef`] is the audit record kept on the issued
/// credential.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "AttestedIdentityWire"))]
pub struct AttestedIdentity {
    method: AttestationMethod,
    subject: AttestedSubject,
    voucher: Voucher,
}

/// Who vouched for an attested identity.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Voucher {
    /// The platform it runs on, such as SPIRE, a cloud's instance identity
    /// or a TPM.
    #[default]
    Platform,
    /// A workload token, with the claims the attestor verified.
    Token(WorkloadToken),
}

/// An attestation as it arrives, before [`AttestedIdentity::new`] or
/// [`AttestationRef::new`] has checked its subject.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct AttestationWire {
    method: AttestationMethod,
    subject: AttestedSubject,
}

/// An attested identity as it arrives, before [`AttestedIdentity::new`] or
/// [`AttestedIdentity::from_token`] has checked it.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct AttestedIdentityWire {
    method: AttestationMethod,
    subject: AttestedSubject,
    #[serde(default)]
    voucher: Voucher,
}

#[cfg(feature = "serde")]
impl TryFrom<AttestedIdentityWire> for AttestedIdentity {
    type Error = DomainError;

    /// A transported identity is rebuilt the way the attestor built it, so
    /// a token's subject is always the one its claims bind.
    fn try_from(wire: AttestedIdentityWire) -> Result<Self, Self::Error> {
        match wire.voucher {
            Voucher::Platform => Ok(Self::new(wire.method, wire.subject)),
            Voucher::Token(token) => Self::from_token(token),
        }
    }
}

impl AttestedIdentity {
    /// Records a successful verification of `subject` via `method`, vouched
    /// for by the platform the workload runs on.
    #[must_use]
    pub fn new(method: AttestationMethod, subject: AttestedSubject) -> Self {
        Self {
            method,
            subject,
            voucher: Voucher::Platform,
        }
    }

    /// Records a workload token the verifier checked: its signature
    /// against the issuer's keys, its pinned algorithm, its expiry,
    /// not-before and issue time, and its audience, the binding of the
    /// bootstrap's challenge and the key it enrols.
    ///
    /// Its subject is the token's issuer and subject together. A credential
    /// issued against it records that, so it can be checked against the
    /// policy again later.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the issuer and subject together
    ///   are too long for an attested subject.
    pub fn from_token(token: WorkloadToken) -> Result<Self, DomainError> {
        Ok(Self {
            method: token.kind().method(),
            subject: token.bound_subject()?,
            voucher: Voucher::Token(token),
        })
    }

    /// The verified attestation method.
    #[must_use]
    pub fn method(&self) -> AttestationMethod {
        self.method
    }

    /// The verified identity, such as a SPIFFE ID, an instance id, or a
    /// token's issuer and subject.
    #[must_use]
    pub fn subject(&self) -> &AttestedSubject {
        &self.subject
    }

    /// Who vouched for it.
    #[must_use]
    pub fn voucher(&self) -> &Voucher {
        &self.voucher
    }

    /// Whether an agent's [`AttestationPolicy`] trusts this attestation.
    ///
    /// A platform's word counts only for a method a platform vouches with.
    /// A token counts only when a trust of the policy accepts its issuer
    /// and subject. An identity claiming a token method without
    /// the token's claims is never trusted.
    #[must_use]
    pub fn is_trusted_by(&self, policy: &AttestationPolicy) -> bool {
        match &self.voucher {
            Voucher::Platform => {
                self.method.origin_scheme().is_some() && policy.trusts(self.method, &self.subject)
            }
            Voucher::Token(token) => policy.accepts_token(token),
        }
    }
}

/// A record of the attestation a credential was issued against, kept for audit.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "AttestationWire"))]
pub struct AttestationRef {
    method: AttestationMethod,
    subject: AttestedSubject,
}

#[cfg(feature = "serde")]
impl From<AttestationWire> for AttestationRef {
    /// A stored audit record keeps the same subject rules as one written
    /// when the credential was issued.
    fn from(wire: AttestationWire) -> Self {
        Self::new(wire.method, wire.subject)
    }
}

impl AttestationRef {
    /// Records an attestation of `subject`, such as a SPIFFE ID or an
    /// instance id.
    #[must_use]
    pub fn new(method: AttestationMethod, subject: AttestedSubject) -> Self {
        Self { method, subject }
    }

    /// The attestation method.
    #[must_use]
    pub fn method(&self) -> AttestationMethod {
        self.method
    }

    /// The attested identity, such as a SPIFFE ID or an instance id.
    #[must_use]
    pub fn subject(&self) -> &AttestedSubject {
        &self.subject
    }
}

/// Checks that an origin names an account, project or workload under one of
/// the known prefixes, with no wildcard.
struct UnderAKnownScheme;

impl Rule for UnderAKnownScheme {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let named = AttestedOrigin::SCHEMES
            .iter()
            .find_map(|scheme| value.strip_prefix(scheme))
            .is_some_and(|rest| !rest.is_empty());
        if named && !value.contains('*') {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "invalid_origin".to_owned(),
            message: message!(
                "agents-an-allowed-origin-names-an-account",
                "an allowed origin names an account, project or workload, like aws:<account>, \
                      gcp:<project> or spiffe://<trust domain>/<path>, without wildcards"
            ),
        })
    }
}

text_value! {
    /// Who an attestation names, such as an instance, a service account or a
    /// workload identity. It is written the way the attestation method
    /// writes it.
    pub struct AttestedSubject;
}

impl TextValue for AttestedSubject {
    const FIELD: &'static str = "subject";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.not_empty().char_length(1..=512).no_control_chars()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Seconds;

    /// A policy trusting AWS IAM and TPM accepts an allowed AWS subject
    /// through AWS IAM but refuses the same subject through TPM.
    #[test]
    fn an_origin_counts_only_for_its_own_method() {
        let policy = AttestationPolicy::new(
            vec![AttestationMethod::Tpm, AttestationMethod::AwsIam],
            Seconds::new(3600),
            vec![AttestedOrigin::new("aws:111122223333").unwrap()],
        )
        .unwrap();

        assert!(policy.allows_origin(AttestationMethod::AwsIam, "aws:111122223333:role/agent"));
        assert!(!policy.allows_origin(AttestationMethod::Tpm, "aws:111122223333:role/agent"));
    }

    /// A policy that trusts TPM origin `tpm:aik:ab12` accepts a TPM subject
    /// with that exact name.
    #[test]
    fn a_tpm_origin_covers_a_tpm_subject() {
        let policy = AttestationPolicy::new(
            vec![AttestationMethod::Tpm],
            Seconds::new(3600),
            vec![AttestedOrigin::new("tpm:aik:ab12").unwrap()],
        )
        .unwrap();

        assert!(policy.allows_origin(AttestationMethod::Tpm, "tpm:aik:ab12"));
    }

    fn origins() -> Vec<AttestedOrigin> {
        vec![AttestedOrigin::new("spiffe://ianua/ns/agents/sa/runner").unwrap()]
    }

    /// A policy trusting SPIFFE but naming no origin is refused. Any workload
    /// anywhere could otherwise pass.
    #[test]
    fn a_policy_must_name_the_origins_it_trusts() {
        let result =
            AttestationPolicy::new(vec![AttestationMethod::Spiffe], Seconds::new(3600), vec![]);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// An empty origin, a bare `aws:`, a number with no prefix, wildcards and
    /// an `http` URL are refused. An AWS account, a GCP project and a SPIFFE
    /// path are accepted.
    #[test]
    fn an_origin_names_an_account_project_or_workload_without_wildcards() {
        for bad in [
            "",
            "aws:",
            "123456789012",
            "aws:*",
            "spiffe://ianua/ns/*",
            "http://x",
        ] {
            assert!(AttestedOrigin::new(bad).is_err(), "{bad}");
        }
        for good in [
            "aws:123456789012",
            "gcp:my-project",
            "spiffe://ianua/ns/agents",
        ] {
            assert!(AttestedOrigin::new(good).is_ok(), "{good}");
        }
    }

    /// An AWS origin covers its exact account and a role beneath it,
    /// but refuses an account with extra digits or the same digits under GCP.
    #[test]
    fn an_origin_covers_its_subjects_only_on_a_boundary() {
        let account = AttestedOrigin::new("aws:123456789012").unwrap();

        assert!(account.covers("aws:123456789012:role/runner"));
        assert!(account.covers("aws:123456789012"));
        assert!(!account.covers("aws:1234567890123:role/runner"));
        assert!(!account.covers("gcp:123456789012"));
    }

    /// A policy trusting AWS IAM accepts a role in its listed account
    /// and refuses a role in another account using the same method.
    #[test]
    fn a_trusted_method_from_an_unlisted_account_is_not_trusted() {
        let policy = AttestationPolicy::new(
            vec![AttestationMethod::AwsIam],
            Seconds::new(3600),
            vec![AttestedOrigin::new("aws:111111111111").unwrap()],
        )
        .unwrap();
        let ours = AttestedIdentity::new(
            AttestationMethod::AwsIam,
            AttestedSubject::new("aws:111111111111:role/agent").unwrap(),
        );
        let theirs = AttestedIdentity::new(
            AttestationMethod::AwsIam,
            AttestedSubject::new("aws:999999999999:role/agent").unwrap(),
        );

        assert!(ours.is_trusted_by(&policy));
        assert!(!theirs.is_trusted_by(&policy));
    }

    /// An empty attested subject is refused.
    #[test]
    fn rejects_empty_subject() {
        assert!(AttestedSubject::new("").is_err());
    }

    /// An audit record of an AWS attestation of `role/agent` reads back
    /// that method and subject.
    #[test]
    fn records_method_and_subject() {
        let attestation = AttestationRef::new(
            AttestationMethod::AwsIam,
            AttestedSubject::new("aws:111122223333:role/agent").unwrap(),
        );
        assert_eq!(attestation.method(), AttestationMethod::AwsIam);
        assert_eq!(
            attestation.subject().as_str(),
            "aws:111122223333:role/agent"
        );
    }

    /// A policy with no trusted method is refused. So is one that asks for
    /// re-attestation every zero seconds.
    #[test]
    fn policy_rejects_empty_or_zero_interval() {
        assert!(AttestationPolicy::new(vec![], Seconds::new(3600), origins()).is_err());
        assert!(
            AttestationPolicy::new(vec![AttestationMethod::Spiffe], Seconds::new(0), origins())
                .is_err()
        );
    }

    /// A policy trusting only SPIFFE permits SPIFFE and refuses TPM. It reads
    /// back its hourly interval.
    #[test]
    fn policy_permits_only_trusted_methods() {
        let policy = AttestationPolicy::new(
            vec![AttestationMethod::Spiffe],
            Seconds::new(3600),
            origins(),
        )
        .unwrap();
        assert!(policy.permits(AttestationMethod::Spiffe));
        assert!(!policy.permits(AttestationMethod::Tpm));
        assert_eq!(policy.reattest_interval_seconds(), Seconds::new(3600));
    }

    /// A SPIFFE identity for the listed runner is trusted. A TPM identity is
    /// not, since the policy does not trust TPM.
    #[test]
    fn attested_identity_checks_against_policy() {
        let policy = AttestationPolicy::new(
            vec![AttestationMethod::Spiffe],
            Seconds::new(3600),
            origins(),
        )
        .unwrap();
        let trusted = AttestedIdentity::new(
            AttestationMethod::Spiffe,
            AttestedSubject::new("spiffe://ianua/ns/agents/sa/runner").unwrap(),
        );
        let untrusted = AttestedIdentity::new(
            AttestationMethod::Tpm,
            AttestedSubject::new("tpm://y").unwrap(),
        );
        assert!(trusted.is_trusted_by(&policy));
        assert!(!untrusted.is_trusted_by(&policy));
        assert!(AttestedSubject::new("").is_err());
    }

    /// A policy trusting SPIFFE and AWS reads back both methods in order and
    /// refuses TPM. An identity reads back its method and subject as given.
    #[test]
    fn a_policy_reports_its_trusted_methods_and_an_identity_its_subject() {
        let policy = AttestationPolicy::new(
            vec![AttestationMethod::Spiffe, AttestationMethod::AwsIam],
            Seconds::new(3600),
            origins(),
        )
        .unwrap();

        assert_eq!(
            policy.trusted_methods(),
            [AttestationMethod::Spiffe, AttestationMethod::AwsIam]
        );
        assert!(policy.permits(AttestationMethod::AwsIam));
        assert!(!policy.permits(AttestationMethod::Tpm));

        let identity = AttestedIdentity::new(
            AttestationMethod::Spiffe,
            AttestedSubject::new("spiffe://cluster/ns/sa").unwrap(),
        );
        assert_eq!(identity.subject().as_str(), "spiffe://cluster/ns/sa");
        assert_eq!(identity.method(), AttestationMethod::Spiffe);
    }

    /// Storage and transport are not trusted. A value that never passed the
    /// constructor must not become valid by being read back.
    #[cfg(feature = "serde")]
    mod serde_goes_through_the_constructor {
        use super::*;

        /// A stored policy with no `allowed_origins` field fails to read. The
        /// field defaults to empty, and an empty list is refused.
        #[cfg(feature = "serde")]
        #[test]
        fn a_stored_policy_naming_no_origin_is_refused() {
            let json = r#"{"trusted_methods":["Spiffe"],"reattest_interval_seconds":3600}"#;

            assert!(serde_json::from_str::<AttestationPolicy>(json).is_err());
        }

        /// A stored policy with an empty method list fails to read.
        #[cfg(feature = "serde")]
        #[test]
        fn a_stored_policy_trusting_no_method_is_refused() {
            let json = r#"{"trusted_methods":[],"reattest_interval_seconds":3600,"allowed_origins":["aws:111122223333"]}"#;

            assert!(serde_json::from_str::<AttestationPolicy>(json).is_err());
        }

        /// A valid policy written to JSON reads back equal.
        #[cfg(feature = "serde")]
        #[test]
        fn a_policy_reads_back_what_it_writes() {
            let policy = AttestationPolicy::new(
                vec![AttestationMethod::Spiffe],
                Seconds::new(3600),
                origins(),
            )
            .unwrap();

            let json = serde_json::to_string(&policy).unwrap();

            assert_eq!(
                serde_json::from_str::<AttestationPolicy>(&json).unwrap(),
                policy
            );
        }

        /// A transported identity with an empty subject fails to read.
        #[cfg(feature = "serde")]
        #[test]
        fn a_transported_identity_with_an_empty_subject_is_refused() {
            let json = r#"{"method":"Spiffe","subject":""}"#;

            assert!(serde_json::from_str::<AttestedIdentity>(json).is_err());
        }

        /// A valid identity written to JSON reads back equal.
        #[cfg(feature = "serde")]
        #[test]
        fn an_identity_reads_back_what_it_writes() {
            let identity = AttestedIdentity::new(
                AttestationMethod::Spiffe,
                AttestedSubject::new("spiffe://ianua/ns/a").unwrap(),
            );

            let json = serde_json::to_string(&identity).unwrap();

            assert_eq!(
                serde_json::from_str::<AttestedIdentity>(&json).unwrap(),
                identity
            );
        }

        /// A stored audit record whose subject holds a bell character fails to
        /// read.
        #[cfg(feature = "serde")]
        #[test]
        fn a_stored_attestation_record_with_a_control_character_is_refused() {
            let json = r#"{"method":"Tpm","subject":"tpm:aik\u0007"}"#;

            assert!(serde_json::from_str::<AttestationRef>(json).is_err());
        }

        /// A valid audit record written to JSON reads back equal.
        #[cfg(feature = "serde")]
        #[test]
        fn an_attestation_record_reads_back_what_it_writes() {
            let record = AttestationRef::new(
                AttestationMethod::Tpm,
                AttestedSubject::new("tpm:aik:ab12").unwrap(),
            );

            let json = serde_json::to_string(&record).unwrap();

            assert_eq!(
                serde_json::from_str::<AttestationRef>(&json).unwrap(),
                record
            );
        }
    }

    /// An AWS role subject and a SPIFFE ID are both accepted as subjects.
    #[test]
    fn a_well_formed_attested_subject_is_accepted() {
        for value in [
            "aws:123456789012:role/agent",
            "spiffe://ianua/ns/agents/sa/runner",
        ] {
            assert!(AttestedSubject::new(value).is_ok(), "{value:?} was refused");
        }
    }

    /// An empty subject and one holding a newline are refused.
    #[test]
    fn a_malformed_attested_subject_is_refused() {
        for value in ["", "a\nb"] {
            assert!(
                AttestedSubject::new(value).is_err(),
                "{value:?} was accepted"
            );
        }
    }

    /// Ann's trust for the runner service account in her cluster.
    fn runner_trust() -> WorkloadTrust {
        WorkloadTrust::new(
            WorkloadKind::Kubernetes,
            WorkloadIssuer::new("https://oidc.cluster.example").unwrap(),
            WorkloadSubject::new("system:serviceaccount:agents:runner").unwrap(),
        )
        .unwrap()
    }

    /// A token from Ann's cluster naming `subject`.
    fn cluster_token(subject: &str) -> AttestedIdentity {
        AttestedIdentity::from_token(
            WorkloadToken::new(
                WorkloadKind::Kubernetes,
                WorkloadIssuer::new("https://oidc.cluster.example").unwrap(),
                WorkloadSubject::new(subject).unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    /// A policy trusting Kubernetes service accounts through Ann's trust.
    fn kubernetes_policy() -> AttestationPolicy {
        AttestationPolicy::with_workloads(
            vec![AttestationMethod::KubernetesServiceAccount],
            Seconds::new(3600),
            Vec::new(),
            vec![runner_trust()],
        )
        .unwrap()
    }

    /// The runner's token is trusted. So is the record a credential keeps
    /// of it, checked again later.
    #[test]
    fn a_token_a_trust_accepts_is_trusted_and_so_is_its_record() {
        let policy = kubernetes_policy();
        let attested = cluster_token("system:serviceaccount:agents:runner");

        assert!(attested.is_trusted_by(&policy));
        assert!(policy.trusts(attested.method(), attested.subject()));
    }

    /// A token for another service account is refused even when it comes
    /// from the cluster named by the policy's workload trust.
    #[test]
    fn a_token_for_another_service_account_is_not_trusted() {
        let attested = cluster_token("system:serviceaccount:agents:mallory");

        assert!(!attested.is_trusted_by(&kubernetes_policy()));
    }

    /// A policy that includes Azure managed identities is refused even
    /// alongside SPIFFE, since Azure cannot bind the bootstrap challenge and key.
    #[test]
    fn a_policy_trusting_azure_managed_identities_is_refused() {
        let policy = AttestationPolicy::with_workloads(
            vec![
                AttestationMethod::AzureManagedIdentity,
                AttestationMethod::Spiffe,
            ],
            Seconds::new(3600),
            origins(),
            Vec::new(),
        );

        assert!(matches!(policy, Err(DomainError::Validation(_))));
    }

    /// A Kubernetes identity presented without token claims is refused,
    /// even when its bound subject matches the policy's trusted workload.
    #[test]
    fn a_token_method_without_its_claims_is_never_trusted() {
        let policy = kubernetes_policy();
        let bound = cluster_token("system:serviceaccount:agents:runner")
            .subject()
            .clone();

        let bare = AttestedIdentity::new(AttestationMethod::KubernetesServiceAccount, bound);

        assert!(!bare.is_trusted_by(&policy));
    }

    /// A policy trusting GitHub Actions with no trust naming a repository
    /// is refused: it would accept every workflow. So is a trust whose
    /// method the policy does not trust.
    #[test]
    fn token_methods_and_trusts_come_together() {
        let no_trust = AttestationPolicy::with_workloads(
            vec![AttestationMethod::GithubActions, AttestationMethod::Spiffe],
            Seconds::new(3600),
            origins(),
            Vec::new(),
        );
        let untrusted_method = AttestationPolicy::with_workloads(
            vec![AttestationMethod::Spiffe],
            Seconds::new(3600),
            origins(),
            vec![runner_trust()],
        );

        assert!(matches!(no_trust, Err(DomainError::Validation(_))));
        assert!(matches!(untrusted_method, Err(DomainError::Validation(_))));
    }

    /// An allowed AWS origin does not cover an OIDC token method, even
    /// when the subject names a role beneath that AWS account.
    #[test]
    fn an_origin_never_covers_a_token_method() {
        let policy = AttestationPolicy::new(
            vec![AttestationMethod::AwsIam],
            Seconds::new(3600),
            vec![AttestedOrigin::new("aws:111122223333").unwrap()],
        )
        .unwrap();

        assert!(!policy.allows_origin(AttestationMethod::OidcToken, "aws:111122223333:role/a"));
    }

    /// A policy over twenty-one trusts is refused.
    #[test]
    fn a_policy_holds_at_most_twenty_workload_trusts() {
        let policy = AttestationPolicy::with_workloads(
            vec![AttestationMethod::KubernetesServiceAccount],
            Seconds::new(3600),
            Vec::new(),
            vec![runner_trust(); MAX_WORKLOAD_TRUSTS + 1],
        );

        assert!(matches!(policy, Err(DomainError::Validation(_))));
    }
}
