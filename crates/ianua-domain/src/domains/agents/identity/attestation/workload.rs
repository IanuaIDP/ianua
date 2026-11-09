//! Workload identity: an agent proves itself with a token the platform it
//! runs on issued, with no secret of its own.
//!
//! A Kubernetes service account token, a GitHub Actions OIDC token and a
//! token from any OIDC issuer all say who issued them (`iss`), whom they
//! are for (`aud`) and which workload they name (`sub`). The verifier
//! behind the app layer's `WorkloadTokenVerifier` port checks the token's
//! signature against the issuer's published keys, pins the algorithm,
//! checks expiry, not-before and issue time, and holds the audience to the
//! binding of the bootstrap's challenge and the key it enrols. A workload
//! asks its platform for a token made for that binding, so a token seen in
//! passing cannot enrol anyone else's key. The verifier hands the issuer
//! and subject over as a [`WorkloadToken`]. Which issuer and subject prove
//! which agent is decided here, by the agent's [`WorkloadTrust`] entries,
//! each matched exactly.
//!
//! An Azure managed identity cannot attest this way: its tokens are only
//! for an audience registered in Entra ID, never one chosen per request,
//! so they cannot carry the binding. See
//! [`AttestationMethod::AzureManagedIdentity`].

use crate::domains::agents::identity::attestation::{AttestationMethod, AttestedSubject};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::rules::url::{UrlRules, UrlShape};
use crate::shared::validation::{Rule, TextValue, ValidationError, Validator, text_value};

/// The issuer GitHub Actions tokens come from, unless an enterprise chose
/// its own.
const GITHUB_ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// What every Kubernetes service account subject starts with.
const SERVICE_ACCOUNT_PREFIX: &str = "system:serviceaccount:";

/// What every GitHub Actions subject starts with.
const GITHUB_REPOSITORY_PREFIX: &str = "repo:";

/// The kind of platform that issued a workload's token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum WorkloadKind {
    /// A Kubernetes service account token, from the cluster's issuer.
    Kubernetes,
    /// A GitHub Actions OIDC token, naming the repository and ref.
    GithubActions,
    /// A token from any OIDC issuer the tenant trusts.
    Oidc,
}

impl WorkloadKind {
    /// The attestation method a token of this kind is.
    #[must_use]
    pub fn method(self) -> AttestationMethod {
        match self {
            Self::Kubernetes => AttestationMethod::KubernetesServiceAccount,
            Self::GithubActions => AttestationMethod::GithubActions,
            Self::Oidc => AttestationMethod::OidcToken,
        }
    }

    /// The stored name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kubernetes => "kubernetes",
            Self::GithubActions => "github_actions",
            Self::Oidc => "oidc",
        }
    }

    /// Refuses an issuer or subject this kind of platform never writes.
    ///
    /// A GitHub Actions trust names GitHub's own issuer. Without this,
    /// Mallory runs her own OIDC issuer, writes `repo:corp/payroll` as the
    /// subject and passes as the payroll repository's workflow.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the issuer or subject does not
    ///   have this kind's shape.
    fn ensure_fits(
        self,
        issuer: &WorkloadIssuer,
        subject: &WorkloadSubject,
    ) -> Result<(), DomainError> {
        let fits = match self {
            Self::Kubernetes => is_service_account(subject.as_str()),
            Self::GithubActions => {
                is_github_issuer(issuer.as_str())
                    && subject.as_str().starts_with(GITHUB_REPOSITORY_PREFIX)
            }
            Self::Oidc => true,
        };
        if fits {
            return Ok(());
        }
        Err(DomainError::invalid(message!(
            "agents-the-issuer-or-subject-is-not",
            format!(
                "the issuer or subject is not one a {} token carries",
                self.as_str()
            )
        )))
    }
}

text_value! {
    /// Who issued a workload's token, its `iss`: an `https` URL with no
    /// query, fragment or wildcard, compared exactly.
    pub struct WorkloadIssuer;
}

impl TextValue for WorkloadIssuer {
    const FIELD: &'static str = "issuer";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.web_url(ISSUER_URL).rule(&ExactName)
    }
}

/// An issuer is an `https` URL short enough that the issuer and subject
/// together fit in an attested subject.
const ISSUER_URL: UrlRules = UrlRules {
    schemes: &["https"],
    max_len: 200,
    shape: UrlShape::Any,
};

text_value! {
    /// The workload a token names, its `sub`, such as
    /// `system:serviceaccount:agents:runner` or
    /// `repo:corp/reports:ref:refs/heads/main`. It is compared exactly.
    pub struct WorkloadSubject;
}

impl TextValue for WorkloadSubject {
    const FIELD: &'static str = "subject";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_empty()
            .char_length(1..=300)
            .no_control_chars()
            .no_whitespace()
            .rule(&ExactName)
    }
}

/// One issuer and subject a tenant trusts to prove an agent.
///
/// It is a federated credential: a token issued by `issuer`, naming
/// `subject`, made for the binding of the bootstrap's challenge and key,
/// proves the agent this trust belongs to. Both are matched exactly. A
/// trust for one repository's main branch is not a trust for its pull
/// requests.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "WorkloadTrustWire"))]
pub struct WorkloadTrust {
    kind: WorkloadKind,
    issuer: WorkloadIssuer,
    subject: WorkloadSubject,
}

/// A trust as it arrives, before [`WorkloadTrust::new`] has checked it.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct WorkloadTrustWire {
    kind: WorkloadKind,
    issuer: WorkloadIssuer,
    subject: WorkloadSubject,
}

#[cfg(feature = "serde")]
impl TryFrom<WorkloadTrustWire> for WorkloadTrust {
    type Error = DomainError;

    /// A stored trust keeps the same rules as one built in code.
    fn try_from(wire: WorkloadTrustWire) -> Result<Self, Self::Error> {
        Self::new(wire.kind, wire.issuer, wire.subject)
    }
}

impl WorkloadTrust {
    /// Trusts a `kind` token from `issuer` naming `subject`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the issuer or subject does not
    ///   have the shape `kind` writes: GitHub's own issuer, or an
    ///   enterprise's under it, and a `repo:` subject, or a
    ///   `system:serviceaccount:<namespace>:<name>` subject.
    pub fn new(
        kind: WorkloadKind,
        issuer: WorkloadIssuer,
        subject: WorkloadSubject,
    ) -> Result<Self, DomainError> {
        kind.ensure_fits(&issuer, &subject)?;
        Ok(Self {
            kind,
            issuer,
            subject,
        })
    }

    /// The kind of platform it trusts.
    #[must_use]
    pub fn kind(&self) -> WorkloadKind {
        self.kind
    }

    /// The issuer a token must come from.
    #[must_use]
    pub fn issuer(&self) -> &WorkloadIssuer {
        &self.issuer
    }

    /// The workload a token must name.
    #[must_use]
    pub fn subject(&self) -> &WorkloadSubject {
        &self.subject
    }

    /// Whether `token` proves the workload this trust names: the same
    /// kind, issuer and subject.
    #[must_use]
    pub fn accepts(&self, token: &WorkloadToken) -> bool {
        self.kind == token.kind && self.issuer == token.issuer && self.subject == token.subject
    }

    /// Whether `bound`, the attested subject a credential was issued
    /// against, names this trust's issuer and subject.
    #[must_use]
    pub fn binds(&self, bound: &AttestedSubject) -> bool {
        bound.as_str() == binding_text(&self.issuer, &self.subject)
    }
}

/// The claims of a workload token the verifier checked: who issued it and
/// which workload it names. Its audience was the binding of the
/// bootstrap's challenge and key, which the verifier held it to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "WorkloadTokenWire"))]
pub struct WorkloadToken {
    kind: WorkloadKind,
    issuer: WorkloadIssuer,
    subject: WorkloadSubject,
}

/// Token claims as they arrive, before [`WorkloadToken::new`] has checked
/// them.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct WorkloadTokenWire {
    kind: WorkloadKind,
    issuer: WorkloadIssuer,
    subject: WorkloadSubject,
}

#[cfg(feature = "serde")]
impl TryFrom<WorkloadTokenWire> for WorkloadToken {
    type Error = DomainError;

    /// Transported claims keep the same rules as claims the verifier read.
    fn try_from(wire: WorkloadTokenWire) -> Result<Self, Self::Error> {
        Self::new(wire.kind, wire.issuer, wire.subject)
    }
}

impl WorkloadToken {
    /// The claims of a `kind` token from `issuer` naming `subject`, once
    /// its signature, algorithm, times and audience were checked.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the issuer or subject does not
    ///   have the shape `kind` writes.
    pub fn new(
        kind: WorkloadKind,
        issuer: WorkloadIssuer,
        subject: WorkloadSubject,
    ) -> Result<Self, DomainError> {
        kind.ensure_fits(&issuer, &subject)?;
        Ok(Self {
            kind,
            issuer,
            subject,
        })
    }

    /// The kind of platform that issued it.
    #[must_use]
    pub fn kind(&self) -> WorkloadKind {
        self.kind
    }

    /// Who issued it.
    #[must_use]
    pub fn issuer(&self) -> &WorkloadIssuer {
        &self.issuer
    }

    /// The workload it names.
    #[must_use]
    pub fn subject(&self) -> &WorkloadSubject {
        &self.subject
    }

    /// The attested subject a credential issued against this token is
    /// bound to: its issuer and subject together, so one issuer's
    /// `repo:corp/payroll` is never another's.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the two together are too long for
    ///   an attested subject. The limits on each keep them short enough.
    pub fn bound_subject(&self) -> Result<AttestedSubject, DomainError> {
        AttestedSubject::new(binding_text(&self.issuer, &self.subject)).map_err(DomainError::from)
    }
}

/// How a credential records the issuer and subject it was bound to.
fn binding_text(issuer: &WorkloadIssuer, subject: &WorkloadSubject) -> String {
    format!("{}#{}", issuer.as_str(), subject.as_str())
}

/// Whether `issuer` is GitHub's: its own issuer, or an enterprise's,
/// which GitHub writes as its own issuer and one path segment, the
/// enterprise's slug.
fn is_github_issuer(issuer: &str) -> bool {
    let Some(rest) = issuer.strip_prefix(GITHUB_ACTIONS_ISSUER) else {
        return false;
    };
    let Some(slug) = rest.strip_prefix('/') else {
        return rest.is_empty();
    };
    !slug.is_empty() && !slug.contains('/')
}

/// Whether `subject` names one service account:
/// `system:serviceaccount:<namespace>:<name>`.
fn is_service_account(subject: &str) -> bool {
    let Some(rest) = subject.strip_prefix(SERVICE_ACCOUNT_PREFIX) else {
        return false;
    };
    let mut parts = rest.split(':');
    let (Some(namespace), Some(name), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    [namespace, name].iter().all(|part| {
        Validator::new(WorkloadSubject::FIELD, part)
            .not_empty()
            .validate_first()
            .is_ok()
    })
}

/// Refuses a wildcard, a query or a fragment: a workload name is matched
/// exactly, never as a pattern.
struct ExactName;

impl Rule for ExactName {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        if !value.contains(['*', '?', '#']) {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "not_exact".to_owned(),
            message: message!(
                "agents-a-workload-is-named-exactly-with",
                "a workload is named exactly, with no wildcard, query or fragment"
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer(value: &str) -> WorkloadIssuer {
        WorkloadIssuer::new(value).unwrap()
    }

    fn subject(value: &str) -> WorkloadSubject {
        WorkloadSubject::new(value).unwrap()
    }

    /// The trust Ann sets for her reports repository's main branch.
    fn main_branch() -> WorkloadTrust {
        WorkloadTrust::new(
            WorkloadKind::GithubActions,
            issuer(GITHUB_ACTIONS_ISSUER),
            subject("repo:corp/reports:ref:refs/heads/main"),
        )
        .unwrap()
    }

    /// A token GitHub issued for `sub`.
    fn github_token(sub: &str) -> WorkloadToken {
        WorkloadToken::new(
            WorkloadKind::GithubActions,
            issuer(GITHUB_ACTIONS_ISSUER),
            subject(sub),
        )
        .unwrap()
    }

    /// A token from the main branch proves the agent the trust belongs to.
    #[test]
    fn a_token_matching_issuer_and_subject_is_accepted() {
        let token = github_token("repo:corp/reports:ref:refs/heads/main");

        assert!(main_branch().accepts(&token));
    }

    /// A pull request token is refused by a trust for the same repository's
    /// main branch because its subject differs.
    #[test]
    fn a_token_for_another_subject_is_refused() {
        let token = github_token("repo:corp/reports:pull_request");

        assert!(!main_branch().accepts(&token));
    }

    /// A GitHub Actions trust cannot name an unrelated OIDC issuer, even
    /// when its subject names the expected repository and branch.
    #[test]
    fn a_github_trust_names_githubs_own_issuer() {
        let trust = WorkloadTrust::new(
            WorkloadKind::GithubActions,
            issuer("https://oidc.mallory.example"),
            subject("repo:corp/reports:ref:refs/heads/main"),
        );

        assert!(matches!(trust, Err(DomainError::Validation(_))));
    }

    /// An enterprise's own GitHub issuer, GitHub's issuer and one slug, is
    /// GitHub's. A deeper path, an empty slug or a look-alike host is not.
    #[test]
    fn an_enterprise_issuer_under_githubs_is_githubs() {
        let trust = |iss: &str| {
            WorkloadTrust::new(
                WorkloadKind::GithubActions,
                issuer(iss),
                subject("repo:corp/reports:ref:refs/heads/main"),
            )
        };

        assert!(trust("https://token.actions.githubusercontent.com/octocat-inc").is_ok());
        assert!(trust("https://token.actions.githubusercontent.com/").is_err());
        assert!(trust("https://token.actions.githubusercontent.com/a/b").is_err());
        assert!(trust("https://token.actions.githubusercontent.com.mallory.example").is_err());
    }

    /// A GitHub Actions trust refuses an OIDC token from another issuer
    /// even though its subject matches the trusted repository and branch.
    #[test]
    fn a_token_from_another_issuer_is_refused() {
        let theirs = WorkloadToken::new(
            WorkloadKind::Oidc,
            issuer("https://oidc.mallory.example"),
            subject("repo:corp/reports:ref:refs/heads/main"),
        )
        .unwrap();

        assert!(!main_branch().accepts(&theirs));
    }

    /// A Kubernetes trust names one service account in one namespace. A
    /// subject that is not a service account, or names only a namespace,
    /// is refused.
    #[test]
    fn a_kubernetes_trust_names_one_service_account() {
        let cluster = || issuer("https://oidc.eks.eu-west-1.amazonaws.com/id/ABC");
        let trust =
            |sub: &str| WorkloadTrust::new(WorkloadKind::Kubernetes, cluster(), subject(sub));

        assert!(trust("system:serviceaccount:agents:runner").is_ok());
        assert!(trust("system:serviceaccount:agents").is_err());
        assert!(trust("system:serviceaccount:agents:").is_err());
        assert!(trust("user:agents:runner").is_err());
    }

    /// A wildcard subject and issuers with fragments, queries or plain
    /// HTTP are refused when constructing exact workload names.
    #[test]
    fn a_workload_is_named_exactly() {
        assert!(WorkloadSubject::new("repo:corp/*").is_err());
        assert!(WorkloadIssuer::new("https://issuer.example/#x").is_err());
        assert!(WorkloadIssuer::new("https://issuer.example/?a=b").is_err());
        assert!(WorkloadIssuer::new("http://issuer.example").is_err());
    }

    /// The subject a credential is bound to joins issuer and subject, and
    /// the trust that names both binds it while another trust does not.
    #[test]
    fn a_bound_subject_names_issuer_and_subject_together() {
        let token = github_token("repo:corp/reports:ref:refs/heads/main");

        let bound = token.bound_subject().unwrap();

        assert_eq!(
            bound.as_str(),
            "https://token.actions.githubusercontent.com#repo:corp/reports:ref:refs/heads/main"
        );
        assert!(main_branch().binds(&bound));
        let other = WorkloadTrust::new(
            WorkloadKind::GithubActions,
            issuer(GITHUB_ACTIONS_ISSUER),
            subject("repo:corp/other:ref:refs/heads/main"),
        )
        .unwrap();
        assert!(!other.binds(&bound));
    }

    /// Every kind has its own stored name and maps to its own method.
    #[test]
    fn each_kind_has_its_own_name_and_method() {
        let kinds = [
            WorkloadKind::Kubernetes,
            WorkloadKind::GithubActions,
            WorkloadKind::Oidc,
        ];
        let names: std::collections::HashSet<&str> =
            kinds.into_iter().map(WorkloadKind::as_str).collect();
        let methods: std::collections::HashSet<AttestationMethod> =
            kinds.into_iter().map(WorkloadKind::method).collect();

        assert_eq!(names.len(), kinds.len());
        assert_eq!(methods.len(), kinds.len());
    }
}
