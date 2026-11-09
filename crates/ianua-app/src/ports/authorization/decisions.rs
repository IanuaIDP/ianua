//! Records of authorization decisions: each answer an app's access check
//! gave, and each request the tenant's policy decided, with the rule and
//! the policy version behind it.
//!
//! Decisions are observable and credentials are not: a record names who
//! was asked about and what was decided, never a token.

use async_trait::async_trait;
use ianua_domain::domains::authorization::access_check::{AccessDecision, AccessQuestion};
use ianua_domain::domains::authorization::policy::action::PolicyAction;
use ianua_domain::domains::authorization::policy::version::PolicyVersion;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ActorRef, DecisionRecordId, Label, PrincipalRef};
use time::OffsetDateTime;

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys};
use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// The one order decision records are listed in: newest first.
    pub enum DecisionRecordSortField {
        /// Order by when the decision was made.
        DecidedAt => "decided_at",
    }
    default = DecidedAt;
    default direction = Desc;
}

impl SortKeys<DecisionRecordSortField> for DecisionRecord {
    fn sort_key(&self, field: DecisionRecordSortField) -> SortKey {
        match field {
            DecisionRecordSortField::DecidedAt => self.decided_at.into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id.as_uuid().into()
    }
}

/// How a decision came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Let through.
    Allowed,
    /// Refused.
    Denied,
    /// Let through only once the caller shows more, such as a stronger
    /// sign-in.
    Challenged,
}

impl Verdict {
    /// The stable name a record and a search use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Challenged => "challenged",
        }
    }
}

/// The policy rule that settled a request, or that none did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchedRule {
    /// This rule settled it.
    Rule(Label),
    /// No rule matched, so the policy's default did.
    Default,
}

/// What a decision rested on.
#[derive(Debug, Clone)]
pub enum DecisionBasis {
    /// A tenant's app asked whether the subject may do something.
    AppCheck {
        /// What was asked.
        question: AccessQuestion,
        /// The answer, with its reason.
        decision: AccessDecision,
    },
    /// The tenant's policy decided a request through the gateway.
    Policy {
        /// The version of the policy that decided.
        version: PolicyVersion,
        /// The rule that settled it.
        matched: MatchedRule,
        /// What the policy said to do.
        action: PolicyAction,
    },
}

/// One authorization decision, as the record keeps it.
#[derive(Debug, Clone)]
pub struct DecisionRecord {
    /// Which record it is.
    pub id: DecisionRecordId,
    /// Who asked: the app's key or account, or the system for the gateway.
    pub asked_by: ActorRef,
    /// Whom the decision was about.
    pub subject: PrincipalRef,
    /// What it rested on.
    pub basis: DecisionBasis,
    /// When it was made.
    pub decided_at: OffsetDateTime,
}

/// A [`DecisionRecord`] as storage holds it, read back through
/// [`DecisionRecord::reconstitute`]: the record, and the verdict it was
/// filed under so a search can find it.
#[derive(Debug, Clone)]
pub struct DecisionRecordRow {
    /// Which record it is.
    pub id: DecisionRecordId,
    /// Who asked.
    pub asked_by: ActorRef,
    /// Whom the decision was about.
    pub subject: PrincipalRef,
    /// What it rested on.
    pub basis: DecisionBasis,
    /// When it was made.
    pub decided_at: OffsetDateTime,
    /// The verdict it was filed under.
    pub verdict: Verdict,
}

impl DecisionRecord {
    /// Rebuilds a record from storage.
    ///
    /// A search finds records by the verdict they were filed under, so a
    /// record whose basis says otherwise would be found as what it is not.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the verdict filed is not
    /// the one the basis gives.
    pub fn reconstitute(row: DecisionRecordRow) -> Result<Self, DomainError> {
        let record = Self {
            id: row.id,
            asked_by: row.asked_by,
            subject: row.subject,
            basis: row.basis,
            decided_at: row.decided_at,
        };
        if record.verdict() != row.verdict {
            return Err(DomainError::corrupt_row(
                "decision record",
                "filed under a verdict its basis does not give",
            ));
        }
        Ok(record)
    }

    /// How the decision came out, read from what it rested on.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        match &self.basis {
            DecisionBasis::AppCheck { decision, .. } if decision.is_allowed() => Verdict::Allowed,
            DecisionBasis::AppCheck { .. } => Verdict::Denied,
            DecisionBasis::Policy { action, .. } if action.is_deny() => Verdict::Denied,
            DecisionBasis::Policy { action, .. } if action.requires_step_up() => {
                Verdict::Challenged
            }
            DecisionBasis::Policy { .. } => Verdict::Allowed,
        }
    }
}

/// Which records a search keeps. Every field left empty keeps everything.
#[derive(Debug, Clone, Default)]
pub struct DecisionFilter {
    /// Only decisions about this subject.
    pub subject: Option<PrincipalRef>,
    /// Only decisions that came out this way.
    pub verdict: Option<Verdict>,
    /// Only decisions made by this version of the policy.
    pub policy_version: Option<PolicyVersion>,
    /// Only decisions this policy rule settled.
    pub rule: Option<Label>,
    /// Only decisions made at or after this time.
    pub since: Option<OffsetDateTime>,
}

/// Dyn-safe port that keeps and searches a tenant's decision records.
#[async_trait]
pub trait DecisionRecordStore: Send + Sync + TenantScoped {
    /// Keeps `record`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the record cannot be written. The
    /// decision is then not handed out: a decision nobody can trace is
    /// refused rather than given.
    async fn record(
        &self,
        tenant_id: &ScopedTenant,
        record: &DecisionRecord,
    ) -> Result<(), DomainError>;

    /// Keeps every record in one atomic batch. A failed batch keeps none,
    /// and no answers are handed out when their evidence cannot be written.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when any record cannot be written.
    async fn record_all(
        &self,
        tenant_id: &ScopedTenant,
        records: &[DecisionRecord],
    ) -> Result<(), DomainError>;

    /// The records `filter` keeps, newest first, one page of them.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the records cannot be read.
    async fn search(
        &self,
        tenant_id: &ScopedTenant,
        filter: &DecisionFilter,
        page: &PageRequest,
    ) -> Result<Page<DecisionRecord>, DomainError>;
}
