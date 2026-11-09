//! Where an approval request stands: the approvals it has, and how it was
//! settled.

use time::OffsetDateTime;

use crate::domains::agents::oversight::approval_status::ApprovalStatus;
use crate::shared::errors::DomainError;
use crate::types::{Human, PrincipalRef};

/// One person's approval of a request, with the person behind the account.
///
/// It keeps the person so two approvals can be told apart by who gave them,
/// not only by the account they used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// Who gave it.
    pub by: Human,
    /// When it was given.
    pub at: OffsetDateTime,
}

/// Whether the first of two approvals has been given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirstOfTwo {
    /// Not given. There is no approval yet, or the action needs only one.
    NotGiven,
    /// Given. The second approval must come from someone else.
    Given(Approval),
}

impl FirstOfTwo {
    /// Reads it back from the stored first approval.
    #[must_use]
    pub fn from_stored(first: Option<Approval>) -> Self {
        first.map_or(Self::NotGiven, Self::Given)
    }

    /// The first approval, when there is one. Storage keeps it in this form.
    #[must_use]
    pub fn approval(&self) -> Option<&Approval> {
        match self {
            Self::Given(first) => Some(first),
            Self::NotGiven => None,
        }
    }
}

/// Who settled a request and when.
///
/// It keeps the person behind the account, as an approval does, so a
/// stored denial or withdrawal reads back with the person who made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    by: Human,
    at: OffsetDateTime,
}

impl Decision {
    /// A decision by `by`, made now.
    ///
    /// Who and when come as one value. An approver with no time, or a time
    /// with no approver, is no use to an auditor.
    pub(super) fn now(by: Human) -> Self {
        Self {
            by,
            at: crate::shared::clock::now(),
        }
    }

    /// The account that decided.
    #[must_use]
    pub fn by(&self) -> PrincipalRef {
        self.by.principal()
    }

    /// The person who decided, with the account they acted through.
    /// Storage keeps the decider in this form.
    #[must_use]
    pub fn decider(&self) -> &Human {
        &self.by
    }

    /// When they decided.
    #[must_use]
    pub fn at(&self) -> OffsetDateTime {
        self.at
    }
}

impl From<&Approval> for Decision {
    fn from(approval: &Approval) -> Self {
        Self {
            by: approval.by.clone(),
            at: approval.at,
        }
    }
}

/// A stored decision, as storage reads it back.
///
/// Only a person grants or denies a request, so the decider is a human with
/// the person behind the account. A decision by an agent or a consumer
/// cannot be stored.
#[derive(Debug)]
pub enum StoredDecision {
    /// Nobody has decided yet.
    Undecided,
    /// Someone decided.
    Decided {
        /// The person who decided.
        by: Human,
        /// When they decided.
        at: OffsetDateTime,
    },
}

/// Where a request stands, with the approvals and decision it has.
///
/// It is one value, not a status beside optional fields. So a request can
/// never read as approved by nobody, or decided at a time with no decider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalState {
    /// Waiting for a decision, perhaps holding the first of two approvals.
    Pending(FirstOfTwo),
    /// Approved. The action may run once.
    Approved {
        /// The approval that granted it.
        approval: Approval,
        /// The first of two approvals, when it needed two.
        first: FirstOfTwo,
    },
    /// The approval was used up by its action.
    Consumed {
        /// The approval that granted it.
        approval: Approval,
        /// The first of two approvals, when it needed two.
        first: FirstOfTwo,
    },
    /// Refused.
    Denied {
        /// Who refused it and when.
        decision: Decision,
        /// A first approval given before the refusal.
        first: FirstOfTwo,
    },
    /// Nobody decided in time.
    Expired(FirstOfTwo),
    /// The run that raised it was stopped, so it was taken back undecided.
    Withdrawn {
        /// Who stopped the run, and when the request was taken back.
        decision: Decision,
        /// A first approval given before it was taken back.
        first: FirstOfTwo,
    },
}

impl ApprovalState {
    /// The status label this state carries.
    #[must_use]
    pub fn status(&self) -> ApprovalStatus {
        match self {
            Self::Pending(_) => ApprovalStatus::Pending,
            Self::Approved { .. } => ApprovalStatus::Approved,
            Self::Consumed { .. } => ApprovalStatus::Consumed,
            Self::Denied { .. } => ApprovalStatus::Denied,
            Self::Expired(_) => ApprovalStatus::Expired,
            Self::Withdrawn { .. } => ApprovalStatus::Withdrawn,
        }
    }

    /// Reads a state back from its stored columns.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when an approved, consumed, denied
    ///   or withdrawn request has no decision.
    /// - [`DomainError::Infrastructure`] when a pending or expired request has
    ///   a decision.
    pub fn from_stored(
        status: ApprovalStatus,
        first: Option<Approval>,
        decision: StoredDecision,
    ) -> Result<Self, DomainError> {
        let first = FirstOfTwo::from_stored(first);
        match (status, decision) {
            (ApprovalStatus::Pending, StoredDecision::Undecided) => Ok(Self::Pending(first)),
            (ApprovalStatus::Expired, StoredDecision::Undecided) => Ok(Self::Expired(first)),
            (status, StoredDecision::Decided { by, at }) => {
                Self::decided(status, by, at, first).ok_or_else(|| Self::contradiction(status))
            }
            (status, StoredDecision::Undecided) => Err(Self::contradiction(status)),
        }
    }

    /// The decided state `status` names, made by `by` at `at`, or `None`
    /// for a status that carries no decision.
    fn decided(
        status: ApprovalStatus,
        by: Human,
        at: OffsetDateTime,
        first: FirstOfTwo,
    ) -> Option<Self> {
        match status {
            ApprovalStatus::Approved => Some(Self::Approved {
                approval: Approval { by, at },
                first,
            }),
            ApprovalStatus::Consumed => Some(Self::Consumed {
                approval: Approval { by, at },
                first,
            }),
            ApprovalStatus::Denied => Some(Self::Denied {
                decision: Decision { by, at },
                first,
            }),
            ApprovalStatus::Withdrawn => Some(Self::Withdrawn {
                decision: Decision { by, at },
                first,
            }),
            ApprovalStatus::Pending | ApprovalStatus::Expired => None,
        }
    }

    fn contradiction(status: ApprovalStatus) -> DomainError {
        DomainError::infra_msg(format!(
            "stored {status:?} approval has a decision that contradicts it"
        ))
    }

    /// The decision, once one was made. A grant reads as a decision by the
    /// account that gave it.
    #[must_use]
    pub fn decision(&self) -> Option<Decision> {
        match self {
            Self::Approved { approval, .. } | Self::Consumed { approval, .. } => {
                Some(Decision::from(approval))
            }
            Self::Denied { decision, .. } | Self::Withdrawn { decision, .. } => {
                Some(decision.clone())
            }
            Self::Pending(_) | Self::Expired(_) => None,
        }
    }

    /// The approval that granted the request, once it is granted.
    #[must_use]
    pub fn approval(&self) -> Option<&Approval> {
        match self {
            Self::Approved { approval, .. } | Self::Consumed { approval, .. } => Some(approval),
            Self::Pending(_) | Self::Denied { .. } | Self::Expired(_) | Self::Withdrawn { .. } => {
                None
            }
        }
    }

    /// Whether the first of two approvals was given.
    #[must_use]
    pub fn first(&self) -> &FirstOfTwo {
        match self {
            Self::Pending(first)
            | Self::Expired(first)
            | Self::Approved { first, .. }
            | Self::Consumed { first, .. }
            | Self::Denied { first, .. }
            | Self::Withdrawn { first, .. } => first,
        }
    }
}

/// What an approval did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalStep {
    /// The first of two approvals is recorded. The action still waits for a
    /// different person.
    AwaitingSecond,
    /// The action is approved.
    Granted,
}
