//! A decision record as its row holds it: read back into the record, and
//! written out from it.
//!
//! What a decision rested on is kept whole in the `basis` column, in the
//! shape this file gives it, so it can be read back as it was. The verdict,
//! the policy version and the rule are kept beside it as well, where a
//! search finds them through an index.

use ianua_app::ports::authorization::{
    DecisionBasis, DecisionRecord, DecisionRecordRow, MatchedRule, Verdict,
};
use ianua_domain::domains::authorization::access_check::{
    AccessDecision, AccessQuestion, AllowedBy, CheckTarget, DeniedBecause,
};
use ianua_domain::domains::authorization::permission::{CustomPermission, PermissionSegment};
use ianua_domain::domains::authorization::policy::action::PolicyAction;
use ianua_domain::domains::authorization::policy::version::PolicyVersion;
use ianua_domain::domains::authorization::relationship::ObjectRef;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DecisionRecordId, Label};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::authorization::principals::{kind_word, principal_from};
use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _, stored_words};

const DECISION: Stored = Stored("decision record");

const ASKED_BY: Kept = Kept {
    entity: DECISION.0,
    column: "asked_by",
    shape: 1,
};

const BASIS: Kept = Kept {
    entity: DECISION.0,
    column: "basis",
    shape: 1,
};

stored_words! {
    Verdict as "verdict" {
        Allowed => "allowed",
        Denied => "denied",
        Challenged => "challenged",
    }
}

/// What a decision rested on, as the `basis` column keeps it.
#[derive(Serialize, Deserialize)]
enum StoredBasis {
    AppCheck {
        action: PermissionSegment,
        target: StoredTarget,
        decision: StoredDecision,
    },
    Policy {
        version: PolicyVersion,
        rule: Option<Label>,
        action: PolicyAction,
    },
}

/// What an app's question was about.
#[derive(Serialize, Deserialize)]
enum StoredTarget {
    AnyOf(PermissionSegment),
    Object(ObjectRef),
}

/// The answer to an app's question.
#[derive(Serialize, Deserialize)]
enum StoredDecision {
    Allowed(StoredAllowed),
    Denied(StoredDenied),
}

/// Why an app's question was answered yes.
#[derive(Serialize, Deserialize)]
enum StoredAllowed {
    Permission(CustomPermission),
    Relation {
        object: ObjectRef,
        relation: PermissionSegment,
    },
}

/// Why an app's question was answered no.
#[derive(Serialize, Deserialize)]
enum StoredDenied {
    UnknownResourceType,
    UndeclaredAction,
    NotHeld,
    TooDeep,
}

impl From<&DecisionBasis> for StoredBasis {
    fn from(basis: &DecisionBasis) -> Self {
        match basis {
            DecisionBasis::AppCheck { question, decision } => Self::AppCheck {
                action: question.action().clone(),
                target: StoredTarget::from(question.target()),
                decision: StoredDecision::from(decision),
            },
            DecisionBasis::Policy {
                version,
                matched,
                action,
            } => Self::Policy {
                version: *version,
                rule: rule_of(matched).cloned(),
                action: action.clone(),
            },
        }
    }
}

impl From<StoredBasis> for DecisionBasis {
    fn from(stored: StoredBasis) -> Self {
        match stored {
            StoredBasis::AppCheck {
                action,
                target,
                decision,
            } => Self::AppCheck {
                question: AccessQuestion::new(action, target.into()),
                decision: decision.into(),
            },
            StoredBasis::Policy {
                version,
                rule,
                action,
            } => Self::Policy {
                version,
                matched: rule.map_or(MatchedRule::Default, MatchedRule::Rule),
                action,
            },
        }
    }
}

impl From<&CheckTarget> for StoredTarget {
    fn from(target: &CheckTarget) -> Self {
        match target {
            CheckTarget::AnyOf(resource_type) => Self::AnyOf(resource_type.clone()),
            CheckTarget::Object(object) => Self::Object(object.clone()),
        }
    }
}

impl From<StoredTarget> for CheckTarget {
    fn from(stored: StoredTarget) -> Self {
        match stored {
            StoredTarget::AnyOf(resource_type) => Self::AnyOf(resource_type),
            StoredTarget::Object(object) => Self::Object(object),
        }
    }
}

impl From<&AccessDecision> for StoredDecision {
    fn from(decision: &AccessDecision) -> Self {
        match decision {
            AccessDecision::Allowed(AllowedBy::Permission(permission)) => {
                Self::Allowed(StoredAllowed::Permission(permission.clone()))
            }
            AccessDecision::Allowed(AllowedBy::Relation { object, relation }) => {
                Self::Allowed(StoredAllowed::Relation {
                    object: object.clone(),
                    relation: relation.clone(),
                })
            }
            AccessDecision::Denied(because) => Self::Denied(StoredDenied::from(*because)),
        }
    }
}

impl From<StoredDecision> for AccessDecision {
    fn from(stored: StoredDecision) -> Self {
        match stored {
            StoredDecision::Allowed(StoredAllowed::Permission(permission)) => {
                Self::Allowed(AllowedBy::Permission(permission))
            }
            StoredDecision::Allowed(StoredAllowed::Relation { object, relation }) => {
                Self::Allowed(AllowedBy::Relation { object, relation })
            }
            StoredDecision::Denied(because) => Self::Denied(because.into()),
        }
    }
}

impl From<DeniedBecause> for StoredDenied {
    fn from(because: DeniedBecause) -> Self {
        match because {
            DeniedBecause::UnknownResourceType => Self::UnknownResourceType,
            DeniedBecause::UndeclaredAction => Self::UndeclaredAction,
            DeniedBecause::NotHeld => Self::NotHeld,
            DeniedBecause::TooDeep => Self::TooDeep,
        }
    }
}

impl From<StoredDenied> for DeniedBecause {
    fn from(stored: StoredDenied) -> Self {
        match stored {
            StoredDenied::UnknownResourceType => Self::UnknownResourceType,
            StoredDenied::UndeclaredAction => Self::UndeclaredAction,
            StoredDenied::NotHeld => Self::NotHeld,
            StoredDenied::TooDeep => Self::TooDeep,
        }
    }
}

/// The rule that settled a policy decision, or none for the default.
fn rule_of(matched: &MatchedRule) -> Option<&Label> {
    match matched {
        MatchedRule::Rule(rule) => Some(rule),
        MatchedRule::Default => None,
    }
}

/// The policy version and rule a search finds `basis` by: none for an
/// app's check.
fn searched_by(basis: &DecisionBasis) -> (Option<PolicyVersion>, Option<&Label>) {
    match basis {
        DecisionBasis::AppCheck { .. } => (None, None),
        DecisionBasis::Policy {
            version, matched, ..
        } => (Some(*version), rule_of(matched)),
    }
}

/// A decision as it is read. The store's checked queries fill it.
pub(super) struct KeptDecision {
    pub(super) id: Uuid,
    pub(super) asked_by: Value,
    pub(super) subject_kind: String,
    pub(super) subject_id: Uuid,
    pub(super) verdict: String,
    pub(super) policy_version: Option<i32>,
    pub(super) rule: Option<String>,
    pub(super) basis: Value,
    pub(super) decided_at: OffsetDateTime,
}

impl KeptDecision {
    /// The record the row holds, rebuilt through its checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a JSON column does not
    /// read, a word is unknown, or the columns a search reads disagree with
    /// the basis.
    pub(super) fn into_record(self) -> Result<DecisionRecord, DomainError> {
        let stored: StoredBasis = BASIS.open(self.basis)?;
        let basis = DecisionBasis::from(stored);
        let (version, rule) = searched_by(&basis);
        let named = (
            version.map(version_column).transpose()?,
            rule.map(Label::as_str),
        );
        if named != (self.policy_version, self.rule.as_deref()) {
            return Err(DomainError::corrupt_row(
                DECISION.0,
                "filed under a version or rule its basis does not name",
            ));
        }
        DecisionRecord::reconstitute(DecisionRecordRow {
            id: DecisionRecordId::from_uuid(self.id),
            asked_by: ASKED_BY.open(self.asked_by)?,
            subject: principal_from(DECISION, &self.subject_kind, self.subject_id)?,
            basis,
            decided_at: self.decided_at,
            verdict: DECISION.choice(&self.verdict)?,
        })
    }
}

/// A decision's columns, as they are written.
pub(super) struct DecisionColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) asked_by: Value,
    pub(super) subject_kind: &'static str,
    pub(super) subject_id: Uuid,
    pub(super) verdict: &'static str,
    pub(super) policy_version: Option<i32>,
    pub(super) rule: Option<&'a str>,
    pub(super) basis: Value,
    pub(super) decided_at: OffsetDateTime,
}

impl<'a> DecisionColumns<'a> {
    /// The columns `record` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value cannot be written
    /// out as JSON, or a version past the column's range.
    pub(super) fn of(record: &'a DecisionRecord) -> Result<Self, DomainError> {
        let (version, rule) = searched_by(&record.basis);
        Ok(Self {
            id: record.id.as_uuid(),
            asked_by: ASKED_BY.seal(&record.asked_by)?,
            subject_kind: kind_word(&record.subject),
            subject_id: record.subject.id(),
            verdict: record.verdict().word(),
            policy_version: version.map(version_column).transpose()?,
            rule: rule.map(Label::as_str),
            basis: BASIS.seal(&StoredBasis::from(&record.basis))?,
            decided_at: record.decided_at,
        })
    }
}

/// Parallel columns for one atomic batch of decision evidence.
#[derive(Default)]
pub(super) struct DecisionBatchColumns {
    pub(super) ids: Vec<Uuid>,
    pub(super) asked_by: Vec<Value>,
    pub(super) subject_kinds: Vec<String>,
    pub(super) subject_ids: Vec<Uuid>,
    pub(super) verdicts: Vec<String>,
    pub(super) policy_versions: Vec<Option<i32>>,
    pub(super) rules: Vec<Option<String>>,
    pub(super) bases: Vec<Value>,
    pub(super) decided_at: Vec<OffsetDateTime>,
}

impl DecisionBatchColumns {
    /// Maps every record with the same checked envelope as a single write.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if any record cannot be encoded.
    pub(super) fn of(records: &[DecisionRecord]) -> Result<Self, DomainError> {
        let mut batch = Self::default();
        for record in records {
            let row = DecisionColumns::of(record)?;
            batch.ids.push(*row.id);
            batch.asked_by.push(row.asked_by);
            batch.subject_kinds.push(row.subject_kind.to_owned());
            batch.subject_ids.push(row.subject_id);
            batch.verdicts.push(row.verdict.to_owned());
            batch.policy_versions.push(row.policy_version);
            batch.rules.push(row.rule.map(str::to_owned));
            batch.bases.push(row.basis);
            batch.decided_at.push(row.decided_at);
        }
        Ok(batch)
    }
}

/// The number column `version` is written to and searched by.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` for a number past the column's
/// range, which no tenant reaches.
pub(super) fn version_column(version: PolicyVersion) -> Result<i32, DomainError> {
    i32::try_from(version.number()).map_err(DomainError::infra)
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::domains::authorization::relationship::ObjectKey;
    use ianua_domain::types::{ActorRef, ApiKeyId};
    use serde_json::json;

    use super::*;

    fn segment(value: &str) -> PermissionSegment {
        PermissionSegment::new("test", value).unwrap()
    }

    fn sealed(basis: &DecisionBasis) -> Value {
        BASIS.seal(&StoredBasis::from(basis)).unwrap()
    }

    /// An app's check is kept in the shape pinned here, the question and
    /// the reason for its answer, and reads back as the same.
    #[test]
    fn an_app_check_is_stored_in_its_pinned_shape() {
        let object = ObjectRef::new(segment("project"), ObjectKey::new("42").unwrap());
        let basis = DecisionBasis::AppCheck {
            question: AccessQuestion::new(segment("read"), CheckTarget::Object(object.clone())),
            decision: AccessDecision::Allowed(AllowedBy::Relation {
                object,
                relation: segment("editor"),
            }),
        };
        let stored = json!({"v": 1, "value": {"AppCheck": {
            "action": "read",
            "target": {"Object": {"resource_type": "project", "key": "42"}},
            "decision": {"Allowed": {"Relation": {
                "object": {"resource_type": "project", "key": "42"},
                "relation": "editor"
            }}}
        }}});

        assert_eq!(sealed(&basis), stored);
        let read: StoredBasis = BASIS.open(stored.clone()).unwrap();
        assert_eq!(sealed(&DecisionBasis::from(read)), stored);
    }

    /// A refusal and a permission are kept in the shapes pinned here.
    #[test]
    fn an_answer_is_stored_in_its_pinned_shape() {
        let refused = DecisionBasis::AppCheck {
            question: AccessQuestion::new(segment("read"), CheckTarget::AnyOf(segment("billing"))),
            decision: AccessDecision::Denied(DeniedBecause::NotHeld),
        };
        let allowed = DecisionBasis::AppCheck {
            question: AccessQuestion::new(segment("read"), CheckTarget::AnyOf(segment("billing"))),
            decision: AccessDecision::Allowed(AllowedBy::Permission(
                CustomPermission::new("billing", "read").unwrap(),
            )),
        };

        assert_eq!(
            sealed(&refused),
            json!({"v": 1, "value": {"AppCheck": {
                "action": "read",
                "target": {"AnyOf": "billing"},
                "decision": {"Denied": "NotHeld"}
            }}})
        );
        assert_eq!(
            sealed(&allowed),
            json!({"v": 1, "value": {"AppCheck": {
                "action": "read",
                "target": {"AnyOf": "billing"},
                "decision": {"Allowed": {"Permission": {"resource": "billing", "action": "read"}}}
            }}})
        );
    }

    /// A policy decision is kept in the shape pinned here, its version,
    /// the rule or none for the default, and the action.
    #[test]
    fn a_policy_decision_is_stored_in_its_pinned_shape() {
        let basis = DecisionBasis::Policy {
            version: PolicyVersion::FIRST,
            matched: MatchedRule::Default,
            action: PolicyAction::Allow,
        };
        let stored = json!({"v": 1, "value": {"Policy": {
            "version": 1,
            "rule": null,
            "action": "Allow"
        }}});

        assert_eq!(sealed(&basis), stored);
    }

    /// Who asked is kept in the shape pinned here: an app's key by its id.
    #[test]
    fn who_asked_is_stored_in_its_pinned_shape() {
        let key = ActorRef::ApiKey(ApiKeyId::from_uuid(Uuid::nil()));
        let stored = json!({"v": 1, "value": {"ApiKey": "00000000-0000-0000-0000-000000000000"}});

        assert_eq!(ASKED_BY.seal(&key).unwrap(), stored);
        let read: ActorRef = ASKED_BY.open(stored.clone()).unwrap();
        assert_eq!(ASKED_BY.seal(&read).unwrap(), stored);
    }
}
