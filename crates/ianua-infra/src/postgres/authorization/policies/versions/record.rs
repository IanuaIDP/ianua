//! One version of a tenant's access policy as its row holds it: read back
//! into the aggregate, and written out from it.

use ianua_domain::domains::authorization::policy::review::Submission;
use ianua_domain::domains::authorization::policy::rule::PolicyRule;
use ianua_domain::domains::authorization::policy::set::{PolicySet, PolicySetRow};
use ianua_domain::domains::authorization::policy::version::{PolicyVersion, VersionBase};
use ianua_domain::shared::errors::DomainError;
use serde_json::Value;
use uuid::Uuid;

use crate::postgres::authorization::principals::{HumanColumns, maybe_human_from};
use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const POLICY_VERSION: Stored = Stored("policy version");

const DEFAULT_ACTION: Kept = Kept {
    entity: POLICY_VERSION.0,
    column: "default_action",
    shape: 1,
};

const RULES: Kept = Kept {
    entity: POLICY_VERSION.0,
    column: "rules",
    shape: 1,
};

/// The word of a version started empty.
const BLANK: &str = "blank";

/// The word of a copy of the version live when it was started.
const COPY: &str = "copy";

/// The word of a past version brought back.
const RESTORE: &str = "restore";

/// A version as it is read. The store's checked queries fill it.
pub(super) struct PolicyVersionRecord {
    pub(super) version: i32,
    pub(super) status: String,
    pub(super) based_on: String,
    pub(super) based_on_version: Option<i32>,
    pub(super) default_action: Value,
    pub(super) rules: Value,
    pub(super) submitted_by_kind: Option<String>,
    pub(super) submitted_by_id: Option<Uuid>,
    pub(super) submitted_by_person: Option<String>,
}

impl PolicyVersionRecord {
    /// The version the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a number is not one, a
    /// word is unknown, a JSON column does not read, or the row breaks a
    /// rule the policy keeps.
    pub(super) fn into_policy(self) -> Result<PolicySet, DomainError> {
        let submitted = maybe_human_from(
            POLICY_VERSION,
            self.submitted_by_kind,
            self.submitted_by_id,
            self.submitted_by_person,
        )?;
        let rules: Vec<PolicyRule> = RULES.open(self.rules)?;
        PolicySet::reconstitute(PolicySetRow {
            rules,
            default_action: DEFAULT_ACTION.open(self.default_action)?,
            status: POLICY_VERSION.choice(&self.status)?,
            version: version_from(self.version)?,
            based_on: base_from(&self.based_on, self.based_on_version)?,
            submitted: submitted.map_or(Submission::NotSubmitted, Submission::By),
        })
    }
}

/// The version a stored number names.
fn version_from(number: i32) -> Result<PolicyVersion, DomainError> {
    let number = u32::try_from(number)
        .map_err(|_| DomainError::corrupt_row(POLICY_VERSION.0, "a negative version"))?;
    PolicyVersion::from_stored(number)
}

/// What a word and a number say a version was started from.
fn base_from(word: &str, version: Option<i32>) -> Result<VersionBase, DomainError> {
    match (word, version) {
        (BLANK, None) => Ok(VersionBase::Blank),
        (COPY, Some(version)) => version_from(version).map(VersionBase::CopyOf),
        (RESTORE, Some(version)) => version_from(version).map(VersionBase::RestoredFrom),
        (_, _) => Err(DomainError::corrupt_row(
            POLICY_VERSION.0,
            "a start that does not fit its version",
        )),
    }
}

/// The number column `version` is written to.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` for a number past the column's
/// range, which no tenant reaches.
pub(super) fn version_column(version: PolicyVersion) -> Result<i32, DomainError> {
    i32::try_from(version.number()).map_err(DomainError::infra)
}

/// A version's columns, as they are written.
pub(super) struct PolicyVersionColumns<'a> {
    pub(super) version: i32,
    pub(super) status: &'static str,
    pub(super) based_on: &'static str,
    pub(super) based_on_version: Option<i32>,
    pub(super) default_action: Value,
    pub(super) rules: Value,
    pub(super) submitted_by: Option<HumanColumns<'a>>,
}

impl<'a> PolicyVersionColumns<'a> {
    /// The columns `policy` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value cannot be written
    /// out as JSON, or a number past the column's range.
    pub(super) fn of(policy: &'a PolicySet) -> Result<Self, DomainError> {
        let base = policy.based_on();
        let submitted_by = match policy.submitted() {
            Submission::NotSubmitted => None,
            Submission::By(human) => Some(HumanColumns::of(human)),
        };
        Ok(Self {
            version: version_column(policy.version())?,
            status: policy.status().word(),
            based_on: base.as_str(),
            based_on_version: base.source().map(version_column).transpose()?,
            default_action: DEFAULT_ACTION.seal(policy.default_action())?,
            rules: RULES.seal(&policy.rules())?,
            submitted_by,
        })
    }
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::domains::authorization::policy::action::PolicyAction;
    use ianua_domain::domains::authorization::policy::condition::PolicyCondition;
    use ianua_domain::types::{Label, PathPrefix, Text};
    use serde_json::json;

    use super::*;

    /// `action` sealed again: how a test compares two actions, which have
    /// no equality of their own.
    fn resealed(action: &PolicyAction) -> Value {
        DEFAULT_ACTION.seal(action).unwrap()
    }

    fn block_admin() -> PolicyRule {
        PolicyRule::new(
            Label::new("rule_name", "block-admin").unwrap(),
            vec![PolicyCondition::PathPrefix(
                PathPrefix::new("/admin").unwrap(),
            )],
            PolicyAction::Deny {
                reason: Text::new("reason", "admin blocked").unwrap(),
            },
            10,
        )
        .unwrap()
    }

    /// The fallback action is written in the shape pinned here, a plain
    /// allow as a word and a refusal with its reason, and reads back.
    #[test]
    fn the_default_action_is_stored_in_its_pinned_shape() {
        let allow = json!({"v": 1, "value": "Allow"});
        let deny = json!({"v": 1, "value": {"Deny": {"reason": "closed"}}});
        let closed = PolicyAction::Deny {
            reason: Text::new("reason", "closed").unwrap(),
        };

        assert_eq!(DEFAULT_ACTION.seal(&PolicyAction::Allow).unwrap(), allow);
        assert_eq!(DEFAULT_ACTION.seal(&closed).unwrap(), deny);
        let read: PolicyAction = DEFAULT_ACTION.open(deny.clone()).unwrap();
        assert_eq!(resealed(&read), deny);
    }

    /// The rules are written in the shape pinned here, each with its name,
    /// conditions, action, priority and whether it is on, and read back.
    #[test]
    fn the_rules_are_stored_in_their_pinned_shape() {
        let stored = json!({"v": 1, "value": [{
            "name": "block-admin",
            "conditions": [{"PathPrefix": "/admin"}],
            "action": {"Deny": {"reason": "admin blocked"}},
            "priority": 10,
            "enabled": true
        }]});

        assert_eq!(RULES.seal(&vec![block_admin()]).unwrap(), stored);
        let read: Vec<PolicyRule> = RULES.open(stored.clone()).unwrap();
        assert_eq!(RULES.seal(&read).unwrap(), stored);
    }

    /// A start reads back from its word and number, and one that does not
    /// fit them is refused.
    #[test]
    fn a_start_reads_back_from_its_word_and_number() {
        let second = PolicyVersion::FIRST.next().unwrap();

        assert_eq!(base_from(BLANK, None).unwrap(), VersionBase::Blank);
        assert_eq!(
            base_from(COPY, Some(1)).unwrap(),
            VersionBase::CopyOf(PolicyVersion::FIRST)
        );
        assert_eq!(
            base_from(RESTORE, Some(2)).unwrap(),
            VersionBase::RestoredFrom(second)
        );
        assert!(matches!(
            base_from(BLANK, Some(1)),
            Err(DomainError::Infrastructure(_))
        ));
    }
}
