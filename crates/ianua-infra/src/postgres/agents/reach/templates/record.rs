//! A task template as its row holds it: read back into the aggregate, and
//! written out from it. Its ceiling, the classes of action it allows, the
//! paths it confines to and its budget are each one JSON value; its other
//! bounds are columns of their own.

use ianua_domain::domains::agents::authority::intent::{IntentDigest, IntentStatement};
use ianua_domain::domains::agents::authority::task_template::{
    TaskTemplate, TaskTemplateRow, TemplateLimits, TemplateState,
};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Label, Seconds, TaskTemplateId};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::authorization::principals::{HumanColumns, human_from, maybe_human_from};
use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const TEMPLATE: Stored = Stored("task template");

const CEILING: Kept = Kept {
    entity: TEMPLATE.0,
    column: "ceiling",
    shape: 1,
};

const ACTION_CLASSES: Kept = Kept {
    entity: TEMPLATE.0,
    column: "action_classes",
    shape: 1,
};

const RESOURCE_SCOPE: Kept = Kept {
    entity: TEMPLATE.0,
    column: "resource_scope",
    shape: 1,
};

const BUDGET: Kept = Kept {
    entity: TEMPLATE.0,
    column: "budget",
    shape: 1,
};

/// A template as it is read. The store's checked queries fill it.
pub(super) struct TemplateRecord {
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) purpose: String,
    pub(super) purpose_digest: Vec<u8>,
    pub(super) ceiling: Value,
    pub(super) action_classes: Value,
    pub(super) max_ttl_seconds: i64,
    pub(super) max_depth: i16,
    pub(super) max_data_class: String,
    pub(super) resource_scope: Value,
    pub(super) budget: Value,
    pub(super) approval: String,
    pub(super) proposed_by_kind: String,
    pub(super) proposed_by_id: Uuid,
    pub(super) proposed_by_person: String,
    pub(super) proposed_at: OffsetDateTime,
    pub(super) approved_by_kind: Option<String>,
    pub(super) approved_by_id: Option<Uuid>,
    pub(super) approved_by_person: Option<String>,
    pub(super) approved_at: Option<OffsetDateTime>,
    pub(super) retired_at: Option<OffsetDateTime>,
}

impl TemplateRecord {
    /// The template the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, a bound is out of range, half an
    /// approval is kept, or the row breaks a rule the template keeps.
    pub(super) fn into_template(mut self) -> Result<TaskTemplate<ResolvedTenant>, DomainError> {
        let state = self.state()?;
        let limits = self.limits()?;
        TaskTemplate::reconstitute(TaskTemplateRow {
            id: TaskTemplateId::from_uuid(self.id),
            name: TEMPLATE.value("name", Label::new("name", self.name))?,
            purpose: TEMPLATE.value("purpose", IntentStatement::new(self.purpose))?,
            digest: digest_from(self.purpose_digest)?,
            ceiling: CEILING.open(self.ceiling)?,
            classes: ACTION_CLASSES.open(self.action_classes)?,
            limits,
            proposed_by: human_from(
                TEMPLATE,
                &self.proposed_by_kind,
                self.proposed_by_id,
                self.proposed_by_person,
            )?,
            proposed_at: self.proposed_at,
            state,
        })
    }

    /// Where the template stands, from who approved it and when, and when
    /// it was withdrawn.
    fn state(&mut self) -> Result<TemplateState, DomainError> {
        let approver = maybe_human_from(
            TEMPLATE,
            self.approved_by_kind.take(),
            self.approved_by_id.take(),
            self.approved_by_person.take(),
        )?;
        TemplateState::from_stored(approver, self.approved_at, self.retired_at)
    }

    /// The bounds the template puts on every delegation.
    fn limits(&mut self) -> Result<TemplateLimits, DomainError> {
        let out_of_range = || DomainError::corrupt_row(TEMPLATE.0, "a bound out of range");
        Ok(TemplateLimits {
            max_ttl_seconds: Seconds::new(
                u32::try_from(self.max_ttl_seconds).map_err(|_| out_of_range())?,
            ),
            max_depth: u8::try_from(self.max_depth).map_err(|_| out_of_range())?,
            max_data_class: DataClassLevel::from_stored(&self.max_data_class)?,
            resource_scope: RESOURCE_SCOPE.open(std::mem::take(&mut self.resource_scope))?,
            budget: BUDGET.open(std::mem::take(&mut self.budget))?,
            approval: TEMPLATE.choice(&self.approval)?,
        })
    }
}

/// The fingerprint of a purpose, from the 32 bytes its column holds.
fn digest_from(bytes: Vec<u8>) -> Result<IntentDigest, DomainError> {
    let whole: [u8; 32] = bytes
        .try_into()
        .map_err(|_| DomainError::corrupt_row(TEMPLATE.0, "a digest that is not 32 bytes"))?;
    Ok(IntentDigest::new(whole))
}

/// A template's columns, as they are written.
pub(super) struct TemplateColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) name: &'a str,
    pub(super) purpose: &'a str,
    pub(super) purpose_digest: &'a [u8],
    pub(super) ceiling: Value,
    pub(super) action_classes: Value,
    pub(super) max_ttl_seconds: i64,
    pub(super) max_depth: i16,
    pub(super) max_data_class: &'static str,
    pub(super) resource_scope: Value,
    pub(super) budget: Value,
    pub(super) approval: &'static str,
    pub(super) proposed_by: HumanColumns<'a>,
    pub(super) proposed_at: OffsetDateTime,
    pub(super) approved_by: Option<HumanColumns<'a>>,
    pub(super) approved_at: Option<OffsetDateTime>,
    pub(super) retired_at: Option<OffsetDateTime>,
}

impl<'a> TemplateColumns<'a> {
    /// The columns `template` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a JSON value cannot be
    /// written out.
    pub(super) fn of(template: &'a TaskTemplate<ResolvedTenant>) -> Result<Self, DomainError> {
        let limits = template.limits();
        Ok(Self {
            id: template.id().as_uuid(),
            name: template.name().as_str(),
            purpose: template.purpose().as_str(),
            purpose_digest: template.digest().as_bytes(),
            ceiling: CEILING.seal(template.ceiling())?,
            action_classes: ACTION_CLASSES.seal(template.classes())?,
            max_ttl_seconds: i64::from(limits.max_ttl_seconds.get()),
            max_depth: i16::from(limits.max_depth),
            max_data_class: limits.max_data_class.as_str(),
            resource_scope: RESOURCE_SCOPE.seal(&limits.resource_scope)?,
            budget: BUDGET.seal(&limits.budget)?,
            approval: limits.approval.word(),
            proposed_by: HumanColumns::of(template.proposed_by()),
            proposed_at: template.proposed_at(),
            approved_by: template.approved_by().map(HumanColumns::of),
            approved_at: template.approved_at(),
            retired_at: template.retired_at(),
        })
    }

    /// The kind of the account that approved the template, if one did.
    pub(super) fn approved_by_kind(&self) -> Option<&'static str> {
        self.approved_by.as_ref().map(|columns| columns.kind)
    }

    /// The account that approved the template, if one did.
    pub(super) fn approved_by_id(&self) -> Option<Uuid> {
        self.approved_by.as_ref().map(|columns| columns.id)
    }

    /// The person who approved the template, if one did.
    pub(super) fn approved_by_person(&self) -> Option<&'a str> {
        self.approved_by.as_ref().map(|columns| columns.person)
    }
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::domains::agents::authority::capability::{
        AgentBudget, CapabilitySet, ResourceScope,
    };
    use ianua_domain::domains::agents::authority::intent::IntentEnvelope;
    use ianua_domain::shared::model::restriction::Restriction;
    use ianua_domain::types::ActionClass;
    use serde_json::json;

    use super::*;

    /// A template's ceiling is written in the shape pinned here, and a row
    /// in that shape reads back the same.
    #[test]
    fn a_ceiling_is_stored_in_its_pinned_shape() {
        let stored = json!({"v": 1, "value": {
            "http": [],
            "messaging": [],
            "resources": [],
            "mcp": {"classed_tools": [], "resources": [], "prompts": []},
        }});

        assert_eq!(CEILING.seal(&CapabilitySet::empty()).unwrap(), stored);
        let read: CapabilitySet = CEILING.open(stored.clone()).unwrap();
        assert_eq!(CEILING.seal(&read).unwrap(), stored);
    }

    /// The classes of action a template allows are written in the shape
    /// pinned here, and a row in that shape reads back the same.
    #[test]
    fn the_action_classes_are_stored_in_their_pinned_shape() {
        let classes = IntentEnvelope::new([ActionClass::Read, ActionClass::Write]);
        let stored = json!({"v": 1, "value": {"allowed": ["Read", "Write"]}});

        assert_eq!(ACTION_CLASSES.seal(&classes).unwrap(), stored);
        let read: IntentEnvelope = ACTION_CLASSES.open(stored.clone()).unwrap();
        assert_eq!(ACTION_CLASSES.seal(&read).unwrap(), stored);
    }

    /// A template confining no path is written in the shape pinned here,
    /// and a row in that shape reads back the same.
    #[test]
    fn the_resource_scope_is_stored_in_its_pinned_shape() {
        let scope: Restriction<ResourceScope> = Restriction::Unrestricted;
        let stored = json!({"v": 1, "value": "unrestricted"});

        assert_eq!(RESOURCE_SCOPE.seal(&scope).unwrap(), stored);
        let read: Restriction<ResourceScope> = RESOURCE_SCOPE.open(stored.clone()).unwrap();
        assert_eq!(RESOURCE_SCOPE.seal(&read).unwrap(), stored);
    }

    /// A template setting no budget is written in the shape pinned here,
    /// and a row in that shape reads back the same.
    #[test]
    fn the_budget_is_stored_in_its_pinned_shape() {
        let budget: Restriction<AgentBudget> = Restriction::Unrestricted;
        let stored = json!({"v": 1, "value": "unrestricted"});

        assert_eq!(BUDGET.seal(&budget).unwrap(), stored);
        let read: Restriction<AgentBudget> = BUDGET.open(stored.clone()).unwrap();
        assert_eq!(BUDGET.seal(&read).unwrap(), stored);
    }
}
