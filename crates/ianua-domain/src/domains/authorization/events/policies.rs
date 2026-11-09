//! Events about policies: their rules, review, activation and simulation.

use time::OffsetDateTime;

use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
use crate::domains::authorization::policy::action::PolicyAction;
use crate::domains::authorization::policy::version::{PolicyVersion, VersionBase};
use crate::shared::events::data::EventData;
use crate::shared::events::event::tenant_event;
use crate::shared::model::two_cases::two_cases;
use crate::types::{Enablement, Label, UrlPath};

/// A rule was added to a policy.
#[derive(Debug)]
pub struct PolicyRuleAdded {
    /// The name of the added rule.
    pub(crate) rule_name: Label,
    /// The rule's priority.
    pub(crate) priority: u16,
    /// When the rule was added.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PolicyRuleAdded => crate::types::event_type::AuthorizationEvent::PolicyRuleAdded,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("rule_name", self.rule_name.to_string())
            .field("priority", self.priority.to_string())
    }
}

/// A rule was removed from a policy.
#[derive(Debug)]
pub struct PolicyRuleRemoved {
    /// The name of the removed rule.
    pub(crate) rule_name: Label,
    /// When the rule was removed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PolicyRuleRemoved => crate::types::event_type::AuthorizationEvent::PolicyRuleRemoved,
    fn payload(&self) -> EventData {
        EventData::new().field("rule_name", self.rule_name.to_string())
    }
}

/// A rule of a draft policy was turned on or off. A disabled rule is
/// skipped when requests are checked, so switching one off can open what it
/// guarded once the draft is activated.
#[derive(Debug)]
pub struct PolicyRuleSwitched {
    /// The draft entry whose participation in policy evaluation changed.
    pub(crate) rule_name: Label,
    /// Whether the rule is now on or off.
    pub(crate) to: Enablement,
    /// When the rule was switched.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PolicyRuleSwitched => crate::types::event_type::AuthorizationEvent::PolicyRuleSwitched,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("rule_name", self.rule_name.to_string())
            .field("state", enablement_text(self.to))
    }
}

/// The action a draft policy falls back to when no rule matches changed.
/// Moving it from deny to allow opens every request no rule names, so the
/// record keeps both actions.
#[derive(Debug)]
pub struct PolicyDefaultActionChanged {
    /// The fallback action before the change.
    pub(crate) previous: PolicyAction,
    /// The fallback action now.
    pub(crate) current: PolicyAction,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PolicyDefaultActionChanged => crate::types::event_type::AuthorizationEvent::PolicyDefaultActionChanged,
    fn payload(&self) -> EventData {
        EventData::new().change(
            "default_action",
            action_text(&self.previous),
            action_text(&self.current),
        )
    }
}

/// A new draft of the tenant's policy was started, empty or from the policy
/// it replaces. Nothing it holds is in use until it is reviewed and
/// activated.
#[derive(Debug)]
pub struct PolicyDraftStarted {
    /// How many rules the draft starts with.
    pub(crate) rule_count: usize,
    /// The draft's version number.
    pub(crate) version: PolicyVersion,
    /// What the draft was started from.
    pub(crate) based_on: VersionBase,
    /// When the draft was started.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PolicyDraftStarted => crate::types::event_type::AuthorizationEvent::PolicyDraftStarted,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("rule_count", self.rule_count.to_string())
            .field("version", self.version.to_string())
            .field("kind", self.based_on.as_str())
            .optional("from", self.based_on.source().map(|v| v.to_string()))
    }
}

/// A policy was submitted for review.
#[derive(Debug)]
pub struct PolicySubmittedForReview {
    /// Number of rules in the policy.
    pub(crate) rule_count: usize,
    /// The version sent to review.
    pub(crate) version: PolicyVersion,
    /// When the submission occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PolicySubmittedForReview => crate::types::event_type::AuthorizationEvent::PolicySubmittedForReview,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("rule_count", self.rule_count.to_string())
            .field("version", self.version.to_string())
    }
}

/// A policy was approved and activated. The version it replaced, if any,
/// raises [`PolicyArchived`] beside it.
#[derive(Debug)]
pub struct PolicyActivated {
    /// Number of rules in the activated policy.
    pub(crate) rule_count: usize,
    /// The version that went live.
    pub(crate) version: PolicyVersion,
    /// When the activation occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PolicyActivated => crate::types::event_type::AuthorizationEvent::PolicyActivated,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("rule_count", self.rule_count.to_string())
            .field("version", self.version.to_string())
    }
}

/// A rule of a draft policy was rewritten where it stands: its name,
/// conditions, action or priority. The record keeps the name before and
/// after.
#[derive(Debug)]
pub struct PolicyRuleChanged {
    /// The rule's name before the change.
    pub(crate) previous_name: Label,
    /// The rule's name now.
    pub(crate) rule_name: Label,
    /// The rule's priority now.
    pub(crate) priority: u16,
    /// When the rule was changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PolicyRuleChanged => crate::types::event_type::AuthorizationEvent::PolicyRuleChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .change(
                "rule_name",
                self.previous_name.to_string(),
                self.rule_name.to_string(),
            )
            .field("priority", self.priority.to_string())
    }
}

/// The rules of a draft policy were put in a new order. The first matching
/// allow decides, so the order is recorded whole.
#[derive(Debug)]
pub struct PolicyRulesReordered {
    /// The rule names in their new order.
    pub(crate) order: Vec<Label>,
    /// When the rules were reordered.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PolicyRulesReordered => crate::types::event_type::AuthorizationEvent::PolicyRulesReordered,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("rule_count", self.order.len().to_string())
            .field(
                "order",
                self.order
                    .iter()
                    .map(Label::as_str)
                    .collect::<Vec<_>>()
                    .join(", "),
            )
    }
}

/// A policy was rejected and sent back to draft.
#[derive(Debug)]
pub struct PolicyRejected {
    /// When the rejection occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PolicyRejected => crate::types::event_type::AuthorizationEvent::PolicyRejected,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

/// A policy was archived: replaced by a newer version, taken out of use, or
/// abandoned as a draft. It is kept as a past version.
#[derive(Debug)]
pub struct PolicyArchived {
    /// The version archived.
    pub(crate) version: PolicyVersion,
    /// When the archival occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PolicyArchived => crate::types::event_type::AuthorizationEvent::PolicyArchived,
    fn payload(&self) -> EventData {
        EventData::new().field("version", self.version.to_string())
    }
}

two_cases! {
    /// What a simulated request was decided as. The payload records it as
    /// the `result_allowed` flag.
    pub enum SimulatedDecision {
        /// Allowed.
        Allowed => true,
        /// Denied.
        Denied => false,
    }
}

/// A policy simulation was run.
///
/// Records what was tested and how it was decided. The app layer adds who
/// ran it when it wraps the event. Many simulations in a row can be someone probing for a
/// way past the policy, so they are worth watching.
#[derive(Debug)]
pub struct PolicySimulated {
    /// The simulated path, if provided.
    pub(crate) simulated_path: Option<UrlPath>,
    /// What the simulated request was decided as.
    pub(crate) result_allowed: SimulatedDecision,
    /// The rule that matched, if any.
    pub(crate) matched_rule: Option<Label>,
    /// The version simulated, which may be a draft or one in review.
    pub(crate) version: PolicyVersion,
    /// When the simulation was run.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PolicySimulated => crate::types::event_type::AuthorizationEvent::PolicySimulated,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("version", self.version.to_string())
            .optional(
                "simulated_path",
                self.simulated_path.as_ref().map(ToString::to_string),
            )
            .field("result_allowed", bool::from(self.result_allowed).to_string())
            .optional(
                "matched_rule",
                self.matched_rule.as_ref().map(ToString::to_string),
            )
    }
}

/// A policy action as the audit trail names it, stable across releases.
fn action_text(action: &PolicyAction) -> &'static str {
    match action {
        PolicyAction::Allow => "allow",
        PolicyAction::Deny { .. } => "deny",
        PolicyAction::RequireAal(AssuranceLevel::Aal1) => "require_aal1",
        PolicyAction::RequireAal(AssuranceLevel::Aal2) => "require_aal2",
        PolicyAction::RequireAal(AssuranceLevel::Aal3) => "require_aal3",
        PolicyAction::RequireDpop => "require_dpop",
        PolicyAction::AuditOnly => "audit_only",
    }
}

/// Whether a rule is on, as the audit trail names it.
fn enablement_text(state: Enablement) -> &'static str {
    match state {
        Enablement::Enabled => "enabled",
        Enablement::Disabled => "disabled",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;

    /// A tenant rejects its policy. The event has an empty payload: the
    /// envelope holds all it says. Archiving names the version kept.
    #[test]
    fn rejecting_records_no_payload_and_archiving_names_the_version() {
        let rejected = PolicyRejected {
            occurred_at: crate::shared::clock::now(),
        };
        let archived = PolicyArchived {
            version: PolicyVersion::FIRST,
            occurred_at: crate::shared::clock::now(),
        };

        assert!(rejected.payload().is_empty());
        assert_eq!(archived.payload().get("version"), Some("1"));
    }

    /// Ann restores version 3 as a new draft, version 5. The record names
    /// both and how the draft started.
    #[test]
    fn a_draft_records_its_version_and_where_it_started() {
        let three = PolicyVersion::parse(3).unwrap();
        let event = PolicyDraftStarted {
            rule_count: 2,
            version: PolicyVersion::parse(5).unwrap(),
            based_on: VersionBase::RestoredFrom(three),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();

        assert_eq!(payload.get("version"), Some("5"));
        assert_eq!(payload.get("kind"), Some("restore"));
        assert_eq!(payload.get("from"), Some("3"));
    }

    /// Ann renames "block-admin" to "block-admin-pages". The record keeps
    /// both names.
    #[test]
    fn a_rule_change_records_the_name_before_and_after() {
        let event = PolicyRuleChanged {
            previous_name: Label::new("rule_name", "block-admin").unwrap(),
            rule_name: Label::new("rule_name", "block-admin-pages").unwrap(),
            priority: 10,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        let Some(FieldValue::Change(change)) = payload.value("rule_name") else {
            panic!("rule_name is not a change");
        };
        assert_eq!(
            (change.from(), change.to()),
            (Some("block-admin"), Some("block-admin-pages"))
        );
    }

    /// Sam moves the draft's fallback from deny to allow. The record keeps
    /// both, so the change that opens every unnamed request is visible.
    #[test]
    fn a_default_action_change_records_both_actions() {
        let event = PolicyDefaultActionChanged {
            previous: PolicyAction::Deny {
                reason: crate::types::Text::new("reason", "closed by default").unwrap(),
            },
            current: PolicyAction::Allow,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        let Some(FieldValue::Change(change)) = payload.value("default_action") else {
            panic!("default_action is not a change");
        };
        assert_eq!((change.from(), change.to()), (Some("deny"), Some("allow")));
    }

    /// Ann switches off "require-mfa". The record names the rule and that it
    /// is now off.
    #[test]
    fn switching_a_rule_records_its_name_and_new_state() {
        let event = PolicyRuleSwitched {
            rule_name: Label::new("rule_name", "require-mfa").unwrap(),
            to: Enablement::Disabled,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        assert_eq!(payload.get("rule_name"), Some("require-mfa"));
        assert_eq!(payload.get("state"), Some("disabled"));
    }
}
