//! Policy actions: what happens when a rule matches.

use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
use crate::types::Text;

/// The action to take when a policy rule matches.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PolicyAction {
    /// Allow the request. No additional requirements.
    Allow,

    /// Deny the request outright.
    Deny {
        /// Why the request was denied (shown to the user).
        reason: Text,
    },

    /// Require a minimum authentication assurance level. A user below it is
    /// asked to sign in again more strongly.
    RequireAal(AssuranceLevel),

    /// Require `DPoP` token binding on this request.
    RequireDpop,

    /// Log the request for audit and let it through. Used to watch a new
    /// rule before it is enforced.
    AuditOnly,
}

impl PolicyAction {
    /// Whether this action blocks the request.
    #[must_use]
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    /// Whether this action allows the request unconditionally.
    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Whether this action asks the caller for more before going on. That is
    /// a higher assurance level or `DPoP` token binding.
    #[must_use]
    pub fn requires_step_up(&self) -> bool {
        matches!(self, Self::RequireAal(_) | Self::RequireDpop)
    }

    /// How a rule with this action reads a condition whose fact is not known.
    ///
    /// A rule that refuses or asks for more matches. An unknown country,
    /// device or risk does not prove the request is safe, so a refusal or a
    /// step-up is never skipped on a guess.
    ///
    /// A rule that allows or only records does not match. It must not grant
    /// on a guess.
    #[must_use]
    pub(super) fn on_unknown_fact(&self) -> UnknownFact {
        match self {
            Self::Deny { .. } | Self::RequireAal(_) | Self::RequireDpop => UnknownFact::Matches,
            Self::Allow | Self::AuditOnly => UnknownFact::DoesNotMatch,
        }
    }
}

/// How a rule reads a condition about a fact nobody knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UnknownFact {
    /// The condition counts as holding.
    Matches,
    /// The condition counts as failing.
    DoesNotMatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deny, an allow, a `DPoP` demand and an AAL2 demand each answer yes
    /// to their own question only. Otherwise the proxy could report a refusal
    /// as allowed, or ask for a second factor on an allowed request.
    #[test]
    fn each_action_answers_yes_to_exactly_the_question_it_is() {
        let deny = PolicyAction::Deny {
            reason: crate::types::Text::new("reason", "blocked").unwrap(),
        };

        assert!(deny.is_deny());
        assert!(!deny.is_allow());
        assert!(!deny.requires_step_up());

        assert!(PolicyAction::Allow.is_allow());
        assert!(!PolicyAction::Allow.is_deny());
        assert!(!PolicyAction::Allow.requires_step_up());

        assert!(PolicyAction::RequireDpop.requires_step_up());
        assert!(!PolicyAction::RequireDpop.is_allow());
        assert!(!PolicyAction::RequireDpop.is_deny());

        let step_up = PolicyAction::RequireAal(AssuranceLevel::Aal2);
        assert!(step_up.requires_step_up());
        assert!(!step_up.is_allow());
        assert!(!step_up.is_deny());
    }

    /// A rule that only audits answers no to all three questions. It neither
    /// refuses nor asks for more, and it is not a plain allow.
    #[test]
    fn audit_only_enforces_nothing() {
        assert!(!PolicyAction::AuditOnly.is_deny());
        assert!(!PolicyAction::AuditOnly.is_allow());
        assert!(!PolicyAction::AuditOnly.requires_step_up());
    }
}
