//! Whether a principal is a person.
//!
//! Some records may only have been made by a person, such as an egress
//! policy or a pipeline. Reading one back checks the stored maker with
//! [`is_person`], so a row naming an agent or a machine caller is refused.

use crate::types::PrincipalRef;

/// Whether `principal` is a person: a tenant user or an organization member.
///
/// An agent and a consumer are not.
#[must_use]
pub(crate) fn is_person(principal: &PrincipalRef) -> bool {
    matches!(principal, PrincipalRef::User(_) | PrincipalRef::OrgUser(_))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AgentId, ConsumerId, OrgUserId, UserId};

    /// A tenant user and an organization member each count as a person.
    #[test]
    fn users_and_organization_members_are_people() {
        assert!(is_person(&PrincipalRef::User(UserId::new())));
        assert!(is_person(&PrincipalRef::OrgUser(OrgUserId::new())));
    }

    /// Agent and consumer principals do not satisfy a check requiring a human
    /// maker of a stored record.
    #[test]
    fn an_agent_or_a_consumer_is_not_a_person() {
        for principal in [
            PrincipalRef::Agent(AgentId::new()),
            PrincipalRef::Consumer(ConsumerId::new()),
        ] {
            assert!(!is_person(&principal));
        }
    }
}
