//! Who acted, as an audit record's columns keep it beside the full label:
//! the acting principal's kind and id, which the filters by actor and an
//! agent's evidence read through an index.

use ianua_domain::types::ActorRef;
use uuid::Uuid;

/// The kind an audit record files an actor under.
pub(crate) const AGENT: &str = "agent";

/// The kind and id the columns keep for `actor`: the principal that acted,
/// so an agent acting for someone is filed under the agent, and no id for
/// the system or someone who never proved who they are.
pub(crate) fn actor_parts(actor: &ActorRef) -> (&'static str, Option<Uuid>) {
    match actor {
        ActorRef::User(id) => ("tenant_user", Some(*id.as_uuid())),
        ActorRef::OrgUser(id) => ("org_user", Some(*id.as_uuid())),
        ActorRef::Operator(id) => ("operator", Some(*id.as_uuid())),
        ActorRef::System => ("system", None),
        ActorRef::Anonymous => ("anonymous", None),
        ActorRef::OAuthClient(id) => ("oauth_client", Some(*id.as_uuid())),
        ActorRef::ApiKey(id) => ("api_key", Some(*id.as_uuid())),
        ActorRef::Service(id) => ("service", Some(*id.as_uuid())),
        ActorRef::Agent { id, .. } => (AGENT, Some(*id.as_uuid())),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{ActingFor, AgentId, UserId};

    use super::*;

    /// An agent acting for Ann is filed under the agent, so its evidence
    /// holds what it did for her.
    #[test]
    fn an_agent_acting_for_someone_is_filed_under_the_agent() {
        let agent = AgentId::new();
        let actor = ActorRef::Agent {
            id: agent,
            on_behalf_of: ActingFor::Principal(Box::new(ActorRef::User(UserId::new()))),
        };

        assert_eq!(actor_parts(&actor), (AGENT, Some(*agent.as_uuid())));
    }

    /// The system and someone anonymous name no one, and each kind keeps
    /// the word its label starts with.
    #[test]
    fn each_kind_is_filed_as_its_label_starts() {
        let user = ActorRef::User(UserId::new());

        assert_eq!(actor_parts(&ActorRef::System), ("system", None));
        assert_eq!(actor_parts(&ActorRef::Anonymous), ("anonymous", None));
        assert!(user.audit_label().starts_with(actor_parts(&user).0));
    }
}
