//! The actor an audit log query names, read from its `actor` parameter.

use ianua_domain::message;
use ianua_domain::types::{
    ActorRef, ApiKeyId, ConsumerId, OAuthClientId, OperatorId, OrgUserId, UserId,
};
use uuid::Uuid;

use crate::error::ApiError;

/// The actor `raw` names: `system`, `anonymous`, or a kind and an id, such
/// as `user:0192...`. The kinds are `user`, `org_user`, `operator`,
/// `api_key`, `oauth_client` and `service`.
///
/// # Errors
///
/// A validation error for a kind no actor has, or an id that is no UUID.
pub(crate) fn actor_named(raw: &str) -> Result<ActorRef, ApiError> {
    match raw {
        "system" => return Ok(ActorRef::System),
        "anonymous" => return Ok(ActorRef::Anonymous),
        _ => {}
    }
    let Some((kind, id)) = raw.split_once(':') else {
        return Err(unknown_actor());
    };
    let id = Uuid::parse_str(id).map_err(|_| unknown_actor())?;
    match kind {
        "user" => Ok(ActorRef::User(UserId::from_uuid(id))),
        "org_user" => Ok(ActorRef::OrgUser(OrgUserId::from_uuid(id))),
        "operator" => Ok(ActorRef::Operator(OperatorId::from_uuid(id))),
        "api_key" => Ok(ActorRef::ApiKey(ApiKeyId::from_uuid(id))),
        "oauth_client" => Ok(ActorRef::OAuthClient(OAuthClientId::from_uuid(id))),
        "service" => Ok(ActorRef::Service(ConsumerId::from_uuid(id))),
        _ => Err(unknown_actor()),
    }
}

/// The refusal of an `actor` parameter that names no actor.
fn unknown_actor() -> ApiError {
    ApiError::validation(message!(
        "api-actor-is-system-anonymous-or-kind",
        "actor is `system`, `anonymous` or `<kind>:<uuid>` with kind user, org_user, \
         operator, api_key, oauth_client or service"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The user filter preserves the supplied UUID in its typed audit reference.
    #[test]
    fn a_kind_and_an_id_name_the_actor() {
        let id = Uuid::now_v7();

        let actor = actor_named(&format!("user:{id}")).ok().unwrap();

        assert!(matches!(actor, ActorRef::User(user) if *user.as_uuid() == id));
    }

    /// The platform itself is named without an id.
    #[test]
    fn the_system_is_named_alone() {
        assert!(matches!(actor_named("system"), Ok(ActorRef::System)));
    }

    /// A kind no actor has is refused.
    #[test]
    fn an_unknown_kind_is_refused() {
        let named = actor_named(&format!("robot:{}", Uuid::now_v7()));

        assert!(named.is_err());
    }

    /// A user's display name cannot substitute for the audit query's UUID.
    #[test]
    fn an_id_that_is_no_uuid_is_refused() {
        assert!(actor_named("user:bob").is_err());
    }
}
