use uuid::Uuid;

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::data::RefKind;
use crate::types::{AgentId, ConsumerId, HumanAccount, OrgUserId, UserId};

/// A subject that can hold authority: a tenant user, an org user, an agent
/// or a consumer.
///
/// A principal is what authority is delegated from, as the agents context
/// uses it. It is also what authority is granted to. A role assignment names
/// a principal, not a user.
///
/// The kind travels with the id. [`PrincipalId`](crate::types::PrincipalId)
/// drops it, which suits the security types that only need to know which
/// human a factor belongs to. A grant needs the kind. Without it, a grant
/// could not tell an agent holding a role from a user holding one, and two
/// kinds sharing a UUID would share the grant.
///
/// It differs from [`ActorRef`](crate::types::ActorRef), which records who
/// performed an action, for audit. That one includes `System` and carries an
/// agent's delegation chain, and neither can be granted a role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PrincipalRef {
    /// A tenant user.
    User(UserId),
    /// An organization member, on the management plane.
    OrgUser(OrgUserId),
    /// An agent, acting under a delegation or holding grants of its own.
    Agent(AgentId),
    /// A consumer, a non-human caller outside the platform. It signs in with
    /// an API key, a client certificate or its own JWT.
    Consumer(ConsumerId),
}

impl PrincipalRef {
    /// A stable label for audit storage, `"<kind>:<uuid>"`, that can be
    /// queried.
    #[must_use]
    pub fn label(&self) -> String {
        format!("{}:{}", self.kind(), self.id())
    }

    /// The kind as stored: `tenant_user`, `org_user`, `agent` or `consumer`.
    ///
    /// Anything that stores a principal in two columns, not one label, keeps
    /// it beside [`id`](Self::id).
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::User(_) => "tenant_user",
            Self::OrgUser(_) => "org_user",
            Self::Agent(_) => "agent",
            Self::Consumer(_) => "consumer",
        }
    }

    /// The underlying UUID, whatever the kind.
    #[must_use]
    pub fn id(&self) -> Uuid {
        match self {
            Self::User(id) => *id.as_uuid(),
            Self::OrgUser(id) => *id.as_uuid(),
            Self::Agent(id) => *id.as_uuid(),
            Self::Consumer(id) => *id.as_uuid(),
        }
    }

    /// The audit reference kind for this principal.
    ///
    /// An event that names a principal shows it as what it is, not as a
    /// user.
    #[must_use]
    pub fn ref_kind(&self) -> RefKind {
        match self {
            Self::User(_) => RefKind::USER,
            Self::OrgUser(_) => RefKind::ORG_USER,
            Self::Agent(_) => RefKind::AGENT,
            Self::Consumer(_) => RefKind::CONSUMER,
        }
    }

    /// The tenant user this refers to, or `None` for any other kind.
    ///
    /// It is for code that acts on people, such as an invitation or a
    /// membership, and not on principals in general.
    #[must_use]
    pub fn as_user(&self) -> Option<UserId> {
        let Self::User(id) = self else {
            return None;
        };
        Some(*id)
    }

    /// The account of the person this refers to, or `None` for an agent or
    /// a consumer, which no person signs in as.
    #[must_use]
    pub fn human_account(&self) -> Option<HumanAccount> {
        match self {
            Self::User(id) => Some(HumanAccount::User(*id)),
            Self::OrgUser(id) => Some(HumanAccount::OrgUser(*id)),
            Self::Agent(_) | Self::Consumer(_) => None,
        }
    }

    /// Rebuilds a principal from its stored kind and id.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when `kind` is not one this version
    ///   knows. A row with an unknown kind is corrupt or was written by a
    ///   newer version. It is not input a caller got wrong.
    pub fn from_parts(kind: &str, id: Uuid) -> Result<Self, DomainError> {
        match kind {
            "tenant_user" => Ok(Self::User(UserId::from_uuid(id))),
            "org_user" => Ok(Self::OrgUser(OrgUserId::from_uuid(id))),
            "agent" => Ok(Self::Agent(AgentId::from_uuid(id))),
            "consumer" => Ok(Self::Consumer(ConsumerId::from_uuid(id))),
            _ => Err(DomainError::corrupt_row("principal", "an unknown kind")),
        }
    }

    /// Parses a [`label`](Self::label) back into a principal.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the label has no `':'`.
    /// - [`DomainError::Validation`] when its UUID does not parse.
    /// - [`DomainError::Infrastructure`] for an unknown kind, as
    ///   [`from_parts`](Self::from_parts) gives.
    pub fn from_label(label: &str) -> Result<Self, DomainError> {
        let (kind, id) = label.split_once(':').ok_or_else(|| {
            DomainError::invalid(message!(
                "values-principal-label-missing",
                "principal label missing ':'"
            ))
        })?;
        let uuid = Uuid::parse_str(id).map_err(|_| {
            DomainError::invalid(message!(
                "values-principal-label-has-invalid-uuid",
                "principal label has invalid uuid"
            ))
        })?;
        Self::from_parts(kind, uuid)
    }
}

impl From<UserId> for PrincipalRef {
    fn from(id: UserId) -> Self {
        Self::User(id)
    }
}

impl From<OrgUserId> for PrincipalRef {
    fn from(id: OrgUserId) -> Self {
        Self::OrgUser(id)
    }
}

impl From<AgentId> for PrincipalRef {
    fn from(id: AgentId) -> Self {
        Self::Agent(id)
    }
}

impl From<ConsumerId> for PrincipalRef {
    fn from(id: ConsumerId) -> Self {
        Self::Consumer(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_kind() -> [PrincipalRef; 4] {
        [
            PrincipalRef::User(UserId::new()),
            PrincipalRef::OrgUser(OrgUserId::new()),
            PrincipalRef::Agent(AgentId::new()),
            PrincipalRef::Consumer(ConsumerId::new()),
        ]
    }

    /// A tenant user and an org user are each a person's account, the same
    /// one back as a principal. An agent and a consumer are nobody's.
    #[test]
    fn only_people_have_an_account() {
        let [user, member, agent, consumer] = every_kind();

        assert!(agent.human_account().is_none());
        assert!(consumer.human_account().is_none());
        assert_eq!(user.human_account().map(PrincipalRef::from), Some(user));
        assert_eq!(member.human_account().map(PrincipalRef::from), Some(member));
    }

    /// A tenant user, an org user, an agent and a consumer each read back
    /// from their own label as the same principal.
    #[test]
    fn label_round_trips_through_from_label() {
        for principal in every_kind() {
            assert_eq!(
                PrincipalRef::from_label(&principal.label()).unwrap(),
                principal
            );
        }
    }

    /// Each kind stored as a kind column and an id column reads back as the
    /// same principal.
    #[test]
    fn parts_round_trip_through_from_parts() {
        for principal in every_kind() {
            assert_eq!(
                PrincipalRef::from_parts(principal.kind(), principal.id()).unwrap(),
                principal
            );
        }
    }

    /// A label with no colon, and one whose id is not a UUID, are refused.
    #[test]
    fn from_label_rejects_bad_input() {
        assert!(PrincipalRef::from_label("no-colon").is_err());
        assert!(PrincipalRef::from_label("tenant_user:not-a-uuid").is_err());
    }

    /// A stored row names the kind `alien`. That is corrupt storage, not a
    /// caller's mistake, so it is an infrastructure error and gets a
    /// different HTTP status from bad input.
    #[test]
    fn an_unknown_kind_is_infrastructure_not_validation() {
        let err = PrincipalRef::from_parts("alien", Uuid::now_v7()).unwrap_err();

        assert!(matches!(err, DomainError::Infrastructure(_)), "{err:?}");
    }

    /// A user and an agent sharing a UUID remain unequal principals with
    /// distinct labels, preserving the identity kind used by grants.
    #[test]
    fn the_same_uuid_under_two_kinds_is_two_principals() {
        let uuid = Uuid::now_v7();
        let user = PrincipalRef::User(UserId::from_uuid(uuid));
        let agent = PrincipalRef::Agent(AgentId::from_uuid(uuid));

        assert_ne!(user, agent);
        assert_ne!(user.label(), agent.label());
    }

    /// A tenant user gives back its user id. An agent, an org user and a
    /// consumer give nothing.
    #[test]
    fn as_user_names_only_a_tenant_user() {
        let user_id = UserId::new();

        assert_eq!(PrincipalRef::User(user_id).as_user(), Some(user_id));
        assert_eq!(PrincipalRef::Agent(AgentId::new()).as_user(), None);
        assert_eq!(PrincipalRef::OrgUser(OrgUserId::new()).as_user(), None);
        assert_eq!(PrincipalRef::Consumer(ConsumerId::new()).as_user(), None);
    }
}
