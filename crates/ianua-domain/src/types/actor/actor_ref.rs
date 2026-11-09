use crate::shared::errors::DomainError;
use crate::shared::events::data::RefKind;
use crate::types::id::{
    AgentId, ApiKeyId, ConsumerId, OAuthClientId, OperatorId, OrgUserId, UserId,
};

/// Who performed a domain action.
///
/// The application layer attaches it to an event after the aggregate makes
/// the event. The aggregate does not know who called it. The application
/// works out the actor from the request, such as a JWT, an API key or an
/// operator session.
///
/// The [`DomainEvent`](crate::shared::events::event::DomainEvent) wrapper
/// carries it for event bus routing and audit logging. The
/// [`AuditRecord`](crate::domains::audit::record::AuditRecord) keeps it for
/// good.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ActorRef {
    /// A tenant user performed the action.
    User(UserId),

    /// An organization member, on the management plane, performed the
    /// action.
    OrgUser(OrgUserId),

    /// A platform operator performed the action, possibly while
    /// impersonating a user.
    Operator(OperatorId),

    /// The platform performed the action on its own, such as a session
    /// expiry or a scheduled key rotation.
    System,

    /// Someone who never proved who they are, such as a sign-in attempt or a
    /// password reset request. It is recorded as such, never as the system.
    Anonymous,

    /// An OAuth client performed the action, machine to machine.
    OAuthClient(OAuthClientId),

    /// An API key performed the action, machine to machine.
    ApiKey(ApiKeyId),

    /// A service identity in a tenant performed the action, machine to
    /// machine.
    Service(ConsumerId),

    /// An agent performed the action, for the principal that delegated to it
    /// or for itself. The `on_behalf_of` chain records who delegated, for
    /// audit.
    Agent {
        /// The acting agent.
        id: AgentId,
        /// Whom the agent acted for.
        on_behalf_of: ActingFor,
    },
}

/// Whom an agent acted for.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ActingFor {
    /// Nobody. The agent acts on its own authority.
    Itself,
    /// The principal that delegated to it.
    Principal(Box<ActorRef>),
}

impl ActorRef {
    /// The audit reference kind for this actor.
    ///
    /// An event that names who did something shows them as what they are,
    /// not as a user. The system and anonymous callers have no record to
    /// link, so they give `None`.
    #[must_use]
    pub fn ref_kind(&self) -> Option<RefKind> {
        match self {
            Self::User(_) => Some(RefKind::USER),
            Self::OrgUser(_) => Some(RefKind::ORG_USER),
            Self::Operator(_) => Some(RefKind::OPERATOR),
            Self::OAuthClient(_) => Some(RefKind::CLIENT),
            Self::ApiKey(_) => Some(RefKind::new("api_key")),
            Self::Service(_) => Some(RefKind::CONSUMER),
            Self::Agent { .. } => Some(RefKind::AGENT),
            Self::System | Self::Anonymous => None,
        }
    }

    /// A stable label for audit storage, `"<kind>:<uuid>"`.
    ///
    /// Unlike the `Debug` form, it keeps the actor's kind, such as org user,
    /// tenant user or operator. It reads cleanly, and the audit log can
    /// filter on it.
    #[must_use]
    pub fn audit_label(&self) -> String {
        match self {
            Self::User(id) => format!("tenant_user:{}", id.as_uuid()),
            Self::OrgUser(id) => format!("org_user:{}", id.as_uuid()),
            Self::Operator(id) => format!("operator:{}", id.as_uuid()),
            Self::System => "system".to_owned(),
            Self::Anonymous => "anonymous".to_owned(),
            Self::OAuthClient(id) => format!("oauth_client:{}", id.as_uuid()),
            Self::ApiKey(id) => format!("api_key:{}", id.as_uuid()),
            Self::Service(id) => format!("service:{}", id.as_uuid()),
            Self::Agent {
                id,
                on_behalf_of: ActingFor::Itself,
            } => format!("agent:{}", id.as_uuid()),
            Self::Agent {
                id,
                on_behalf_of: ActingFor::Principal(principal),
            } => format!(
                "agent:{} on_behalf_of {}",
                id.as_uuid(),
                principal.audit_label()
            ),
        }
    }

    /// Reads back one principal written by [`audit_label`](Self::audit_label).
    ///
    /// It refuses an agent's delegation chain. A `*_by` column says who, one
    /// principal, and the columns that hold one derive their indexed uuid
    /// from that. A chain reaching one would mean the schema and this
    /// function disagree about what is stored.
    ///
    /// # Errors
    ///
    /// A stored label this cannot read is corrupt data, not a caller's
    /// mistake.
    ///
    /// - [`DomainError::Infrastructure`] when the label names no known kind.
    /// - [`DomainError::Infrastructure`] when it carries a delegation chain.
    /// - [`DomainError::Infrastructure`] when it does not end in a uuid.
    pub fn from_audit_label(label: &str) -> Result<Self, DomainError> {
        match label {
            "system" => return Ok(Self::System),
            "anonymous" => return Ok(Self::Anonymous),
            _ => {}
        }

        let refused =
            || DomainError::corrupt_row("actor label", "a label this version cannot read");
        let (kind, id) = label.split_once(':').ok_or_else(refused)?;
        let uuid = uuid::Uuid::parse_str(id).map_err(|_| refused())?;

        match kind {
            "tenant_user" => Ok(Self::User(UserId::from_uuid(uuid))),
            "org_user" => Ok(Self::OrgUser(OrgUserId::from_uuid(uuid))),
            "operator" => Ok(Self::Operator(OperatorId::from_uuid(uuid))),
            "oauth_client" => Ok(Self::OAuthClient(OAuthClientId::from_uuid(uuid))),
            "api_key" => Ok(Self::ApiKey(ApiKeyId::from_uuid(uuid))),
            "service" => Ok(Self::Service(ConsumerId::from_uuid(uuid))),
            "agent" => Ok(Self::Agent {
                id: AgentId::from_uuid(uuid),
                on_behalf_of: ActingFor::Itself,
            }),
            _ => Err(refused()),
        }
    }

    /// Reads back a whole actor written by [`audit_label`](Self::audit_label),
    /// an agent's delegation chain included, as an audit record keeps it.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Infrastructure`] when a part of the label
    /// cannot be read, or something other than an agent acts for another.
    pub fn from_recorded_label(label: &str) -> Result<Self, DomainError> {
        let Some((acting, behalf)) = label.split_once(" on_behalf_of ") else {
            return Self::from_audit_label(label);
        };
        let Self::Agent { id, .. } = Self::from_audit_label(acting)? else {
            return Err(DomainError::corrupt_row(
                "actor label",
                "only an agent acts for another",
            ));
        };
        Ok(Self::Agent {
            id,
            on_behalf_of: ActingFor::Principal(Box::new(Self::from_recorded_label(behalf)?)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An agent acting for itself is labelled `agent:<uuid>`, with no
    /// `on_behalf_of` part.
    #[test]
    fn autonomous_agent_label_omits_on_behalf_of() {
        let id = AgentId::new();
        let actor = ActorRef::Agent {
            id,
            on_behalf_of: ActingFor::Itself,
        };
        assert_eq!(actor.audit_label(), format!("agent:{}", id.as_uuid()));
    }

    /// Each kind a `*_by` column can hold, from tenant user to service, is
    /// labelled and read back as the same kind. One read back as another
    /// kind would put the action on the wrong plane.
    #[test]
    fn every_single_principal_round_trips() {
        let cases = [
            ActorRef::User(UserId::new()),
            ActorRef::OrgUser(OrgUserId::new()),
            ActorRef::Operator(OperatorId::new()),
            ActorRef::System,
            ActorRef::Anonymous,
            ActorRef::OAuthClient(OAuthClientId::new()),
            ActorRef::ApiKey(ApiKeyId::new()),
            ActorRef::Service(ConsumerId::new()),
        ];

        for actor in cases {
            let label = actor.audit_label();
            let parsed = ActorRef::from_audit_label(&label).expect(&label);
            assert_eq!(parsed.audit_label(), label);
        }
    }

    /// Ann is an organization member. Her stored label reads back as an org
    /// user, never as a tenant user, though both kinds use the same id form.
    #[test]
    fn an_org_user_does_not_read_back_as_a_tenant_user() {
        let org = ActorRef::OrgUser(OrgUserId::new());

        let parsed = ActorRef::from_audit_label(&org.audit_label()).unwrap();

        assert!(matches!(parsed, ActorRef::OrgUser(_)), "{parsed:?}");
    }

    /// An agent acting for Bob is labelled with the whole chain. Reading that
    /// label back as one principal is refused, since a `*_by` column holds
    /// one principal and the chain belongs in the audit log.
    #[test]
    fn a_delegation_chain_is_refused() {
        let chained = ActorRef::Agent {
            id: AgentId::new(),
            on_behalf_of: ActingFor::Principal(Box::new(ActorRef::User(UserId::new()))),
        };

        assert!(ActorRef::from_audit_label(&chained.audit_label()).is_err());
    }

    /// An agent acting for another agent acting for Bob reads back from its
    /// recorded label whole, every link of the chain kept.
    #[test]
    fn a_recorded_chain_reads_back_whole() {
        let chained = ActorRef::Agent {
            id: AgentId::new(),
            on_behalf_of: ActingFor::Principal(Box::new(ActorRef::Agent {
                id: AgentId::new(),
                on_behalf_of: ActingFor::Principal(Box::new(ActorRef::User(UserId::new()))),
            })),
        };
        let label = chained.audit_label();

        let parsed = ActorRef::from_recorded_label(&label).unwrap();

        assert_eq!(parsed.audit_label(), label);
    }

    /// A recorded delegation chain led by a tenant user is rejected as corrupt
    /// storage because only agents may act for another principal.
    #[test]
    fn a_recorded_chain_led_by_a_person_is_refused() {
        let label = format!(
            "tenant_user:{} on_behalf_of tenant_user:{}",
            UserId::new().as_uuid(),
            UserId::new().as_uuid()
        );

        assert!(matches!(
            ActorRef::from_recorded_label(&label),
            Err(DomainError::Infrastructure(_))
        ));
    }

    /// `wizard:not-a-uuid` and `nonsense` are refused, and as corrupt data,
    /// not as bad input.
    #[test]
    fn an_unknown_kind_is_refused() {
        assert!(ActorRef::from_audit_label("wizard:not-a-uuid").is_err());
        assert!(matches!(
            ActorRef::from_audit_label("nonsense"),
            Err(DomainError::Infrastructure(_))
        ));
    }

    /// An agent acting for a tenant user is labelled
    /// `agent:<uuid> on_behalf_of tenant_user:<uuid>`, so the audit log
    /// shows both.
    #[test]
    fn delegated_agent_label_records_the_chain() {
        let agent = AgentId::new();
        let user = UserId::new();
        let actor = ActorRef::Agent {
            id: agent,
            on_behalf_of: ActingFor::Principal(Box::new(ActorRef::User(user))),
        };
        assert_eq!(
            actor.audit_label(),
            format!(
                "agent:{} on_behalf_of tenant_user:{}",
                agent.as_uuid(),
                user.as_uuid()
            )
        );
    }
}
