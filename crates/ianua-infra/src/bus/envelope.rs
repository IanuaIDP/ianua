//! A published event as it travels on the bus: the audit record it was
//! kept as, written as JSON, on the subject its scope and type name.
//!
//! Subjects read `tenant.<tenant>.<event type>`,
//! `org.<organization>.<event type>` and `platform.<event type>`, ids in
//! their simple form without hyphens, so a consumer listens to one tenant,
//! one organization, or every one with a wildcard. A bus server puts them
//! under the deployment's [`Namespace`](crate::namespace::Namespace), as
//! `ianua.tenant.<tenant>.<event type>` by default.

use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::chain::{ChainDepth, EventOrigin};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

/// Where an event belongs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "id")]
pub enum EventScope {
    /// One tenant's.
    Tenant(Uuid),
    /// One organization's, not a tenant of it.
    Organization(Uuid),
    /// The platform's own.
    Platform,
}

/// One published event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// The id of the audit record it was kept as, and the id the bus keeps
    /// one copy by.
    pub id: Uuid,
    /// Where it belongs.
    pub scope: EventScope,
    /// The organization that owns the tenant, when the record knows it.
    pub organization_id: Option<Uuid>,
    /// Its type, such as `identity.user_registered`.
    pub event_type: String,
    /// Who acted, as the audit record labels them.
    pub actor: String,
    /// What it says, as the audit record keeps it.
    pub payload: Value,
    /// When it happened.
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: OffsetDateTime,
    /// How deep in a workflow chain the work that raised it was: 0 for an
    /// event raised outside any workflow. Sealed with the rest, so a depth
    /// changed on the way breaks the seal.
    #[serde(default)]
    pub chain_depth: u8,
}

impl EventEnvelope {
    /// The depth an envelope carries for an event raised from `origin`: 0
    /// for one raised outside any workflow.
    #[must_use]
    pub fn chain_depth_of(origin: EventOrigin) -> u8 {
        match origin {
            EventOrigin::Outside => 0,
            EventOrigin::Execution(depth) => depth.get(),
        }
    }

    /// Where the event came from, by the depth it carries: outside any
    /// workflow at 0, else from an execution that deep.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` for a depth no chain reaches.
    pub fn origin(&self) -> Result<EventOrigin, DomainError> {
        if self.chain_depth == 0 {
            return Ok(EventOrigin::Outside);
        }
        ChainDepth::from_stored(self.chain_depth).map(EventOrigin::Execution)
    }

    /// The subject the event is published on, under the deployment's
    /// namespace.
    #[must_use]
    pub fn subject(&self) -> String {
        match self.scope {
            EventScope::Tenant(tenant) => {
                format!("tenant.{}.{}", tenant.simple(), self.event_type)
            }
            EventScope::Organization(organization) => {
                format!("org.{}.{}", organization.simple(), self.event_type)
            }
            EventScope::Platform => format!("platform.{}", self.event_type),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(scope: EventScope) -> EventEnvelope {
        EventEnvelope {
            id: Uuid::now_v7(),
            scope,
            organization_id: None,
            event_type: "identity.user_registered".to_owned(),
            actor: "system".to_owned(),
            payload: Value::Null,
            occurred_at: OffsetDateTime::UNIX_EPOCH,
            chain_depth: 0,
        }
    }

    /// A tenant's event is published under the tenant's id without hyphens
    /// and its type.
    #[test]
    fn a_tenant_event_is_published_under_its_tenant() {
        let tenant = Uuid::now_v7();

        let subject = envelope(EventScope::Tenant(tenant)).subject();

        assert_eq!(
            subject,
            format!("tenant.{}.identity.user_registered", tenant.simple())
        );
        assert!(!subject.contains('-'));
    }

    /// A platform event names no tenant or organization.
    #[test]
    fn a_platform_event_names_no_owner() {
        assert_eq!(
            envelope(EventScope::Platform).subject(),
            "platform.identity.user_registered"
        );
    }

    /// Under the default namespace, every scope's subject is the one the
    /// platform has always published on.
    #[test]
    fn the_default_namespace_publishes_on_the_subjects_used_before() {
        let namespace = crate::namespace::Namespace::default();
        let tenant = Uuid::now_v7();
        let organization = Uuid::now_v7();

        let subjects = [
            EventScope::Tenant(tenant),
            EventScope::Organization(organization),
            EventScope::Platform,
        ]
        .map(|scope| namespace.subject(&envelope(scope).subject()));

        assert_eq!(
            subjects,
            [
                format!("ianua.tenant.{}.identity.user_registered", tenant.simple()),
                format!(
                    "ianua.org.{}.identity.user_registered",
                    organization.simple()
                ),
                "ianua.platform.identity.user_registered".to_owned(),
            ]
        );
    }
}
