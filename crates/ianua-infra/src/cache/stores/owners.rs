//! Whose an entry or an event is: one tenant's, one organization's, or the
//! platform's. An event drops the entries of the owner it was raised for,
//! and raises that owner's version.

use ianua_domain::shared::events::event::DomainEvent;
use uuid::Uuid;

use crate::bus::EventScope;

/// Whose an entry or an event is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Owner {
    /// One tenant's.
    Tenant(Uuid),
    /// One organization's, not a tenant of it.
    Organization(Uuid),
    /// The platform's own.
    Platform,
}

impl Owner {
    /// The owner `event` was raised for, as its audit record and the bus
    /// subject it goes out on name it.
    pub(crate) fn of_event(event: &DomainEvent) -> Self {
        if let Some(tenant) = event.tenant_id() {
            return Self::Tenant(*tenant.as_uuid());
        }
        event
            .organization_id()
            .map_or(Self::Platform, |organization| {
                Self::Organization(*organization.as_uuid())
            })
    }

    /// The owner as a part of a key, the id in its simple form.
    pub(crate) fn word(self) -> String {
        match self {
            Self::Tenant(tenant) => format!("tenant:{}", tenant.simple()),
            Self::Organization(organization) => format!("org:{}", organization.simple()),
            Self::Platform => "platform".to_owned(),
        }
    }
}

impl From<EventScope> for Owner {
    fn from(scope: EventScope) -> Self {
        match scope {
            EventScope::Tenant(tenant) => Self::Tenant(tenant),
            EventScope::Organization(organization) => Self::Organization(organization),
            EventScope::Platform => Self::Platform,
        }
    }
}

/// Whose an entry is: the owner whose version it is kept under, and the
/// organization above it, whose events drop it too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Owners {
    /// The owner whose version the entry is kept under.
    pub(crate) owner: Owner,
    /// The organization the owner belongs to, when its events reach the
    /// entry as well.
    pub(crate) within: Option<Owner>,
}

impl Owners {
    /// Owned by `owner` alone.
    pub(crate) fn only(owner: Owner) -> Self {
        Self {
            owner,
            within: None,
        }
    }

    /// Whether an event of `owner` reaches the entry.
    pub(crate) fn reached_by(self, owner: Owner) -> bool {
        self.owner == owner || self.within == Some(owner)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::test_support::events::{sample_organization_event, sample_tenant_event};
    use ianua_domain::types::{OrganizationId, TenantId};

    use super::*;
    use crate::test_support::rows::at;

    /// A tenant's event is the tenant's, an organization's event the
    /// organization's, as the bus subjects name them.
    #[test]
    fn an_event_is_owned_as_its_subject_names_it() {
        let tenant = TenantId::new();
        let organization = OrganizationId::new();

        let tenant_owner = Owner::of_event(&sample_tenant_event(tenant));
        let organization_owner = Owner::of_event(&sample_organization_event(organization, at(1)));

        assert_eq!(tenant_owner, Owner::Tenant(*tenant.as_uuid()));
        assert_eq!(
            organization_owner,
            Owner::Organization(*organization.as_uuid())
        );
    }

    /// An entry within an organization is reached by the organization's
    /// events and its own owner's, and by no other.
    #[test]
    fn an_entry_is_reached_by_its_owner_and_the_organization_above() {
        let tenant = Owner::Tenant(Uuid::now_v7());
        let organization = Owner::Organization(Uuid::now_v7());
        let owners = Owners {
            owner: tenant,
            within: Some(organization),
        };

        assert!(owners.reached_by(tenant));
        assert!(owners.reached_by(organization));
        assert!(!owners.reached_by(Owner::Tenant(Uuid::now_v7())));
        assert!(!owners.reached_by(Owner::Platform));
    }
}
