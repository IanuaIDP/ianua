//! Who may change a tenant's topics, subscriptions and schemas.
//!
//! A topic's status, schema, retention and class decide which messages flow
//! and who may read them. So every change to one names who makes it and
//! needs the messaging right for it.
//!
//! A topic, a schema or a subscription is made by a person with the
//! messaging create right, or by a consumer acting with a
//! [`ConsumerAuthority`](crate::domains::consumers::authority::ConsumerAuthority)
//! whose roles give it that right. Each records which.

use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::permission::{MessagingAction, SystemPermission};
use crate::domains::consumers::authority::ConsumerAuthority;
use crate::domains::data_classification::level::DataClassLevel;
use crate::shared::errors::DomainError;
use crate::types::{ActorRef, ConsumerId, Human};

/// The right a consumer's roles must give before it makes a topic, a
/// schema or a subscription of its own.
const CONSUMER_CREATES: SystemPermission = SystemPermission::Messaging(MessagingAction::Create);

/// A person changing a topic, a subscription or a schema, with what they
/// hold.
///
/// Sam may only view messaging. Without this check, he pauses the
/// `payments.settled` topic and every payment confirmation stops.
#[derive(Debug, Clone, Copy)]
pub struct MessagingControl<'a> {
    authority: &'a TenantAuthority,
}

impl<'a> MessagingControl<'a> {
    /// The person `authority` names, acting with what it says they hold.
    #[must_use]
    pub fn new(authority: &'a TenantAuthority) -> Self {
        Self { authority }
    }

    /// The person acting.
    #[must_use]
    pub fn by(&self) -> &'a Human {
        self.authority.who()
    }

    /// Refuses the change unless the person holds the messaging right for
    /// `action`, through their roles or an active break-glass grant.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when they do not hold it.
    pub fn ensure_may(&self, action: MessagingAction) -> Result<(), DomainError> {
        self.authority
            .ensure_holds(SystemPermission::Messaging(action))
    }

    /// The most sensitive data the person may see now.
    pub(crate) fn clearance(&self) -> DataClassLevel {
        self.authority.data_clearance()
    }
}

/// Who is handed a topic's messages: a person, with what they hold, or a
/// consumer that signed in, with its stored clearance.
///
/// Its clearance comes from the person's rights or the consumer's record,
/// never from the request.
#[derive(Debug, Clone, Copy)]
pub enum MessagingReader<'a> {
    /// A person, with what they hold.
    Person(&'a MessagingControl<'a>),
    /// A consumer that signed in, with what its roles give it.
    Consumer(&'a ConsumerAuthority),
}

impl MessagingReader<'_> {
    /// The most sensitive data the reader may be handed.
    pub(crate) fn clearance(&self) -> DataClassLevel {
        match self {
            Self::Person(control) => control.clearance(),
            Self::Consumer(authority) => authority.clearance(),
        }
    }

    /// Refuses unless the person holds the messaging consume right, or the
    /// consumer's roles give it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when they do not.
    pub(crate) fn ensure_may_consume(&self) -> Result<(), DomainError> {
        match self {
            Self::Person(control) => control.ensure_may(MessagingAction::Consume),
            Self::Consumer(authority) => {
                authority.ensure_holds(SystemPermission::Messaging(MessagingAction::Consume))
            }
        }
    }
}

/// Who makes a topic, a schema or a subscription: a person with the
/// messaging create right, or a consumer whose roles give it.
#[derive(Debug, Clone, Copy)]
pub enum MessagingCreator<'a> {
    /// A person, with what they hold.
    Person(&'a MessagingControl<'a>),
    /// A consumer that signed in, with what its roles give it.
    Consumer(&'a ConsumerAuthority),
}

impl MessagingCreator<'_> {
    /// Who made it, once they may create in messaging.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person, or the consumer's
    ///   roles, do not give the messaging create right.
    pub(crate) fn ensure_may_create(&self) -> Result<CreatedBy, DomainError> {
        match self {
            Self::Person(control) => {
                control.ensure_may(MessagingAction::Create)?;
                Ok(CreatedBy::Person(control.by().clone()))
            }
            Self::Consumer(authority) => {
                authority.ensure_holds(CONSUMER_CREATES)?;
                Ok(CreatedBy::Consumer(*authority.id()))
            }
        }
    }
}

/// Who made a topic or a schema, as it records them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreatedBy {
    /// A person, through one of their accounts.
    Person(Human),
    /// An external application authenticated with its tenant consumer credential.
    Consumer(ConsumerId),
}

impl CreatedBy {
    /// Who made it, as the actor an audit record names.
    #[must_use]
    pub fn actor(&self) -> ActorRef {
        match self {
            Self::Person(person) => ActorRef::from(person.account()),
            Self::Consumer(id) => ActorRef::Service(*id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::messaging::fixtures::holding;

    /// Publishing permission alone does not grant messaging management.
    #[test]
    fn the_publish_right_does_not_manage_topics() {
        let control = holding(&[SystemPermission::Messaging(MessagingAction::Publish)]);

        let result = control.ensure_may(MessagingAction::Manage);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Fay manages messaging. That covers archiving a topic too.
    #[test]
    fn the_full_messaging_right_covers_archiving() {
        let control = holding(&[SystemPermission::Messaging(MessagingAction::Manage)]);

        assert!(control.ensure_may(MessagingAction::Delete).is_ok());
    }

    /// A topic "billing-sync" made is audited as that service's doing, and
    /// one Fay made as hers, never the other way round.
    #[test]
    fn a_creator_is_audited_as_the_person_or_service_it_was() {
        let service = ConsumerId::new();
        let fay = holding(&[SystemPermission::Messaging(MessagingAction::Create)]);
        let by_fay = MessagingCreator::Person(&fay).ensure_may_create().unwrap();

        assert!(matches!(
            CreatedBy::Consumer(service).actor(),
            ActorRef::Service(id) if id == service
        ));
        assert_eq!(by_fay, CreatedBy::Person(fay.by().clone()));
        assert!(matches!(
            by_fay.actor(),
            ActorRef::User(_) | ActorRef::OrgUser(_)
        ));
    }
}
