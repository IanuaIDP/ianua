//! Who acts in messaging: a person in their tenant, or a consumer that
//! signed in with its own credential.
//!
//! Topics, schemas and subscriptions are made by either, and messages are
//! published and pulled by either. Each records who it was, so the caller
//! is worked out once into what the domain asks for.

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::domains::consumers::authority::ConsumerAuthority;
use ianua_domain::domains::messaging::control::{
    MessagingControl, MessagingCreator, MessagingReader,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ActorRef, HumanAccount};

use crate::acting::{ConsumerAuthorities, TenantAuthorities};
use crate::context::{CallerContext, ConsumerCaller};
use crate::error::AppError;
use crate::tenancy::ScopedTenant;

/// Who calls a messaging use case open to people and consumers alike.
// A caller is made once per request and only ever lent out, so the size of
// the person's context costs one copy, not one per call.
#[allow(clippy::large_enum_variant)]
pub enum MessagingCaller {
    /// A person acting in their tenant.
    Person(CallerContext),
    /// A consumer calling with its own credential.
    Consumer(ConsumerCaller),
}

impl MessagingCaller {
    /// The tenant the caller acts in.
    #[must_use]
    pub fn tenant(&self) -> ScopedTenant {
        match self {
            Self::Person(caller) => caller.tenant(),
            Self::Consumer(caller) => *caller.tenant(),
        }
    }
}

/// A messaging caller, worked out into what the domain asks for.
pub(crate) enum MessagingActor {
    /// A person, with what they hold in the tenant now.
    Person(TenantAuthority),
    /// A consumer that signed in, with what its roles give it now.
    Consumer(ConsumerAuthority),
}

impl MessagingActor {
    /// What `caller` acts with: a person's authority from `people`, or a
    /// consumer's from its own sign-in through `consumers`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the session, key or credential no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not act in the tenant.
    /// - `AppError::Internal` when a store fails.
    pub(crate) async fn of(
        caller: &MessagingCaller,
        people: &dyn TenantAuthorities,
        consumers: &dyn ConsumerAuthorities,
    ) -> Result<Self, AppError> {
        match caller {
            MessagingCaller::Person(caller) => Ok(Self::Person(people.authority(caller).await?)),
            MessagingCaller::Consumer(caller) => {
                Ok(Self::Consumer(consumers.authority(caller).await?))
            }
        }
    }

    /// What `make` builds with the actor as the creator the domain records.
    ///
    /// # Errors
    ///
    /// Whatever `make` refuses, as an app error.
    pub(crate) fn creating<R>(
        &self,
        make: impl FnOnce(MessagingCreator<'_>) -> Result<R, DomainError>,
    ) -> Result<R, AppError> {
        let made = match self {
            Self::Person(authority) => {
                let control = MessagingControl::new(authority);
                make(MessagingCreator::Person(&control))
            }
            Self::Consumer(authority) => make(MessagingCreator::Consumer(authority)),
        };
        made.map_err(AppError::from_domain)
    }

    /// What `check` answers with the actor as the reader the domain hands
    /// messages to.
    ///
    /// # Errors
    ///
    /// Whatever `check` refuses, as an app error.
    pub(crate) fn reading<R>(
        &self,
        check: impl FnOnce(MessagingReader<'_>) -> Result<R, DomainError>,
    ) -> Result<R, AppError> {
        let checked = match self {
            Self::Person(authority) => {
                let control = MessagingControl::new(authority);
                check(MessagingReader::Person(&control))
            }
            Self::Consumer(authority) => check(MessagingReader::Consumer(authority)),
        };
        checked.map_err(AppError::from_domain)
    }

    /// Refuses unless the person holds `right`, or the consumer's roles
    /// give it.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when they do not.
    pub(crate) fn ensure_holds(&self, right: SystemPermission) -> Result<(), AppError> {
        match self {
            Self::Person(authority) => authority.ensure_holds(right),
            Self::Consumer(authority) => authority.ensure_holds(right),
        }
        .map_err(AppError::from_domain)
    }

    /// The actor an audit record names.
    pub(crate) fn actor(&self) -> ActorRef {
        match self {
            Self::Person(authority) => match authority.who().account() {
                HumanAccount::User(id) => ActorRef::User(id),
                HumanAccount::OrgUser(id) => ActorRef::OrgUser(id),
            },
            Self::Consumer(authority) => ActorRef::Service(*authority.id()),
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::MessagingAction;

    use super::*;
    use crate::test_support::acting::{FakeConsumerAuthorities, FakeTenantAuthorities, Refusal};
    use crate::test_support::consumers::{key_caller, test_key_digest};
    use crate::test_support::{block_on, test_ctx};

    const PUBLISH: SystemPermission = SystemPermission::Messaging(MessagingAction::Publish);

    fn actor_of(caller: &MessagingCaller, people: &FakeTenantAuthorities) -> MessagingActor {
        let consumers = FakeConsumerAuthorities::holding(&[PUBLISH]);
        block_on(MessagingActor::of(caller, people, &consumers)).unwrap()
    }

    /// Ann publishes from the dashboard. She acts with what she holds, and
    /// the record names her.
    #[test]
    fn a_person_acts_with_what_they_hold() {
        let caller = MessagingCaller::Person(test_ctx());

        let actor = actor_of(&caller, &FakeTenantAuthorities::holding(&[PUBLISH]));

        assert!(actor.ensure_holds(PUBLISH).is_ok());
        assert!(matches!(actor.actor(), ActorRef::User(_)));
    }

    /// "billing-sync" publishes with its own key. It acts with what its
    /// role gives it, and the record names it as a service.
    #[test]
    fn a_consumer_acts_with_what_its_roles_give() {
        let caller = MessagingCaller::Consumer(key_caller(test_key_digest()));

        let actor = actor_of(
            &caller,
            &FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        assert!(actor.ensure_holds(PUBLISH).is_ok());
        assert!(matches!(actor.actor(), ActorRef::Service(_)));
    }
}
