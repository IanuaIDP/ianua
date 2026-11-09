//! What a consumer holds when it acts, worked out from the tenant's records.
//!
//! A consumer makes topics, schemas and subscriptions of its own. Each one
//! names it as its creator and needs the right for it. If the caller wrote
//! the consumer's id, any service could make things in another's name. If
//! nobody read its roles, "billing-sync", given only the right to publish,
//! would make topics and subscribe to whatever it liked.

use crate::domains::authorization::authority::{Holdings, TenantAccess};
use crate::domains::authorization::permission::SystemPermission;
use crate::domains::consumers::consumer::Consumer;
use crate::domains::consumers::sign_in::ConsumerSignIn;
use crate::domains::data_classification::level::DataClassLevel;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{ConsumerId, Expiry, PrincipalRef};

/// An active consumer acting in its tenant, with what its roles give it now
/// and the most sensitive data it may receive.
///
/// Only [`ConsumerAuthority::of`] makes one, from the consumer, its sign-in
/// and the tenant's records. Its fields are private, so no caller names
/// another consumer, adds a right or raises its clearance.
#[derive(Debug, Clone)]
pub struct ConsumerAuthority {
    consumer: ConsumerId,
    holdings: Holdings,
    clearance: DataClassLevel,
    until: Expiry,
}

impl ConsumerAuthority {
    /// `consumer`, which signed in as `signed_in` shows, acting with what
    /// its roles in `access` give it.
    ///
    /// A request naming "billing-sync" acts as it only once its own
    /// credential was checked. Without the proof, any caller would make
    /// topics and subscriptions in its name.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `signed_in` is another consumer's.
    /// - [`DomainError::Forbidden`] when the consumer is disabled.
    /// - [`DomainError::Infrastructure`] when the records name a role or
    ///   group that is not there.
    pub fn of<T: TenantScope>(
        consumer: &Consumer<T>,
        signed_in: &ConsumerSignIn,
        access: &TenantAccess<'_, T>,
    ) -> Result<Self, DomainError> {
        if signed_in.consumer() != consumer.id() {
            return Err(DomainError::forbidden(message!(
                "consumers-the-sign-in-was-another-consumer",
                "the sign-in was another consumer's"
            )));
        }
        if !consumer.is_active() {
            return Err(DomainError::forbidden(message!(
                "consumers-a-disabled-consumer-may-not-act",
                "a disabled consumer may not act"
            )));
        }
        Ok(Self {
            consumer: *consumer.id(),
            holdings: access.standing_of(PrincipalRef::Consumer(*consumer.id()))?,
            clearance: consumer.clearance(),
            until: signed_in.until(),
        })
    }

    /// When the credential it signed in with stops working, as its sign-in
    /// found it.
    #[must_use]
    pub fn until(&self) -> Expiry {
        self.until
    }

    /// The consumer acting.
    #[must_use]
    pub fn id(&self) -> &ConsumerId {
        &self.consumer
    }

    /// The most sensitive data it may receive, as the consumer stores it.
    #[must_use]
    pub fn clearance(&self) -> DataClassLevel {
        self.clearance
    }

    /// Whether its roles give `right`, as it is or through a wider
    /// permission.
    #[must_use]
    pub fn holds(&self, right: SystemPermission) -> bool {
        self.holdings
            .handout()
            .system
            .iter()
            .any(|held| held.implies(&right))
    }

    /// Refuses unless its roles give `right`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when they do not.
    pub fn ensure_holds(&self, right: SystemPermission) -> Result<(), DomainError> {
        if self.holds(right) {
            return Ok(());
        }
        Err(DomainError::forbidden(message!(
            "authorization-this-needs",
            format!("this needs {right}")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::{ConsumersAction, MessagingAction};
    use crate::domains::consumers::fixtures::{
        ConsumerRecords, billing_sync, key_sign_in, sam_holding,
    };

    const PUBLISH: SystemPermission = SystemPermission::Messaging(MessagingAction::Publish);
    const CREATE: SystemPermission = SystemPermission::Messaging(MessagingAction::Create);

    /// "billing-sync" holds a role that may publish. Its authority names it
    /// and holds publishing, and nothing its roles do not give. It carries
    /// the clearance the consumer stores.
    #[test]
    fn a_consumer_holds_what_its_roles_give() {
        let consumer = billing_sync();
        let records = ConsumerRecords::consumer_holding(consumer.id(), &[PUBLISH]);

        let authority =
            ConsumerAuthority::of(&consumer, &key_sign_in(&consumer), &records.access()).unwrap();

        assert_eq!(authority.id(), consumer.id());
        assert_eq!(authority.clearance(), consumer.clearance());
        assert!(authority.holds(PUBLISH));
        assert!(matches!(
            authority.ensure_holds(CREATE),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// Disabling a consumer prevents its existing sign-in proof from
    /// producing authority, even when its roles permit creating topics.
    #[test]
    fn a_disabled_consumer_gets_no_authority() {
        let mut consumer = billing_sync();
        let signed_in = key_sign_in(&consumer);
        let admin = sam_holding(&[SystemPermission::Consumers(ConsumersAction::Update)]);
        consumer.disable(&admin).unwrap();
        let records = ConsumerRecords::consumer_holding(consumer.id(), &[CREATE]);

        let authority = ConsumerAuthority::of(&consumer, &signed_in, &records.access());

        assert!(matches!(authority, Err(DomainError::Forbidden(_))));
    }

    /// A sign-in proof for another consumer cannot produce authority for
    /// billing-sync's roles.
    #[test]
    fn another_consumers_sign_in_gives_no_authority() {
        let consumer = billing_sync();
        let cron_job = billing_sync();
        let records = ConsumerRecords::consumer_holding(consumer.id(), &[CREATE]);

        let authority =
            ConsumerAuthority::of(&consumer, &key_sign_in(&cron_job), &records.access());

        assert!(matches!(authority, Err(DomainError::Forbidden(_))));
    }

    /// A consumer nobody gave a role holds nothing.
    #[test]
    fn a_consumer_without_roles_holds_nothing() {
        let consumer = billing_sync();
        let records = ConsumerRecords::empty();

        let authority =
            ConsumerAuthority::of(&consumer, &key_sign_in(&consumer), &records.access()).unwrap();

        assert!(!authority.holds(PUBLISH));
    }
}
