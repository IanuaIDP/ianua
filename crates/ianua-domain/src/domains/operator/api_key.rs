//! Operator API keys, which let an operator's CLI and scripts act on the
//! operator plane without a password.
//!
//! Key format: `opk_{secret}`. The `opk_` prefix lets secret scanners find
//! a leaked key. Only the key's hash is kept, never the key.

use time::OffsetDateTime;

use crate::domains::operator::control::OperatorAuthority;
use crate::domains::operator::events::{OperatorApiKeyCreated, OperatorApiKeyRevoked};
use crate::domains::operator::identity::Operator;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{RaisedEvents, RaisesComplete};
use crate::shared::model::row_check::RowCheck;
use crate::types::{EventLabel, Expiry, KeyPrefix, OperatorId, Revocation, TokenHash};

/// The start every operator key's visible prefix has.
pub(crate) const OPERATOR_KEY_PREFIX: &str = "opk_";

/// What an operator gives to make a key of their own.
pub struct NewOperatorApiKey {
    /// The key's visible start, which begins with `OPERATOR_KEY_PREFIX`.
    pub key_prefix: KeyPrefix,
    /// The hash of the whole key.
    pub key_hash: TokenHash,
    /// When the key stops working, or that it never does.
    pub expires_at: Expiry,
}

/// Stored fields of an [`OperatorApiKey`], read back by repositories.
pub struct OperatorApiKeyRow {
    /// The operator the key acts for.
    pub operator_id: OperatorId,
    /// The key's visible start.
    pub key_prefix: KeyPrefix,
    /// The hash of the whole key.
    pub key_hash: TokenHash,
    /// When the key stops working, or that it never does.
    pub expires_at: Expiry,
    /// Whether it was revoked, and when.
    pub revocation: Revocation,
    /// When the key was made.
    pub created_at: OffsetDateTime,
}

/// A key an operator made for themselves, acting as them on the operator
/// plane while it works.
///
/// It acts for the operator who made it and nobody else, so a key is
/// always made and revoked by that operator. Bob cannot make a key that
/// acts as Carol, and Carol cannot quietly end the key Bob's deploy relies
/// on. An operator who sees a key misused stops it by disabling its holder,
/// which stops every key they hold at once and names who did it.
#[derive(Debug, Clone)]
pub struct OperatorApiKey {
    operator_id: OperatorId,
    key_prefix: KeyPrefix,
    key_hash: TokenHash,
    expires_at: Expiry,
    revocation: Revocation,
    created_at: OffsetDateTime,
    raised: RaisedEvents,
}

impl OperatorApiKey {
    /// Makes a new working key for the operator `by`, who asks for it and
    /// is `holder`, as stored. Raises `operator.operator_api_key_created`,
    /// naming the holder by their address.
    ///
    /// The key is always the asking operator's own. A key made through
    /// another key ends no later than it, so a leaked key cannot make one
    /// that outlives it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `holder` is not the operator `by`
    ///   acts as.
    /// - [`DomainError::Validation`] when the prefix does not begin with
    ///   `OPERATOR_KEY_PREFIX`.
    /// - [`DomainError::Validation`] when the expiry has already passed.
    /// - [`DomainError::Forbidden`] when `by` acts through a key that ends
    ///   before the new one would, or the new one would never end.
    pub fn create(
        new: NewOperatorApiKey,
        by: &OperatorAuthority,
        holder: &Operator,
    ) -> Result<Self, DomainError> {
        if holder.id() != by.operator() {
            return Err(DomainError::forbidden(message!(
                "operator-a-key-is-made-for-the",
                "a key is made for the operator who asks for it"
            )));
        }
        let mut key = Self::made(new, by)?;
        key.raised.raise_platform(OperatorApiKeyCreated {
            operator_id: key.operator_id,
            operator_label: holder.label(),
            key_prefix: key.key_prefix.clone(),
            occurred_at: key.created_at,
        });
        Ok(key)
    }

    /// The working key `new` describes, for the operator `by`, once its
    /// prefix and expiry hold.
    fn made(new: NewOperatorApiKey, by: &OperatorAuthority) -> Result<Self, DomainError> {
        if !has_operator_prefix(&new.key_prefix) {
            return Err(DomainError::invalid(message!(
                "operator-an-operator-key-s-prefix-begins",
                format!("an operator key's prefix begins with {OPERATOR_KEY_PREFIX}")
            )));
        }
        let now = crate::shared::clock::now();
        if new.expires_at.has_passed(now) {
            return Err(DomainError::invalid(message!(
                "oauth-the-key-s-expiry-has-already",
                "the key's expiry has already passed"
            )));
        }
        by.ensure_outlasts(new.expires_at)?;
        Ok(Self {
            operator_id: *by.operator(),
            key_prefix: new.key_prefix,
            key_hash: new.key_hash,
            expires_at: new.expires_at,
            revocation: Revocation::InForce,
            created_at: now,
            raised: RaisedEvents::default(),
        })
    }

    /// Rebuilds an operator API key from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row's prefix does not
    ///   begin with `OPERATOR_KEY_PREFIX`.
    /// - [`DomainError::Infrastructure`] when the row says the key expires,
    ///   or was revoked, before it was made.
    pub fn reconstitute(row: OperatorApiKeyRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            operator_id: row.operator_id,
            key_prefix: row.key_prefix,
            key_hash: row.key_hash,
            expires_at: row.expires_at,
            revocation: row.revocation,
            created_at: row.created_at,
            raised: RaisedEvents::default(),
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &OperatorApiKeyRow) -> Result<(), DomainError> {
        RowCheck::of("operator API key")
            .holds(
                has_operator_prefix(&row.key_prefix),
                "a prefix that is no operator key's",
            )
            .holds(
                row.expires_at
                    .instant()
                    .is_none_or(|at| row.created_at < at),
                "expires before it was made",
            )
            .in_order_if(
                row.created_at,
                row.revocation.revoked_at(),
                "revoked before it was made",
            )
            .finish()
    }

    /// The operator the key acts for.
    #[must_use]
    pub fn operator_id(&self) -> &OperatorId {
        &self.operator_id
    }

    /// The key's visible start, such as `opk_01J...`.
    #[must_use]
    pub fn key_prefix(&self) -> &KeyPrefix {
        &self.key_prefix
    }

    /// The hash of the whole key.
    #[must_use]
    pub fn key_hash(&self) -> &TokenHash {
        &self.key_hash
    }

    /// When the key stops working, or that it never does.
    #[must_use]
    pub fn expires_at(&self) -> Expiry {
        self.expires_at
    }

    /// Whether it was revoked, and when.
    #[must_use]
    pub fn revocation(&self) -> Revocation {
        self.revocation
    }

    /// When the key was made.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Whether the key works at `now`: it was not revoked and has not
    /// expired. It is expired from its expiry instant on.
    #[must_use]
    pub fn works_at(&self, now: OffsetDateTime) -> bool {
        !self.revocation.is_revoked() && !self.expires_at.has_passed(now)
    }

    /// Revokes the key, for the operator `by` it acts for. Irreversible.
    /// Raises `operator.operator_api_key_revoked` naming the key, with
    /// `holder_label` as the name of the operator it acted for.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is another operator.
    /// - [`DomainError::InvalidTransition`] when it is already revoked. The
    ///   first revocation time is kept.
    pub fn revoke(
        &mut self,
        by: &OperatorAuthority,
        holder_label: EventLabel,
    ) -> Result<(), DomainError> {
        self.revoke_without_event(by)?;
        self.raised.raise_platform(OperatorApiKeyRevoked {
            operator_id: self.operator_id,
            operator_label: holder_label,
            key_prefix: Some(self.key_prefix.clone()),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Revokes the key for `by` without a record of its own, for a change
    /// that records itself as a whole.
    fn revoke_without_event(&mut self, by: &OperatorAuthority) -> Result<(), DomainError> {
        if *by.operator() != self.operator_id {
            return Err(DomainError::forbidden(message!(
                "operator-only-the-operator-a-key-acts",
                "only the operator a key acts for revokes it"
            )));
        }
        if self.revocation.is_revoked() {
            return Err(DomainError::invalid_transition(message!(
                "operator-the-operator-key-is-already-revoked",
                "the operator key is already revoked"
            )));
        }
        self.revocation = Revocation::Revoked {
            at: crate::shared::clock::now(),
        };
        Ok(())
    }
}

impl RaisesComplete for OperatorApiKey {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

/// Every key an operator still had in force, revoked at once by that
/// operator, and recorded as one change.
///
/// Revoking each key on its own would write one record per key. The
/// operator did one thing, so it is one record, naming no single key.
#[derive(Debug)]
pub struct EveryKeyRevocation {
    count: u64,
    raised: RaisedEvents,
}

impl EveryKeyRevocation {
    /// Revokes each of `keys` still in force, for the operator `by` they
    /// act for, with `holder_label` naming that operator. Keys already
    /// revoked are left as they are. Raises one
    /// `operator.operator_api_key_revoked` naming no key when any was
    /// revoked, and nothing when none was.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when a key in force acts for another
    ///   operator than `by`.
    pub fn revoke<'a>(
        keys: impl IntoIterator<Item = &'a mut OperatorApiKey>,
        by: &OperatorAuthority,
        holder_label: EventLabel,
    ) -> Result<Self, DomainError> {
        let mut count: u64 = 0;
        for key in keys.into_iter().filter(|key| !key.revocation.is_revoked()) {
            key.revoke_without_event(by)?;
            count = count.saturating_add(1);
        }
        let mut revocation = Self {
            count,
            raised: RaisedEvents::default(),
        };
        if count > 0 {
            revocation.raised.raise_platform(OperatorApiKeyRevoked {
                operator_id: *by.operator(),
                operator_label: holder_label,
                key_prefix: None,
                occurred_at: crate::shared::clock::now(),
            });
        }
        Ok(revocation)
    }

    /// How many keys were revoked.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.count
    }
}

impl RaisesComplete for EveryKeyRevocation {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

/// Whether `prefix` begins as every operator key's does.
fn has_operator_prefix(prefix: &KeyPrefix) -> bool {
    prefix.as_str().starts_with(OPERATOR_KEY_PREFIX)
}

#[cfg(test)]
pub(crate) mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::operator::control::tests::operator_named;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::raised_complete_names;

    fn new_key(prefix: &str, expires_at: Expiry) -> NewOperatorApiKey {
        NewOperatorApiKey {
            key_prefix: KeyPrefix::new(prefix).unwrap(),
            key_hash: TokenHash::from_stored("hash".to_owned()),
            expires_at,
        }
    }

    /// `operator` acting through their password.
    fn acting(operator: &Operator) -> OperatorAuthority {
        OperatorAuthority::assumed(*operator.id())
    }

    /// A working key `operator` made, ending at `expires_at`.
    pub(crate) fn key_of(operator: &Operator, expires_at: Expiry) -> OperatorApiKey {
        OperatorApiKey::create(new_key("opk_01J", expires_at), &acting(operator), operator).unwrap()
    }

    fn row_of(key: &OperatorApiKey) -> OperatorApiKeyRow {
        OperatorApiKeyRow {
            operator_id: key.operator_id,
            key_prefix: key.key_prefix.clone(),
            key_hash: key.key_hash.clone(),
            expires_at: key.expires_at,
            revocation: key.revocation,
            created_at: key.created_at,
        }
    }

    fn now() -> OffsetDateTime {
        crate::shared::clock::now()
    }

    /// Bob makes a key for his CLI. It acts for Bob, keeps only the hash,
    /// and works at once.
    #[test]
    fn a_new_key_is_its_makers_and_works() {
        let bob = operator_named("bob");

        let key = key_of(&bob, Expiry::Never);

        assert_eq!(key.operator_id(), bob.id());
        assert_eq!(key.key_hash().as_str(), "hash");
        assert!(key.works_at(now()));
    }

    /// Creating an operator key with the organization-key prefix is rejected
    /// as invalid input.
    #[test]
    fn a_key_without_the_operator_prefix_is_refused() {
        let bob = operator_named("bob");

        let made = OperatorApiKey::create(new_key("oak_01J", Expiry::Never), &acting(&bob), &bob);

        assert!(matches!(made, Err(DomainError::Validation(_))));
    }

    /// Bob makes a key that ended an hour ago. It is refused, since it
    /// could never be used.
    #[test]
    fn a_key_that_has_already_ended_is_refused() {
        let bob = operator_named("bob");
        let ended = Expiry::At(now() - Duration::hours(1));

        let made = OperatorApiKey::create(new_key("opk_01J", ended), &acting(&bob), &bob);

        assert!(matches!(made, Err(DomainError::Validation(_))));
    }

    /// A key expiring tomorrow cannot create a nonexpiring key, but it can
    /// create one that expires twelve hours sooner.
    #[test]
    fn a_key_made_through_a_key_ends_no_later_than_it() {
        let bob = operator_named("bob");
        let tomorrow = now() + Duration::days(1);
        let leaked = key_of(&bob, Expiry::At(tomorrow));
        let through_leaked = OperatorAuthority::of_key(&bob, &leaked, now()).unwrap();
        let today = Expiry::At(tomorrow - Duration::hours(12));

        let forever =
            OperatorApiKey::create(new_key("opk_02J", Expiry::Never), &through_leaked, &bob);
        let shorter = OperatorApiKey::create(new_key("opk_03J", today), &through_leaked, &bob);

        assert!(matches!(forever, Err(DomainError::Forbidden(_))));
        assert!(shorter.is_ok());
    }

    /// Bob revokes his key. It stops working, and revoking it again is
    /// refused with the first time kept.
    #[test]
    fn a_revoked_key_stops_working_and_stays_revoked_once() {
        let bob = operator_named("bob");
        let mut key = key_of(&bob, Expiry::Never);
        key.revoke(&acting(&bob), bob.label()).unwrap();
        let first = key.revocation().revoked_at();

        let again = key.revoke(&acting(&bob), bob.label());

        assert!(!key.works_at(now()));
        assert!(matches!(again, Err(DomainError::InvalidTransition(_))));
        assert_eq!(key.revocation().revoked_at(), first);
    }

    /// Carol cannot revoke Bob's API key, which remains usable after her
    /// request is rejected.
    #[test]
    fn only_the_operator_a_key_acts_for_revokes_it() {
        let bob = operator_named("bob");
        let carol = operator_named("carol");
        let mut key = key_of(&bob, Expiry::Never);

        let revoked = key.revoke(&acting(&carol), carol.label());

        assert!(matches!(revoked, Err(DomainError::Forbidden(_))));
        assert!(key.works_at(now()));
    }

    /// Bob's key is stored and read back. It reads back as it was.
    #[test]
    fn a_stored_key_reads_back() {
        let key = key_of(&operator_named("bob"), Expiry::Never);

        let read = OperatorApiKey::reconstitute(row_of(&key)).unwrap();

        assert_eq!(read.key_prefix(), key.key_prefix());
        assert_eq!(read.created_at(), key.created_at());
    }

    /// An operator key stored with an organization-key prefix is rejected
    /// as corrupt during reconstitution.
    #[test]
    fn a_stored_key_without_the_operator_prefix_is_refused() {
        let key = key_of(&operator_named("bob"), Expiry::Never);
        let row = OperatorApiKeyRow {
            key_prefix: KeyPrefix::new("oak_01J").unwrap(),
            ..row_of(&key)
        };

        assert!(refused_as_corrupt(&OperatorApiKey::reconstitute(row)));
    }

    /// A stored key says it expired, or was revoked, before it was made.
    /// Loading either is refused as a corrupt row.
    #[test]
    fn a_stored_key_ending_before_it_was_made_is_refused() {
        let key = key_of(&operator_named("bob"), Expiry::Never);
        let before = key.created_at() - Duration::seconds(1);
        let expired = OperatorApiKeyRow {
            expires_at: Expiry::At(before),
            ..row_of(&key)
        };
        let revoked = OperatorApiKeyRow {
            revocation: Revocation::Revoked { at: before },
            ..row_of(&key)
        };

        assert!(refused_as_corrupt(&OperatorApiKey::reconstitute(expired)));
        assert!(refused_as_corrupt(&OperatorApiKey::reconstitute(revoked)));
    }

    /// The `key_prefix` a record of `events` carries.
    fn prefix_in(events: &[DomainEvent]) -> Option<String> {
        events[0].payload().get("key_prefix").map(str::to_owned)
    }

    /// Bob makes a key. The creation is raised, naming the key.
    #[test]
    fn making_a_key_raises_operator_api_key_created() {
        let mut key = key_of(&operator_named("bob"), Expiry::Never);

        let events = key.take_events();

        assert_eq!(
            events[0].event_type().to_string(),
            "operator.operator_api_key_created"
        );
        assert_eq!(prefix_in(&events).as_deref(), Some("opk_01J"));
    }

    /// Bob cannot create an API key while naming Carol as its holder.
    #[test]
    fn a_key_for_another_holder_is_refused() {
        let bob = operator_named("bob");
        let carol = operator_named("carol");

        let made = OperatorApiKey::create(new_key("opk_01J", Expiry::Never), &acting(&bob), &carol);

        assert!(matches!(made, Err(DomainError::Forbidden(_))));
    }

    /// Bob revokes his key. The revocation is raised, naming the key.
    #[test]
    fn revoking_a_key_raises_operator_api_key_revoked() {
        let bob = operator_named("bob");
        let mut key = key_of(&bob, Expiry::Never);
        raised_complete_names(&mut key);

        key.revoke(&acting(&bob), bob.label()).unwrap();

        let events = key.take_events();
        assert_eq!(
            events[0].event_type().to_string(),
            "operator.operator_api_key_revoked"
        );
        assert_eq!(prefix_in(&events).as_deref(), Some("opk_01J"));
    }

    /// Carol's revocation of Bob's key is rejected; after Bob revokes it,
    /// a second revocation also fails and raises no further event.
    #[test]
    fn a_refused_revocation_raises_nothing() {
        let bob = operator_named("bob");
        let carol = operator_named("carol");
        let mut key = key_of(&bob, Expiry::Never);
        let by_carol = key.revoke(&acting(&carol), carol.label());
        key.revoke(&acting(&bob), bob.label()).unwrap();
        raised_complete_names(&mut key);

        let again = key.revoke(&acting(&bob), bob.label());

        assert!(by_carol.is_err());
        assert!(again.is_err());
        assert!(raised_complete_names(&mut key).is_empty());
    }

    /// Bob's key is read back from storage. Loading it is no change, so it
    /// has raised nothing.
    #[test]
    fn a_key_read_back_from_storage_has_raised_nothing() {
        let key = key_of(&operator_named("bob"), Expiry::Never);

        let mut read = OperatorApiKey::reconstitute(row_of(&key)).unwrap();

        assert!(raised_complete_names(&mut read).is_empty());
    }

    /// Bob holds two keys in force and one he revoked earlier, and revokes
    /// them all. Both in force go, and one record naming no single key is
    /// raised.
    #[test]
    fn revoking_every_key_raises_one_record_naming_no_key() {
        let bob = operator_named("bob");
        let mut revoked_before = key_of(&bob, Expiry::Never);
        revoked_before.revoke(&acting(&bob), bob.label()).unwrap();
        let mut keys = [
            key_of(&bob, Expiry::Never),
            key_of(&bob, Expiry::Never),
            revoked_before,
        ];

        let mut revocation =
            EveryKeyRevocation::revoke(keys.iter_mut(), &acting(&bob), bob.label()).unwrap();

        let events = revocation.take_events();
        assert_eq!(revocation.count(), 2);
        assert!(keys.iter().all(|key| !key.works_at(now())));
        assert_eq!(events.len(), 1);
        assert_eq!(prefix_in(&events).as_deref(), Some("*"));
    }

    /// Bob holds no key in force and revokes them all. Nothing changed, so
    /// nothing is raised.
    #[test]
    fn revoking_every_key_of_none_raises_nothing() {
        let bob = operator_named("bob");

        let mut revocation =
            EveryKeyRevocation::revoke(Vec::new(), &acting(&bob), bob.label()).unwrap();

        assert_eq!(revocation.count(), 0);
        assert!(raised_complete_names(&mut revocation).is_empty());
    }

    /// Carol's bulk revocation rejects Bob's key and leaves that key usable.
    #[test]
    fn revoking_every_key_of_another_operator_is_refused() {
        let bob = operator_named("bob");
        let carol = operator_named("carol");
        let mut keys = [key_of(&bob, Expiry::Never)];

        let refused = EveryKeyRevocation::revoke(keys.iter_mut(), &acting(&carol), carol.label());

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(keys[0].works_at(now()));
    }
}
