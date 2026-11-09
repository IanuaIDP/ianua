//! The consumer aggregate: a non-human caller a tenant lets through the
//! gateway.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authorization::permission::ConsumersAction;
use crate::domains::consumers::control::ConsumerControl;
use crate::domains::consumers::credential::ConsumerCredentialKind;
use crate::domains::consumers::credentials::{
    ConsumerCredentials, CredentialRotation, HeldCredential, PreviousCredential,
};
use crate::domains::consumers::events::{
    ConsumerClearanceChanged, ConsumerCreated, ConsumerCredentialExpiryChanged,
    ConsumerCredentialOverlapEnded, ConsumerCredentialRotated, ConsumerDeleted,
    ConsumerDescriptionChanged, ConsumerDisabled, ConsumerEnabled, ConsumerQuotaChanged,
    ConsumerRenamed,
};
use crate::domains::consumers::quota::ConsumerQuota;
use crate::domains::consumers::takeover::ConsumerTakeover;
use crate::domains::data_classification::level::DataClassLevel;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::shared::model::transition::{InvalidTransition, checked};
use crate::types::{ActorRef, ConsumerId, EventLabel, Expiry, Issuer, Label, Setting};

/// Whether a consumer may send traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ConsumerStatus {
    /// Its requests go through.
    Active,
    /// Every request it sends is denied.
    Disabled,
}

impl ConsumerStatus {
    /// Moves to `to`. Active and disabled swap.
    ///
    /// # Errors
    ///
    /// - [`InvalidTransition`] when the consumer is already in `to`.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
        checked(self, to, |from, to| from != to)
    }
}

/// What a new consumer is made from.
pub struct CreateConsumerParams {
    /// Display name, such as `"payment-processor"`.
    pub name: Label,
    /// A description, when given.
    pub description: Option<Label>,
    /// How it signs in.
    pub credential: ConsumerCredentialKind,
    /// When its credential stops working.
    pub credential_expiry: Expiry,
    /// How many requests it may send.
    pub quota: ConsumerQuota,
    /// The most sensitive data it may receive.
    pub clearance: DataClassLevel,
}

/// A consumer as storage keeps it, checked again by
/// [`Consumer::reconstitute`].
pub struct ConsumerRow {
    /// The consumer's id.
    pub id: ConsumerId,
    /// Display name.
    pub name: Label,
    /// A description, when given.
    pub description: Option<Label>,
    /// The credential it signs in with.
    pub credential: HeldCredential,
    /// The credential it used before its last rotation, while it still
    /// works.
    pub previous_credential: PreviousCredential,
    /// How many requests it may send.
    pub quota: ConsumerQuota,
    /// Current status.
    pub status: ConsumerStatus,
    /// The most sensitive data it may receive.
    pub clearance: DataClassLevel,
    /// Who created this consumer.
    pub created_by: ActorRef,
    /// When created.
    pub created_at: OffsetDateTime,
    /// When last modified.
    pub updated_at: OffsetDateTime,
}

/// A non-human caller in one tenant.
///
/// It is read and written only through stores opened for its tenant. See
/// [`crate::isolation`].
///
/// A consumer has a credential and a status, and nothing about what it may
/// reach. It is a [`PrincipalRef`](crate::types::PrincipalRef), so its rights
/// are the roles it is given. People, org users and agents get theirs the
/// same way.
#[derive(Debug, Clone)]
pub struct Consumer<T: TenantScope> {
    id: ConsumerId,
    name: Label,
    description: Option<Label>,
    credentials: ConsumerCredentials,
    quota: ConsumerQuota,
    status: ConsumerStatus,
    clearance: DataClassLevel,
    created_by: ActorRef,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> Consumer<T> {
    /// Creates an active consumer in a tenant whose own token issuer is
    /// `tenant_issuer`, recording the person `control` names as its
    /// creator. A new consumer holds no role, so this needs only the create
    /// right. Raises `consumers.consumer_created`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not create
    ///   consumers.
    /// - [`DomainError::Forbidden`] when the consumer's clearance is above
    ///   the person's own.
    /// - [`DomainError::Forbidden`] when the credential trusts tokens from
    ///   `tenant_issuer`. See [`ConsumerCredentialKind::ensure_foreign_to`].
    /// - [`DomainError::Validation`] when the credential's expiry has already
    ///   passed.
    pub fn create(
        params: CreateConsumerParams,
        tenant_issuer: &Issuer,
        control: &ConsumerControl<'_>,
    ) -> Result<Self, DomainError> {
        control.ensure_may(ConsumersAction::Create)?;
        control.ensure_may_clear(params.clearance)?;
        params.credential.ensure_foreign_to(tenant_issuer)?;
        let credentials = ConsumerCredentials::issue(params.credential, params.credential_expiry)?;
        let now = crate::shared::clock::now();
        let mut consumer = Self {
            id: ConsumerId::new(),
            name: params.name,
            description: params.description,
            credentials,
            quota: params.quota,
            status: ConsumerStatus::Active,
            clearance: params.clearance,
            created_by: control.actor(),
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        consumer.raised.raise(ConsumerCreated {
            consumer_id: consumer.id,
            consumer_label: consumer.label(),
            occurred_at: now,
        });
        Ok(consumer)
    }

    /// Rebuilds a consumer from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the consumer
    ///   changed before it was created.
    /// - [`DomainError::Infrastructure`] when it keeps a previous credential
    ///   that is the current one, or an overlap that ends before the
    ///   consumer was made or longer after its last change than a rotation
    ///   allows.
    pub fn reconstitute(row: ConsumerRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            name: row.name,
            description: row.description,
            credentials: ConsumerCredentials::stored(row.credential, row.previous_credential),
            quota: row.quota,
            status: row.status,
            clearance: row.clearance,
            created_by: row.created_by,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &ConsumerRow) -> Result<(), DomainError> {
        RowCheck::of("consumer")
            .holds(
                ConsumerCredentials::stored_parts_fit(
                    &row.credential,
                    &row.previous_credential,
                    row.created_at,
                    row.updated_at,
                ),
                "a kept credential its rotation could not have left",
            )
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was created",
            )
            .finish()
    }

    /// The consumer's id.
    #[must_use]
    pub fn id(&self) -> &ConsumerId {
        &self.id
    }

    /// Display name.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// The description, when given.
    #[must_use]
    pub fn description(&self) -> Option<&Label> {
        self.description.as_ref()
    }

    /// How it signs in with its current credential.
    #[must_use]
    pub fn credential(&self) -> &ConsumerCredentialKind {
        self.credentials.current().kind()
    }

    /// Its current credential, with its expiry, and the previous one while
    /// an overlap lasts.
    #[must_use]
    pub fn credentials(&self) -> &ConsumerCredentials {
        &self.credentials
    }

    /// How many requests it may send.
    #[must_use]
    pub fn quota(&self) -> ConsumerQuota {
        self.quota
    }

    /// Current status.
    #[must_use]
    pub fn status(&self) -> ConsumerStatus {
        self.status
    }

    /// Whether this consumer is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == ConsumerStatus::Active
    }

    /// The most sensitive data it may receive.
    ///
    /// A topic classed above it takes no subscription for it, whoever
    /// makes the subscription.
    #[must_use]
    pub fn clearance(&self) -> DataClassLevel {
        self.clearance
    }

    /// Changes the most sensitive data it may receive.
    ///
    /// Raising it lets the consumer subscribe to topics it could not reach
    /// before, as granting a role would. So this needs the full consumers
    /// right. Sam may update consumers. Without this check, he clears
    /// "billing-sync" for restricted data and subscribes it to salaries.
    /// Raises `consumers.clearance_changed` when the clearance moves;
    /// clearing it for what it already has raises nothing.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person does not manage
    ///   consumers.
    /// - [`DomainError::Forbidden`] when `clearance` is above the person's
    ///   own.
    pub fn change_clearance(
        &mut self,
        clearance: DataClassLevel,
        control: &ConsumerControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(ConsumersAction::Manage)?;
        control.ensure_may_clear(clearance)?;
        let previous = std::mem::replace(&mut self.clearance, clearance);
        self.updated_at = crate::shared::clock::now();
        if previous == clearance {
            return Ok(());
        }
        self.raised.raise(ConsumerClearanceChanged {
            consumer_id: self.id,
            consumer_label: self.label(),
            previous,
            current: clearance,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Who created this consumer.
    #[must_use]
    pub fn created_by(&self) -> &ActorRef {
        &self.created_by
    }

    /// Disables the consumer. All requests using its credentials are denied.
    /// Raises `consumers.consumer_disabled`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not update
    ///   consumers.
    /// - [`DomainError::InvalidTransition`] when it is already disabled.
    pub fn disable(&mut self, control: &ConsumerControl<'_>) -> Result<(), DomainError> {
        self.move_to(ConsumerStatus::Disabled, control)?;
        self.raised.raise(ConsumerDisabled {
            consumer_id: self.id,
            consumer_label: self.label(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Re-enables a disabled consumer. Raises `consumers.consumer_enabled`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not update
    ///   consumers.
    /// - [`DomainError::InvalidTransition`] when it is already active.
    pub fn enable(&mut self, control: &ConsumerControl<'_>) -> Result<(), DomainError> {
        self.move_to(ConsumerStatus::Active, control)?;
        self.raised.raise(ConsumerEnabled {
            consumer_id: self.id,
            consumer_label: self.label(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    fn move_to(
        &mut self,
        to: ConsumerStatus,
        control: &ConsumerControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(ConsumersAction::Update)?;
        self.status = self.status.try_transition(to)?;
        self.updated_at = crate::shared::clock::now();
        Ok(())
    }

    /// Replaces the credential with a new one, keeping the old one working
    /// for the overlap `rotation` asks, so callers can move over.
    ///
    /// Whoever sets it can sign in as this consumer with every role it
    /// holds, so `takeover` must have been worked out for this consumer.
    /// [`ConsumerTakeover::of`] checks the person holds all it holds.
    /// Raises `consumers.credential_rotated` with when the old one stops.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `takeover` was worked out for
    ///   another consumer.
    /// - [`DomainError::Forbidden`] when the new credential trusts tokens
    ///   from `tenant_issuer`, as in [`Self::create`].
    /// - [`DomainError::Validation`] when the new credential is the current
    ///   one, has already expired, or the overlap is longer than
    ///   `MAX_OVERLAP`.
    pub fn rotate_credential(
        &mut self,
        rotation: CredentialRotation,
        tenant_issuer: &Issuer,
        takeover: &ConsumerTakeover<'_>,
    ) -> Result<(), DomainError> {
        takeover.ensure_for(&self.id)?;
        rotation.credential.ensure_foreign_to(tenant_issuer)?;
        self.credentials = self.credentials.rotated(rotation)?;
        self.updated_at = crate::shared::clock::now();
        self.raised.raise(ConsumerCredentialRotated {
            consumer_id: self.id,
            consumer_label: self.label(),
            previous_works_until: self.credentials.previous_works_until(self.updated_at),
            expiry: self.credentials.current().expiry(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Stops the previous credential before its overlap runs out, once every
    /// caller moved to the new one. Raises
    /// `consumers.credential_overlap_ended`.
    ///
    /// It only takes access away, so the update right is enough.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not update
    ///   consumers.
    /// - [`DomainError::InvalidTransition`] when no previous credential is
    ///   kept.
    pub fn end_credential_overlap(
        &mut self,
        control: &ConsumerControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(ConsumersAction::Update)?;
        self.credentials = self.credentials.without_previous()?;
        self.updated_at = crate::shared::clock::now();
        self.raised.raise(ConsumerCredentialOverlapEnded {
            consumer_id: self.id,
            consumer_label: self.label(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Changes when the current credential stops working. Raises
    /// `consumers.credential_expiry_changed` with both expiries.
    ///
    /// A later expiry keeps a credential working that would have stopped,
    /// much as issuing it again would. So this needs the full consumers
    /// right. Sam may update consumers. Without this, he keeps a
    /// contractor's key working for years.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person does not manage
    ///   consumers.
    /// - [`DomainError::Validation`] when `expiry` has already passed.
    pub fn change_credential_expiry(
        &mut self,
        expiry: Expiry,
        control: &ConsumerControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(ConsumersAction::Manage)?;
        let previous = self.credentials.current().expiry();
        self.credentials = self.credentials.expiring(expiry)?;
        self.updated_at = crate::shared::clock::now();
        self.raised.raise(ConsumerCredentialExpiryChanged {
            consumer_id: self.id,
            consumer_label: self.label(),
            previous,
            current: expiry,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Changes how many requests the consumer may send.
    ///
    /// A larger quota lets it send more than its contract paid for, so this
    /// needs the full consumers right. Raises `consumers.quota_changed` when
    /// the quota moves; setting the one it has raises nothing.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person does not manage
    ///   consumers.
    pub fn change_quota(
        &mut self,
        quota: ConsumerQuota,
        control: &ConsumerControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(ConsumersAction::Manage)?;
        let previous = std::mem::replace(&mut self.quota, quota);
        self.updated_at = crate::shared::clock::now();
        if previous == quota {
            return Ok(());
        }
        self.raised.raise(ConsumerQuotaChanged {
            consumer_id: self.id,
            consumer_label: self.label(),
            previous,
            current: quota,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Updates the display name. Raises `consumers.consumer_renamed`, which
    /// keeps both names.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not update
    ///   consumers.
    pub fn rename(
        &mut self,
        name: Label,
        control: &ConsumerControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(ConsumersAction::Update)?;
        let previous = std::mem::replace(&mut self.name, name);
        self.updated_at = crate::shared::clock::now();
        self.raised.raise(ConsumerRenamed {
            consumer_id: self.id,
            previous_name: EventLabel::of(previous.as_str()),
            current_name: self.label(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Describes the consumer as `description` says, or leaves it without a
    /// description when unset. Raises `consumers.description_changed` when
    /// that changed it; setting the one it has raises nothing.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not update
    ///   consumers.
    pub fn change_description(
        &mut self,
        description: Setting<Label>,
        control: &ConsumerControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(ConsumersAction::Update)?;
        let description = match description {
            Setting::Set(label) => Some(label),
            Setting::Unset => None,
        };
        if description == self.description {
            return Ok(());
        }
        self.description = description;
        self.updated_at = crate::shared::clock::now();
        self.raised.raise(ConsumerDescriptionChanged {
            consumer_id: self.id,
            consumer_label: self.label(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Deletes this consumer once the person may delete consumers and it is
    /// disabled. Raises `consumers.consumer_deleted`, taken once the
    /// consumer is removed from storage.
    ///
    /// A consumer is disabled first, so its credential is refused, and the
    /// services relying on it are seen to fail, before it is gone. Sam
    /// deletes "billing-sync" in one slip. Without the order, the payroll
    /// run that calls it stops with nobody having seen it coming.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not delete
    ///   consumers.
    /// - [`DomainError::Forbidden`] while the consumer is active.
    pub fn delete(&mut self, control: &ConsumerControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(ConsumersAction::Delete)?;
        if self.is_active() {
            return Err(DomainError::forbidden(message!(
                "consumers-a-consumer-is-disabled-before-it",
                "a consumer is disabled before it is deleted"
            )));
        }
        self.raised.raise(ConsumerDeleted {
            consumer_id: self.id,
            consumer_label: self.label(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// How the audit trail names this consumer: its name as it is now,
    /// copied into each event so the entry stays readable after a rename or
    /// once the consumer is gone.
    fn label(&self) -> EventLabel {
        EventLabel::of(self.name.as_str())
    }
}

impl<T: TenantScope> Raises for Consumer<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for Consumer<T> {
    type Id = ConsumerId;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::{DataAccessAction, SystemPermission};
    use crate::domains::consumers::fixtures::{ConsumerRecords, sam_holding};
    use crate::domains::consumers::quota::{QuotaPeriod, RequestAllowance};
    use crate::domains::consumers::sign_in::PresentedToken;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::{anyone_holding, assumed_authority};
    use crate::test_support::builders::label;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{
        CertificateFingerprint, FederatedSubject, HttpsUrl, Human, HumanAccount, KeyPrefix,
        Lifetime, PersonKey, RotationOverlap, TenantId, TokenHash, UserId,
    };

    /// Someone changing consumers who holds `system` and no custom
    /// permission.
    fn holding(system: &[SystemPermission]) -> ConsumerControl<'static> {
        ConsumerControl::new(anyone_holding(system))
    }

    /// Someone who manages consumers.
    fn consumer_admin() -> ConsumerControl<'static> {
        holding(&[SystemPermission::ManageConsumers])
    }

    /// Someone who may only view consumers.
    fn consumer_viewer() -> ConsumerControl<'static> {
        holding(&[SystemPermission::Consumers(ConsumersAction::View)])
    }

    /// Sam, who manages consumers, taking over `consumer`, which holds no
    /// role.
    fn takeover_of(consumer: &ConsumerId) -> ConsumerTakeover<'static> {
        let sam = sam_holding(&[SystemPermission::ManageConsumers]);
        ConsumerTakeover::of(&sam, &ConsumerRecords::empty().access(), consumer).unwrap()
    }

    fn api_key_params() -> CreateConsumerParams {
        CreateConsumerParams {
            name: label("payment-processor"),
            description: Some(label("Processes payments")),
            credential: ConsumerCredentialKind::ApiKey {
                prefix: KeyPrefix::new("sk_live_abc").unwrap(),
                key_hash: TokenHash::from_stored("hash123".to_owned()),
            },
            credential_expiry: Expiry::Never,
            quota: ConsumerQuota::Unlimited,
            clearance: DataClassLevel::Internal,
        }
    }

    fn test_consumer() -> Consumer<ResolvedTenant> {
        Consumer::create(api_key_params(), &tenant_issuer(), &consumer_admin()).unwrap()
    }

    fn client_cert() -> ConsumerCredentialKind {
        ConsumerCredentialKind::ClientCert {
            fingerprint: CertificateFingerprint::parse(
                "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
            )
            .unwrap(),
        }
    }

    /// A rotation to `credential`, never expiring, with the old one stopped
    /// at once.
    fn at_once(credential: ConsumerCredentialKind) -> CredentialRotation {
        CredentialRotation {
            credential,
            expiry: Expiry::Never,
            overlap: RotationOverlap::Immediate,
        }
    }

    /// A rotation to `credential`, never expiring, with the old one kept
    /// for a day.
    fn keeping_a_day(credential: ConsumerCredentialKind) -> CredentialRotation {
        CredentialRotation {
            overlap: RotationOverlap::For(Lifetime::new(time::Duration::days(1)).unwrap()),
            ..at_once(credential)
        }
    }

    /// The consumer as storage would keep it.
    fn stored(consumer: &Consumer<ResolvedTenant>) -> ConsumerRow {
        ConsumerRow {
            id: consumer.id,
            name: consumer.name.clone(),
            description: consumer.description.clone(),
            credential: consumer.credentials.current().clone(),
            previous_credential: consumer.credentials.previous().clone(),
            quota: consumer.quota,
            status: consumer.status,
            clearance: consumer.clearance,
            created_by: consumer.created_by.clone(),
            created_at: consumer.created_at,
            updated_at: consumer.updated_at,
        }
    }

    /// A caller with only the consumer view right cannot create a consumer
    /// with an API key.
    #[test]
    fn a_viewer_cannot_create_a_consumer() {
        let result = Consumer::<ResolvedTenant>::create(
            api_key_params(),
            &tenant_issuer(),
            &consumer_viewer(),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Ann creates a consumer. It records Ann's account as its creator,
    /// not a name the caller wrote.
    #[test]
    fn a_consumer_records_the_person_who_created_it() {
        let ann_id = UserId::new();
        let ann = Human::new(
            HumanAccount::User(ann_id),
            PersonKey::new("ann@acme.test").unwrap(),
        );
        let held = [SystemPermission::ManageConsumers];
        let control = ConsumerControl::new(assumed_authority(&ann, TenantId::new(), &held, &[]));

        let consumer =
            Consumer::<ResolvedTenant>::create(api_key_params(), &tenant_issuer(), &control)
                .unwrap();

        assert!(matches!(consumer.created_by(), ActorRef::User(id) if *id == ann_id));
    }

    /// A viewer cannot re-enable a disabled consumer; the consumer remains
    /// inactive after the refusal.
    #[test]
    fn a_viewer_cannot_enable_a_consumer() {
        let mut consumer = test_consumer();
        consumer.disable(&consumer_admin()).unwrap();

        let result = consumer.enable(&consumer_viewer());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(!consumer.is_active());
    }

    /// A viewer cannot disable an active consumer; the consumer remains
    /// active after the refusal.
    #[test]
    fn a_viewer_cannot_disable_a_consumer() {
        let mut consumer = test_consumer();

        let result = consumer.disable(&consumer_viewer());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(consumer.is_active());
    }

    /// A takeover proof for another consumer cannot rotate this consumer
    /// to a certificate, leaving its API key credential in place.
    #[test]
    fn a_takeover_of_another_consumer_does_not_rotate_this_one() {
        let mut consumer = test_consumer();
        let cron_job = takeover_of(&ConsumerId::new());

        let result =
            consumer.rotate_credential(at_once(client_cert()), &tenant_issuer(), &cron_job);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(matches!(
            consumer.credential(),
            ConsumerCredentialKind::ApiKey { .. }
        ));
    }

    /// A viewer's rename request is rejected, preserving the consumer's
    /// payment-processor name.
    #[test]
    fn a_viewer_cannot_rename_a_consumer() {
        let mut consumer = test_consumer();

        let result = consumer.rename(label("analytics-worker"), &consumer_viewer());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(consumer.name().as_str(), "payment-processor");
    }

    fn tenant_issuer() -> Issuer {
        Issuer::new("https://acme.ianua.test").unwrap()
    }

    /// An admin creates "payment-processor" with a description. It starts
    /// active and keeps the name and description it was given.
    #[test]
    fn create_produces_active_consumer() {
        let consumer = test_consumer();
        assert!(consumer.is_active());
        assert_eq!(consumer.name().as_str(), "payment-processor");
        assert!(consumer.description().is_some());
    }

    /// An admin disables a consumer and then turns it back on. It stops being
    /// active and then is active again.
    #[test]
    fn disable_and_enable() {
        let mut consumer = test_consumer();
        consumer.disable(&consumer_admin()).unwrap();
        assert!(!consumer.is_active());
        consumer.enable(&consumer_admin()).unwrap();
        assert!(consumer.is_active());
    }

    /// Fay manages consumers and deletes "billing-sync" once it is
    /// disabled.
    #[test]
    fn a_disabled_consumer_may_be_deleted() {
        let mut consumer = test_consumer();
        consumer.disable(&consumer_admin()).unwrap();

        assert!(consumer.delete(&consumer_admin()).is_ok());
    }

    /// Deleting an active consumer is forbidden even for a consumer manager.
    #[test]
    fn an_active_consumer_is_not_deleted() {
        let mut consumer = test_consumer();

        let result = consumer.delete(&consumer_admin());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A viewer cannot delete a consumer even after an administrator disables it.
    #[test]
    fn a_viewer_cannot_delete_a_consumer() {
        let mut consumer = test_consumer();
        consumer.disable(&consumer_admin()).unwrap();

        let result = consumer.delete(&consumer_viewer());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Enabling an active consumer, or disabling a disabled one, is an error.
    /// A repeat click does not count as a real change.
    #[test]
    fn enabling_or_disabling_twice_is_refused() {
        let mut consumer = test_consumer();
        let admin = consumer_admin();

        assert!(consumer.enable(&admin).is_err());
        consumer.disable(&admin).unwrap();
        assert!(consumer.disable(&admin).is_err());
    }

    /// A consumer moves from an API key to a client certificate. It now signs
    /// in by certificate and its change time moves forward.
    #[test]
    fn rotate_credential_updates() {
        let mut consumer = test_consumer();
        let old_updated = consumer.updated_at();
        let takeover = takeover_of(consumer.id());
        consumer
            .rotate_credential(at_once(client_cert()), &tenant_issuer(), &takeover)
            .unwrap();
        assert!(matches!(
            consumer.credential(),
            ConsumerCredentialKind::ClientCert { .. }
        ));
        assert!(consumer.updated_at() >= old_updated);
    }

    /// An admin renames "payment-processor" to "analytics-worker". The
    /// consumer reports the new name.
    #[test]
    fn a_renamed_consumer_shows_its_new_name() {
        let mut consumer = test_consumer();
        consumer
            .rename(label("analytics-worker"), &consumer_admin())
            .unwrap();
        assert_eq!(consumer.name().as_str(), "analytics-worker");
    }

    /// A consumer owns topics, subscriptions and schemas by this id. If two
    /// consumers both read back a nil id, each could edit the other's.
    #[test]
    fn a_consumer_carries_its_own_id() {
        let consumer = test_consumer();

        assert_ne!(*consumer.id().as_uuid(), uuid::Uuid::nil());
        assert_eq!(Aggregate::id(&consumer), consumer.id());
    }

    fn jwt_consumer(issuer: &str) -> Consumer<ResolvedTenant> {
        Consumer::create(
            CreateConsumerParams {
                name: label("billing-sync"),
                description: None,
                credential: ConsumerCredentialKind::JwtBearer {
                    issuer: Issuer::new(issuer).unwrap(),
                    subject: FederatedSubject::new("billing-sync").unwrap(),
                    jwks_uri: HttpsUrl::new("https://login.acme.com/jwks.json").unwrap(),
                },
                credential_expiry: Expiry::Never,
                quota: ConsumerQuota::Unlimited,
                clearance: DataClassLevel::Internal,
            },
            &tenant_issuer(),
            &consumer_admin(),
        )
        .unwrap()
    }

    /// A consumer rejects its configured token issuer when the tenant's
    /// current issuer has the same address.
    #[test]
    fn a_consumer_refuses_tokens_once_the_tenant_takes_its_issuer() {
        let consumer = jwt_consumer("https://login.acme.com");
        let taken = Issuer::new("https://login.acme.com").unwrap();

        let result = consumer.ensure_trusts_token_from(&taken, &taken);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A disabled consumer rejects token trust checks even when the supplied
    /// issuer still matches its configured outside issuer.
    #[test]
    fn a_disabled_consumer_trusts_no_token() {
        let mut consumer = jwt_consumer("https://login.acme.com");
        consumer.disable(&consumer_admin()).unwrap();
        let token = Issuer::new("https://login.acme.com").unwrap();

        let result = consumer.ensure_trusts_token_from(&token, &tenant_issuer());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// An active consumer accepts a token from its own outside issuer while
    /// the tenant keeps a different one.
    #[test]
    fn an_active_consumer_trusts_its_own_issuer() {
        let consumer = jwt_consumer("https://login.acme.com");
        let token = Issuer::new("https://login.acme.com").unwrap();

        assert!(
            consumer
                .ensure_trusts_token_from(&token, &tenant_issuer())
                .is_ok()
        );
    }

    /// A stored consumer says it was changed one second before it was made.
    /// Loading it is refused as a corrupt row.
    #[test]
    fn a_stored_consumer_changed_before_it_was_created_is_refused() {
        let consumer = test_consumer();
        let row = ConsumerRow {
            updated_at: consumer.created_at - time::Duration::SECOND,
            ..stored(&consumer)
        };

        assert!(refused_as_corrupt(
            &Consumer::<ResolvedTenant>::reconstitute(row)
        ));
    }

    fn presented(digest: &str) -> TokenHash {
        TokenHash::from_stored(digest.to_owned())
    }

    /// "payment-processor" signs in with its own API key. The proof names
    /// it.
    #[test]
    fn a_consumer_signs_in_with_its_own_key() {
        let consumer = test_consumer();

        let signed_in = consumer.sign_in_with_key(&presented("hash123")).unwrap();

        assert_eq!(signed_in.consumer(), consumer.id());
    }

    /// A wrong API key cannot sign in, and disabling the consumer also
    /// prevents sign-in with its correct key.
    #[test]
    fn a_wrong_key_or_a_disabled_consumer_does_not_sign_in() {
        let mut consumer = test_consumer();

        let guessed = consumer.sign_in_with_key(&presented("guess"));
        consumer.disable(&consumer_admin()).unwrap();
        let disabled = consumer.sign_in_with_key(&presented("hash123"));

        assert!(matches!(guessed, Err(DomainError::Forbidden(_))));
        assert!(matches!(disabled, Err(DomainError::Forbidden(_))));
    }

    /// After immediate rotation to a certificate, another certificate and
    /// the old API key are rejected while the configured certificate signs in.
    #[test]
    fn only_the_consumers_own_certificate_signs_it_in() {
        let mut consumer = test_consumer();
        let takeover = takeover_of(consumer.id());
        consumer
            .rotate_credential(at_once(client_cert()), &tenant_issuer(), &takeover)
            .unwrap();
        let ConsumerCredentialKind::ClientCert { fingerprint } = client_cert() else {
            unreachable!("client_cert is a certificate credential")
        };
        let eves = CertificateFingerprint::from_digest([7; 32]);

        let by_eve = consumer.sign_in_with_certificate(&eves);
        let by_old_key = consumer.sign_in_with_key(&presented("hash123"));
        let by_own = consumer.sign_in_with_certificate(&fingerprint);

        assert!(matches!(by_eve, Err(DomainError::Forbidden(_))));
        assert!(matches!(by_old_key, Err(DomainError::Forbidden(_))));
        assert!(by_own.is_ok());
    }

    /// Consumer token sign-in rejects a wrong subject or issuer and accepts
    /// the configured issuer and subject together.
    #[test]
    fn a_token_signs_in_only_from_the_consumers_issuer_for_its_subject() {
        let consumer = jwt_consumer("https://login.acme.com");
        let (ours, eves) = (
            Issuer::new("https://login.acme.com").unwrap(),
            Issuer::new("https://eve.example.com").unwrap(),
        );
        let (own, other) = (
            FederatedSubject::new("billing-sync").unwrap(),
            FederatedSubject::new("payroll-sync").unwrap(),
        );
        let token = |issuer, subject| PresentedToken { issuer, subject };

        let other_subject = consumer.sign_in_with_token(token(&ours, &other), &tenant_issuer());
        let eves_issuer = consumer.sign_in_with_token(token(&eves, &own), &tenant_issuer());
        let its_own = consumer.sign_in_with_token(token(&ours, &own), &tenant_issuer());

        assert!(matches!(other_subject, Err(DomainError::Forbidden(_))));
        assert!(matches!(eves_issuer, Err(DomainError::Forbidden(_))));
        assert!(its_own.is_ok());
    }

    /// The update right cannot raise a consumer's clearance above internal;
    /// a manager cleared for restricted data can then make that change.
    #[test]
    fn changing_a_consumers_clearance_needs_the_full_right() {
        let mut consumer = test_consumer();
        let updater = holding(&[SystemPermission::Consumers(ConsumersAction::Update)]);

        let by_updater = consumer.change_clearance(DataClassLevel::Restricted, &updater);
        let unchanged = consumer.clearance();
        consumer
            .change_clearance(DataClassLevel::Restricted, &cleared_admin())
            .unwrap();

        assert!(matches!(by_updater, Err(DomainError::Forbidden(_))));
        assert_eq!(unchanged, DataClassLevel::Internal);
        assert_eq!(consumer.clearance(), DataClassLevel::Restricted);
    }

    /// Someone who manages consumers and may see restricted data.
    fn cleared_admin() -> ConsumerControl<'static> {
        holding(&[
            SystemPermission::ManageConsumers,
            SystemPermission::Data(DataAccessAction::Restricted),
        ])
    }

    /// A manager with internal clearance cannot raise a consumer to
    /// restricted, leaving its internal clearance unchanged.
    #[test]
    fn a_consumer_is_cleared_for_no_more_than_the_person_clearing_it() {
        let mut consumer = test_consumer();

        let raised = consumer.change_clearance(DataClassLevel::Restricted, &consumer_admin());

        assert!(matches!(raised, Err(DomainError::Forbidden(_))));
        assert_eq!(consumer.clearance(), DataClassLevel::Internal);
    }

    /// The text of `field` in `event`'s payload, for a field the event
    /// records as a change.
    fn change_of(event: &DomainEvent, field: &str) -> (String, String) {
        match event.payload().value(field) {
            Some(FieldValue::Change(change)) => (
                change.from().unwrap_or_default().to_owned(),
                change.to().unwrap_or_default().to_owned(),
            ),
            other => panic!("{field} is not a change: {other:?}"),
        }
    }

    /// Ann creates "payment-processor". Its creation is raised.
    #[test]
    fn creating_raises_consumers_consumer_created() {
        let mut consumer = test_consumer();

        assert_eq!(raised_names(&mut consumer), ["consumers.consumer_created"]);
    }

    /// Ann disables "payment-processor", turns it back on, rotates its
    /// credential, disables it again and deletes it. Each step is raised,
    /// in order.
    #[test]
    fn each_change_to_a_consumer_is_raised_in_order() {
        let mut consumer = test_consumer();
        raised_names(&mut consumer);
        let admin = consumer_admin();
        let takeover = takeover_of(consumer.id());

        consumer.disable(&admin).unwrap();
        consumer.enable(&admin).unwrap();
        consumer
            .rotate_credential(at_once(client_cert()), &tenant_issuer(), &takeover)
            .unwrap();
        consumer.disable(&admin).unwrap();
        consumer.delete(&admin).unwrap();

        assert_eq!(
            raised_names(&mut consumer),
            [
                "consumers.consumer_disabled",
                "consumers.consumer_enabled",
                "consumers.credential_rotated",
                "consumers.consumer_disabled",
                "consumers.consumer_deleted",
            ]
        );
    }

    /// Ann renames "payment-processor" to "analytics-worker". The rename is
    /// raised with both names.
    #[test]
    fn renaming_raises_both_names() {
        let mut consumer = test_consumer();
        raised_names(&mut consumer);

        consumer
            .rename(label("analytics-worker"), &consumer_admin())
            .unwrap();

        let events = raised(&mut consumer);
        assert_eq!(
            events[0].event_type().to_string(),
            "consumers.consumer_renamed"
        );
        assert_eq!(
            change_of(&events[0], "name"),
            (
                "payment-processor".to_owned(),
                "analytics-worker".to_owned()
            )
        );
    }

    /// Ann describes "payment-processor" anew, then clears the description.
    /// Each change is raised; setting the description it already has
    /// raises nothing.
    #[test]
    fn a_description_is_changed_and_cleared() {
        let mut consumer = test_consumer();
        raised_names(&mut consumer);
        let admin = consumer_admin();

        consumer
            .change_description(Setting::Set(label("Settles card payments")), &admin)
            .unwrap();
        consumer
            .change_description(Setting::Set(label("Settles card payments")), &admin)
            .unwrap();
        consumer.change_description(Setting::Unset, &admin).unwrap();

        assert!(consumer.description().is_none());
        assert_eq!(
            raised_names(&mut consumer),
            [
                "consumers.description_changed",
                "consumers.description_changed"
            ]
        );
    }

    /// A viewer cannot clear the consumer's description, which remains set
    /// after the refusal.
    #[test]
    fn a_viewer_cannot_change_a_description() {
        let mut consumer = test_consumer();

        let result = consumer.change_description(Setting::Unset, &consumer_viewer());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(consumer.description().is_some());
    }

    /// Ann clears "payment-processor" for restricted data, up from
    /// internal. The change is raised with both levels. Clearing it for
    /// restricted again raises nothing.
    #[test]
    fn a_clearance_change_is_raised_once_with_both_levels() {
        let mut consumer = test_consumer();
        raised_names(&mut consumer);

        consumer
            .change_clearance(DataClassLevel::Restricted, &cleared_admin())
            .unwrap();
        let events = raised(&mut consumer);
        consumer
            .change_clearance(DataClassLevel::Restricted, &cleared_admin())
            .unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(
            change_of(&events[0], "clearance"),
            ("internal".to_owned(), "restricted".to_owned())
        );
        assert!(raised_names(&mut consumer).is_empty());
    }

    /// A viewer's disable, rename and delete requests all fail without
    /// raising any consumer events.
    #[test]
    fn a_refused_consumer_change_raises_nothing() {
        let mut consumer = test_consumer();
        raised_names(&mut consumer);

        let disabled = consumer.disable(&consumer_viewer());
        let renamed = consumer.rename(label("analytics-worker"), &consumer_viewer());
        let deleted = consumer.delete(&consumer_viewer());

        assert!(disabled.is_err());
        assert!(renamed.is_err());
        assert!(deleted.is_err());
        assert!(raised_names(&mut consumer).is_empty());
    }

    /// A consumer read back from storage has raised nothing; only a change
    /// made after loading is recorded.
    #[test]
    fn a_consumer_read_back_from_storage_has_raised_nothing() {
        let consumer = test_consumer();

        let mut read_back = Consumer::<ResolvedTenant>::reconstitute(stored(&consumer)).unwrap();

        assert!(raised_names(&mut read_back).is_empty());
    }

    fn start() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()
    }

    /// "payment-processor" as it stands right after Ann moved it to a client
    /// certificate at `start`, keeping its API key for a day.
    fn mid_rotation() -> Consumer<ResolvedTenant> {
        let _frozen = crate::shared::clock::freeze(start());
        let mut consumer = test_consumer();
        let takeover = takeover_of(consumer.id());
        consumer
            .rotate_credential(keeping_a_day(client_cert()), &tenant_issuer(), &takeover)
            .unwrap();
        consumer
    }

    /// Ann moves "payment-processor" to a certificate, keeping its key for a
    /// day. An hour later both the key and the certificate sign it in.
    #[test]
    fn the_old_key_signs_in_while_the_overlap_lasts() {
        let consumer = mid_rotation();
        let _later = crate::shared::clock::freeze(start() + time::Duration::hours(1));
        let ConsumerCredentialKind::ClientCert { fingerprint } = client_cert() else {
            unreachable!("client_cert is a certificate credential")
        };

        assert!(consumer.sign_in_with_key(&presented("hash123")).is_ok());
        assert!(consumer.sign_in_with_certificate(&fingerprint).is_ok());
    }

    /// Ann moves "payment-processor" to a certificate, keeping its key for a
    /// day. A sign-in with the old key holds until the overlap ends; one
    /// with the certificate, which never expires, holds on.
    #[test]
    fn a_sign_in_holds_until_its_credential_stops() {
        let consumer = mid_rotation();
        let _later = crate::shared::clock::freeze(start() + time::Duration::hours(1));
        let ConsumerCredentialKind::ClientCert { fingerprint } = client_cert() else {
            unreachable!("client_cert is a certificate credential")
        };

        let by_key = consumer.sign_in_with_key(&presented("hash123")).unwrap();
        let by_certificate = consumer.sign_in_with_certificate(&fingerprint).unwrap();

        assert_eq!(
            by_key.until(),
            Expiry::At(start() + time::Duration::days(1))
        );
        assert_eq!(by_certificate.until(), Expiry::Never);
    }

    /// The old API key cannot sign in at the exact end of its one-day
    /// rotation overlap.
    #[test]
    fn the_old_key_is_refused_once_the_overlap_ends() {
        let consumer = mid_rotation();
        let _later = crate::shared::clock::freeze(start() + time::Duration::days(1));

        let by_old_key = consumer.sign_in_with_key(&presented("hash123"));

        assert!(matches!(by_old_key, Err(DomainError::Forbidden(_))));
    }

    /// Ann moves "payment-processor" to a certificate, keeping its key for a
    /// day. The rotation records the day's end as when the old key stops.
    #[test]
    fn a_rotation_records_when_the_old_credential_stops() {
        let mut consumer = mid_rotation();

        let events = raised(&mut consumer);
        let rotated = events.last().unwrap();

        assert_eq!(
            rotated.payload().get("previous_works_until"),
            Some((start() + time::Duration::days(1)).to_string().as_str())
        );
    }

    /// A viewer cannot end a credential overlap; an updater can end it,
    /// after which the old key fails and an overlap-ended event is raised.
    #[test]
    fn ending_the_overlap_needs_the_update_right() {
        let mut consumer = mid_rotation();
        let _later = crate::shared::clock::freeze(start() + time::Duration::hours(1));
        let updater = holding(&[SystemPermission::Consumers(ConsumersAction::Update)]);

        let by_viewer = consumer.end_credential_overlap(&consumer_viewer());
        consumer.end_credential_overlap(&updater).unwrap();

        assert!(matches!(by_viewer, Err(DomainError::Forbidden(_))));
        assert!(consumer.sign_in_with_key(&presented("hash123")).is_err());
        assert_eq!(
            raised_names(&mut consumer).last().map(String::as_str),
            Some("consumers.credential_overlap_ended")
        );
    }

    /// A consumer with no previous credential has no overlap to end. Ending
    /// one is refused.
    #[test]
    fn ending_an_overlap_that_is_not_there_is_refused() {
        let mut consumer = test_consumer();

        let ended = consumer.end_credential_overlap(&consumer_admin());

        assert!(matches!(ended, Err(DomainError::InvalidTransition(_))));
    }

    /// A key issued for thirty days cannot sign in on the thirty-first day.
    #[test]
    fn an_expired_key_does_not_sign_in() {
        let consumer = {
            let _frozen = crate::shared::clock::freeze(start());
            Consumer::<ResolvedTenant>::create(
                CreateConsumerParams {
                    credential_expiry: Expiry::At(start() + time::Duration::days(30)),
                    ..api_key_params()
                },
                &tenant_issuer(),
                &consumer_admin(),
            )
            .unwrap()
        };
        let _later = crate::shared::clock::freeze(start() + time::Duration::days(31));

        let signed_in = consumer.sign_in_with_key(&presented("hash123"));

        assert!(matches!(signed_in, Err(DomainError::Forbidden(_))));
    }

    /// Ann creates a consumer whose key expired yesterday. It is refused.
    #[test]
    fn a_consumer_cannot_be_created_with_an_expired_credential() {
        let _frozen = crate::shared::clock::freeze(start());

        let created = Consumer::<ResolvedTenant>::create(
            CreateConsumerParams {
                credential_expiry: Expiry::At(start() - time::Duration::days(1)),
                ..api_key_params()
            },
            &tenant_issuer(),
            &consumer_admin(),
        );

        assert!(matches!(created, Err(DomainError::Validation(_))));
    }

    /// An updater cannot change credential expiry; a manager can set it
    /// thirty days ahead, producing the sole expiry-change event.
    #[test]
    fn changing_a_credentials_expiry_needs_the_full_right() {
        let mut consumer = test_consumer();
        raised_names(&mut consumer);
        let updater = holding(&[SystemPermission::Consumers(ConsumersAction::Update)]);
        let later = Expiry::At(crate::shared::clock::now() + time::Duration::days(30));

        let by_updater = consumer.change_credential_expiry(Expiry::Never, &updater);
        consumer
            .change_credential_expiry(later, &consumer_admin())
            .unwrap();

        assert!(matches!(by_updater, Err(DomainError::Forbidden(_))));
        assert_eq!(consumer.credentials().current().expiry(), later);
        assert_eq!(
            raised_names(&mut consumer),
            ["consumers.credential_expiry_changed"]
        );
    }

    fn daily(requests: u64) -> ConsumerQuota {
        ConsumerQuota::Limited(RequestAllowance::new(requests, QuotaPeriod::Day).unwrap())
    }

    /// An updater cannot set a consumer quota; a manager can then set the
    /// allowance to 10,000 requests a day.
    #[test]
    fn changing_a_quota_needs_the_full_right() {
        let mut consumer = test_consumer();
        let updater = holding(&[SystemPermission::Consumers(ConsumersAction::Update)]);

        let by_updater = consumer.change_quota(daily(1_000_000), &updater);
        consumer
            .change_quota(daily(10_000), &consumer_admin())
            .unwrap();

        assert!(matches!(by_updater, Err(DomainError::Forbidden(_))));
        assert_eq!(consumer.quota(), daily(10_000));
    }

    /// Fay sets a daily quota of 10000 on "payment-processor". The change is
    /// raised once with both quotas. Setting it again raises nothing.
    #[test]
    fn a_quota_change_is_raised_once_with_both_quotas() {
        let mut consumer = test_consumer();
        raised_names(&mut consumer);

        consumer
            .change_quota(daily(10_000), &consumer_admin())
            .unwrap();
        let events = raised(&mut consumer);
        consumer
            .change_quota(daily(10_000), &consumer_admin())
            .unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(
            change_of(&events[0], "quota"),
            ("unlimited".to_owned(), "10000 per day".to_owned())
        );
        assert!(raised_names(&mut consumer).is_empty());
    }

    /// A consumer mid-rotation, as storage keeps it, reads back. A row whose
    /// kept credential is the current one, or whose overlap runs a month past
    /// its last change, is refused as corrupt.
    #[test]
    fn a_stored_overlap_a_rotation_could_not_leave_is_refused() {
        let consumer = mid_rotation();
        let current = consumer.credentials.current().clone();
        let kept_twice = ConsumerRow {
            previous_credential: PreviousCredential::Overlapping {
                credential: current,
                until: start() + time::Duration::hours(1),
            },
            ..stored(&consumer)
        };
        let PreviousCredential::Overlapping { credential, .. } = consumer.credentials.previous()
        else {
            unreachable!("the rotation keeps the old key")
        };
        let month_long = ConsumerRow {
            previous_credential: PreviousCredential::Overlapping {
                credential: credential.clone(),
                until: start() + time::Duration::days(30),
            },
            ..stored(&consumer)
        };

        assert!(Consumer::<ResolvedTenant>::reconstitute(stored(&consumer)).is_ok());
        assert!(refused_as_corrupt(
            &Consumer::<ResolvedTenant>::reconstitute(kept_twice)
        ));
        assert!(refused_as_corrupt(
            &Consumer::<ResolvedTenant>::reconstitute(month_long)
        ));
    }
}
