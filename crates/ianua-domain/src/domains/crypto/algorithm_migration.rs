//! Moving a tenant from one signing algorithm to another without downtime.
//!
//! A migration runs in four steps:
//! 1. **Plan**: choose the source and target algorithms.
//! 2. **Start**: create a new key with the target algorithm. Both keys are
//!    published, and the old key still signs.
//! 3. **Promote**: make the new key the primary signer.
//! 4. **Complete**: revoke the old key once relying parties have updated.
//!
//! A started migration can be rolled back until it is promoted. A migration
//! that is only planned is cancelled instead.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::crypto::control::CryptoControlCheck;
use crate::domains::crypto::events::migration::{
    AlgorithmMigrationCancelled, AlgorithmMigrationCompleted, AlgorithmMigrationPlanned,
    AlgorithmMigrationPromoted, AlgorithmMigrationRolledBack, AlgorithmMigrationStarted,
};
use crate::domains::crypto::migration_status::{InvalidMigrationTransition, MigrationStatus};
use crate::domains::crypto::signing_key::{SigningAlgorithm, SigningKey};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::types::{KeyId, Text};

/// Where a migration stands, with the key it moves to once that key exists.
///
/// It is one value, not a status beside an optional target key. So a
/// migration past planning always names the key that signing moves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationState {
    /// Planned, with no target key yet.
    Planned,
    /// The target key exists and is published.
    InProgress(KeyId),
    /// The target key signs, and the source key still verifies.
    Validating(KeyId),
    /// The source key is revoked.
    Completed(KeyId),
    /// Undone after the target key was made.
    RolledBack(KeyId),
    /// Called off before it started.
    Cancelled,
}

impl MigrationState {
    /// The status label this state carries.
    #[must_use]
    pub fn status(&self) -> MigrationStatus {
        match self {
            Self::Planned => MigrationStatus::Planned,
            Self::InProgress(_) => MigrationStatus::InProgress,
            Self::Validating(_) => MigrationStatus::Validating,
            Self::Completed(_) => MigrationStatus::Completed,
            Self::RolledBack(_) => MigrationStatus::RolledBack,
            Self::Cancelled => MigrationStatus::Cancelled,
        }
    }

    /// Reads a state back from its stored status and target key.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when a started migration has no
    ///   target key.
    /// - [`DomainError::Infrastructure`] when a migration that never started
    ///   has one.
    pub fn from_stored(
        status: MigrationStatus,
        target_key_id: Option<KeyId>,
    ) -> Result<Self, DomainError> {
        match (status, target_key_id) {
            (MigrationStatus::Planned, None) => Ok(Self::Planned),
            (MigrationStatus::Cancelled, None) => Ok(Self::Cancelled),
            (MigrationStatus::InProgress, Some(key)) => Ok(Self::InProgress(key)),
            (MigrationStatus::Validating, Some(key)) => Ok(Self::Validating(key)),
            (MigrationStatus::Completed, Some(key)) => Ok(Self::Completed(key)),
            (MigrationStatus::RolledBack, Some(key)) => Ok(Self::RolledBack(key)),
            (status, _) => Err(DomainError::infra_msg(format!(
                "stored {status:?} algorithm migration has a target key that contradicts it"
            ))),
        }
    }

    /// The key the migration moves to, once it exists.
    #[must_use]
    pub fn target_key_id(&self) -> Option<&KeyId> {
        match self {
            Self::InProgress(key)
            | Self::Validating(key)
            | Self::Completed(key)
            | Self::RolledBack(key) => Some(key),
            Self::Planned | Self::Cancelled => None,
        }
    }
}

/// One tenant's move from one signing algorithm to another.
///
/// The migration names the old and new key IDs, so the app layer can create,
/// promote and revoke the keys in step with it. It records each step. It
/// does not change the keys itself.
#[derive(Debug)]
pub struct AlgorithmMigration<T: TenantScope> {
    /// The algorithm being migrated away from.
    source_algorithm: SigningAlgorithm,
    /// The algorithm being migrated to.
    target_algorithm: SigningAlgorithm,
    /// The key ID of the old signing key.
    source_key_id: KeyId,
    /// Where the migration stands, with its target key once it has one.
    state: MigrationState,
    /// When the migration was planned.
    created_at: OffsetDateTime,
    /// When the status last changed.
    updated_at: OffsetDateTime,
    /// What it raised and has not handed over yet.
    raised: Raised<T>,
    /// Which plane this belongs to. See [`crate::isolation`].
    _scope: PhantomData<T>,
}

/// Persisted state for repository hydration.
pub struct AlgorithmMigrationRow {
    /// The algorithm being migrated away from.
    pub source_algorithm: SigningAlgorithm,
    /// The algorithm being migrated to.
    pub target_algorithm: SigningAlgorithm,
    /// The key ID of the source signing key.
    pub source_key_id: KeyId,
    /// Where the migration stands. See [`MigrationState::from_stored`].
    pub state: MigrationState,
    /// When the migration was planned.
    pub created_at: OffsetDateTime,
    /// When the status last changed.
    pub updated_at: OffsetDateTime,
}

impl<T: TenantScope> AlgorithmMigration<T> {
    /// Plans a migration away from `source`, the current signing key, to
    /// `target_algorithm`.
    ///
    /// The source algorithm is read from the key, so the record cannot claim
    /// a change the key set does not make. The migration starts in `Planned`
    /// status. The app layer calls [`start`](Self::start) after it creates
    /// the new key. Raises `crypto.migration_planned`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change signing keys.
    /// - [`DomainError::Validation`] when the target algorithm is the source
    ///   one. There is nothing to migrate, and the key set would end up with
    ///   two keys of one algorithm and a record claiming a change.
    pub fn plan(
        source: &SigningKey,
        target_algorithm: SigningAlgorithm,
        by: &impl CryptoControlCheck,
    ) -> Result<Self, DomainError> {
        by.ensure_may_change_keys()?;
        if source.algorithm() == target_algorithm {
            return Err(DomainError::invalid(message!(
                "crypto-a-migration-moves-to-a-different",
                "a migration moves to a different signing algorithm"
            )));
        }
        let now = crate::shared::clock::now();
        let mut migration = Self {
            source_algorithm: source.algorithm(),
            target_algorithm,
            source_key_id: source.kid().clone(),
            state: MigrationState::Planned,
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        migration.raised.raise(AlgorithmMigrationPlanned {
            source_algorithm: migration.source_algorithm,
            target_algorithm,
            source_key_id: migration.source_key_id.clone(),
            occurred_at: now,
        });
        Ok(migration)
    }

    /// Rebuilds a migration from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row migrates to the
    ///   algorithm it starts from.
    /// - [`DomainError::Infrastructure`] when the row migrates onto the key it
    ///   starts from.
    /// - [`DomainError::Infrastructure`] when the row changed before it was
    ///   planned.
    pub fn reconstitute(row: AlgorithmMigrationRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            source_algorithm: row.source_algorithm,
            target_algorithm: row.target_algorithm,
            source_key_id: row.source_key_id,
            state: row.state,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &AlgorithmMigrationRow) -> Result<(), DomainError> {
        RowCheck::of("algorithm migration")
            .holds(
                row.source_algorithm != row.target_algorithm,
                "a migration to the algorithm it starts from",
            )
            .holds(
                row.state.target_key_id() != Some(&row.source_key_id),
                "a migration onto the key it moves away from",
            )
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was planned",
            )
            .finish()
    }

    /// The algorithm being migrated away from.
    #[must_use]
    pub fn source_algorithm(&self) -> SigningAlgorithm {
        self.source_algorithm
    }

    /// The algorithm being migrated to.
    #[must_use]
    pub fn target_algorithm(&self) -> SigningAlgorithm {
        self.target_algorithm
    }

    /// The old key's ID.
    #[must_use]
    pub fn source_key_id(&self) -> &KeyId {
        &self.source_key_id
    }

    /// The new key's ID, once it exists.
    #[must_use]
    pub fn target_key_id(&self) -> Option<&KeyId> {
        self.state.target_key_id()
    }

    /// Where the migration stands, with its target key once it has one.
    #[must_use]
    pub fn state(&self) -> &MigrationState {
        &self.state
    }

    /// Current migration status.
    #[must_use]
    pub fn status(&self) -> MigrationStatus {
        self.state.status()
    }

    /// When the migration was planned.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When the status last changed.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Starts the migration onto `target`, a new key with the target
    /// algorithm that is already created and in the JWKS. Raises
    /// `crypto.migration_started`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change signing keys.
    /// - [`DomainError::Validation`] when `target` is the source key.
    /// - [`DomainError::Validation`] when the algorithm of `target` is not the
    ///   one the migration moves to.
    /// - [`DomainError::InvalidTransition`] when the migration is not in
    ///   `Planned` status.
    pub fn start(
        &mut self,
        target: &SigningKey,
        by: &impl CryptoControlCheck,
    ) -> Result<(), DomainError> {
        by.ensure_may_change_keys()?;
        if *target.kid() == self.source_key_id {
            return Err(DomainError::invalid(message!(
                "crypto-a-migration-moves-onto-a-new",
                "a migration moves onto a new key, not the one it leaves"
            )));
        }
        if target.algorithm() != self.target_algorithm {
            return Err(DomainError::invalid(message!(
                "crypto-the-new-key-must-use-the",
                "the new key must use the algorithm the migration moves to"
            )));
        }
        self.move_to(MigrationState::InProgress(target.kid().clone()))?;
        self.raised.raise(AlgorithmMigrationStarted {
            target_key_id: target.kid().clone(),
            target_algorithm: self.target_algorithm,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Records that the target key is now the primary signer.
    ///
    /// The source key stays in the JWKS so its tokens still verify during the
    /// grace period. Relying parties should refresh their JWKS cache.
    /// Raises `crypto.migration_promoted`, naming the target key.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change signing keys.
    /// - [`DomainError::InvalidTransition`] when the migration is not in
    ///   `InProgress` status.
    pub fn promote(&mut self, by: &impl CryptoControlCheck) -> Result<(), DomainError> {
        by.ensure_may_change_keys()?;
        let target =
            self.carry_target_to(MigrationStatus::Validating, MigrationState::Validating)?;
        self.raised.raise(AlgorithmMigrationPromoted {
            target_key_id: target,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Completes the migration, once the app layer has revoked the source
    /// key. Raises `crypto.migration_completed`.
    ///
    /// The target key is then the only active signing key.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change signing keys.
    /// - [`DomainError::InvalidTransition`] when the migration is not in
    ///   `Validating` status.
    pub fn complete(&mut self, by: &impl CryptoControlCheck) -> Result<(), DomainError> {
        by.ensure_may_change_keys()?;
        self.carry_target_to(MigrationStatus::Completed, MigrationState::Completed)?;
        self.raised.raise(AlgorithmMigrationCompleted {
            target_algorithm: self.target_algorithm,
            source_key_id: self.source_key_id.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Rolls back the migration to the source algorithm, which still signs,
    /// for `reason`. Raises `crypto.migration_rolled_back` with the reason.
    ///
    /// The app layer should revoke any target key made during the migration.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change signing keys.
    /// - [`DomainError::InvalidTransition`] when the migration is not in
    ///   `InProgress` status. Once the target key is promoted, the source key
    ///   is rotated out, and going back is a new migration.
    pub fn rollback(
        &mut self,
        reason: Text,
        by: &impl CryptoControlCheck,
    ) -> Result<(), DomainError> {
        by.ensure_may_change_keys()?;
        self.carry_target_to(MigrationStatus::RolledBack, MigrationState::RolledBack)?;
        self.raised.raise(AlgorithmMigrationRolledBack {
            source_algorithm: self.source_algorithm,
            reason,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Cancels a planned migration before it starts. Raises
    /// `crypto.migration_cancelled`.
    ///
    /// Once a migration has started and its key exists, use
    /// [`rollback`](Self::rollback) instead.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change signing keys.
    /// - [`DomainError::InvalidTransition`] when the migration is not in
    ///   `Planned` status.
    pub fn cancel(&mut self, by: &impl CryptoControlCheck) -> Result<(), DomainError> {
        by.ensure_may_change_keys()?;
        self.move_to(MigrationState::Cancelled)?;
        self.raised.raise(AlgorithmMigrationCancelled {
            target_algorithm: self.target_algorithm,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Moves to the state `to` builds from the target key, which every state
    /// past `Planned` carries, and returns that key.
    fn carry_target_to(
        &mut self,
        status: MigrationStatus,
        to: fn(KeyId) -> MigrationState,
    ) -> Result<KeyId, InvalidMigrationTransition> {
        let Some(target) = self.state.target_key_id().cloned() else {
            return Err(InvalidMigrationTransition {
                from: self.status(),
                to: status,
            });
        };
        self.move_to(to(target.clone()))?;
        Ok(target)
    }

    fn move_to(&mut self, to: MigrationState) -> Result<(), InvalidMigrationTransition> {
        self.status().try_transition(to.status())?;
        self.state = to;
        self.updated_at = crate::shared::clock::now();
        Ok(())
    }
}

impl<T: TenantScope> Raises for AlgorithmMigration<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::authority::TenantAuthority;
    use crate::domains::authorization::permission::{CryptoAction, SystemPermission};
    use crate::domains::crypto::signing_key::NewSigningKey;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::shared::security::secret::Secret;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{Expiry, PublicKeyPem};

    fn keeper() -> &'static TenantAuthority {
        anyone_holding(&[SystemPermission::Crypto(CryptoAction::Update)])
    }

    fn viewer() -> &'static TenantAuthority {
        anyone_holding(&[SystemPermission::Crypto(CryptoAction::View)])
    }

    fn key(kid: &str, algorithm: SigningAlgorithm) -> SigningKey {
        SigningKey::create(NewSigningKey {
            kid: KeyId::new(kid).unwrap(),
            algorithm,
            public_key: PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----",
            )
            .unwrap(),
            private_key: Secret::new("arn:aws:kms:us-east-1:123:key/abc"),
            expires_at: Expiry::Never,
        })
    }

    fn old_key() -> SigningKey {
        key("old-key", SigningAlgorithm::Rs256)
    }

    fn new_key() -> SigningKey {
        key("new-key", SigningAlgorithm::Es256)
    }

    fn plan() -> AlgorithmMigration<ResolvedTenant> {
        AlgorithmMigration::plan(&old_key(), SigningAlgorithm::Es256, keeper()).unwrap()
    }

    fn reason() -> Text {
        Text::new("reason", "the new key would not verify").unwrap()
    }

    /// Read-only key authority cannot plan a migration to another algorithm.
    #[test]
    fn a_viewer_may_not_plan_a_migration() {
        let planned = AlgorithmMigration::<ResolvedTenant>::plan(
            &old_key(),
            SigningAlgorithm::Es256,
            viewer(),
        );

        assert!(matches!(planned, Err(DomainError::Forbidden(_))));
    }

    /// A key viewer cannot start, cancel, promote, roll back or complete a
    /// migration. The planned and started migrations retain their statuses.
    #[test]
    fn a_viewer_may_not_move_a_migration_on() {
        let mut planned = plan();
        let mut started = plan();
        started.start(&new_key(), keeper()).unwrap();

        let refused = [
            planned.start(&new_key(), viewer()),
            planned.cancel(viewer()),
            started.promote(viewer()),
            started.rollback(reason(), viewer()),
            started.complete(viewer()),
        ];

        for step in refused {
            assert!(matches!(step, Err(DomainError::Forbidden(_))));
        }
        assert_eq!(planned.status(), MigrationStatus::Planned);
        assert_eq!(started.status(), MigrationStatus::InProgress);
    }

    /// A tenant plans a move from RS256 to RS256. It is refused, because
    /// nothing would change.
    #[test]
    fn a_migration_to_the_same_algorithm_is_refused() {
        let same = AlgorithmMigration::<ResolvedTenant>::plan(
            &old_key(),
            SigningAlgorithm::Rs256,
            keeper(),
        );

        assert!(matches!(same, Err(DomainError::Validation(_))));
    }

    /// Starting a migration onto the very key it leaves is refused and it
    /// stays planned. Saved, it would fail to load again and could never be
    /// promoted or rolled back.
    #[test]
    fn a_migration_onto_the_key_it_leaves_is_refused() {
        let mut m = plan();

        assert!(matches!(
            m.start(&old_key(), keeper()),
            Err(DomainError::Validation(_))
        ));
        assert_eq!(m.status(), MigrationStatus::Planned);
    }

    /// A migration planned to ES256 is started with an EdDSA key. It is
    /// refused.
    #[test]
    fn a_migration_onto_a_key_of_another_algorithm_is_refused() {
        let mut m = plan();

        let result = m.start(&key("ed-key", SigningAlgorithm::EdDsa), keeper());

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A plan from RS256 to ES256 starts planned, names both algorithms and
    /// has no target key yet.
    #[test]
    fn plan_creates_in_planned_status() {
        let m = plan();
        assert_eq!(m.status(), MigrationStatus::Planned);
        assert_eq!(m.source_algorithm(), SigningAlgorithm::Rs256);
        assert_eq!(m.target_algorithm(), SigningAlgorithm::Es256);
        assert!(m.target_key_id().is_none());
    }

    /// A migration is started onto `new-key`, promoted and completed. It
    /// passes through in progress and validating and ends terminal.
    #[test]
    fn full_migration_lifecycle() {
        let mut m = plan();

        m.start(&new_key(), keeper()).unwrap();
        assert_eq!(m.status(), MigrationStatus::InProgress);
        assert_eq!(m.target_key_id().unwrap().as_str(), "new-key");

        m.promote(keeper()).unwrap();
        assert_eq!(m.status(), MigrationStatus::Validating);

        m.complete(keeper()).unwrap();
        assert_eq!(m.status(), MigrationStatus::Completed);
        assert!(m.status().is_terminal());
    }

    /// A started migration, not yet promoted, is rolled back. It ends rolled
    /// back and terminal.
    #[test]
    fn rollback_from_in_progress() {
        let mut m = plan();
        m.start(&new_key(), keeper()).unwrap();

        m.rollback(reason(), keeper()).unwrap();
        assert_eq!(m.status(), MigrationStatus::RolledBack);
        assert!(m.status().is_terminal());
    }

    /// After promotion, a rollback is refused and the migration stays
    /// validating. The source key was rotated out and cannot sign again.
    #[test]
    fn a_promoted_migration_is_not_rolled_back() {
        let mut m = plan();
        m.start(&new_key(), keeper()).unwrap();
        m.promote(keeper()).unwrap();

        assert!(m.rollback(reason(), keeper()).is_err());
        assert_eq!(m.status(), MigrationStatus::Validating);
    }

    /// A completed migration cannot be rolled back.
    #[test]
    fn cannot_rollback_after_completed() {
        let mut m = plan();
        m.start(&new_key(), keeper()).unwrap();
        m.promote(keeper()).unwrap();
        m.complete(keeper()).unwrap();

        assert!(m.rollback(reason(), keeper()).is_err());
    }

    /// An admin cancels a plan before any key exists. It ends cancelled and
    /// terminal.
    #[test]
    fn cancel_planned_migration() {
        let mut m = plan();
        m.cancel(keeper()).unwrap();
        assert_eq!(m.status(), MigrationStatus::Cancelled);
        assert!(m.status().is_terminal());
    }

    /// A started migration already made a key, so cancelling it is refused.
    /// It must be rolled back instead.
    #[test]
    fn cannot_cancel_in_progress() {
        let mut m = plan();
        m.start(&new_key(), keeper()).unwrap();
        assert!(m.cancel(keeper()).is_err());
    }

    /// A planned migration with no target key cannot be promoted or
    /// completed.
    #[test]
    fn cannot_skip_steps() {
        let mut m = plan();
        assert!(m.promote(keeper()).is_err());
        assert!(m.complete(keeper()).is_err());
    }

    /// A tenant moves from ES256 to EdDSA. The migration runs through every
    /// step and ends on EdDSA.
    #[test]
    fn a_migration_to_eddsa_runs_to_completion() {
        let mut m = AlgorithmMigration::<ResolvedTenant>::plan(
            &key("es-key", SigningAlgorithm::Es256),
            SigningAlgorithm::EdDsa,
            keeper(),
        )
        .unwrap();

        m.start(&key("ed-key", SigningAlgorithm::EdDsa), keeper())
            .unwrap();
        m.promote(keeper()).unwrap();
        m.complete(keeper()).unwrap();

        assert_eq!(m.target_algorithm(), SigningAlgorithm::EdDsa);
    }

    /// Five minutes after planning, the migration is started. `updated_at`
    /// moves to that moment and `created_at` stays, so a stalled migration
    /// and a progressing one look different.
    #[test]
    fn advancing_a_migration_moves_the_timestamp_readers_watch() {
        let mut migration = plan();
        let created = migration.created_at();
        let later = migration.updated_at() + time::Duration::minutes(5);

        let _frozen = crate::shared::clock::freeze(later);
        migration.start(&new_key(), keeper()).unwrap();

        assert_eq!(migration.updated_at(), later);
        assert_eq!(migration.created_at(), created);
    }

    fn stored(migration: &AlgorithmMigration<ResolvedTenant>) -> AlgorithmMigrationRow {
        AlgorithmMigrationRow {
            source_algorithm: migration.source_algorithm,
            target_algorithm: migration.target_algorithm,
            source_key_id: migration.source_key_id.clone(),
            state: migration.state.clone(),
            created_at: migration.created_at,
            updated_at: migration.updated_at,
        }
    }

    /// A stored migration moves to the algorithm it starts from. Loading it
    /// is refused as corrupt.
    #[test]
    fn a_stored_migration_to_its_own_algorithm_is_refused() {
        let mut row = stored(&plan());
        row.target_algorithm = row.source_algorithm;

        assert!(refused_as_corrupt(
            &AlgorithmMigration::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored migration names its source key as its target. Loading it is
    /// refused as corrupt.
    #[test]
    fn a_stored_migration_onto_the_key_it_leaves_is_refused() {
        let mut row = stored(&plan());
        row.state = MigrationState::InProgress(row.source_key_id.clone());

        assert!(refused_as_corrupt(
            &AlgorithmMigration::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// Ann plans a move from RS256 to ES256. The plan is raised.
    #[test]
    fn planning_raises_crypto_migration_planned() {
        let mut m = plan();

        assert_eq!(raised_names(&mut m), ["crypto.migration_planned"]);
    }

    /// Ann starts the migration onto `new-key`, promotes it and completes
    /// it. Each step is raised, in order, and the promotion names the key
    /// that now signs.
    #[test]
    fn each_step_of_a_migration_is_raised_in_order() {
        let mut m = plan();
        raised_names(&mut m);

        m.start(&new_key(), keeper()).unwrap();
        m.promote(keeper()).unwrap();
        m.complete(keeper()).unwrap();

        let events = raised(&mut m);
        let names: Vec<String> = events.iter().map(|e| e.event_type().to_string()).collect();
        assert_eq!(
            names,
            [
                "crypto.migration_started",
                "crypto.migration_promoted",
                "crypto.migration_completed",
            ]
        );
        assert_eq!(events[1].payload().get("target_key_id"), Some("new-key"));
    }

    /// Ann starts a migration and rolls it back because the new key would
    /// not verify. The rollback is raised with her reason.
    #[test]
    fn a_rollback_is_raised_with_its_reason() {
        let mut m = plan();
        m.start(&new_key(), keeper()).unwrap();
        raised_names(&mut m);

        m.rollback(reason(), keeper()).unwrap();

        let events = raised(&mut m);
        assert_eq!(
            events[0].event_type().to_string(),
            "crypto.migration_rolled_back"
        );
        assert_eq!(
            events[0].payload().get("reason"),
            Some("the new key would not verify")
        );
    }

    /// Ann cancels a plan before any key exists. The cancellation is
    /// raised.
    #[test]
    fn cancelling_raises_crypto_migration_cancelled() {
        let mut m = plan();
        raised_names(&mut m);

        m.cancel(keeper()).unwrap();

        assert_eq!(raised_names(&mut m), ["crypto.migration_cancelled"]);
    }

    /// A viewer's start and cancellation attempts and a keeper's premature
    /// promotion are refused without raising any events.
    #[test]
    fn a_refused_migration_step_raises_nothing() {
        let mut m = plan();
        raised_names(&mut m);

        let started = m.start(&new_key(), viewer());
        let cancelled = m.cancel(viewer());
        let promoted = m.promote(keeper());

        assert!(started.is_err());
        assert!(cancelled.is_err());
        assert!(promoted.is_err());
        assert!(raised_names(&mut m).is_empty());
    }

    /// A migration read back from storage has raised nothing; only a step
    /// taken after loading is recorded.
    #[test]
    fn a_migration_read_back_from_storage_has_raised_nothing() {
        let mut m = AlgorithmMigration::<ResolvedTenant>::reconstitute(stored(&plan())).unwrap();

        assert!(raised_names(&mut m).is_empty());
    }
}
