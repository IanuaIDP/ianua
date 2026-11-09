//! Revoke operator API key: an operator ends one key of their own, named
//! by its prefix.

use std::sync::Arc;

use ianua_domain::domains::operator::control::OperatorAuthority;
use ianua_domain::message;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{EventLabel, KeyPrefix};

use crate::acting::OperatorAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::OperatorCaller;
use crate::error::{AppError, OrConflict, OrInternal};
use crate::ports::operator::OperatorKeyStore;
use crate::ports::shared::ControlPlaneLabelResolver;
use crate::use_case::Command;
use crate::use_cases::operator::lookup::owned_key;

/// The ports [`RevokeOperatorUseCase`] and
/// [`RevokeAllOperatorUseCase`](crate::use_cases::operator::keys::RevokeAllOperatorUseCase)
/// need.
#[derive(ianua_macros::Fakes)]
pub struct RevokeOperatorPorts {
    /// Operator keys.
    pub key_store: Arc<dyn OperatorKeyStore>,
    /// Labels captured into the audit payload.
    pub control_plane_label_resolver: Arc<dyn ControlPlaneLabelResolver>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

impl RevokeOperatorPorts {
    /// How the audit record names the operator `by` whose keys go, falling
    /// back to their id.
    ///
    /// A label is only a name on the record, so a failed lookup degrades to
    /// the id rather than holding up a revocation.
    pub(super) async fn holder_label(&self, by: &OperatorAuthority) -> EventLabel {
        self.control_plane_label_resolver
            .operator(by.operator())
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| EventLabel::of(&by.operator().to_string()))
    }

    /// Finishes a revocation that is already saved: records `events`, what
    /// the revocation raised, as done by `by`. Each
    /// `operator.operator_api_key_revoked` drops the key's cached caller
    /// once kept.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` if the audit record cannot be written.
    pub(super) async fn settle_revocation(
        &self,
        auditor: &RequestAuditor,
        by: &OperatorAuthority,
        events: Vec<DomainEvent>,
    ) -> Result<(), AppError> {
        auditor.dispatch_by(&by.actor(), events).await.or_internal()
    }
}

/// Revokes one of the calling operator's keys.
pub struct RevokeOperatorUseCase {
    ports: RevokeOperatorPorts,
}

impl RevokeOperatorUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: RevokeOperatorPorts) -> Self {
        Self { ports }
    }
}

impl Command for RevokeOperatorUseCase {
    type Caller = OperatorCaller;
    type Input = KeyPrefix;
    type Output = Result<(), AppError>;

    /// Revokes the calling operator's key found by `key_prefix`, and records
    /// `operator.operator_api_key_revoked`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for a missing acting operator/key; `Forbidden` for an unusable key or disabled operator.
    /// - `AppError::NotFound` for an unknown prefix or foreign key; `Domain` for an already revoked key.
    /// - `AppError::Conflict` for a concurrent revocation; `Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &OperatorCaller,
        auditor: &RequestAuditor,
        key_prefix: KeyPrefix,
    ) -> Result<(), AppError> {
        let authority = self.ports.operator_authorities.authority(caller).await?;
        let mut key = owned_key(self.ports.key_store.as_ref(), &key_prefix, &authority).await?;
        let holder = self.ports.holder_label(&authority).await;
        key.revoke(&authority, holder)
            .map_err(AppError::from_domain)?;
        self.ports.key_store.save(&key).await.or_conflict(message!(
            "operator-the-key-was-revoked-meanwhile",
            "the key was revoked meanwhile"
        ))?;
        self.ports
            .settle_revocation(auditor, &authority, key.take_events())
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::clock;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::OperatorId;

    use super::*;
    use crate::test_support::acting::{FakeOperatorAuthorities, Refusal};
    use crate::test_support::operator::{
        FakeOperatorKeyStore, stored_operator_key, test_operator_caller, test_operator_id,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    const BOBS_KEY: &str = "opk_bob";

    struct Setup {
        uc: RevokeOperatorUseCase,
        keys: Arc<FakeOperatorKeyStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn holding(owner: OperatorId, authorities: FakeOperatorAuthorities) -> Self {
            let keys = Arc::new(FakeOperatorKeyStore::holding([stored_operator_key(
                owner, BOBS_KEY,
            )]));
            Self {
                uc: RevokeOperatorUseCase::new(RevokeOperatorPorts {
                    key_store: keys.clone(),
                    operator_authorities: Arc::new(authorities),
                    ..RevokeOperatorPorts::fakes()
                }),
                keys,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn new() -> Self {
            Self::holding(test_operator_id(), FakeOperatorAuthorities::admitting())
        }

        fn revoke(&self, prefix: &str) -> Result<(), AppError> {
            block_on(self.uc.execute(
                &test_operator_caller(),
                &test_auditor(self.audit.clone()),
                KeyPrefix::new(prefix).unwrap(),
            ))
        }

        fn works(&self) -> bool {
            block_on(self.keys.find_by_prefix(&KeyPrefix::new(BOBS_KEY).unwrap()))
                .unwrap()
                .unwrap()
                .works_at(clock::now())
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Bob names a key that does not exist. It is not found and nothing is
    /// recorded.
    #[test]
    fn revoke_by_prefix_returns_not_found_when_no_key() {
        let setup = Setup::new();

        let result = setup.revoke("opk_nonexistent");

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(setup.recorded().is_empty());
    }

    /// Bob revokes his key. It stops working and the revocation is recorded.
    #[test]
    fn revoke_by_prefix_succeeds_and_audits() {
        let setup = Setup::new();

        setup.revoke(BOBS_KEY).unwrap();

        assert!(!setup.works());
        assert_eq!(setup.recorded(), vec!["operator.operator_api_key_revoked"]);
    }

    /// Bob revokes his key twice. The second is refused as a transition the
    /// key cannot make.
    #[test]
    fn revoking_a_revoked_key_is_refused() {
        let setup = Setup::new();
        setup.revoke(BOBS_KEY).unwrap();

        let result = setup.revoke(BOBS_KEY);

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::InvalidTransition(_)))
        ));
    }

    /// Another operator's key answers not found when revocation is
    /// requested, and the key remains usable.
    #[test]
    fn another_operators_key_reads_as_missing() {
        let setup = Setup::holding(OperatorId::new(), FakeOperatorAuthorities::admitting());

        let result = setup.revoke(BOBS_KEY);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(setup.works());
    }

    /// A disabled operator's authority refusal prevents revocation and
    /// leaves the target key usable.
    #[test]
    fn a_disabled_operator_is_refused() {
        let setup = Setup::holding(
            test_operator_id(),
            FakeOperatorAuthorities::refusing(Refusal::Forbidden),
        );

        let result = setup.revoke(BOBS_KEY);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.works());
    }

    /// An unauthenticated operator cannot revoke a key.
    #[test]
    fn a_signed_out_operator_is_refused() {
        let setup = Setup::holding(
            test_operator_id(),
            FakeOperatorAuthorities::refusing(Refusal::SignedOut),
        );

        let result = setup.revoke(BOBS_KEY);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
