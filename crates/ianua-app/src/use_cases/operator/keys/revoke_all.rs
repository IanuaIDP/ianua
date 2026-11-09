//! Revoke all operator API keys: an operator ends every key of their own
//! at once.

use ianua_domain::domains::operator::api_key::{EveryKeyRevocation, OperatorApiKey};
use ianua_domain::domains::operator::control::OperatorAuthority;
use ianua_domain::message;
use ianua_domain::shared::events::raised::RaisesComplete as _;

use crate::auditor::RequestAuditor;
use crate::context::OperatorCaller;
use crate::error::{AppError, OrConflict, OrInternal};
use crate::use_case::Command;
use crate::use_cases::operator::keys::RevokeOperatorPorts;

/// Revokes every key the calling operator holds.
pub struct RevokeAllOperatorUseCase {
    ports: RevokeOperatorPorts,
}

impl RevokeAllOperatorUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: RevokeOperatorPorts) -> Self {
        Self { ports }
    }

    /// Revokes each of `by`'s keys still in force, as one revocation, and
    /// writes them all in one step: every one, or none when another
    /// revocation of one of them landed first.
    async fn revoke_each(&self, by: &OperatorAuthority) -> Result<EveryKeyRevocation, AppError> {
        let store = self.ports.key_store.as_ref();
        let held = store.list_by_operator(by.operator()).await.or_internal()?;
        let mut in_force: Vec<OperatorApiKey> = held.into_iter().filter(in_force).collect();
        let holder = self.ports.holder_label(by).await;
        let revocation = EveryKeyRevocation::revoke(in_force.iter_mut(), by, holder)
            .map_err(AppError::from_domain)?;
        if in_force.is_empty() {
            return Ok(revocation);
        }
        store
            .revoke_together(by.operator(), &in_force)
            .await
            .or_conflict(message!(
                "operator-one-of-the-keys-was-revoked",
                "one of the keys was revoked meanwhile; none was revoked here"
            ))?;
        Ok(revocation)
    }
}

impl Command for RevokeAllOperatorUseCase {
    type Caller = OperatorCaller;
    type Input = ();
    type Output = Result<u64, AppError>;

    /// Revokes every key the calling operator holds and returns how many
    /// went. Then `operator.operator_api_key_revoked` is recorded for all of
    /// them.
    ///
    /// Revoking nothing changes nothing, so it writes no audit record.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's operator or key no
    ///   longer exists.
    /// - `AppError::Forbidden` when the caller's key no longer works or
    ///   their account is disabled.
    /// - `AppError::Conflict` when another revocation of one of the keys
    ///   landed first. None of them was revoked by this call, so no key is
    ///   left revoked without its record, and a retry revokes what is still
    ///   in force.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &OperatorCaller,
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<u64, AppError> {
        let authority = self.ports.operator_authorities.authority(caller).await?;
        let mut revocation = self.revoke_each(&authority).await?;
        let count = revocation.count();
        if count == 0 {
            return Ok(count);
        }
        self.ports
            .settle_revocation(auditor, &authority, revocation.take_events())
            .await?;
        Ok(count)
    }
}

/// Whether `key` has not been revoked yet.
fn in_force(key: &OperatorApiKey) -> bool {
    !key.revocation().is_revoked()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::shared::clock;
    use ianua_domain::types::OperatorId;

    use super::*;
    use crate::ports::operator::OperatorKeyStore;
    use crate::test_support::acting::{FakeOperatorAuthorities, Refusal};
    use crate::test_support::operator::{
        FakeOperatorKeyStore, stored_operator_key, test_operator_caller, test_operator_id,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    struct Setup {
        uc: RevokeAllOperatorUseCase,
        keys: Arc<FakeOperatorKeyStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn holding(
            keys: impl IntoIterator<Item = OperatorApiKey>,
            authorities: FakeOperatorAuthorities,
        ) -> Self {
            Self::over(Arc::new(FakeOperatorKeyStore::holding(keys)), authorities)
        }

        fn over(keys: Arc<FakeOperatorKeyStore>, authorities: FakeOperatorAuthorities) -> Self {
            Self {
                uc: RevokeAllOperatorUseCase::new(RevokeOperatorPorts {
                    key_store: keys.clone(),
                    operator_authorities: Arc::new(authorities),
                    ..RevokeOperatorPorts::fakes()
                }),
                keys,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn revoke_all(&self) -> Result<u64, AppError> {
            block_on(self.uc.execute(
                &test_operator_caller(),
                &test_auditor(self.audit.clone()),
                (),
            ))
        }

        fn working_keys_of(&self, operator: OperatorId) -> usize {
            block_on(self.keys.list_by_operator(&operator))
                .unwrap()
                .iter()
                .filter(|key| key.works_at(clock::now()))
                .count()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn bobs_two_keys() -> [OperatorApiKey; 2] {
        [
            stored_operator_key(test_operator_id(), "opk_bob_1"),
            stored_operator_key(test_operator_id(), "opk_bob_2"),
        ]
    }

    /// Bob ends both his keys. Both stop working, the count says two, and
    /// one revocation is recorded for all of them.
    #[test]
    fn revoke_all_returns_count() {
        let setup = Setup::holding(bobs_two_keys(), FakeOperatorAuthorities::admitting());

        let count = setup.revoke_all().unwrap();

        assert_eq!(count, 2);
        assert_eq!(setup.working_keys_of(test_operator_id()), 0);
        assert_eq!(setup.recorded(), vec!["operator.operator_api_key_revoked"]);
    }

    /// A concurrent revocation makes bulk revocation conflict; the other
    /// key remains usable and this call records no revocation.
    #[test]
    fn a_key_revoked_meanwhile_turns_the_whole_revocation_down() {
        let keys = FakeOperatorKeyStore::revoking_meanwhile(bobs_two_keys(), "opk_bob_1");
        let setup = Setup::over(Arc::new(keys), FakeOperatorAuthorities::admitting());

        let result = setup.revoke_all();

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(setup.working_keys_of(test_operator_id()), 1);
        assert!(setup.recorded().is_empty());
    }

    /// Bob ends all his keys. Carol's key is not his and keeps working.
    #[test]
    fn another_operators_keys_are_left_alone() {
        let carol = OperatorId::new();
        let setup = Setup::holding(
            [
                stored_operator_key(test_operator_id(), "opk_bob_1"),
                stored_operator_key(carol, "opk_carol_1"),
            ],
            FakeOperatorAuthorities::admitting(),
        );

        setup.revoke_all().unwrap();

        assert_eq!(setup.working_keys_of(carol), 1);
    }

    /// Bob holds no key. Revoking all of them changes nothing, so nothing
    /// is recorded.
    #[test]
    fn revoking_nothing_changes_nothing() {
        let setup = Setup::holding([], FakeOperatorAuthorities::admitting());

        let count = setup.revoke_all().unwrap();

        assert_eq!(count, 0);
        assert!(setup.recorded().is_empty());
    }

    /// A disabled operator's authority refusal prevents bulk revocation,
    /// leaving both keys usable.
    #[test]
    fn a_disabled_operator_is_refused() {
        let setup = Setup::holding(
            bobs_two_keys(),
            FakeOperatorAuthorities::refusing(Refusal::Forbidden),
        );

        let result = setup.revoke_all();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.working_keys_of(test_operator_id()), 2);
    }

    /// An unauthenticated operator cannot revoke all keys.
    #[test]
    fn a_signed_out_operator_is_refused() {
        let setup = Setup::holding(
            bobs_two_keys(),
            FakeOperatorAuthorities::refusing(Refusal::SignedOut),
        );

        let result = setup.revoke_all();

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
