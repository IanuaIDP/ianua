//! Enable operator: one operator lets a disabled one back in.

use std::sync::Arc;

use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::OperatorId;

use crate::acting::OperatorAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::OperatorCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::operator::OperatorStore;
use crate::use_case::Command;
use crate::use_cases::operator::lookup::existing_operator;

/// The ports [`EnableOperatorUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct EnableOperatorPorts {
    /// Platform operators.
    pub operator_store: Arc<dyn OperatorStore>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Re-enables another operator's disabled account.
pub struct EnableOperatorUseCase {
    ports: EnableOperatorPorts,
}

impl EnableOperatorUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: EnableOperatorPorts) -> Self {
        Self { ports }
    }
}

impl Command for EnableOperatorUseCase {
    type Caller = OperatorCaller;
    type Input = OperatorId;
    type Output = Result<(), AppError>;

    /// Re-enables the operator `operator_id` and records
    /// `operator.operator_enabled`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's operator or key no
    ///   longer exists.
    /// - `AppError::Forbidden` when the caller's key no longer works, their
    ///   account is disabled, or they name themselves.
    /// - `AppError::NotFound` if the operator doesn't exist.
    /// - `AppError::Domain` if the operator is already active.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &OperatorCaller,
        auditor: &RequestAuditor,
        operator_id: OperatorId,
    ) -> Result<(), AppError> {
        let authority = self.ports.operator_authorities.authority(caller).await?;
        let mut operator =
            existing_operator(self.ports.operator_store.as_ref(), &operator_id).await?;
        operator.enable(&authority).map_err(AppError::from_domain)?;
        self.ports
            .operator_store
            .save(&operator)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), operator.take_events())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::operator::status::OperatorStatus;

    use super::*;
    use crate::test_support::acting::{FakeOperatorAuthorities, Refusal};
    use crate::test_support::operator::{FakeOperatorStore, stored_operator, test_operator_caller};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    struct Setup {
        uc: EnableOperatorUseCase,
        store: Arc<FakeOperatorStore>,
        audit: Arc<FakeEventDispatcher>,
        carol: OperatorId,
    }

    impl Setup {
        fn with(authorities: FakeOperatorAuthorities, carol_stands: OperatorStatus) -> Self {
            let carol = OperatorId::new();
            let store = Arc::new(FakeOperatorStore::holding([stored_operator(
                carol,
                "carol@ianua.dev",
                carol_stands,
            )]));
            Self {
                uc: EnableOperatorUseCase::new(EnableOperatorPorts {
                    operator_store: store.clone(),
                    operator_authorities: Arc::new(authorities),
                }),
                store,
                audit: Arc::new(FakeEventDispatcher::new()),
                carol,
            }
        }

        fn new() -> Self {
            Self::with(
                FakeOperatorAuthorities::admitting(),
                OperatorStatus::Disabled,
            )
        }

        fn enable(&self, operator: OperatorId) -> Result<(), AppError> {
            block_on(self.uc.execute(
                &test_operator_caller(),
                &test_auditor(self.audit.clone()),
                operator,
            ))
        }

        fn status_of_carol(&self) -> OperatorStatus {
            block_on(self.store.find_by_id(&self.carol))
                .unwrap()
                .unwrap()
                .status()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Bob lets Carol back in. She is active again and the change recorded.
    #[test]
    fn enable_operator_and_audits() {
        let setup = Setup::new();

        setup.enable(setup.carol).unwrap();

        assert_eq!(setup.status_of_carol(), OperatorStatus::Active);
        assert_eq!(setup.recorded(), vec!["operator.operator_enabled"]);
    }

    /// Carol is already active. Enabling her again is refused as a
    /// transition the account cannot make, and nothing is recorded.
    #[test]
    fn enable_already_active_is_refused() {
        let setup = Setup::with(FakeOperatorAuthorities::admitting(), OperatorStatus::Active);

        let result = setup.enable(setup.carol);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(setup.recorded().is_empty());
    }

    /// Bob names an operator who does not exist. It is not found and
    /// nothing is recorded.
    #[test]
    fn enable_nonexistent_returns_not_found() {
        let setup = Setup::new();

        let result = setup.enable(OperatorId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(setup.recorded().is_empty());
    }

    /// A disabled operator's authority refusal prevents enabling another
    /// operator, whose account remains disabled.
    #[test]
    fn a_disabled_operator_is_refused() {
        let setup = Setup::with(
            FakeOperatorAuthorities::refusing(Refusal::Forbidden),
            OperatorStatus::Disabled,
        );

        let result = setup.enable(setup.carol);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.status_of_carol(), OperatorStatus::Disabled);
    }

    /// An unauthenticated operator cannot enable another account.
    #[test]
    fn a_signed_out_operator_is_refused() {
        let setup = Setup::with(
            FakeOperatorAuthorities::refusing(Refusal::SignedOut),
            OperatorStatus::Disabled,
        );

        let result = setup.enable(setup.carol);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
