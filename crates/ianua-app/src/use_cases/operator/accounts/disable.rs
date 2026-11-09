//! Disable operator: one operator stops another, with every grant they
//! hold.

use std::sync::Arc;

use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::OperatorId;

use crate::acting::OperatorAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::OperatorCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::operator::{ImpersonationGrantStore, OperatorStore};
use crate::use_case::Command;
use crate::use_cases::operator::lookup::existing_operator;

/// The ports [`DisableOperatorUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DisableOperatorPorts {
    /// Platform operators.
    pub operator_store: Arc<dyn OperatorStore>,
    /// Impersonation grants, every one of which the operator loses.
    pub grant_store: Arc<dyn ImpersonationGrantStore>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Disables another operator's account.
pub struct DisableOperatorUseCase {
    ports: DisableOperatorPorts,
}

impl DisableOperatorUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: DisableOperatorPorts) -> Self {
        Self { ports }
    }
}

impl Command for DisableOperatorUseCase {
    type Caller = OperatorCaller;
    type Input = OperatorId;
    type Output = Result<(), AppError>;

    /// Disables the operator `operator_id`, revokes every impersonation
    /// grant they hold, and records `operator.operator_disabled`, which
    /// drops their cached callers once kept.
    ///
    /// The operator acting is active and never disables themselves, so the
    /// platform always keeps someone who can run it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's operator or key no
    ///   longer exists.
    /// - `AppError::Forbidden` when the caller's key no longer works, their
    ///   account is disabled, or they name themselves.
    /// - `AppError::NotFound` if the operator doesn't exist.
    /// - `AppError::Domain` if the operator is already disabled.
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
        operator
            .disable(&authority)
            .map_err(AppError::from_domain)?;
        self.ports
            .operator_store
            .save(&operator)
            .await
            .or_internal()?;
        self.ports
            .grant_store
            .revoke_all_for_operator(&operator_id)
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
    use crate::test_support::operator::{
        FakeOperatorStore, stored_operator, test_operator_caller, test_operator_id,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    struct Setup {
        uc: DisableOperatorUseCase,
        store: Arc<FakeOperatorStore>,
        audit: Arc<FakeEventDispatcher>,
        carol: OperatorId,
    }

    impl Setup {
        fn with(authorities: FakeOperatorAuthorities) -> Self {
            let carol = OperatorId::new();
            let store = Arc::new(FakeOperatorStore::holding([
                stored_operator(test_operator_id(), "bob@ianua.dev", OperatorStatus::Active),
                stored_operator(carol, "carol@ianua.dev", OperatorStatus::Active),
            ]));
            let uc = DisableOperatorUseCase::new(DisableOperatorPorts {
                operator_store: store.clone(),
                operator_authorities: Arc::new(authorities),
                ..DisableOperatorPorts::fakes()
            });
            Self {
                uc,
                store,
                audit: Arc::new(FakeEventDispatcher::new()),
                carol,
            }
        }

        fn new() -> Self {
            Self::with(FakeOperatorAuthorities::admitting())
        }

        fn disable(&self, operator: OperatorId) -> Result<(), AppError> {
            block_on(self.uc.execute(
                &test_operator_caller(),
                &test_auditor(self.audit.clone()),
                operator,
            ))
        }

        fn status_of(&self, operator: OperatorId) -> OperatorStatus {
            block_on(self.store.find_by_id(&operator))
                .unwrap()
                .unwrap()
                .status()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Bob disables Carol. She is disabled and the change recorded.
    #[test]
    fn disable_operator_and_audits() {
        let setup = Setup::new();

        setup.disable(setup.carol).unwrap();

        assert_eq!(setup.status_of(setup.carol), OperatorStatus::Disabled);
        assert_eq!(setup.recorded(), vec!["operator.operator_disabled"]);
    }

    /// Bob names an operator who does not exist. It is not found and
    /// nothing is recorded.
    #[test]
    fn disabling_an_unknown_operator_is_not_found() {
        let setup = Setup::new();

        let result = setup.disable(OperatorId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(setup.recorded().is_empty());
    }

    /// Bob disables Carol twice. The second is refused as a transition the
    /// account cannot make.
    #[test]
    fn disable_already_disabled_returns_domain_error() {
        let setup = Setup::new();
        setup.disable(setup.carol).unwrap();

        let result = setup.disable(setup.carol);

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// An operator cannot disable their own account, which remains active.
    #[test]
    fn an_operator_cannot_disable_themselves() {
        let setup = Setup::new();

        let result = setup.disable(test_operator_id());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.status_of(test_operator_id()), OperatorStatus::Active);
    }

    /// A disabled operator's authority refusal prevents disabling another
    /// operator, whose account remains active.
    #[test]
    fn a_disabled_operator_is_refused() {
        let setup = Setup::with(FakeOperatorAuthorities::refusing(Refusal::Forbidden));

        let result = setup.disable(setup.carol);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.status_of(setup.carol), OperatorStatus::Active);
    }

    /// An unauthenticated operator cannot disable another account.
    #[test]
    fn a_signed_out_operator_is_refused() {
        let setup = Setup::with(FakeOperatorAuthorities::refusing(Refusal::SignedOut));

        let result = setup.disable(setup.carol);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
