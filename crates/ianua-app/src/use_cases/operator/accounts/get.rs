//! Get operator: one platform operator, by id.

use std::sync::Arc;

use ianua_domain::domains::operator::identity::Operator;
use ianua_domain::types::OperatorId;

use crate::acting::OperatorAuthorities;
use crate::context::OperatorCaller;
use crate::error::AppError;
use crate::ports::operator::OperatorStore;
use crate::use_case::Query;
use crate::use_cases::operator::lookup::existing_operator;

/// The ports [`GetOperatorUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetOperatorPorts {
    /// Platform operators.
    pub operator_store: Arc<dyn OperatorStore>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Reads one platform operator.
pub struct GetOperatorUseCase {
    ports: GetOperatorPorts,
}

impl GetOperatorUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetOperatorPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetOperatorUseCase {
    type Caller = OperatorCaller;
    type Input = OperatorId;
    type Output = Result<Operator, AppError>;

    /// The operator `id`, for an operator acting now.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's operator or key no
    ///   longer exists.
    /// - `AppError::Forbidden` when the caller's key no longer works or
    ///   their account is disabled.
    /// - `AppError::NotFound` if the operator doesn't exist.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(&self, caller: &OperatorCaller, id: OperatorId) -> Result<Operator, AppError> {
        self.ports.operator_authorities.authority(caller).await?;
        existing_operator(self.ports.operator_store.as_ref(), &id).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::operator::status::OperatorStatus;

    use super::*;
    use crate::test_support::acting::{FakeOperatorAuthorities, Refusal};
    use crate::test_support::block_on;
    use crate::test_support::operator::{FakeOperatorStore, stored_operator, test_operator_caller};

    fn reading(authorities: FakeOperatorAuthorities, carol: OperatorId) -> GetOperatorUseCase {
        GetOperatorUseCase::new(GetOperatorPorts {
            operator_store: Arc::new(FakeOperatorStore::holding([stored_operator(
                carol,
                "carol@ianua.dev",
                OperatorStatus::Active,
            )])),
            operator_authorities: Arc::new(authorities),
        })
    }

    /// Bob looks Carol up. He sees her.
    #[test]
    fn returns_the_named_operator() {
        let carol = OperatorId::new();
        let uc = reading(FakeOperatorAuthorities::admitting(), carol);

        let found = block_on(uc.execute(&test_operator_caller(), carol)).unwrap();

        assert_eq!(found.email().as_str(), "carol@ianua.dev");
    }

    /// Bob names an operator who does not exist. It is not found.
    #[test]
    fn an_unknown_operator_is_not_found() {
        let uc = reading(FakeOperatorAuthorities::admitting(), OperatorId::new());

        let result = block_on(uc.execute(&test_operator_caller(), OperatorId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A disabled operator's authority refusal prevents reading another
    /// operator's account.
    #[test]
    fn a_disabled_operator_is_refused() {
        let carol = OperatorId::new();
        let uc = reading(FakeOperatorAuthorities::refusing(Refusal::Forbidden), carol);

        let result = block_on(uc.execute(&test_operator_caller(), carol));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An unauthenticated operator cannot read another operator's account.
    #[test]
    fn a_signed_out_operator_is_refused() {
        let carol = OperatorId::new();
        let uc = reading(FakeOperatorAuthorities::refusing(Refusal::SignedOut), carol);

        let result = block_on(uc.execute(&test_operator_caller(), carol));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
