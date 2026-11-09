//! Create operator: an operator registers another platform engineer.

use std::sync::Arc;

use ianua_domain::domains::operator::identity::Operator;
use ianua_domain::message;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{Email, OperatorId, PasswordHash};

use crate::acting::OperatorAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::OperatorCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::operator::OperatorStore;
use crate::use_case::Command;

/// The ports [`CreateOperatorUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreateOperatorPorts {
    /// Platform operators.
    pub operator_store: Arc<dyn OperatorStore>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// The account a new operator signs in with.
pub struct CreateOperatorRequest {
    /// The address the operator signs in with.
    pub email: Email,
    /// Their password, already hashed.
    pub password_hash: PasswordHash,
}

/// Registers a new platform operator, made by one who is acting now.
pub struct CreateOperatorUseCase {
    ports: CreateOperatorPorts,
}

impl CreateOperatorUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: CreateOperatorPorts) -> Self {
        Self { ports }
    }

    /// Refuses an address another operator already signs in with.
    async fn ensure_email_free(&self, email: &Email) -> Result<(), AppError> {
        let taken = self
            .ports
            .operator_store
            .find_by_email(email)
            .await
            .or_internal()?;
        match taken {
            Some(_) => Err(AppError::Conflict(message!(
                "operator-operator-with-this-email-already-exists",
                "operator with this email already exists"
            ))),
            None => Ok(()),
        }
    }
}

impl Command for CreateOperatorUseCase {
    type Caller = OperatorCaller;
    type Input = CreateOperatorRequest;
    type Output = Result<OperatorId, AppError>;

    /// Creates a new active operator account and records
    /// `operator.operator_created`, naming the operator who made it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's operator or key no
    ///   longer exists.
    /// - `AppError::Forbidden` when the caller's key no longer works or
    ///   their account is disabled.
    /// - `AppError::Conflict` if an operator with the same email already
    ///   exists.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &OperatorCaller,
        auditor: &RequestAuditor,
        request: CreateOperatorRequest,
    ) -> Result<OperatorId, AppError> {
        let authority = self.ports.operator_authorities.authority(caller).await?;
        self.ensure_email_free(&request.email).await?;
        let mut operator = Operator::create(
            OperatorId::new(),
            request.email,
            request.password_hash,
            &authority,
        )
        .map_err(AppError::from_domain)?;
        self.ports
            .operator_store
            .save(&operator)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), operator.take_events())
            .await
            .or_internal()?;
        Ok(*operator.id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeOperatorAuthorities, Refusal};
    use crate::test_support::operator::{FakeOperatorStore, test_operator_caller};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    struct Setup {
        uc: CreateOperatorUseCase,
        store: Arc<FakeOperatorStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn with(authorities: FakeOperatorAuthorities) -> Self {
            let store = Arc::new(FakeOperatorStore::empty());
            Self {
                uc: CreateOperatorUseCase::new(CreateOperatorPorts {
                    operator_store: store.clone(),
                    operator_authorities: Arc::new(authorities),
                }),
                store,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn new() -> Self {
            Self::with(FakeOperatorAuthorities::admitting())
        }

        fn create(&self, email: &str) -> Result<OperatorId, AppError> {
            block_on(self.uc.execute(
                &test_operator_caller(),
                &test_auditor(self.audit.clone()),
                CreateOperatorRequest {
                    email: Email::new(email).unwrap(),
                    password_hash: PasswordHash::from_stored("hash".to_owned()),
                },
            ))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Bob registers Alice as an operator. She is saved and the change
    /// recorded.
    #[test]
    fn create_operator_and_audits() {
        let setup = Setup::new();

        setup.create("alice@ianua.dev").unwrap();

        assert_eq!(setup.store.count(), 1);
        assert_eq!(setup.recorded(), vec!["operator.operator_created"]);
    }

    /// Bob registers Alice twice. The second is refused as a conflict and
    /// only the first is recorded.
    #[test]
    fn duplicate_email_returns_conflict() {
        let setup = Setup::new();
        setup.create("alice@ianua.dev").unwrap();

        let result = setup.create("alice@ianua.dev");

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(setup.store.count(), 1);
        assert_eq!(setup.recorded().len(), 1);
    }

    /// A disabled operator's authority refusal prevents creating another
    /// operator account, leaving the store empty.
    #[test]
    fn a_disabled_operator_is_refused() {
        let setup = Setup::with(FakeOperatorAuthorities::refusing(Refusal::Forbidden));

        let result = setup.create("mallory@ianua.dev");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.store.count(), 0);
    }

    /// An unauthenticated operator cannot create an account, and no
    /// creation event is recorded.
    #[test]
    fn a_signed_out_operator_is_refused() {
        let setup = Setup::with(FakeOperatorAuthorities::refusing(Refusal::SignedOut));

        let result = setup.create("mallory@ianua.dev");

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(setup.recorded().is_empty());
    }
}
