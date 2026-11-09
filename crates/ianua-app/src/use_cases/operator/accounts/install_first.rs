//! Install first operator: the platform's first operator, made once when it
//! is installed, since there is nobody yet to make one.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::password::PasswordHasher as _;
use ianua_domain::domains::operator::identity::Operator;
use ianua_domain::domains::organization::access::auth_config::OrganizationAuthConfig;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::shared::validation::Validator;
use ianua_domain::types::{ActorRef, Email, OperatorId, PasswordHash};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::CredentialBreachChecker;
use crate::ports::operator::OperatorStore;
use crate::services::authentication::password_hashing::PasswordHashing;
use crate::use_case::Command;
use crate::use_cases::organization::password_breach::ensure_password_unbreached;

/// The ports [`InstallFirstOperatorUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct InstallFirstOperatorPorts {
    /// Platform operators.
    pub operator_store: Arc<dyn OperatorStore>,
    /// Hashes the first operator's password, under the node's cap on
    /// hashes running at once.
    pub hashing: PasswordHashing,
    /// Looks the first operator's password up in known breaches.
    pub breach_checker: Arc<dyn CredentialBreachChecker>,
}

/// The account the first operator signs in with, as whoever installs the
/// platform names it.
///
/// No `Debug`: it carries the password.
pub struct InstallFirstOperatorRequest {
    /// The address the operator signs in with.
    pub email: Email,
    /// Their password, as given.
    pub password: Secret,
}

/// What installing the first operator did.
#[derive(Debug, PartialEq, Eq)]
pub enum FirstOperator {
    /// The first operator was made just now.
    Installed(OperatorId),
    /// An operator already existed, so nothing was touched.
    AlreadyInstalled,
}

/// Makes the platform's first operator, once.
pub struct InstallFirstOperatorUseCase {
    ports: InstallFirstOperatorPorts,
}

impl InstallFirstOperatorUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: InstallFirstOperatorPorts) -> Self {
        Self { ports }
    }

    async fn is_installed(&self) -> Result<bool, AppError> {
        self.ports.operator_store.any_exists().await.or_internal()
    }

    /// The hash of `password` once it meets the platform's password rules,
    /// the ones every new organization starts with, breached passwords
    /// blocked among them.
    async fn checked_password(&self, password: &Secret) -> Result<PasswordHash, AppError> {
        let rules = OrganizationAuthConfig::default();
        Validator::new("password", password.expose())
            .password(&rules.settings().password_policy)
            .validate_first()
            .map_err(|error| AppError::from_domain(error.into()))?;
        let checker = self.ports.breach_checker.as_ref();
        ensure_password_unbreached(checker, rules.breached_passwords(), password).await?;
        let hasher = self.ports.hashing.permitted().await?;
        hasher.hash(password.expose()).or_internal()
    }
}

impl Command for InstallFirstOperatorUseCase {
    type Caller = ();
    type Input = InstallFirstOperatorRequest;
    type Output = Result<FirstOperator, AppError>;

    /// Makes the first operator unless any operator exists, and records
    /// `operator.operator_created`, by the platform, when it does.
    ///
    /// It is run by whoever installs the platform, before anyone can sign
    /// in, so it takes no caller. Once any operator exists it makes nobody;
    /// every later operator is made by an operator. The password is held to
    /// the rules every new organization starts with: the platform's most
    /// powerful account gets no weaker one. A breached password is refused,
    /// and so is one the breach service cannot look up.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the password breaks the rules, appears in
    ///   known breaches, or could not be looked up.
    /// - `AppError::Busy` when no hash could start on this node in time.
    /// - `AppError::Internal` on persistence, hashing or audit failure.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        request: InstallFirstOperatorRequest,
    ) -> Result<FirstOperator, AppError> {
        if self.is_installed().await? {
            return Ok(FirstOperator::AlreadyInstalled);
        }
        let password_hash = self.checked_password(&request.password).await?;
        let mut operator = Operator::install_first(OperatorId::new(), request.email, password_hash);
        self.ports
            .operator_store
            .save(&operator)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ActorRef::System, operator.take_events())
            .await
            .or_internal()?;
        Ok(FirstOperator::Installed(*operator.id()))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::credentials::breach::BreachStatus;
    use ianua_domain::domains::operator::status::OperatorStatus;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::test_support::fakes::FakeHasher;

    use super::*;
    use crate::test_support::authentication::{
        FakeBreachChecker, UnreachableBreachChecker, hashing_with,
    };
    use crate::test_support::operator::{FakeOperatorStore, stored_operator};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    struct Installed {
        result: Result<FirstOperator, AppError>,
        store: Arc<FakeOperatorStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    fn install_with(store: FakeOperatorStore, password: &str) -> Installed {
        install_checking(store, password, Arc::new(FakeBreachChecker::default()))
    }

    /// Installs the first operator into `store` with `password`, looked up
    /// in `breaches`.
    fn install_checking(
        store: FakeOperatorStore,
        password: &str,
        breaches: Arc<dyn CredentialBreachChecker>,
    ) -> Installed {
        let store = Arc::new(store);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = InstallFirstOperatorUseCase::new(InstallFirstOperatorPorts {
            operator_store: store.clone(),
            hashing: hashing_with(Arc::new(FakeHasher)),
            breach_checker: breaches,
        });
        let request = InstallFirstOperatorRequest {
            email: Email::new("root@ianua.dev").unwrap(),
            password: Secret::new(password),
        };
        let result = block_on(use_case.execute(&(), &test_auditor(audit.clone()), request));
        Installed {
            result,
            store,
            audit,
        }
    }

    fn install(store: FakeOperatorStore) -> Installed {
        install_with(store, "SecureP@ssw0rd!")
    }

    /// The platform starts for the first time with no operator. The one its
    /// installer names is made, active, its password hashed, and that is
    /// recorded.
    #[test]
    fn the_first_operator_is_made_on_a_fresh_platform() {
        let installed = install(FakeOperatorStore::empty());

        let Ok(FirstOperator::Installed(id)) = installed.result else {
            panic!("the first operator was not made");
        };
        let made = block_on(installed.store.find_by_id(&id)).unwrap().unwrap();
        assert!(made.is_active());
        assert_eq!(made.password_hash().as_str(), "fake$SecureP@ssw0rd!");
        assert_eq!(
            installed.audit.records.lock().unwrap().as_slice(),
            ["operator.operator_created"]
        );
    }

    /// With an operator already installed, installation returns already
    /// installed, retains one account and records no creation event.
    #[test]
    fn an_installed_platform_makes_no_second_first_operator() {
        let bob = stored_operator(OperatorId::new(), "bob@ianua.dev", OperatorStatus::Active);

        let installed = install(FakeOperatorStore::holding([bob]));

        assert_eq!(installed.result.unwrap(), FirstOperator::AlreadyInstalled);
        assert_eq!(installed.store.count(), 1);
        assert!(installed.audit.records.lock().unwrap().is_empty());
    }

    /// A weak first-operator password is refused without storing an
    /// operator or recording a creation event.
    #[test]
    fn a_weak_password_is_refused() {
        let installed = install_with(FakeOperatorStore::empty(), "short");

        assert!(matches!(
            installed.result,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
        assert_eq!(installed.store.count(), 0);
        assert!(installed.audit.records.lock().unwrap().is_empty());
    }

    /// A breached first-operator password is refused, leaving the operator
    /// store empty.
    #[test]
    fn a_breached_password_is_refused() {
        let breaches = Arc::new(FakeBreachChecker {
            status: BreachStatus::Breached(9),
        });

        let installed = install_checking(FakeOperatorStore::empty(), "SecureP@ssw0rd!", breaches);

        assert!(matches!(installed.result, Err(AppError::Domain(_))));
        assert_eq!(installed.store.count(), 0);
    }

    /// An unavailable breach checker prevents installing the first
    /// operator, leaving the store empty.
    #[test]
    fn a_password_the_breach_service_cannot_look_up_is_refused() {
        let installed = install_checking(
            FakeOperatorStore::empty(),
            "SecureP@ssw0rd!",
            Arc::new(UnreachableBreachChecker::default()),
        );

        assert!(matches!(installed.result, Err(AppError::Domain(_))));
        assert_eq!(installed.store.count(), 0);
    }
}
