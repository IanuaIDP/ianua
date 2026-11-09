//! The platform's first operator: `ianua operator create --email <address>`,
//! the password read from `OPERATOR_PASSWORD`, made through the app's
//! install use case and refused once any operator exists.

use ianua_api::state::Deps;
use ianua_app::auditor::RequestAuditor;
use ianua_app::services::authentication::password_hashing::PasswordHashing;
use ianua_app::services::kept_together::kept_together;
use ianua_app::use_case::Command as _;
use ianua_app::use_cases::operator::accounts::{
    FirstOperator, InstallFirstOperatorPorts, InstallFirstOperatorRequest,
    InstallFirstOperatorUseCase,
};
use ianua_assembly::deps::Adapters;

use crate::api;
use crate::config::Config;
use crate::config::operator::FirstOperatorConfig;
use crate::error::ServerError;
use crate::install::InstallError;
use crate::platform::Platform;

/// Makes the first operator the configuration names, unless an operator
/// exists, and says on standard output what it did. The password is never
/// printed.
///
/// # Errors
///
/// [`ServerError`] when the adapters cannot be built, the operator command
/// was not what ran, or the operator cannot be made.
pub async fn run(platform: &Platform, config: &Config) -> Result<(), ServerError> {
    let Some(operator) = &config.first_operator else {
        return Err(InstallError::NoOperatorNamed.into());
    };
    let deps = api::deps(platform, config)?;
    match create(&deps, operator).await? {
        FirstOperator::Installed(id) => println!(
            "Made the platform's first operator {id}, signing in as {}.",
            operator.email.as_str()
        ),
        FirstOperator::AlreadyInstalled => {
            println!("An operator exists already, so nobody was made; operators make the rest.");
        }
    }
    Ok(())
}

/// Makes `operator` the platform's first operator unless any operator
/// exists, in one unit.
///
/// # Errors
///
/// [`InstallError::Refused`] when the password breaks the rules or the
/// database will not take the write.
pub async fn create(
    deps: &Deps,
    operator: &FirstOperatorConfig,
) -> Result<FirstOperator, InstallError> {
    let use_case = InstallFirstOperatorUseCase::new(InstallFirstOperatorPorts {
        operator_store: deps.adapters.operator_store.clone(),
        hashing: password_hashing(&deps.adapters),
        breach_checker: deps.adapters.credential_breach_checker.clone(),
    });
    let auditor = RequestAuditor::system(deps.adapters.event_dispatcher.clone());
    let request = InstallFirstOperatorRequest {
        email: operator.email.clone(),
        password: operator.password.clone(),
    };
    kept_together(
        deps.adapters.unit_of_work.as_ref(),
        use_case.execute(&(), &auditor, request),
    )
    .await
    .map_err(|cause| InstallError::Refused {
        what: "the first operator",
        cause,
    })
}

/// Hashing passwords under this node's cap on hashes at once, as every
/// use case that takes a password does.
#[must_use]
pub(crate) fn password_hashing(a: &Adapters) -> PasswordHashing {
    PasswordHashing::new(a.password_hasher.clone(), a.password_hash_permits.clone())
}
