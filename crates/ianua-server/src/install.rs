//! The self-hosted installer: the one organization, its first tenant and
//! its first owner, made through the app's install use case, and the
//! platform's first operator (see [`operator`]).
//!
//! The platform was built before either runs, so the schema and the roles
//! are up to date. Both run again safely: once what they make exists they
//! change nothing and say so.

pub mod operator;

use ianua_api::state::Deps;
use ianua_app::auditor::RequestAuditor;
use ianua_app::error::AppError;
use ianua_app::services::kept_together::kept_together;
use ianua_app::use_case::Command as _;
use ianua_app::use_cases::onboarding::founding::{Founded, Founder, FoundingPorts, SetupToken};
use ianua_app::use_cases::onboarding::{InstallRequest, InstallUseCase, Installation as Installed};
use ianua_assembly::deps::{Adapters, Settings};

use crate::api;
use crate::config::Config;
use crate::config::installation::Installation;
use crate::error::ServerError;
use crate::platform::Platform;

/// Why the installer made nothing.
#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    /// The configuration was read for another command, so it names no
    /// organization to install.
    #[error(
        "the configuration was not read for the install command, so it names nothing to install"
    )]
    NothingNamed,
    /// No first operator was named, which only `ianua operator create`
    /// does.
    #[error("no first operator was named; run `ianua operator create --email <address>`")]
    NoOperatorNamed,
    /// The use case refused or failed.
    #[error("{what} could not be made")]
    Refused {
        /// What was being made.
        what: &'static str,
        /// Why.
        #[source]
        cause: AppError,
    },
}

/// What a run of the installer found or made.
pub enum Outcome {
    /// The organization was made just now.
    Made(Founded),
    /// An organization was there already: nothing changed.
    AlreadyInstalled,
}

impl Outcome {
    /// The one-time setup token to hand to the installer, only when this run
    /// created the owner. It must never be included in diagnostic output.
    #[must_use]
    pub fn setup_token(&self) -> Option<&str> {
        let Self::Made(founded) = self else {
            return None;
        };
        match &founded.setup_token {
            SetupToken::Issued(token) => Some(token.expose()),
            SetupToken::NotIssued => None,
        }
    }
}

/// Makes the installation's organization, first tenant and owner, as the
/// configuration's `Installation` names them, unless an organization
/// exists, and says on standard output what it did. The owner's password
/// is never printed; the one-time setup token that confirms their address
/// is, once.
///
/// # Errors
///
/// [`ServerError`] when the adapters cannot be built or the organization
/// cannot be made.
pub async fn run(platform: &Platform, config: &Config) -> Result<(), ServerError> {
    let Some(installation) = &config.installation else {
        return Err(InstallError::NothingNamed.into());
    };
    let deps = api::deps(platform, config)?;
    let outcome = install(&deps, installation).await?;
    report(installation, outcome);
    Ok(())
}

/// Makes the organization `installation` names unless one exists, in one
/// unit: a run that fails part way keeps nothing. A second process that
/// made it first counts as installed.
///
/// # Errors
///
/// [`InstallError::Refused`] when the use case refuses the configured
/// names or password, or the database will not take the write.
pub async fn install(deps: &Deps, installation: &Installation) -> Result<Outcome, InstallError> {
    let use_case = install_use_case(&deps.adapters, &deps.settings);
    let auditor = RequestAuditor::system(deps.adapters.event_dispatcher.clone());
    let unit = deps.adapters.unit_of_work.as_ref();
    let made = kept_together(
        unit,
        use_case.execute(&(), &auditor, request_for(installation)),
    )
    .await;
    match made {
        Ok(Installed::Created(founded)) => Ok(Outcome::Made(founded)),
        Ok(Installed::AlreadyInstalled) | Err(AppError::Conflict(_)) => {
            Ok(Outcome::AlreadyInstalled)
        }
        Err(cause) => Err(InstallError::Refused {
            what: "the installation's organization",
            cause,
        }),
    }
}

/// The install use case, founding through the same ports the API's
/// sign-up founds through.
#[must_use]
pub(crate) fn install_use_case(a: &Adapters, s: &Settings) -> InstallUseCase {
    InstallUseCase::new(
        Founder::new(
            operator::password_hashing(a),
            s.domain_limits.clone(),
            s.compliance_limits.clone(),
            FoundingPorts {
                random: a.secure_random.clone(),
                org_store: a.organization_store.clone(),
                subscriptions: a.org_subscription_store.clone(),
                tenant_store: a.tenant_store.clone(),
                org_user_store: a.org_user_store.clone(),
                setup_token_store: a.org_token_store_installation_setup.clone(),
                token_generator: a.refresh_token_generator.clone(),
                breach_checker: a.credential_breach_checker.clone(),
            },
        )
        .with_platform_hosts(s.platform_hosts.clone()),
    )
}

/// What the install use case is asked to found.
fn request_for(installation: &Installation) -> InstallRequest {
    InstallRequest {
        organization_name: installation.organization_name.clone(),
        tenant_name: installation.tenant_name.clone(),
        owner_email: installation.owner_email.clone(),
        owner_display_name: installation.owner_display_name.clone(),
        owner_password: installation.owner_password.expose().to_owned(),
    }
}

/// Says on standard output what the run did, the setup token among it
/// when one was issued: it is shown here once and kept nowhere in the
/// clear.
fn report(installation: &Installation, outcome: Outcome) {
    let Outcome::Made(founded) = outcome else {
        println!("Already installed: an organization exists, so nothing was changed.");
        return;
    };
    println!(
        "Installed organization '{}' with its first tenant '{}'.",
        founded.org_slug, founded.tenant_slug
    );
    println!(
        "Its owner signs in as {}, with the password INSTALL_OWNER_PASSWORD holds.",
        installation.owner_email.as_str()
    );
    let SetupToken::Issued(token) = founded.setup_token else {
        return;
    };
    println!();
    println!("Confirm the owner's address within a day with this one-time setup token:");
    println!("  {}", token.expose());
    println!("Send it as {{\"token\": \"...\"}} to POST /api/v1/users/confirm-installer.");
    println!("It is shown only now.");
}
