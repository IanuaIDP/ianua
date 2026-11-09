//! Creating a no-mail installation through the real installer command.

use ianua_boot::shutdown::Shutdown;
use ianua_server::command::Command;
use ianua_server::config::Config;
use ianua_server::platform::Platform;
use ianua_server::{api, install, serve};

use super::{Stack, StackError};
use crate::wire::onboarding::Founded;

/// The installer's result, kept independent of application and domain types.
/// The setup proof has no diagnostic representation.
pub enum Installed {
    /// The organization exists with the one-time proof shown to its installer.
    Made {
        /// What was founded, as the signup scenarios identify it.
        founded: Founded,
        /// The owner's one-time installation proof.
        setup_token: Option<String>,
    },
    /// An organization already existed and was left unchanged.
    AlreadyThere,
}

/// The first organization and owner given to `ianua install`.
/// Contains the initial password and deliberately has no `Debug`.
pub struct Install {
    /// The organization's display name.
    pub organization_name: String,
    /// Its first tenant's display name.
    pub tenant_name: String,
    /// The owner's address, not yet verified by the installer.
    pub owner_email: String,
    /// The owner's display name.
    pub owner_name: String,
    /// The owner's initial password.
    pub owner_password: String,
}

impl Stack {
    /// Runs the real installation composition with a result for its operator,
    /// without capturing or printing a setup token in scenario output.
    ///
    /// # Errors
    ///
    /// Returns configuration, startup, installation or shutdown failures.
    pub async fn installed(&self, install: &Install) -> Result<Installed, StackError> {
        let vars = self.install_environment(install);
        let shutdown = Shutdown::new(super::STOP_GRACE);
        let outcome = async {
            let config = Config::read(&vars, &Command::Install)?;
            let platform = Platform::build(&config, &shutdown).await?;
            let deps = api::deps(&platform, &config)?;
            let installation = config
                .installation
                .as_ref()
                .ok_or(install::InstallError::NothingNamed)?;
            let result = install::install(&deps, installation).await?;
            let setup_token = result.setup_token().map(str::to_owned);
            Ok::<_, ianua_server::error::ServerError>(installed_outcome(result, setup_token))
        }
        .await;
        shutdown.stop();
        shutdown.join().await?;
        outcome.map_err(|cause| StackError::Platform {
            what: "install its first organization",
            cause,
        })
    }

    /// Runs `ianua install` against this self-hosted stack. It does not
    /// confirm the owner's address or change an existing installation.
    ///
    /// # Errors
    ///
    /// [`StackError::Platform`] when configuration or the install is refused.
    pub async fn install(&self, install: &Install) -> Result<(), StackError> {
        let vars = self.install_environment(install);
        serve::perform(&Command::Install, &vars)
            .await
            .map_err(|cause| StackError::Platform {
                what: "install its first organization",
                cause,
            })
    }

    /// Adds the command-only installation settings without altering serving.
    fn install_environment(&self, install: &Install) -> ianua_boot::env::Env {
        self.settings.env_including([
            (
                "INSTALL_ORGANIZATION_NAME",
                install.organization_name.as_str(),
            ),
            ("INSTALL_TENANT_NAME", install.tenant_name.as_str()),
            ("INSTALL_OWNER_EMAIL", install.owner_email.as_str()),
            ("INSTALL_OWNER_NAME", install.owner_name.as_str()),
            ("INSTALL_OWNER_PASSWORD", install.owner_password.as_str()),
        ])
    }
}

/// Converts the installer's result to the scenario's wire-shaped account identifiers.
fn installed_outcome(result: install::Outcome, setup_token: Option<String>) -> Installed {
    match result {
        install::Outcome::AlreadyInstalled => Installed::AlreadyThere,
        install::Outcome::Made(made) => Installed::Made {
            founded: Founded {
                organization_id: made.organization_id.to_string(),
                org_slug: made.org_slug,
                tenant_id: made.tenant_id.to_string(),
                tenant_slug: made.tenant_slug,
                admin_user_id: made.admin_user_id.to_string(),
                status: "provisioning".to_owned(),
            },
            setup_token,
        },
    }
}
