//! The organization `ianua install` makes for a self-hosted installation:
//! its name, its first tenant and its owner, read from settings only that
//! command reads.

use std::fmt;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{DisplayName, Email};

use crate::command::Command;

/// The settings only the install command reads.
const INSTALL_SETTINGS: [&str; 6] = [
    "INSTALL_ORGANIZATION_NAME",
    "INSTALL_TENANT_NAME",
    "INSTALL_OWNER_EMAIL",
    "INSTALL_OWNER_NAME",
    "INSTALL_OWNER_PASSWORD",
    "INSTALL_OWNER_PASSWORD_FILE",
];

/// The organization the install command makes. `Debug` shows no password.
#[derive(Clone)]
pub struct Installation {
    /// The display label assigned to the organization created during installation.
    pub organization_name: String,
    /// Name of its first tenant.
    pub tenant_name: String,
    /// The owner's address, which is also how they sign in.
    pub owner_email: Email,
    /// The owner's name, as the dashboard shows it.
    pub owner_display_name: DisplayName,
    /// The owner's first password.
    pub owner_password: Secret,
}

impl fmt::Debug for Installation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Installation")
            .field("organization_name", &self.organization_name)
            .field("tenant_name", &self.tenant_name)
            .field("owner_email", &self.owner_email)
            .field("owner_display_name", &self.owner_display_name)
            .finish_non_exhaustive()
    }
}

impl Installation {
    /// The organization `command` makes, read from `vars`, or `None` for
    /// any other command.
    ///
    /// # Errors
    ///
    /// - [`ConfigError::Missing`] when the install command runs without
    ///   the organization's name, or the owner's address or password.
    /// - [`ConfigError::Contradicts`] when an install setting is set for
    ///   another command, which never reads it: the owner's first password
    ///   left in a server's environment outlives the one run that needed
    ///   it.
    pub fn read(vars: &Env, command: &Command) -> Read<Option<Self>> {
        let Command::Install = command else {
            return refuse_install_settings(vars).map(|()| None);
        };
        let limits = DomainLimits::default();
        let owner_name = vars.text("INSTALL_OWNER_NAME", "Owner")?;
        Ok(Some(Self {
            organization_name: vars.required("INSTALL_ORGANIZATION_NAME")?,
            tenant_name: vars.text("INSTALL_TENANT_NAME", "Main")?,
            owner_email: vars.required_parsed("INSTALL_OWNER_EMAIL", Email::new)?,
            owner_display_name: DisplayName::new(owner_name, &limits.display_name)
                .map_err(|cause| ConfigError::rejected("INSTALL_OWNER_NAME", cause))?,
            owner_password: vars.required_secret("INSTALL_OWNER_PASSWORD")?,
        }))
    }
}

/// Refuses the install settings where nothing reads them.
fn refuse_install_settings(vars: &Env) -> Read<()> {
    for name in INSTALL_SETTINGS {
        if vars.optional(name)?.is_some() {
            return Err(ConfigError::contradicts(
                name,
                "is only read by `ianua install`; remove it from every other command's environment",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installing() -> Vec<(&'static str, &'static str)> {
        vec![
            ("INSTALL_ORGANIZATION_NAME", "Acme"),
            ("INSTALL_OWNER_EMAIL", "owner@acme.com"),
            ("INSTALL_OWNER_PASSWORD", "a long first password"),
        ]
    }

    /// The install command reads its organization and owner.
    #[test]
    fn the_install_command_reads_its_organization_and_owner() {
        let installation = Installation::read(&Env::of(installing()), &Command::Install)
            .unwrap()
            .unwrap();

        assert_eq!(installation.organization_name, "Acme");
        assert_eq!(installation.tenant_name, "Main");
        assert_eq!(
            installation.owner_password.expose(),
            "a long first password"
        );
    }

    /// Installation without the owner's email fails with the missing
    /// owner-email setting.
    #[test]
    fn an_installation_without_its_owner_is_refused() {
        let pairs: Vec<_> = installing()
            .into_iter()
            .filter(|(name, _)| *name != "INSTALL_OWNER_EMAIL")
            .collect();

        let read = Installation::read(&Env::of(pairs), &Command::Install);

        assert!(
            matches!(read, Err(ConfigError::Missing { name }) if name == "INSTALL_OWNER_EMAIL")
        );
    }

    /// Installation debug output omits the owner's password.
    #[test]
    fn an_installation_never_prints_the_owners_password() {
        let installation = Installation::read(&Env::of(installing()), &Command::Install).unwrap();

        assert!(!format!("{installation:?}").contains("a long first password"));
    }

    /// Serving with installation settings is refused as contradictory.
    #[test]
    fn install_settings_beside_another_command_are_refused() {
        let read = Installation::read(&Env::of(installing()), &Command::Serve);

        assert!(matches!(read, Err(ConfigError::Contradicts { .. })));
    }

    /// Any other command, with no install setting, reads none.
    #[test]
    fn another_command_reads_no_installation() {
        let read = Installation::read(&Env::of([]), &Command::Serve).unwrap();

        assert!(read.is_none());
    }
}
