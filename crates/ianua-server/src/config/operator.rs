//! The platform's first operator, as `ianua operator create` makes them:
//! their address from the command line, their password from a setting
//! only that command reads.

use std::fmt;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::Email;

use crate::command::Command;

/// The setting holding the first operator's password.
const PASSWORD: &str = "OPERATOR_PASSWORD";

/// The first operator to make. `Debug` shows no password.
#[derive(Clone)]
pub struct FirstOperatorConfig {
    /// The address they sign in with, from `--email`.
    pub email: Email,
    /// `OPERATOR_PASSWORD` or the file `OPERATOR_PASSWORD_FILE` names.
    pub password: Secret,
}

impl fmt::Debug for FirstOperatorConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FirstOperatorConfig")
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}

impl FirstOperatorConfig {
    /// The first operator `command` makes, their password read from `vars`,
    /// or `None` for any other command.
    ///
    /// # Errors
    ///
    /// - [`ConfigError::Missing`] when the operator command runs with no
    ///   password set.
    /// - [`ConfigError::Contradicts`] when the password is set for another
    ///   command, which never reads it: a password left in a server's
    ///   environment outlives the one run that needed it.
    pub fn read(vars: &Env, command: &Command) -> Read<Option<Self>> {
        let Command::CreateOperator { email } = command else {
            return refuse_password(vars).map(|()| None);
        };
        Ok(Some(Self {
            email: email.clone(),
            password: vars.required_secret(PASSWORD)?,
        }))
    }
}

/// Refuses the first operator's password where nothing reads it.
fn refuse_password(vars: &Env) -> Read<()> {
    if vars.secret(PASSWORD)?.is_none() {
        return Ok(());
    }
    Err(ConfigError::contradicts(
        PASSWORD,
        "is only read by `ianua operator create`; remove it once the first operator is made",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create() -> Command {
        Command::CreateOperator {
            email: Email::new("root@ianua.dev").unwrap(),
        }
    }

    /// The operator command reads the password, and never prints it.
    #[test]
    fn the_operator_command_reads_the_password_and_never_prints_it() {
        let vars = Env::of([(PASSWORD, "a long operator password")]);

        let operator = FirstOperatorConfig::read(&vars, &create())
            .unwrap()
            .unwrap();

        assert_eq!(operator.password.expose(), "a long operator password");
        assert_eq!(operator.email.as_str(), "root@ianua.dev");
        assert!(!format!("{operator:?}").contains("a long operator password"));
    }

    /// Operator creation without a password fails with the missing-password setting.
    #[test]
    fn the_operator_command_without_a_password_is_refused() {
        let read = FirstOperatorConfig::read(&Env::default(), &create());

        assert!(matches!(read, Err(ConfigError::Missing { name }) if name.starts_with(PASSWORD)));
    }

    /// A serving node refuses the first-operator password setting as contradictory.
    #[test]
    fn the_password_beside_another_command_is_refused() {
        let vars = Env::of([(PASSWORD, "a long operator password")]);

        let read = FirstOperatorConfig::read(&vars, &Command::Serve);

        assert!(matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == PASSWORD));
    }

    /// Any other command reads no operator.
    #[test]
    fn any_other_command_reads_no_operator() {
        assert!(
            FirstOperatorConfig::read(&Env::default(), &Command::Serve)
                .unwrap()
                .is_none()
        );
    }
}
