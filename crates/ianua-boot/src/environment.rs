//! What kind of environment the process runs in, which the readers of
//! several areas take to choose their defaults.

use crate::env::{Env, Read};

/// What kind of environment the process runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    /// Production: every check meant for production holds.
    Production,
    /// Development: error chains in answers, plain-text logs, and the
    /// checks meant for production relaxed where a setting says so.
    Development,
}

impl Environment {
    /// `APP_ENV`. Unset is production: development puts internal error
    /// chains in answers, so it is asked for by name.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`](crate::env::ConfigError::Invalid) for any
    /// other word.
    pub fn read(vars: &Env) -> Read<Self> {
        vars.choice(
            "APP_ENV",
            Self::Production,
            &[
                ("production", Self::Production),
                ("prod", Self::Production),
                ("development", Self::Development),
                ("dev", Self::Development),
            ],
        )
    }

    /// Whether this is production.
    #[must_use]
    pub fn is_production(self) -> bool {
        matches!(self, Self::Production)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Omitting APP_ENV keeps production checks enabled without configuration.
    #[test]
    fn unset_is_production() {
        assert_eq!(
            Environment::read(&Env::of([])).unwrap(),
            Environment::Production
        );
    }

    /// Development is only had by asking for it by name.
    #[test]
    fn development_is_asked_for_by_name() {
        assert_eq!(
            Environment::read(&Env::of([("APP_ENV", "dev")])).unwrap(),
            Environment::Development
        );
        assert!(Environment::read(&Env::of([("APP_ENV", "staging")])).is_err());
    }
}
