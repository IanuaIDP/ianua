//! Which stage of a product a tenant serves: production, staging or
//! development.
//!
//! An organization keeps one tenant per stage of the same product, as
//! Clerk keeps development and production instances. The label lets the
//! dashboard tell them apart and lets a clone copy one stage into another.

use std::fmt;

/// The stage of a product a tenant serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TenantEnvironment {
    /// The tenant real users sign in to.
    #[default]
    Production,
    /// A rehearsal of production, for checks before a release.
    Staging,
    /// A tenant for building and trying things out.
    Development,
}

impl TenantEnvironment {
    /// Every environment, in the order they are shown.
    pub const ALL: [Self; 3] = [Self::Production, Self::Staging, Self::Development];

    /// The stable name storage and the API use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Staging => "staging",
            Self::Development => "development",
        }
    }

    /// The environment stored under `value`.
    ///
    /// Returns `None` for a name the domain does not define, which the
    /// storage adapter reports as corrupted data rather than bad input.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|environment| environment.as_str() == value)
    }
}

impl fmt::Display for TenantEnvironment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each environment is written by its stored name and read back as the
    /// same environment.
    #[test]
    fn every_environment_reads_back_from_its_name() {
        for environment in TenantEnvironment::ALL {
            assert_eq!(
                TenantEnvironment::parse(environment.as_str()),
                Some(environment)
            );
        }
    }

    /// A stored `prod` or `Production` is no environment, so the row it came
    /// from is reported as corrupt rather than read as production.
    #[test]
    fn an_unknown_name_is_no_environment() {
        assert_eq!(TenantEnvironment::parse("prod"), None);
        assert_eq!(TenantEnvironment::parse("Production"), None);
    }

    /// A tenant nobody labelled serves production.
    #[test]
    fn the_default_is_production() {
        assert_eq!(TenantEnvironment::default(), TenantEnvironment::Production);
    }
}
