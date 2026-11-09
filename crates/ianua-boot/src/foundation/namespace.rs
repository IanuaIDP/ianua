//! The namespace every name on the bus server and the cache server sits
//! under, read alike by the server and the gateway, so two deployments,
//! such as staging and production, can share one bus server and one cache
//! server. A deployment that names none keeps the names the platform has
//! always used.

use ianua_infra::namespace::Namespace;

use crate::env::{Env, Read};

impl Env {
    /// The namespace `name` sets, or `ianua` when it is unset.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Rejected`](crate::env::ConfigError::Rejected) when it
    /// is not 1 to 32 lower-case letters,
    /// digits and dashes, starting and ending with a letter or a digit.
    pub fn namespace(&self, name: &str) -> Read<Namespace> {
        let read = self.parsed(name, |value| Namespace::new(&value))?;
        Ok(read.unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::ConfigError;

    /// With no namespace set, the deployment keeps the platform's own
    /// names.
    #[test]
    fn with_no_namespace_set_the_platform_names_are_kept() {
        let namespace = Env::of([]).namespace("NAMESPACE").unwrap();

        assert_eq!(namespace, Namespace::default());
        assert_eq!(namespace.as_str(), "ianua");
    }

    /// A namespace set is read as written.
    #[test]
    fn a_namespace_set_is_read() {
        let namespace = Env::of([("NAMESPACE", "staging")])
            .namespace("NAMESPACE")
            .unwrap();

        assert_eq!(namespace.as_str(), "staging");
    }

    /// Dots, colons, uppercase letters and a leading dash are refused in
    /// the namespace, with its setting named in each error.
    #[test]
    fn a_namespace_that_breaks_a_name_is_refused() {
        for refused in ["ianua.prod", "ianua:prod", "Staging", "-staging"] {
            let read = Env::of([("NAMESPACE", refused)]).namespace("NAMESPACE");

            assert!(
                matches!(read, Err(ConfigError::Rejected { ref name, .. }) if name == "NAMESPACE"),
                "{refused:?}"
            );
        }
    }
}
