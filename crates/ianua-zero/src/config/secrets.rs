//! Startup validation of mounted-secret and Vault settings.
//!
//! These settings are checked for valid paths, paired credentials and
//! production TLS, then discarded. The gateway has no runtime consumer
//! resolving tenant secret references from these settings.

use std::path::PathBuf;
use std::time::Duration;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_boot::environment::Environment;
use url::Url;

/// Checks secret settings without retaining unused credentials.
///
/// # Errors
///
/// Invalid paths, Vault addresses or timeouts, unpaired address and token,
/// a namespace without a Vault, or a plain HTTP Vault in production.
pub(crate) fn validate(vars: &Env, environment: Environment) -> Read<()> {
    files(vars)?;
    vault(vars, environment)
}

/// `GATEWAY_SECRETS_DIR`, which must be absolute: a relative directory
/// would depend on where the process was started.
fn files(vars: &Env) -> Read<PathBuf> {
    let name = "GATEWAY_SECRETS_DIR";
    let directory = vars
        .path(name)?
        .unwrap_or_else(|| PathBuf::from("/run/secrets"));
    if !directory.is_absolute() {
        return Err(ConfigError::invalid(name, "must be an absolute path"));
    }
    Ok(directory)
}

/// Checks the Vault address, token, namespace and timeout in setting order.
fn vault(vars: &Env, environment: Environment) -> Read<()> {
    let address = vault_address(vars, environment)?;
    let token = vars.secret("VAULT_TOKEN")?;
    let namespace = vars.optional("VAULT_NAMESPACE")?;
    vault_timeout(vars)?;
    match (address, token) {
        (Some(_), Some(_)) => Ok(()),
        (Some(_), None) => Err(ConfigError::missing(
            "VAULT_TOKEN or VAULT_TOKEN_FILE, which VAULT_ADDR needs,",
        )),
        (None, Some(_)) => Err(ConfigError::contradicts(
            "VAULT_TOKEN",
            "is set without VAULT_ADDR",
        )),
        (None, None) if namespace.is_some() => Err(ConfigError::contradicts(
            "VAULT_NAMESPACE",
            "is set without VAULT_ADDR",
        )),
        (None, None) => Ok(()),
    }
}

/// The configured Vault deadline, validated even when no Vault address is set.
fn vault_timeout(vars: &Env) -> Read<Duration> {
    vars.seconds_in("VAULT_TIMEOUT_SECONDS", Duration::from_secs(5), 1..=60)
}

/// Checks that `VAULT_ADDR` uses TLS in production before accepting its credential settings.
fn vault_address(vars: &Env, environment: Environment) -> Read<Option<Url>> {
    let name = "VAULT_ADDR";
    let Some(address) = vars.url(name)? else {
        return Ok(None);
    };
    if environment.is_production() && address.scheme() != "https" {
        return Err(ConfigError::invalid(
            name,
            "must be https in production, since the token is sent with every read",
        ));
    }
    Ok(Some(address))
}

#[cfg(test)]
mod tests {
    use Environment::{Development, Production};

    use super::*;

    /// Empty settings validate with the absolute default directory and five-second timeout.
    #[test]
    fn defaults_validate_an_absolute_directory_and_bounded_timeout() {
        let vars = Env::of([]);
        assert!(validate(&vars, Production).is_ok());
        assert_eq!(files(&vars).unwrap(), PathBuf::from("/run/secrets"));
        assert_eq!(vault_timeout(&vars).unwrap(), Duration::from_secs(5));
    }

    /// A TLS Vault with its token and namespace passes startup validation.
    #[test]
    fn a_configured_vault_passes_startup_validation() {
        let vars = Env::of([
            ("VAULT_ADDR", "https://vault.internal:8200"),
            ("VAULT_TOKEN", "hvs.s3cret"),
            ("VAULT_NAMESPACE", "tenants"),
        ]);

        assert!(validate(&vars, Production).is_ok());
    }

    /// A Vault address without a token is rejected with the missing token setting named.
    #[test]
    fn a_vault_address_without_its_token_is_refused() {
        let read = validate(
            &Env::of([("VAULT_ADDR", "https://vault.internal:8200")]),
            Production,
        );

        assert!(
            matches!(read, Err(ConfigError::Missing { name }) if name.starts_with("VAULT_TOKEN"))
        );
    }

    /// A token without a Vault address is refused without exposing it in either error format.
    #[test]
    fn a_token_without_a_vault_is_refused() {
        let read = validate(&Env::of([("VAULT_TOKEN", "hvs.s3cret")]), Production);
        let error = read.unwrap_err();

        assert!(matches!(&error, ConfigError::Contradicts { name, .. } if name == "VAULT_TOKEN"));
        assert!(!format!("{error:?}").contains("hvs.s3cret"));
        assert!(!error.to_string().contains("hvs.s3cret"));
    }

    /// A namespace with no Vault is refused.
    #[test]
    fn a_namespace_without_a_vault_is_refused() {
        let read = validate(&Env::of([("VAULT_NAMESPACE", "tenants")]), Production);

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "VAULT_NAMESPACE")
        );
    }

    /// A plain HTTP Vault address is rejected in production but accepted in development.
    #[test]
    fn a_plain_http_vault_is_refused_in_production_only() {
        let vars = Env::of([
            ("VAULT_ADDR", "http://vault.internal:8200"),
            ("VAULT_TOKEN", "hvs.s3cret"),
        ]);

        assert!(matches!(
            validate(&vars, Production),
            Err(ConfigError::Invalid { name, .. }) if name == "VAULT_ADDR"
        ));
        assert!(validate(&vars, Development).is_ok());
    }

    /// A relative secrets directory is rejected with the directory setting named.
    #[test]
    fn a_relative_secrets_directory_is_refused() {
        let read = validate(&Env::of([("GATEWAY_SECRETS_DIR", "secrets")]), Production);

        assert!(
            matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "GATEWAY_SECRETS_DIR")
        );
    }

    /// Vault timeouts remain bounded even when no Vault address is configured.
    #[test]
    fn vault_timeouts_are_always_validated() {
        for seconds in ["0", "61"] {
            let read = validate(&Env::of([("VAULT_TIMEOUT_SECONDS", seconds)]), Production);
            assert!(
                matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "VAULT_TIMEOUT_SECONDS")
            );
        }
    }
}
