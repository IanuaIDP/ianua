//! Host configuration shared by the API, worker and gateway.

use ianua_domain::domains::tenant::hosts::PlatformAddressing;
use ianua_domain::types::DomainName;

use crate::env::{ConfigError, Env, Read};

/// Reads the platform shape, refusing explicit choices without their TLS prerequisites.
/// Without suitable TLS the default is custom domains only. A private ACME
/// authority uses the same DNS-01 path, with privately reachable nameservers.
///
/// # Errors
///
/// Returns a configuration error for an unknown shape or incomplete prerequisites.
pub fn addressing(vars: &Env) -> Read<PlatformAddressing> {
    let wildcard = vars.flag("PLATFORM_WILDCARD_TLS", false)?;
    let nested = vars.optional("ACME_DIRECTORY_URL")?.is_some()
        && !vars.list("DNS_NAMESERVERS")?.is_empty()
        && vars.optional("PROXY_PUBLIC_ADDRESS")?.is_some();
    let installed = matches!(
        vars.text("DEPLOYMENT", "cloud")?.as_str(),
        "self_hosted" | "self-hosted"
    );
    let default = match (installed, wildcard, nested) {
        (true, true, _) => PlatformAddressing::Flat,
        (false, _, true) => PlatformAddressing::Nested,
        _ => PlatformAddressing::Disabled,
    };
    let chosen = vars.choice(
        "PLATFORM_ADDRESSING",
        default,
        &[
            ("off", PlatformAddressing::Disabled),
            ("flat", PlatformAddressing::Flat),
            ("nested", PlatformAddressing::Nested),
        ],
    )?;
    AddressTls { wildcard, nested }.ensure_supports(chosen)
}

/// Certificate prerequisites for the two platform address shapes.
struct AddressTls {
    wildcard: bool,
    nested: bool,
}

impl AddressTls {
    /// Refuses an explicit shape whose certificate prerequisites are absent.
    fn ensure_supports(&self, chosen: PlatformAddressing) -> Read<PlatformAddressing> {
        match chosen {
            PlatformAddressing::Flat if !self.wildcard => Err(ConfigError::contradicts(
                "PLATFORM_ADDRESSING",
                "flat requires PLATFORM_WILDCARD_TLS=true and an operator-managed wildcard certificate",
            )),
            PlatformAddressing::Nested if !self.nested => Err(ConfigError::contradicts(
                "PLATFORM_ADDRESSING",
                "nested requires ACME_DIRECTORY_URL, DNS_NAMESERVERS and PROXY_PUBLIC_ADDRESS; delegate the apps domain to those nameservers",
            )),
            PlatformAddressing::Disabled => {
                tracing::info!("platform addresses are off; only custom domains are served");
                Ok(chosen)
            }
            _ => Ok(chosen),
        }
    }
}

/// Collects deployment hosts whose leading labels cannot be organization slugs.
///
/// # Errors
///
/// Returns a configuration error for malformed explicit hosts or public URLs.
pub fn reserved_hosts(vars: &Env) -> Read<Vec<DomainName>> {
    let mut names = vars.list("PLATFORM_HOSTS")?;
    names.extend(vars.list("DNS_NAMESERVERS")?);
    for setting in [
        "APP_BASE_URL",
        "API_BASE_URL",
        "OAUTH_DEVICE_VERIFICATION_URI",
    ] {
        let Some(value) = vars.optional(setting)? else {
            continue;
        };
        let url = url::Url::parse(&value).map_err(|cause| ConfigError::rejected(setting, cause))?;
        if let Some(host) = url.host_str() {
            names.push(host.to_owned());
        }
    }
    names.extend(vars.optional("PROXY_BASE_DOMAIN")?);
    names
        .into_iter()
        .map(|name| {
            DomainName::new(name).map_err(|cause| ConfigError::rejected("PLATFORM_HOSTS", cause))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An installation with an operator wildcard defaults to the one-label shape.
    #[test]
    fn installed_wildcard_defaults_to_flat() {
        let vars = Env::of([
            ("DEPLOYMENT", "self_hosted"),
            ("PLATFORM_WILDCARD_TLS", "true"),
        ]);
        assert_eq!(addressing(&vars).unwrap(), PlatformAddressing::Flat);
    }

    /// Without TLS prerequisites, platform addresses default to disabled
    /// and explicitly requesting nested addresses is refused.
    #[test]
    fn no_tls_defaults_to_custom_domains_only() {
        assert_eq!(
            addressing(&Env::of([])).unwrap(),
            PlatformAddressing::Disabled
        );
        assert!(addressing(&Env::of([("PLATFORM_ADDRESSING", "nested")])).is_err());
    }

    /// Public or private ACME uses nested addresses only with an authoritative DNS path.
    #[test]
    fn a_private_authority_and_nameserver_support_nested() {
        let vars = Env::of([
            ("ACME_DIRECTORY_URL", "https://ca.internal/directory"),
            ("DNS_NAMESERVERS", "ns1.internal.example"),
            ("PROXY_PUBLIC_ADDRESS", "10.0.0.1"),
            ("PLATFORM_ADDRESSING", "nested"),
        ]);
        assert_eq!(addressing(&vars).unwrap(), PlatformAddressing::Nested);
    }
}
