//! Reserved organization slugs protect the deployment's hostnames.

use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{DomainName, TenantSlug};

/// Refuses an organization slug matching a platform label or the first
/// label of any configured deployment host, or the sixteen hexadecimal
/// characters used for generated tenant labels. Hosts are supplied by the
/// composition root, so custom dashboard and API names are reserved too.
///
/// # Errors
///
/// Returns `DomainError::Validation` when the slug is reserved.
pub fn ensure_organization_label(
    slug: &TenantSlug,
    hosts: &[DomainName],
) -> Result<(), DomainError> {
    let fixed = ["app", "api", "www", "ns1", "ns2"];
    let generated =
        slug.as_str().len() == 16 && slug.as_str().bytes().all(|byte| byte.is_ascii_hexdigit());
    let reserved = generated
        || fixed.contains(&slug.as_str())
        || hosts
            .iter()
            .any(|host| host.as_str().split('.').next() == Some(slug.as_str()));
    if reserved {
        return Err(DomainError::invalid(message!(
            "organization-the-organization-slug-is-reserved-for",
            "the organization slug is reserved for the platform"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::config::SlugLimits;

    /// Built-in hosts, the configured console label and generated tenant
    /// labels are reserved; an ordinary name such as Acme remains usable.
    #[test]
    fn platform_and_deployment_labels_are_reserved() {
        let hosts = [DomainName::new("console.example.com").unwrap()];
        for name in [
            "app",
            "api",
            "www",
            "ns1",
            "ns2",
            "console",
            "abcdef0123456789",
        ] {
            let refused = TenantSlug::new(name, &SlugLimits::default()).map_or(true, |slug| {
                ensure_organization_label(&slug, &hosts).is_err()
            });
            assert!(refused, "{name}");
        }
        let slug = TenantSlug::new("acme", &SlugLimits::default()).unwrap();
        assert!(ensure_organization_label(&slug, &hosts).is_ok());
    }
}
