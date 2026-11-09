use crate::shared::validation::rules::url::{UrlRules, UrlShape};
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{HttpUrl, HttpsUrl, TenantSlug};

text_value! {
    /// Who issued a token or assertion, the `iss` a verifier holds it to.
    ///
    /// An OIDC `iss` and a SAML `EntityID` are identifiers, not routes. A
    /// relying party compares them for equality, and for OIDC discovery it
    /// fetches them. So an issuer is always an absolute URL. A tenant's
    /// issuer includes the deployment's base URL. Two deployments that share
    /// an org slug and tenant slug must not issue under the same name, or an
    /// assertion made by one would pass checks against the other.
    ///
    /// Every tenant issuer comes from [`Issuer::of_tenant`]. So the `iss` in
    /// a token, the `Issuer` in an assertion and the `iss` in a signed
    /// security event token always agree.
    pub struct Issuer;
}

impl TextValue for Issuer {
    const FIELD: &'static str = "issuer";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.web_url(RULES)
    }
}

const RULES: UrlRules = UrlRules {
    schemes: &["http", "https"],
    max_len: 4096,
    shape: UrlShape::Any,
};

impl Issuer {
    /// The issuer of a tenant's tokens, the tenant's own address under the
    /// platform's base URL.
    #[must_use]
    pub fn of_tenant(
        app_base_url: &HttpsUrl,
        org_slug: &TenantSlug,
        tenant_slug: &TenantSlug,
    ) -> Self {
        Self(format!(
            "{}/api/v1/organizations/{}/tenants/{}",
            app_base_url.as_str().trim_end_matches('/'),
            org_slug.as_str(),
            tenant_slug.as_str()
        ))
    }
}

/// A tenant's own configured issuer.
impl From<&HttpUrl> for Issuer {
    fn from(url: &HttpUrl) -> Self {
        Self(url.as_str().to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::config::SlugLimits;

    fn slug(value: &str) -> TenantSlug {
        TenantSlug::new(value, &SlugLimits::default()).unwrap()
    }

    fn base(url: &str) -> HttpsUrl {
        HttpsUrl::new(url).unwrap()
    }

    /// Tenant `prod` of org `acme` on `https://idp.example.com` issues as
    /// `.../api/v1/organizations/acme/tenants/prod` under that base URL.
    #[test]
    fn a_tenant_issuer_is_the_tenant_under_the_base_url() {
        let issuer = Issuer::of_tenant(
            &base("https://idp.example.com"),
            &slug("acme"),
            &slug("prod"),
        );

        assert_eq!(
            issuer.as_str(),
            "https://idp.example.com/api/v1/organizations/acme/tenants/prod"
        );
    }

    /// A base URL configured with a trailing `/` gives the same issuer, with
    /// no `//` in it.
    #[test]
    fn a_trailing_slash_on_the_base_url_is_not_doubled() {
        let issuer = Issuer::of_tenant(
            &base("https://idp.example.com/"),
            &slug("acme"),
            &slug("prod"),
        );

        assert_eq!(
            issuer.as_str(),
            "https://idp.example.com/api/v1/organizations/acme/tenants/prod"
        );
    }

    /// Identical organization and tenant slugs under different deployment
    /// URLs produce distinct issuers for token validation.
    #[test]
    fn the_same_tenant_under_two_deployments_has_two_issuers() {
        let eu = Issuer::of_tenant(
            &base("https://eu.example.com"),
            &slug("acme"),
            &slug("prod"),
        );
        let us = Issuer::of_tenant(
            &base("https://us.example.com"),
            &slug("acme"),
            &slug("prod"),
        );

        assert_ne!(eu, us);
    }

    /// A built tenant issuer passes the same check as one read from
    /// configuration.
    #[test]
    fn a_tenant_issuer_passes_the_issuer_rules() {
        let issuer = Issuer::of_tenant(
            &base("https://idp.example.com"),
            &slug("acme"),
            &slug("prod"),
        );

        assert!(Issuer::new(issuer.as_str()).is_ok());
    }

    /// A tenant's configured issuer, `http://localhost:8080/realms/acme`,
    /// becomes an issuer with the same text.
    #[test]
    fn a_configured_issuer_converts_unchanged() {
        let configured = HttpUrl::new("http://localhost:8080/realms/acme").unwrap();

        assert_eq!(
            Issuer::from(&configured).as_str(),
            "http://localhost:8080/realms/acme"
        );
    }

    /// An `ftp://` issuer, a relative path and an empty issuer are all
    /// refused.
    #[test]
    fn rejects_other_schemes_relative_and_empty_issuers() {
        assert!(Issuer::new("ftp://idp.example.com").is_err());
        assert!(Issuer::new("/api/v1/organizations/acme").is_err());
        assert!(Issuer::new("").is_err());
    }
}
