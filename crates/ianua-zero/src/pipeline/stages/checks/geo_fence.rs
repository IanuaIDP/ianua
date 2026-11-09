//! Holding a client to a country fence.
//!
//! A country on the block list is refused, and so is one outside a
//! non-empty allow list. A client whose country is unknown is refused
//! whatever the fence: every fence names a country, so every fence needs
//! one to decide, and a block list cannot show a client is not where it
//! blocks.

use ianua_domain::domains::proxy::stages::decision::StageDecision;
use ianua_domain::domains::proxy::stages::stage::GeoFenceConfig;
use ianua_domain::types::{CountryCode, DenialStatus, Fact};

use super::{deny, pass};

/// The decision `config` takes on a client in `country`.
pub(super) fn verdict(config: &GeoFenceConfig, country: Fact<&CountryCode>) -> StageDecision {
    if config.allowed_countries.is_empty() && config.blocked_countries.is_empty() {
        return deny(
            DenialStatus::FORBIDDEN,
            "geo_fence: the fence names no country",
        );
    }
    let Fact::Known(country) = country else {
        return deny(DenialStatus::FORBIDDEN, "geo_fence: the country is unknown");
    };
    if config.blocked_countries.contains(country) {
        return deny(
            DenialStatus::FORBIDDEN,
            &format!("geo_fence: country {country} is blocked"),
        );
    }
    let outside_allowed =
        !config.allowed_countries.is_empty() && !config.allowed_countries.contains(country);
    if outside_allowed {
        return deny(
            DenialStatus::FORBIDDEN,
            &format!("geo_fence: country {country} is not allowed"),
        );
    }
    pass(&format!("geo_fence: country {country} allowed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn country(code: &str) -> CountryCode {
        CountryCode::new(code).unwrap()
    }

    fn fence(allowed: &[&str], blocked: &[&str]) -> GeoFenceConfig {
        GeoFenceConfig {
            allowed_countries: allowed.iter().map(|code| country(code)).collect(),
            blocked_countries: blocked.iter().map(|code| country(code)).collect(),
        }
    }

    fn at(code: &str, config: &GeoFenceConfig) -> StageDecision {
        verdict(config, Fact::Known(&country(code)))
    }

    #[test]
    fn an_allowed_country_passes() {
        assert!(!at("US", &fence(&["US"], &[])).is_terminal());
        assert!(!at("US", &fence(&[], &["CN"])).is_terminal());
    }

    #[test]
    fn a_blocked_country_is_refused() {
        assert!(at("CN", &fence(&[], &["CN"])).is_terminal());
    }

    #[test]
    fn a_country_outside_the_allow_list_is_refused() {
        assert!(at("US", &fence(&["DE"], &[])).is_terminal());
    }

    #[test]
    fn an_unknown_country_is_refused_by_an_allow_list() {
        assert!(verdict(&fence(&["US"], &[]), Fact::Unknown).is_terminal());
    }

    /// A block-list-only country fence returns a terminal decision when
    /// the client's country is unknown.
    #[test]
    fn an_unknown_country_is_refused_by_a_block_list_too() {
        assert!(verdict(&fence(&[], &["CN"]), Fact::Unknown).is_terminal());
    }

    /// A fence naming no country is a stage set up to check nothing; it
    /// refuses rather than lets everyone through.
    #[test]
    fn a_fence_naming_no_country_refuses() {
        assert!(at("US", &fence(&[], &[])).is_terminal());
    }
}
