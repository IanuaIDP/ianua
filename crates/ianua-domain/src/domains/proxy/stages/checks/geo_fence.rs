//! Holding a client to a country fence.
//!
//! A country on the block list is refused, and so is one outside a
//! non-empty allow list. A client whose country is unknown, because the
//! country database does not place its address, gets through a fence that
//! only blocks, and is refused by one that allows a list: a block list
//! names where nobody may come from, an allow list where somebody must.
//!
//! A lookup that failed is not an unknown country. The caller refuses it
//! before asking the fence: a database that is down would otherwise let
//! every client past every block list.

use crate::domains::proxy::stages::decision::StageDecision;
use crate::domains::proxy::stages::stage::GeoFenceConfig;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{CountryCode, DenialStatus, Fact};

/// Why a fence refused a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FenceRefusal {
    /// The fence names no country. Saving one is refused; a stored one
    /// checks nothing, so it refuses rather than lets everyone through.
    NamesNoCountry,
    /// The client's country is on the block list.
    Blocked(CountryCode),
    /// The client's country is not on the allow list.
    NotAllowed(CountryCode),
    /// The allow list cannot be met by a client nobody could place.
    Unplaced,
}

/// What a fence makes of one client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FenceRuling {
    /// The client may come in.
    Admitted,
    /// The client is refused.
    Refused(FenceRefusal),
}

impl FenceRuling {
    /// The stage decision the ruling comes to: a 403 for a refusal.
    #[must_use]
    pub fn decision(&self) -> StageDecision {
        let Self::Refused(refusal) = self else {
            return StageDecision::Pass {
                reason: "geo_fence: admitted".to_owned(),
            };
        };
        let reason = match refusal {
            FenceRefusal::NamesNoCountry => "geo_fence: the fence names no country".to_owned(),
            FenceRefusal::Blocked(country) => format!("geo_fence: country {country} is blocked"),
            FenceRefusal::NotAllowed(country) => {
                format!("geo_fence: country {country} is not allowed")
            }
            FenceRefusal::Unplaced => "geo_fence: the country is unknown".to_owned(),
        };
        StageDecision::Deny {
            status: DenialStatus::FORBIDDEN,
            reason,
        }
    }
}

impl GeoFenceConfig {
    /// Refuses a fence naming no country, and one naming a country both
    /// allowed and blocked.
    pub(crate) fn validate(&self) -> Result<(), DomainError> {
        if self.allowed_countries.is_empty() && self.blocked_countries.is_empty() {
            return Err(DomainError::invalid(message!(
                "proxy-a-geofence-stage-needs-a-country",
                "a geofence stage needs a country to allow or block"
            )));
        }
        let Some(both) = self
            .allowed_countries
            .iter()
            .find(|c| self.blocked_countries.contains(c))
        else {
            return Ok(());
        };
        Err(DomainError::invalid(message!(
            "proxy-is-both-allowed-and-blocked",
            format!("{both} is both allowed and blocked")
        )))
    }

    /// Whether a client placed in `country` may come in.
    ///
    /// `Fact::Unknown` stands for an address the country database does not
    /// place. A lookup that failed or did not answer in time is not that:
    /// the caller refuses it without asking.
    #[must_use]
    pub fn admits(&self, country: Fact<&CountryCode>) -> FenceRuling {
        if self.allowed_countries.is_empty() && self.blocked_countries.is_empty() {
            return FenceRuling::Refused(FenceRefusal::NamesNoCountry);
        }
        let Fact::Known(country) = country else {
            return self.unplaced();
        };
        if self.blocked_countries.contains(country) {
            return FenceRuling::Refused(FenceRefusal::Blocked(country.clone()));
        }
        if !self.allowed_countries.is_empty() && !self.allowed_countries.contains(country) {
            return FenceRuling::Refused(FenceRefusal::NotAllowed(country.clone()));
        }
        FenceRuling::Admitted
    }

    /// What the fence makes of a client nobody could place: through a
    /// block list, not through an allow list.
    fn unplaced(&self) -> FenceRuling {
        if self.allowed_countries.is_empty() {
            return FenceRuling::Admitted;
        }
        FenceRuling::Refused(FenceRefusal::Unplaced)
    }
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

    fn at(code: &str, config: &GeoFenceConfig) -> FenceRuling {
        config.admits(Fact::Known(&country(code)))
    }

    #[test]
    fn an_allowed_country_comes_in() {
        assert_eq!(at("US", &fence(&["US"], &[])), FenceRuling::Admitted);
        assert_eq!(at("US", &fence(&[], &["CN"])), FenceRuling::Admitted);
    }

    #[test]
    fn a_blocked_country_is_refused() {
        assert_eq!(
            at("CN", &fence(&[], &["CN"])),
            FenceRuling::Refused(FenceRefusal::Blocked(country("CN")))
        );
    }

    #[test]
    fn a_country_outside_the_allow_list_is_refused() {
        assert_eq!(
            at("US", &fence(&["DE"], &[])),
            FenceRuling::Refused(FenceRefusal::NotAllowed(country("US")))
        );
    }

    /// Ann connects from an address the country database does not place.
    /// The fence only blocks North Korea, and nothing says she is there, so
    /// she comes in.
    #[test]
    fn an_unplaced_client_passes_a_block_list() {
        assert_eq!(
            fence(&[], &["KP"]).admits(Fact::Unknown),
            FenceRuling::Admitted
        );
    }

    /// A country allow list containing only Germany refuses a client with
    /// an unknown country as unplaced.
    #[test]
    fn an_unplaced_client_is_refused_by_an_allow_list() {
        assert_eq!(
            fence(&["DE"], &["KP"]).admits(Fact::Unknown),
            FenceRuling::Refused(FenceRefusal::Unplaced)
        );
    }

    /// A fence naming no country is a stage set up to check nothing; it
    /// refuses rather than lets everyone through.
    #[test]
    fn a_fence_naming_no_country_refuses() {
        assert_eq!(
            at("US", &fence(&[], &[])),
            FenceRuling::Refused(FenceRefusal::NamesNoCountry)
        );
    }

    #[test]
    fn a_refusal_is_a_403_and_an_admission_a_pass() {
        let refused = at("CN", &fence(&[], &["CN"])).decision();

        assert!(matches!(
            refused,
            StageDecision::Deny { status, .. } if status == DenialStatus::FORBIDDEN
        ));
        assert!(!FenceRuling::Admitted.decision().is_terminal());
    }
}
