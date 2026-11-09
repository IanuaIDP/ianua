//! Where a person has signed in from before.
//!
//! Two of a sign-in's risk signals compare it with the past: a country the
//! person has never signed in from, and a jump from the last place they
//! signed in that no traveller could make in the time between.

use time::OffsetDateTime;

use crate::domains::authentication::risk_engine::assessment::IpGeolocation;
use crate::domains::authentication::risk_engine::step_up::Familiarity;
use crate::types::{CountryCode, Fact};

/// The countries a person has signed in from, and their latest sign-in.
#[derive(Debug, Clone, Default)]
pub struct SignInHistory {
    countries: Vec<CountryCode>,
    last: Fact<(IpGeolocation, OffsetDateTime)>,
}

impl SignInHistory {
    /// A history from the countries signed in from and the latest sign-in.
    #[must_use]
    pub fn new(countries: Vec<CountryCode>, last: Fact<(IpGeolocation, OffsetDateTime)>) -> Self {
        Self { countries, last }
    }

    /// The countries the person has signed in from.
    #[must_use]
    pub fn countries(&self) -> &[CountryCode] {
        &self.countries
    }

    /// Where and when the person last signed in, when known.
    #[must_use]
    pub fn last(&self) -> Fact<(&IpGeolocation, OffsetDateTime)> {
        self.last.as_ref().map(|(place, at)| (place, *at))
    }

    /// Whether a sign-in from `here` is from a country the person has signed
    /// in from before.
    ///
    /// A first sign-in has nothing to compare with, so any place is known.
    /// Once there is a history, a place that cannot be found counts as new.
    /// An address the geolocator cannot place, or a geolocator that is down,
    /// must not let someone from another country skip the new-country check.
    #[must_use]
    pub fn country_familiarity(&self, here: Fact<&IpGeolocation>) -> Familiarity {
        if self.countries.is_empty() {
            return Familiarity::Known;
        }
        match here {
            Fact::Known(place) if self.countries.contains(place.country_code()) => {
                Familiarity::Known
            }
            Fact::Known(_) | Fact::Unknown => Familiarity::New,
        }
    }

    /// Whether `here` is placed in a country the person has never signed
    /// in from, once they have signed in from at least one.
    ///
    /// Unlike [`country_familiarity`](Self::country_familiarity), which
    /// fails closed for asking a second factor, this names a sign of risk
    /// on the record: a place that cannot be found names no country, and a
    /// first placed sign-in has nothing to compare with. Pat's first
    /// sign-in, in Germany, is not news; two days later one from Brazil is.
    #[must_use]
    pub fn is_new_country(&self, here: Fact<&IpGeolocation>) -> bool {
        let Fact::Known(place) = here else {
            return false;
        };
        !self.countries.is_empty() && !self.countries.contains(place.country_code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn place(country: &str) -> IpGeolocation {
        IpGeolocation::new(52.5, 13.4, CountryCode::new(country).unwrap(), None).unwrap()
    }

    /// Pat has signed in from Germany before. Brazil is a new country,
    /// Germany is not, and a place that cannot be found names none.
    #[test]
    fn only_a_placed_country_never_signed_in_from_is_new() {
        let history = SignInHistory::new(vec![CountryCode::new("DE").unwrap()], Fact::Unknown);

        assert!(history.is_new_country(Fact::Known(&place("BR"))));
        assert!(!history.is_new_country(Fact::Known(&place("DE"))));
        assert!(!history.is_new_country(Fact::Unknown));
    }

    /// Pat has never signed in from a place that could be found, so his
    /// first placed sign-in, wherever it is, is no new country.
    #[test]
    fn a_first_placed_sign_in_is_no_new_country() {
        let history = SignInHistory::default();

        assert!(!history.is_new_country(Fact::Known(&place("BR"))));
    }

    /// Sam has signed in from Germany before. Another sign-in from Germany is
    /// known, and one from Brazil is new.
    #[test]
    fn a_country_signed_in_from_before_is_known() {
        let history = SignInHistory::new(vec![CountryCode::new("DE").unwrap()], Fact::Unknown);

        assert_eq!(
            history.country_familiarity(Fact::Known(&place("DE"))),
            Familiarity::Known
        );
        assert_eq!(
            history.country_familiarity(Fact::Known(&place("BR"))),
            Familiarity::New
        );
    }

    /// An unknown location is new once sign-in history exists; without history,
    /// both known countries and unknown locations count as familiar.
    #[test]
    fn only_a_first_sign_in_counts_an_unplaceable_address_as_known() {
        let first = SignInHistory::default();
        let seen = SignInHistory::new(vec![CountryCode::new("DE").unwrap()], Fact::Unknown);

        assert_eq!(
            first.country_familiarity(Fact::Known(&place("BR"))),
            Familiarity::Known
        );
        assert_eq!(first.country_familiarity(Fact::Unknown), Familiarity::Known);
        assert_eq!(seen.country_familiarity(Fact::Unknown), Familiarity::New);
    }
}
