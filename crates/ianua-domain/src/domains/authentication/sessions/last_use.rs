//! Where a session was last used, and what that makes of the next use.
//!
//! A cookie or token copied off Pat's laptop works anywhere. What gives
//! the copy away is where it turns up: a use of Pat's session from Poznań
//! twenty minutes after one from Berlin is further than Pat could have
//! gone. So a session keeps where it was last seen, and each use from
//! another network is held against it.
//!
//! It freezes only on the journey the sign-in's risk check treats as more
//! than a nuisance: faster than 200 km/h over more than a lookup's error,
//! and between two countries. A change of network inside one country is
//! nothing, as is a phone hopping between its carrier and a cafe's
//! Wi-Fi: carriers route whole countries through one gateway, so inside a
//! country a fast "journey" says more about the carrier than about Pat.

use time::OffsetDateTime;

use crate::domains::authentication::risk_engine::assessment::{IpGeolocation, TravelVelocity};
use crate::domains::authentication::risk_engine::origin::AttemptOrigin;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{Fact, IpAddress};

text_value! {
    /// The network a caller came from, as the sign-in's failures count it:
    /// an IPv4 address or an IPv6 `/64`.
    pub struct CallerNetwork;
}

impl TextValue for CallerNetwork {
    const FIELD: &'static str = "caller_network";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.length(1..=64)
    }
}

impl CallerNetwork {
    /// The network of the caller at `ip`, when anyone saw it.
    #[must_use]
    pub fn of(ip: Fact<&IpAddress>) -> Fact<Self> {
        let origin = AttemptOrigin::of(ip);
        if !origin.is_observed() {
            return Fact::Unknown;
        }
        Self::new(origin.to_string()).map_or(Fact::Unknown, Fact::Known)
    }
}

/// Where and from which network a session was last used.
///
/// A use from an address that cannot be placed is never written here, so
/// `place` is always where a use was placed, however old.
#[derive(Debug, Clone)]
pub struct LastUse {
    network: CallerNetwork,
    place: IpGeolocation,
    at: OffsetDateTime,
}

impl LastUse {
    /// A last use from `network`, in `place`, at `at`.
    #[must_use]
    pub fn new(network: CallerNetwork, place: IpGeolocation, at: OffsetDateTime) -> Self {
        Self { network, place, at }
    }

    /// The network the session was last used from.
    #[must_use]
    pub fn network(&self) -> &CallerNetwork {
        &self.network
    }

    /// Where the session was last used.
    #[must_use]
    pub fn place(&self) -> &IpGeolocation {
        &self.place
    }

    /// When the session was last used there.
    #[must_use]
    pub fn at(&self) -> OffsetDateTime {
        self.at
    }

    /// This last use seen again at `now`, on the same network: in `place`
    /// when the new use could be placed, where it was otherwise.
    pub(super) fn stamped(&self, place: Fact<IpGeolocation>, now: OffsetDateTime) -> Self {
        Self {
            network: self.network.clone(),
            place: match place {
                Fact::Known(place) => place,
                Fact::Unknown => self.place.clone(),
            },
            at: now,
        }
    }

    /// Whether a use at `now` from `here` makes a journey from this use
    /// that no traveller would make: another country, reached at a speed
    /// the sign-in's risk check calls suspicious or impossible.
    pub(super) fn is_fast_travel_to(&self, here: &IpGeolocation, now: OffsetDateTime) -> bool {
        if self.place.country_code() == here.country_code() {
            return false;
        }
        let velocity = TravelVelocity::compute(&self.place, here, self.at, now);
        velocity.is_suspicious() || velocity.is_impossible()
    }
}

/// One use of a session as it was seen: the network it came from and
/// where that network was placed, when it could be placed.
#[derive(Debug, Clone)]
pub struct ObservedUse {
    /// The network the use came from.
    pub network: CallerNetwork,
    /// Where it was placed. Unknown when the geolocator had no answer or
    /// could not be asked, so it never freezes a session.
    pub place: Fact<IpGeolocation>,
}

/// What one use of a session comes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UseNoted {
    /// Nothing new: the session stays as it stands and nothing is written.
    Unchanged,
    /// Where the session was last used changed, or was seen again: the
    /// new last use is written.
    Moved,
    /// The use does not look like the person who signed in: the session
    /// is stopped.
    LooksTakenOver,
}

/// How someone gets back into a session stopped because it looked taken
/// over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WayBack {
    /// Holding a second factor that lifts a freeze: the session freezes and
    /// their factor lifts it.
    OwnFactor,
    /// Holding none: a freeze nothing could lift would lock them out for
    /// good, so the session ends and they sign in again.
    FreshSignIn,
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::types::CountryCode;

    fn network(ip: &str) -> CallerNetwork {
        CallerNetwork::of(Fact::Known(&IpAddress::new(ip).unwrap()))
            .known()
            .cloned()
            .unwrap()
    }

    fn place(latitude: f64, longitude: f64, country: &str) -> IpGeolocation {
        IpGeolocation::new(
            latitude,
            longitude,
            CountryCode::new(country).unwrap(),
            None,
        )
        .unwrap()
    }

    fn berlin() -> IpGeolocation {
        place(52.52, 13.405, "DE")
    }

    fn poznan() -> IpGeolocation {
        place(52.40, 16.92, "PL")
    }

    /// Pat's use in Berlin is followed twenty minutes later by one in
    /// Poznań: 240 km away, 720 km/h, another country.
    #[test]
    fn twenty_minutes_from_berlin_to_poznan_is_fast_travel() {
        let last = LastUse::new(network("198.18.0.7"), berlin(), crate::shared::clock::now());

        let after = last.at() + Duration::minutes(20);

        assert!(last.is_fast_travel_to(&poznan(), after));
    }

    /// Three days later the same trip is an ordinary one.
    #[test]
    fn the_same_trip_days_later_is_no_fast_travel() {
        let last = LastUse::new(network("198.18.0.7"), berlin(), crate::shared::clock::now());

        let after = last.at() + Duration::days(3);

        assert!(!last.is_fast_travel_to(&poznan(), after));
    }

    /// Berlin and Munich are 500 km apart, but a phone that goes from a
    /// Berlin café's Wi-Fi to a carrier routing through Munich makes that
    /// "journey" in a second. Within one country nothing freezes.
    #[test]
    fn a_fast_hop_inside_one_country_is_no_fast_travel() {
        let last = LastUse::new(network("198.18.0.7"), berlin(), crate::shared::clock::now());
        let munich = place(48.14, 11.58, "DE");

        let after = last.at() + Duration::minutes(1);

        assert!(!last.is_fast_travel_to(&munich, after));
    }

    /// Frankfurt (Oder) and Słubice stand on either side of one bridge:
    /// two countries, but a lookup could put either in the other, so it
    /// is not fast travel.
    #[test]
    fn a_hop_within_lookup_error_across_a_border_is_no_fast_travel() {
        let last = LastUse::new(
            network("198.18.0.7"),
            place(52.34, 14.55, "DE"),
            crate::shared::clock::now(),
        );
        let slubice = place(52.35, 14.56, "PL");

        let after = last.at() + Duration::seconds(30);

        assert!(!last.is_fast_travel_to(&slubice, after));
    }

    /// Moving on the same network only changes when it was last seen,
    /// keeping where it was when this use could not be placed.
    #[test]
    fn a_stamp_keeps_the_place_when_the_new_use_cannot_be_placed() {
        let network = network("198.18.0.7");
        let at = crate::shared::clock::now();
        let last = LastUse::new(network.clone(), berlin(), at);

        let stamped = last.stamped(Fact::Unknown, at + Duration::minutes(5));

        assert_eq!(stamped.network(), &network);
        assert_eq!(stamped.at(), at + Duration::minutes(5));
        assert_eq!(stamped.place().country_code().as_str(), "DE");
    }

    /// An address nobody saw is no network at all.
    #[test]
    fn an_unobserved_address_is_no_network() {
        assert!(matches!(CallerNetwork::of(Fact::Unknown), Fact::Unknown));
    }
}
