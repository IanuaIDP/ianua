use time::OffsetDateTime;

use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{CountryCode, Fact};

/// Geographic location resolved from an IP address.
///
/// Infrastructure resolves it with a geolocation database, such as `MaxMind`
/// `GeoIP2` or `IP2Location`. The domain uses it to detect impossible travel
/// and to score risk.
///
/// JSON is read through [`new`](Self::new), so a location off the globe
/// cannot come in that way either.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "IpGeolocationWire"))]
pub struct IpGeolocation {
    /// Latitude in decimal degrees, from -90 to 90.
    latitude: f64,
    /// Longitude in decimal degrees, from -180 to 180.
    longitude: f64,
    /// ISO 3166-1 alpha-2 country code, such as `"JP"` or `"US"`.
    country_code: CountryCode,
    /// City name, if known, such as `"Tokyo"` or `"New York"`.
    city: Option<String>,
}

/// An [`IpGeolocation`] as JSON spells it, before its coordinates are checked.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct IpGeolocationWire {
    latitude: f64,
    longitude: f64,
    country_code: CountryCode,
    city: Option<String>,
}

#[cfg(feature = "serde")]
impl TryFrom<IpGeolocationWire> for IpGeolocation {
    type Error = DomainError;

    fn try_from(wire: IpGeolocationWire) -> Result<Self, Self::Error> {
        Self::new(wire.latitude, wire.longitude, wire.country_code, wire.city)
    }
}

impl IpGeolocation {
    /// A geolocation from resolved coordinates.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when a coordinate is not a number or lies
    ///   off the globe. A distance computed from one is not a number either,
    ///   and every speed check on it would answer no.
    pub fn new(
        latitude: f64,
        longitude: f64,
        country_code: CountryCode,
        city: Option<String>,
    ) -> Result<Self, DomainError> {
        let on_the_globe =
            (-90.0..=90.0).contains(&latitude) && (-180.0..=180.0).contains(&longitude);
        if !on_the_globe {
            return Err(DomainError::invalid(message!(
                "authentication-a-location-s-coordinates-must-lie",
                "a location's coordinates must lie on the globe"
            )));
        }
        Ok(Self {
            latitude,
            longitude,
            country_code,
            city,
        })
    }

    /// Latitude in decimal degrees.
    #[must_use]
    pub fn latitude(&self) -> f64 {
        self.latitude
    }

    /// Longitude in decimal degrees.
    #[must_use]
    pub fn longitude(&self) -> f64 {
        self.longitude
    }

    /// ISO 3166-1 alpha-2 country code.
    #[must_use]
    pub fn country_code(&self) -> &CountryCode {
        &self.country_code
    }

    /// City name, if resolved.
    #[must_use]
    pub fn city(&self) -> Option<&str> {
        self.city.as_deref()
    }

    /// Great-circle distance to another location in kilometers.
    ///
    /// It uses the Haversine formula, which is accurate enough to detect
    /// impossible travel.
    #[must_use]
    pub fn distance_km(&self, other: &Self) -> f64 {
        const EARTH_RADIUS_KM: f64 = 6371.0;

        let lat1 = self.latitude.to_radians();
        let lat2 = other.latitude.to_radians();
        let dlat = (other.latitude - self.latitude).to_radians();
        let dlon = (other.longitude - self.longitude).to_radians();

        let a = (dlat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (dlon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().asin();

        EARTH_RADIUS_KM * c
    }
}

/// How far apart two lookups of the same place can land, in kilometres.
///
/// IP geolocation names a city at best and is often off by tens of
/// kilometres. A sign-in from the next city a minute after another is the
/// same person on the same network, not impossible travel.
pub(crate) const GEOLOCATION_UNCERTAINTY_KM: f64 = 100.0;

/// How fast a user would have to travel between two login locations in the
/// time between them.
///
/// Only [`compute`](Self::compute) makes one, so the speed always follows
/// from the distance and the time. It is written out but never read back.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TravelVelocity {
    /// Distance between the two locations in kilometers.
    distance_km: f64,
    /// Time between the two logins in seconds.
    duration_seconds: u64,
    /// Implied speed in km/h.
    speed_kmh: f64,
}

impl TravelVelocity {
    /// The travel velocity between two geolocated logins.
    ///
    /// A gap under one second counts as one second. Two sign-ins far apart
    /// in the same instant are the clearest case of impossible travel. At one
    /// second they read as faster than anything can move.
    #[must_use]
    pub fn compute(
        from: &IpGeolocation,
        to: &IpGeolocation,
        from_time: OffsetDateTime,
        to_time: OffsetDateTime,
    ) -> Self {
        let duration = crate::shared::clock::between(from_time, to_time).abs();
        let duration_seconds = duration.whole_seconds().unsigned_abs().max(1);

        let distance_km = from.distance_km(to);
        let hours = duration.as_seconds_f64().max(1.0) / 3600.0;
        let speed_kmh = distance_km / hours;

        Self {
            distance_km,
            duration_seconds,
            speed_kmh,
        }
    }

    /// Distance between the two locations in kilometers.
    #[must_use]
    pub fn distance_km(&self) -> f64 {
        self.distance_km
    }

    /// Time between the two logins in seconds.
    #[must_use]
    pub fn duration_seconds(&self) -> u64 {
        self.duration_seconds
    }

    /// Implied travel speed in km/h.
    #[must_use]
    pub fn speed_kmh(&self) -> f64 {
        self.speed_kmh
    }

    /// Whether this velocity is physically impossible.
    ///
    /// A commercial jet cruises at about 900 km/h. Anything above 1000 km/h
    /// is impossible travel, such as a VPN hop, stolen credentials or a
    /// hijacked session. It applies only over more than
    /// `GEOLOCATION_UNCERTAINTY_KM`. Closer than that, the two places may
    /// be one place that a lookup put in two nearby cities.
    #[must_use]
    pub fn is_impossible(&self) -> bool {
        self.beyond_lookup_error() && self.speed_kmh > 1000.0
    }

    /// Whether this velocity is suspicious but possible.
    ///
    /// It lies between 200 km/h and 1000 km/h. That could be a domestic
    /// flight, but it deserves a look. Like
    /// [`is_impossible`](Self::is_impossible), it applies only over more than
    /// `GEOLOCATION_UNCERTAINTY_KM`.
    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        self.beyond_lookup_error() && self.speed_kmh > 200.0 && self.speed_kmh <= 1000.0
    }

    /// Whether the distance is more than a location lookup can be off by.
    fn beyond_lookup_error(&self) -> bool {
        self.distance_km > GEOLOCATION_UNCERTAINTY_KM
    }
}

/// Risk level assessed for a login attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RiskLevel {
    /// A normal login with nothing unusual.
    Low,
    /// Something small is unusual, such as a new device or an odd time.
    Medium,
    /// Something big is unusual, such as a new country or suspicious travel.
    High,
    /// Impossible travel or a known-compromised credential.
    Critical,
}

/// What the system should do about the assessed risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RiskAction {
    /// Let the login go on as normal.
    Allow,
    /// Require step-up MFA before granting access.
    StepUpMfa,
    /// Block the login.
    Block,
}

/// The risk assessment of a login attempt.
///
/// Built at sign-in from the IP's geolocation and the user's recent login
/// history.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct LoginRiskAssessment {
    /// The assessed risk level.
    risk_level: RiskLevel,
    /// The recommended action.
    action: RiskAction,
    /// The current login's geolocation, if resolved.
    current_location: Fact<IpGeolocation>,
    /// Travel velocity from the previous login, if calculable.
    travel_velocity: Fact<TravelVelocity>,
    /// Reasons for the assessed risk.
    reasons: Vec<String>,
}

/// Where a sign-in came from and how fast the person would have had to travel.
pub struct TravelEvidence {
    /// Where this sign-in came from.
    pub current_location: Fact<IpGeolocation>,
    /// The speed implied since the last one.
    pub travel_velocity: Fact<TravelVelocity>,
}

impl LoginRiskAssessment {
    /// An assessment with this level, action, travel evidence and reasons.
    #[must_use]
    pub fn new(
        risk_level: RiskLevel,
        action: RiskAction,
        travel: TravelEvidence,
        reasons: Vec<String>,
    ) -> Self {
        let TravelEvidence {
            current_location,
            travel_velocity,
        } = travel;
        Self {
            risk_level,
            action,
            current_location,
            travel_velocity,
            reasons,
        }
    }

    /// A low-risk assessment for a normal login.
    #[must_use]
    pub fn low_risk() -> Self {
        Self {
            risk_level: RiskLevel::Low,
            action: RiskAction::Allow,
            current_location: Fact::Unknown,
            travel_velocity: Fact::Unknown,
            reasons: Vec::new(),
        }
    }

    /// The assessed risk level.
    #[must_use]
    pub fn risk_level(&self) -> RiskLevel {
        self.risk_level
    }

    /// The recommended action.
    #[must_use]
    pub fn action(&self) -> RiskAction {
        self.action
    }

    /// The current login's geolocation.
    #[must_use]
    pub fn current_location(&self) -> Fact<&IpGeolocation> {
        self.current_location.as_ref()
    }

    /// Travel velocity from the previous login.
    #[must_use]
    pub fn travel_velocity(&self) -> Fact<&TravelVelocity> {
        self.travel_velocity.as_ref()
    }

    /// Reasons for the risk level.
    #[must_use]
    pub fn reasons(&self) -> &[String] {
        &self.reasons
    }

    /// Whether the login should be blocked.
    #[must_use]
    pub fn should_block(&self) -> bool {
        self.action == RiskAction::Block
    }

    /// Whether step-up MFA is required.
    #[must_use]
    pub fn requires_step_up(&self) -> bool {
        self.action == RiskAction::StepUpMfa
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;

    fn tokyo() -> IpGeolocation {
        IpGeolocation::new(
            35.6762,
            139.6503,
            CountryCode::new("JP").unwrap(),
            Some("Tokyo".to_owned()),
        )
        .unwrap()
    }

    fn new_york() -> IpGeolocation {
        IpGeolocation::new(
            40.7128,
            -74.0060,
            CountryCode::new("US").unwrap(),
            Some("New York".to_owned()),
        )
        .unwrap()
    }

    fn london() -> IpGeolocation {
        IpGeolocation::new(
            51.5074,
            -0.1278,
            CountryCode::new("GB").unwrap(),
            Some("London".to_owned()),
        )
        .unwrap()
    }

    /// A Tokyo lookup reports the coordinates, `JP` and "Tokyo" it was made
    /// with.
    #[test]
    fn a_location_reports_its_coordinates_country_and_city() {
        let geo = tokyo();
        assert!((geo.latitude() - 35.6762).abs() < 0.001);
        assert!((geo.longitude() - 139.6503).abs() < 0.001);
        assert_eq!(geo.country_code().as_str(), "JP");
        assert_eq!(geo.city(), Some("Tokyo"));
    }

    /// Two lookups of Tokyo are less than a kilometre apart.
    #[test]
    fn distance_same_location_is_zero() {
        let a = tokyo();
        let b = tokyo();
        assert!(a.distance_km(&b) < 1.0);
    }

    /// Tokyo to New York comes out between 10,500 and 11,200 km. The real
    /// great-circle distance is about 10,838 km.
    #[test]
    fn distance_tokyo_to_new_york_is_roughly_10800km() {
        let distance = tokyo().distance_km(&new_york());
        assert!(distance > 10_500.0 && distance < 11_200.0);
    }

    /// Tokyo to London and London to Tokyo give the same distance.
    #[test]
    fn distance_is_symmetric() {
        let d1 = tokyo().distance_km(&london());
        let d2 = london().distance_km(&tokyo());
        assert!((d1 - d2).abs() < 0.1);
    }

    /// Sign-ins from Tokyo and then New York five minutes apart imply over
    /// 100,000 km/h. That is impossible travel.
    #[test]
    fn impossible_travel_tokyo_to_new_york_in_5_minutes() {
        let now = crate::shared::clock::now();
        let five_min_later = now + time::Duration::minutes(5);

        let velocity = TravelVelocity::compute(&tokyo(), &new_york(), now, five_min_later);

        assert!(velocity.is_impossible());
        assert!(velocity.speed_kmh() > 100_000.0);
    }

    /// Tokyo and then New York 14 hours apart is about 774 km/h. That is a
    /// flight, so it is not impossible.
    #[test]
    fn normal_travel_tokyo_to_new_york_in_14_hours() {
        let now = crate::shared::clock::now();
        let fourteen_hours = now + time::Duration::hours(14);

        let velocity = TravelVelocity::compute(&tokyo(), &new_york(), now, fourteen_hours);

        assert!(!velocity.is_impossible());
        assert!(velocity.speed_kmh() > 700.0 && velocity.speed_kmh() < 900.0);
    }

    /// London and then New York 10 hours apart is about 560 km/h. That is
    /// suspicious but not impossible.
    #[test]
    fn suspicious_but_not_impossible() {
        let now = crate::shared::clock::now();
        let velocity =
            TravelVelocity::compute(&london(), &new_york(), now, now + time::Duration::hours(10));

        assert!(velocity.is_suspicious());
        assert!(!velocity.is_impossible());
    }

    /// Tokyo and New York sign-ins at the same instant count as impossible travel.
    #[test]
    fn a_zero_gap_between_far_places_is_impossible_travel() {
        let now = crate::shared::clock::now();
        let velocity = TravelVelocity::compute(&tokyo(), &new_york(), now, now);
        assert!(velocity.is_impossible());
    }

    /// A latitude that is not a number, an infinite longitude, latitude 91
    /// and longitude -181 are each refused.
    #[test]
    fn coordinates_off_the_globe_are_refused() {
        let country = CountryCode::new("JP").unwrap();
        for (lat, lon) in [
            (f64::NAN, 0.0),
            (0.0, f64::INFINITY),
            (91.0, 0.0),
            (0.0, -181.0),
        ] {
            assert!(IpGeolocation::new(lat, lon, country.clone(), None).is_err());
        }
    }

    /// Two sign-ins from Tokyo five minutes apart are neither suspicious nor
    /// impossible.
    #[test]
    fn same_location_is_not_suspicious() {
        let now = crate::shared::clock::now();
        let velocity =
            TravelVelocity::compute(&tokyo(), &tokyo(), now, now + time::Duration::minutes(5));

        assert!(!velocity.is_suspicious());
        assert!(!velocity.is_impossible());
    }

    /// Low sorts below Medium, Medium below High and High below Critical, so
    /// thresholds can be compared with `<`.
    #[test]
    fn risk_levels_are_ordered() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }

    /// A low-risk assessment allows the sign-in. It neither blocks nor asks
    /// for a step-up.
    #[test]
    fn low_risk_allows_login() {
        let assessment = LoginRiskAssessment::low_risk();
        assert_eq!(assessment.risk_level(), RiskLevel::Low);
        assert_eq!(assessment.action(), RiskAction::Allow);
        assert!(!assessment.should_block());
        assert!(!assessment.requires_step_up());
    }

    /// A critical assessment for impossible travel blocks the sign-in, asks
    /// for no step-up and keeps its one reason.
    #[test]
    fn critical_risk_blocks_login() {
        let assessment = LoginRiskAssessment::new(
            RiskLevel::Critical,
            RiskAction::Block,
            TravelEvidence {
                current_location: Fact::Known(new_york()),
                travel_velocity: Fact::Unknown,
            },
            vec!["impossible travel detected".to_owned()],
        );

        assert!(assessment.should_block());
        assert!(!assessment.requires_step_up());
        assert_eq!(assessment.reasons().len(), 1);
    }

    /// A high assessment for a new country asks for a step-up and does not
    /// block.
    #[test]
    fn high_risk_requires_step_up() {
        let assessment = LoginRiskAssessment::new(
            RiskLevel::High,
            RiskAction::StepUpMfa,
            TravelEvidence {
                current_location: Fact::Unknown,
                travel_velocity: Fact::Unknown,
            },
            vec!["new country".to_owned()],
        );

        assert!(assessment.requires_step_up());
        assert!(!assessment.should_block());
    }

    /// Each risk level is written as its variant name, such as `"High"`, and
    /// read back from it. Renaming a variant fails here instead of breaking
    /// saved data.
    #[cfg(feature = "serde")]
    #[test]
    fn risk_level_is_stored_under_its_variant_name() {
        assert_eq!(serde_json::to_string(&RiskLevel::Low).unwrap(), r#""Low""#);
        assert_eq!(
            serde_json::to_string(&RiskLevel::Medium).unwrap(),
            r#""Medium""#
        );
        assert_eq!(
            serde_json::to_string(&RiskLevel::High).unwrap(),
            r#""High""#
        );
        assert_eq!(
            serde_json::to_string(&RiskLevel::Critical).unwrap(),
            r#""Critical""#
        );
        assert_eq!(
            serde_json::from_str::<RiskLevel>(r#""Low""#).unwrap(),
            RiskLevel::Low
        );
        assert_eq!(
            serde_json::from_str::<RiskLevel>(r#""Medium""#).unwrap(),
            RiskLevel::Medium
        );
        assert_eq!(
            serde_json::from_str::<RiskLevel>(r#""High""#).unwrap(),
            RiskLevel::High
        );
        assert_eq!(
            serde_json::from_str::<RiskLevel>(r#""Critical""#).unwrap(),
            RiskLevel::Critical
        );
    }

    /// Each risk action is written as its variant name, such as
    /// `"StepUpMfa"`, and read back from it. Renaming a variant fails here
    /// instead of breaking saved data.
    #[cfg(feature = "serde")]
    #[test]
    fn risk_action_is_stored_under_its_variant_name() {
        assert_eq!(
            serde_json::to_string(&RiskAction::Allow).unwrap(),
            r#""Allow""#
        );
        assert_eq!(
            serde_json::to_string(&RiskAction::StepUpMfa).unwrap(),
            r#""StepUpMfa""#
        );
        assert_eq!(
            serde_json::to_string(&RiskAction::Block).unwrap(),
            r#""Block""#
        );
        assert_eq!(
            serde_json::from_str::<RiskAction>(r#""Allow""#).unwrap(),
            RiskAction::Allow
        );
        assert_eq!(
            serde_json::from_str::<RiskAction>(r#""StepUpMfa""#).unwrap(),
            RiskAction::StepUpMfa
        );
        assert_eq!(
            serde_json::from_str::<RiskAction>(r#""Block""#).unwrap(),
            RiskAction::Block
        );
    }

    /// Tokyo to New York is 10,800 to 11,200 km either way, London to New
    /// York 5,400 to 5,700 km, and Tokyo to itself under 1 km. Every travel
    /// check is built on this distance.
    #[test]
    fn the_distance_between_two_places_is_their_great_circle_distance() {
        let tokyo_to_new_york = tokyo().distance_km(&new_york());

        assert!(
            (10_800.0..11_200.0).contains(&tokyo_to_new_york),
            "got {tokyo_to_new_york} km"
        );
        assert!(tokyo().distance_km(&tokyo()) < 1.0);
        assert!(
            (tokyo_to_new_york - new_york().distance_km(&tokyo())).abs() < 1.0,
            "distance is the same in both directions"
        );

        let london_to_new_york = london().distance_km(&new_york());
        assert!(
            (5_400.0..5_700.0).contains(&london_to_new_york),
            "got {london_to_new_york} km"
        );
    }

    /// Tokyo and then New York two hours apart reports the distance, a gap of
    /// 7,200 seconds and a speed of distance over two hours. An analyst reads
    /// these to judge the verdict.
    #[test]
    fn a_velocity_reports_the_distance_and_the_time_it_was_computed_from() {
        let departure = OffsetDateTime::UNIX_EPOCH;
        let arrival = departure + Duration::hours(2);

        let velocity = TravelVelocity::compute(&tokyo(), &new_york(), departure, arrival);

        assert!(
            (10_800.0..11_200.0).contains(&velocity.distance_km()),
            "got {} km",
            velocity.distance_km()
        );
        assert_eq!(velocity.duration_seconds(), 7_200);
        assert!(
            (velocity.speed_kmh() - velocity.distance_km() / 2.0).abs() < 1.0,
            "the speed is the distance over the elapsed hours"
        );
    }

    /// Exactly 1000 km/h is suspicious, not impossible, and so is 999.9.
    /// 1000.1 km/h is impossible and not merely suspicious. A jet
    /// cruises near the line, so a sign-in on it is not blocked.
    #[test]
    fn the_thousand_an_hour_boundary_is_suspicious_and_not_impossible() {
        let at_boundary = velocity_at(1_000.0);
        let just_over = velocity_at(1_000.1);
        let just_under = velocity_at(999.9);

        assert!(!at_boundary.is_impossible(), "the boundary is reachable");
        assert!(at_boundary.is_suspicious());

        assert!(just_over.is_impossible());
        assert!(
            !just_over.is_suspicious(),
            "impossible travel is not merely suspicious"
        );

        assert!(!just_under.is_impossible());
        assert!(just_under.is_suspicious());
    }

    /// 80 and 200 km/h are not suspicious, but 200.1 km/h is. A fast train
    /// at the top of ordinary ground travel raises no flag.
    #[test]
    fn the_two_hundred_an_hour_boundary_is_not_yet_suspicious() {
        assert!(!velocity_at(200.0).is_suspicious());
        assert!(velocity_at(200.1).is_suspicious());
        assert!(!velocity_at(80.0).is_suspicious());
    }

    /// A velocity at exactly `speed_kmh`, over an hour.
    ///
    /// Computing it from two places and a window cannot land on a round
    /// speed, because the distance is a Haversine float and the window is
    /// whole seconds. The boundary is exactly where these checks are decided.
    fn velocity_at(speed_kmh: f64) -> TravelVelocity {
        TravelVelocity {
            distance_km: speed_kmh,
            duration_seconds: 3_600,
            speed_kmh,
        }
    }

    /// A lookup puts Ann's network in two cities 40 km apart a minute apart,
    /// which reads as 2,400 km/h. It is within lookup error, so it is
    /// neither impossible nor suspicious.
    #[test]
    fn nearby_cities_a_minute_apart_are_not_travel() {
        let jitter = TravelVelocity {
            distance_km: 40.0,
            duration_seconds: 60,
            speed_kmh: 2_400.0,
        };

        assert!(!jitter.is_impossible());
        assert!(!jitter.is_suspicious());
    }

    /// A location read from JSON with latitude 91 is refused, the same as
    /// one built with [`IpGeolocation::new`].
    #[cfg(feature = "serde")]
    #[test]
    fn a_location_off_the_globe_is_refused_from_json() {
        let json = serde_json::json!({
            "latitude": 91.0,
            "longitude": 0.0,
            "country_code": "JP",
            "city": null,
        });

        assert!(serde_json::from_value::<IpGeolocation>(json).is_err());
    }

    /// An assessment built with New York, a Tokyo to New York velocity and
    /// the reason "impossible travel" hands back all three. The sign-in
    /// decision and its audit line read them from here.
    #[test]
    fn an_assessment_reports_the_location_velocity_and_reasons_it_was_given() {
        let departure = OffsetDateTime::UNIX_EPOCH;
        let velocity = TravelVelocity::compute(
            &tokyo(),
            &new_york(),
            departure,
            departure + Duration::hours(2),
        );

        let assessment = LoginRiskAssessment::new(
            RiskLevel::High,
            RiskAction::Block,
            TravelEvidence {
                current_location: Fact::Known(new_york()),
                travel_velocity: Fact::Known(velocity),
            },
            vec!["impossible travel".to_owned()],
        );

        assert_eq!(
            assessment
                .current_location()
                .known()
                .and_then(|place| place.city()),
            Some("New York")
        );
        assert!(assessment.travel_velocity().known().is_some());
        assert_eq!(assessment.reasons(), ["impossible travel"]);
        assert!(assessment.should_block());
    }

    /// A low-risk assessment carries no location, no velocity and no reasons,
    /// and does not block. So an ordinary sign-in's audit line has no reason
    /// on it.
    #[test]
    fn a_low_risk_assessment_carries_no_location_velocity_or_reasons() {
        let assessment = LoginRiskAssessment::low_risk();

        assert!(assessment.current_location().known().is_none());
        assert!(assessment.travel_velocity().known().is_none());
        assert!(assessment.reasons().is_empty());
        assert!(!assessment.should_block());
    }
}
