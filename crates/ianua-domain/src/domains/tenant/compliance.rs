use std::ops::RangeInclusive;

use time::OffsetDateTime;

use crate::domains::tenant::compliance_limits::ComplianceLimits;
#[cfg(feature = "serde")]
use crate::domains::tenant::compliance_limits::RETENTION_DAYS_EVER;
use crate::shared::model::two_cases::two_cases;
use crate::shared::validation::ValidationError;
use crate::shared::validation::numeric::validate_range;

/// A legal jurisdiction that data can be required to stay inside.
///
/// Each value is a jurisdiction, not a continent. Continents do not write
/// privacy law. Grouping by continent would, for example, count London as
/// inside the European Union. A customer who pays for EU residency is paying
/// for exactly that not to happen.
///
/// # Adequacy is not residency
///
/// The EU has adequacy decisions for the United Kingdom, Switzerland, Japan
/// and others. Personal data may lawfully be *transferred* there. That is a
/// different question from where data *resides*. A contract saying "our data
/// stays in the EU" is not kept by storing it in Zurich. So a residency is
/// met only by the exact same jurisdiction, never by an adequate one.
///
/// The list is fixed in code, not in configuration. Adding a jurisdiction
/// needs infrastructure there first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DataResidency {
    /// The European Union and the wider EEA. GDPR.
    Eu,

    /// The United Kingdom. UK GDPR and the Data Protection Act, a regime
    /// separate from the EU's.
    Uk,

    /// Switzerland. Neither EU nor EEA. The revised FADP applies.
    Switzerland,

    /// The United States.
    Us,

    /// Canada. PIPEDA applies federally. Some provinces, such as British
    /// Columbia and Nova Scotia, require some public-sector data to stay in
    /// the country.
    Canada,

    /// Brazil. LGPD.
    Brazil,

    /// India. The Digital Personal Data Protection Act.
    India,

    /// Japan. APPI.
    Japan,

    /// Australia. The Privacy Act.
    Australia,

    /// Singapore. PDPA.
    Singapore,
}

impl DataResidency {
    /// The jurisdiction's name in an audit record, such as `eu`.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Eu => "eu",
            Self::Uk => "uk",
            Self::Switzerland => "switzerland",
            Self::Us => "us",
            Self::Canada => "canada",
            Self::Brazil => "brazil",
            Self::India => "india",
            Self::Japan => "japan",
            Self::Australia => "australia",
            Self::Singapore => "singapore",
        }
    }
}

two_cases! {
    /// Whether platform operators may act as one of the tenant's users.
    /// Stored as the `allow_operator_impersonation` flag.
    pub enum OperatorImpersonation {
        /// Operators may impersonate users, and every time is audited.
        Allowed => true,
        /// Operators may not impersonate users.
        Forbidden => false,
    }
}

impl OperatorImpersonation {
    /// The rule's name in an audit record: `allowed` or `forbidden`.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Forbidden => "forbidden",
        }
    }
}

/// Where a tenant's data must stay: inside one jurisdiction, or anywhere.
///
/// Written to JSON as the jurisdiction, or `null` for anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(from = "Option<DataResidency>", into = "Option<DataResidency>")
)]
pub enum Residency {
    /// No constraint: any region the operator runs.
    #[default]
    Anywhere,
    /// Inside this jurisdiction only.
    Within(DataResidency),
}

impl Residency {
    /// The constraint a stored value records: none means anywhere.
    #[must_use]
    pub fn from_stored(bloc: Option<DataResidency>) -> Self {
        bloc.map_or(Self::Anywhere, Self::Within)
    }

    /// The constraint's name in an audit record: the jurisdiction, or
    /// `anywhere`.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Anywhere => "anywhere",
            Self::Within(bloc) => bloc.as_str(),
        }
    }
}

impl From<Option<DataResidency>> for Residency {
    fn from(bloc: Option<DataResidency>) -> Self {
        Self::from_stored(bloc)
    }
}

impl From<Residency> for Option<DataResidency> {
    fn from(residency: Residency) -> Self {
        match residency {
            Residency::Anywhere => None,
            Residency::Within(bloc) => Some(bloc),
        }
    }
}

/// How long audit records written before the last shortening of the
/// retention are kept.
///
/// A shorter retention applies to records written from then on. Records
/// already written keep the period they were written under. Otherwise a cut
/// from ten years to 30 days would let the next purge delete years of audit
/// that people relied on being kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OlderRecords {
    /// The retention was never shortened.
    #[default]
    SameRetention,
    /// Records written before `written_before` are kept `days` days.
    KeptLonger {
        /// How long they are kept.
        days: u32,
        /// When the retention was shortened.
        written_before: OffsetDateTime,
    },
}

#[cfg(feature = "serde")]
impl OlderRecords {
    /// These records as read back beside a retention of `current` days.
    ///
    /// Only shortening the retention leaves a longer period behind, and it
    /// is one a posture once had. So it is longer than `current` and inside
    /// `RETENTION_DAYS_EVER`.
    fn checked_against(self, current: u32) -> Result<Self, ValidationError> {
        let Self::KeptLonger { days, .. } = self else {
            return Ok(self);
        };
        let longer = current.saturating_add(1)..=*RETENTION_DAYS_EVER.end();
        validate_range("older_records_days", days, longer)?;
        Ok(self)
    }
}

/// Per-tenant compliance requirements: data residency, audit retention and
/// operator access.
///
/// Every posture has its retention days checked when it is built.
/// Operator impersonation grants read their permission from it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "CompliancePostureWire"))]
pub struct CompliancePosture {
    data_residency: Residency,
    audit_retention_days: u32,
    allow_operator_impersonation: OperatorImpersonation,
    #[cfg_attr(feature = "serde", serde(default))]
    older_records: OlderRecords,
}

/// A posture as it arrives, before [`CompliancePosture::new`] has checked it.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct CompliancePostureWire {
    data_residency: Option<DataResidency>,
    audit_retention_days: u32,
    allow_operator_impersonation: OperatorImpersonation,
    #[serde(default)]
    older_records: OlderRecords,
}

#[cfg(feature = "serde")]
impl TryFrom<CompliancePostureWire> for CompliancePosture {
    type Error = ValidationError;

    /// A posture read back is checked against the widest retention any
    /// posture may have, not the deployment's current range. A deployment
    /// that narrows its range still loads the tenants it set up earlier.
    /// A longer period kept for older records must be one a shortening
    /// could have left: longer than the retention, and inside
    /// `RETENTION_DAYS_EVER`.
    fn try_from(wire: CompliancePostureWire) -> Result<Self, Self::Error> {
        let posture = Self::within(
            RETENTION_DAYS_EVER,
            Residency::from_stored(wire.data_residency),
            wire.audit_retention_days,
            wire.allow_operator_impersonation,
        )?;
        Ok(Self {
            older_records: wire
                .older_records
                .checked_against(posture.audit_retention_days)?,
            ..posture
        })
    }
}

impl CompliancePosture {
    /// Builds a compliance posture within the deployment's limits.
    ///
    /// # Errors
    ///
    /// - [`ValidationError::OutOfRange`] when `audit_retention_days` is
    ///   outside the range `limits` allows.
    pub fn new(
        data_residency: Residency,
        audit_retention_days: u32,
        impersonation: OperatorImpersonation,
        limits: &ComplianceLimits,
    ) -> Result<Self, ValidationError> {
        Self::within(
            limits.retention_days(),
            data_residency,
            audit_retention_days,
            impersonation,
        )
    }

    fn within(
        allowed: RangeInclusive<u32>,
        data_residency: Residency,
        audit_retention_days: u32,
        impersonation: OperatorImpersonation,
    ) -> Result<Self, ValidationError> {
        validate_range("audit_retention_days", audit_retention_days, allowed)?;
        Ok(Self {
            data_residency,
            audit_retention_days,
            allow_operator_impersonation: impersonation,
            older_records: OlderRecords::SameRetention,
        })
    }

    /// The posture a new tenant gets, from the deployment's defaults.
    ///
    /// The limits are checked when they are built, so this posture always
    /// lies inside their range.
    #[must_use]
    pub fn default_from(limits: &ComplianceLimits) -> Self {
        Self {
            data_residency: limits.default_data_residency(),
            audit_retention_days: limits.default_retention_days(),
            allow_operator_impersonation: limits.default_operator_impersonation(),
            older_records: OlderRecords::SameRetention,
        }
    }

    /// The jurisdiction this tenant's data must stay inside, or that it may
    /// be anywhere.
    #[must_use]
    pub fn data_residency(&self) -> Residency {
        self.data_residency
    }

    /// How many days audit events are kept before they may be deleted.
    #[must_use]
    pub fn audit_retention_days(&self) -> u32 {
        self.audit_retention_days
    }

    /// Whether operators may act as this tenant's users.
    #[must_use]
    pub fn operator_impersonation(&self) -> OperatorImpersonation {
        self.allow_operator_impersonation
    }

    /// How long records written before the last shortening are kept.
    #[must_use]
    pub fn older_records(&self) -> OlderRecords {
        self.older_records
    }

    /// This posture, replacing `before` at `now`.
    ///
    /// When it keeps records for less time than `before` kept any of them,
    /// the records already written keep the longer period.
    #[must_use]
    pub fn following(self, before: &Self, now: OffsetDateTime) -> Self {
        let kept_before = before.days_kept_at(now);
        if self.audit_retention_days >= kept_before {
            return self;
        }
        Self {
            older_records: OlderRecords::KeptLonger {
                days: kept_before,
                written_before: now,
            },
            ..self
        }
    }

    /// The instant before which every audit event may be deleted, counted
    /// back from `from`.
    ///
    /// While records written before a shortening still have time left under
    /// the longer period, the cutoff is counted from that period. So no
    /// record is deleted before its own period ends.
    #[must_use]
    pub fn retention_cutoff(&self, from: OffsetDateTime) -> OffsetDateTime {
        let duration = time::Duration::days(i64::from(self.days_kept_at(from)));
        from.saturating_sub(duration)
    }

    /// The longest any record still kept must be kept, at `now`.
    fn days_kept_at(&self, now: OffsetDateTime) -> u32 {
        let OlderRecords::KeptLonger {
            days,
            written_before,
        } = self.older_records
        else {
            return self.audit_retention_days;
        };
        let older_still_kept =
            written_before > now.saturating_sub(time::Duration::days(i64::from(days)));
        if older_still_kept {
            return days.max(self.audit_retention_days);
        }
        self.audit_retention_days
    }

    /// Whether an event recorded at `event_time` is older than the retention
    /// period at `now`.
    #[must_use]
    pub fn is_expired(&self, event_time: OffsetDateTime, now: OffsetDateTime) -> bool {
        event_time < self.retention_cutoff(now)
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::tenant::compliance_limits::ComplianceLimitsParams;

    fn limits() -> ComplianceLimits {
        ComplianceLimits::default()
    }

    /// A deployment starts new tenants at 730 days with impersonation
    /// forbidden. A new tenant's posture takes exactly those values.
    #[test]
    fn default_from_uses_config_values() {
        let l = ComplianceLimits::new(ComplianceLimitsParams {
            min_retention_days: 30,
            max_retention_days: 3650,
            default_retention_days: 730,
            default_operator_impersonation: OperatorImpersonation::Forbidden,
            ..ComplianceLimitsParams::default()
        })
        .unwrap();

        let posture = CompliancePosture::default_from(&l);

        assert_eq!(posture.data_residency(), Residency::Anywhere);
        assert_eq!(posture.audit_retention_days(), 730);
        assert_eq!(
            posture.operator_impersonation(),
            OperatorImpersonation::Forbidden
        );
    }

    /// With the built-in limits, a new tenant may keep data anywhere, keeps
    /// audit events for 365 days and forbids impersonation until it turns
    /// it on.
    #[test]
    fn default_from_standard_config() {
        let posture = CompliancePosture::default_from(&limits());

        assert_eq!(posture.data_residency(), Residency::Anywhere);
        assert_eq!(posture.audit_retention_days(), 365);
        assert_eq!(
            posture.operator_impersonation(),
            OperatorImpersonation::Forbidden
        );
    }

    /// A tenant asks for EU residency, six years of audit and no
    /// impersonation. The posture keeps all three.
    #[test]
    fn accepts_valid_posture() {
        let posture = CompliancePosture::new(
            Residency::Within(DataResidency::Eu),
            2190,
            OperatorImpersonation::Forbidden,
            &limits(),
        )
        .unwrap();

        assert_eq!(
            posture.data_residency(),
            Residency::Within(DataResidency::Eu)
        );
        assert_eq!(posture.audit_retention_days(), 2190);
        assert_eq!(
            posture.operator_impersonation(),
            OperatorImpersonation::Forbidden
        );
    }

    /// A retention of 30 days, the lowest the default limits allow, is
    /// accepted.
    #[test]
    fn accepts_minimum_retention() {
        assert!(
            CompliancePosture::new(
                Residency::Anywhere,
                30,
                OperatorImpersonation::Allowed,
                &limits()
            )
            .is_ok()
        );
    }

    /// A retention of 3650 days, the highest the default limits allow, is
    /// accepted.
    #[test]
    fn accepts_maximum_retention() {
        assert!(
            CompliancePosture::new(
                Residency::Anywhere,
                3650,
                OperatorImpersonation::Allowed,
                &limits()
            )
            .is_ok()
        );
    }

    /// A retention of 29 days, one below the limit, is refused as out of
    /// range on the `audit_retention_days` field.
    #[test]
    fn rejects_below_minimum_retention() {
        let err = CompliancePosture::new(
            Residency::Anywhere,
            29,
            OperatorImpersonation::Allowed,
            &limits(),
        )
        .unwrap_err();

        assert_eq!(err.field(), Some("audit_retention_days"));
        assert_eq!(err.code(), "out_of_range");
    }

    /// A retention of 3651 days, one above the limit, is refused as out of
    /// range on the `audit_retention_days` field.
    #[test]
    fn rejects_above_maximum_retention() {
        let err = CompliancePosture::new(
            Residency::Anywhere,
            3651,
            OperatorImpersonation::Allowed,
            &limits(),
        )
        .unwrap_err();

        assert_eq!(err.field(), Some("audit_retention_days"));
        assert_eq!(err.code(), "out_of_range");
    }

    /// A retention of zero days is refused, so audit events are never
    /// deleted the moment they are written.
    #[test]
    fn rejects_zero_retention() {
        assert!(
            CompliancePosture::new(
                Residency::Anywhere,
                0,
                OperatorImpersonation::Allowed,
                &limits()
            )
            .is_err()
        );
    }

    /// A deployment allows 90 to 730 days. 90 and 730 are accepted, while
    /// 89 and 731 are refused.
    #[test]
    fn respects_custom_limits() {
        let l = ComplianceLimits::new(ComplianceLimitsParams {
            min_retention_days: 90,
            max_retention_days: 730,
            default_retention_days: 180,
            ..ComplianceLimitsParams::default()
        })
        .unwrap();

        assert!(
            CompliancePosture::new(Residency::Anywhere, 89, OperatorImpersonation::Allowed, &l)
                .is_err()
        );
        assert!(
            CompliancePosture::new(Residency::Anywhere, 90, OperatorImpersonation::Allowed, &l)
                .is_ok()
        );
        assert!(
            CompliancePosture::new(Residency::Anywhere, 730, OperatorImpersonation::Allowed, &l)
                .is_ok()
        );
        assert!(
            CompliancePosture::new(Residency::Anywhere, 731, OperatorImpersonation::Allowed, &l)
                .is_err()
        );
    }

    /// A tenant may declare residency in each of the ten jurisdictions. None
    /// is refused.
    #[test]
    fn every_jurisdiction_is_accepted() {
        let l = limits();
        for jurisdiction in [
            DataResidency::Eu,
            DataResidency::Uk,
            DataResidency::Switzerland,
            DataResidency::Us,
            DataResidency::Canada,
            DataResidency::Brazil,
            DataResidency::India,
            DataResidency::Japan,
            DataResidency::Australia,
            DataResidency::Singapore,
        ] {
            assert!(
                CompliancePosture::new(
                    Residency::Within(jurisdiction),
                    365,
                    OperatorImpersonation::Allowed,
                    &l
                )
                .is_ok(),
                "{jurisdiction:?} must be declarable"
            );
        }
    }

    /// A tenant declares no residency, so its data may be anywhere. That is
    /// accepted.
    #[test]
    fn no_residency_accepted() {
        assert!(
            CompliancePosture::new(
                Residency::Anywhere,
                365,
                OperatorImpersonation::Allowed,
                &limits()
            )
            .is_ok()
        );
    }

    /// A tenant keeps audit events for 365 days. The cutoff lies exactly 365
    /// days before now.
    #[test]
    fn retention_cutoff_subtracts_days() {
        let posture = CompliancePosture::new(
            Residency::Anywhere,
            365,
            OperatorImpersonation::Allowed,
            &limits(),
        )
        .unwrap();
        let now = crate::shared::clock::now();
        let cutoff = posture.retention_cutoff(now);

        assert_eq!(now - cutoff, Duration::days(365));
    }

    /// With 30 days of retention, an event from 29 days ago is kept.
    #[test]
    fn event_within_retention_is_not_expired() {
        let posture = CompliancePosture::new(
            Residency::Anywhere,
            30,
            OperatorImpersonation::Allowed,
            &limits(),
        )
        .unwrap();
        let now = crate::shared::clock::now();
        let recent_event = now - Duration::days(29);

        assert!(!posture.is_expired(recent_event, now));
    }

    /// With 30 days of retention, an event from 31 days ago may be deleted.
    #[test]
    fn event_beyond_retention_is_expired() {
        let posture = CompliancePosture::new(
            Residency::Anywhere,
            30,
            OperatorImpersonation::Allowed,
            &limits(),
        )
        .unwrap();
        let now = crate::shared::clock::now();
        let old_event = now - Duration::days(31);

        assert!(posture.is_expired(old_event, now));
    }

    /// With 30 days of retention, an event from exactly 30 days ago is still
    /// kept. Only events older than the cutoff may be deleted.
    #[test]
    fn event_exactly_at_cutoff_is_not_expired() {
        let posture = CompliancePosture::new(
            Residency::Anywhere,
            30,
            OperatorImpersonation::Allowed,
            &limits(),
        )
        .unwrap();
        let now = crate::shared::clock::now();
        let boundary_event = now - Duration::days(30);

        assert!(!posture.is_expired(boundary_event, now));
    }

    /// A stored posture with zero days of retention is read from JSON. It is
    /// refused, so reading back never skips the retention check.
    #[cfg(feature = "serde")]
    #[test]
    fn a_posture_read_from_json_with_retention_out_of_range_is_refused() {
        let json = r#"{"data_residency":null,"audit_retention_days":0,"allow_operator_impersonation":true}"#;

        assert!(serde_json::from_str::<CompliancePosture>(json).is_err());
    }

    /// A tenant was saved with 5,000 days, beyond today's default range. It
    /// still loads, so narrowing a deployment's range does not lock out
    /// tenants it set up earlier.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_posture_outside_todays_range_still_loads() {
        let json = r#"{"data_residency":null,"audit_retention_days":5000,"allow_operator_impersonation":true}"#;

        let restored = serde_json::from_str::<CompliancePosture>(json).unwrap();

        assert_eq!(restored.audit_retention_days(), 5000);
        assert!(!limits().retention_days().contains(&5000));
    }

    /// A posture with EU residency, 365 days and no impersonation is written
    /// to JSON and read back. It comes back equal.
    #[cfg(feature = "serde")]
    #[test]
    fn a_valid_posture_round_trips_through_json() {
        let posture = CompliancePosture::new(
            Residency::Within(DataResidency::Eu),
            365,
            OperatorImpersonation::Forbidden,
            &limits(),
        )
        .unwrap();

        let json = serde_json::to_string(&posture).unwrap();
        let restored: CompliancePosture = serde_json::from_str(&json).unwrap();

        assert_eq!(restored, posture);
    }

    /// A posture shortened from 365 to 30 days reads back with its longer
    /// retention for older records. Changing that stored period to 20 days,
    /// below the current retention, or 40,000 days, beyond the allowed range,
    /// makes deserialization fail.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_longer_period_no_shortening_leaves_is_refused() {
        let posture = |days| {
            CompliancePosture::new(
                Residency::Anywhere,
                days,
                OperatorImpersonation::Forbidden,
                &limits(),
            )
            .unwrap()
        };
        let cut_at = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let shortened = posture(30).following(&posture(365), cut_at);
        let json = serde_json::to_string(&shortened).unwrap();
        let too_short = json.replace("\"days\":365", "\"days\":20");
        let too_long = json.replace("\"days\":365", "\"days\":40000");

        assert!(serde_json::from_str::<CompliancePosture>(&json).is_ok());
        assert!(serde_json::from_str::<CompliancePosture>(&too_short).is_err());
        assert!(serde_json::from_str::<CompliancePosture>(&too_long).is_err());
    }

    /// The EU differs from the UK and Switzerland, and the US from Canada.
    /// A tenant paying for EU residency never has its data counted as
    /// staying in the EU when it sits in London.
    #[test]
    fn jurisdictions_are_distinct_from_one_another() {
        assert_ne!(
            DataResidency::Eu,
            DataResidency::Uk,
            "the UK left the EU; conflating them is the exact promise this type protects"
        );
        assert_ne!(DataResidency::Eu, DataResidency::Switzerland);
        assert_ne!(DataResidency::Us, DataResidency::Canada);
    }

    /// Each of the ten jurisdictions is written to JSON and read back as the
    /// same one.
    #[cfg(feature = "serde")]
    #[test]
    fn every_jurisdiction_survives_the_round_trip_to_storage() {
        for jurisdiction in [
            DataResidency::Eu,
            DataResidency::Uk,
            DataResidency::Switzerland,
            DataResidency::Us,
            DataResidency::Canada,
            DataResidency::Brazil,
            DataResidency::India,
            DataResidency::Japan,
            DataResidency::Australia,
            DataResidency::Singapore,
        ] {
            let json = serde_json::to_string(&jurisdiction).unwrap();
            let restored: DataResidency = serde_json::from_str(&json).unwrap();
            assert_eq!(jurisdiction, restored);
        }
    }

    /// Acme keeps audit for ten years and cuts it to 30 days. Forty days
    /// later, a record written the day before the cut is still kept, since
    /// it was written under ten years. Once ten years have passed, only the
    /// 30-day period is left.
    #[test]
    fn a_shorter_retention_spares_records_already_written() {
        let wide = ComplianceLimits::new(ComplianceLimitsParams {
            min_retention_days: 30,
            max_retention_days: 3650,
            default_retention_days: 730,
            ..ComplianceLimitsParams::default()
        })
        .unwrap();
        let posture = |days| {
            CompliancePosture::new(
                Residency::Anywhere,
                days,
                OperatorImpersonation::Forbidden,
                &wide,
            )
            .unwrap()
        };
        let cut_at = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let shortened = posture(30).following(&posture(3650), cut_at);
        let written_before = cut_at - Duration::days(1);
        let forty_days_on = cut_at + Duration::days(40);

        assert!(!shortened.is_expired(written_before, forty_days_on));
        assert!(posture(30).is_expired(written_before, forty_days_on));
        assert_eq!(
            shortened.retention_cutoff(cut_at + Duration::days(3651)),
            cut_at + Duration::days(3651) - Duration::days(30)
        );
    }
}
