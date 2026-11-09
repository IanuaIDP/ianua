//! Device posture: what is known about the device a request comes from, and
//! the rule a route's pipeline holds it to.
//!
//! A device agent or a mobile device manager reports the facts. The gateway
//! looks them up for the request's device and hands them to the posture
//! stage. A fact nobody reported is unknown, and an unknown fact never
//! passes a rule that asks for it. A laptop whose disk encryption nobody
//! checked is treated like one without it.
//!
//! Which device a request comes from is a
//! [`RequestDevice`]: a verified device certificate first, else the
//! trusted device the person's session was signed in from. With neither
//! the device is unknown, and [`PostureRule::evaluate_for`] passes no rule
//! for it, since no report can be tied to it.

use std::collections::{BTreeMap, BTreeSet};

use time::{Duration, OffsetDateTime};

use crate::domains::proxy::request::device::RequestDevice;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_range;
use crate::types::{Fact, Seconds, TrustedDeviceId};

/// The shortest a posture report may be trusted for, in seconds.
const MIN_REPORT_AGE_SECS: u32 = 60;

/// The longest a posture report may be trusted for: a week.
const MAX_REPORT_AGE_SECS: u32 = 7 * 86_400;

/// How far ahead of the gateway's clock a report may be dated. Past this it
/// is refused, so a report dated next year cannot stay fresh all year.
const REPORT_CLOCK_SKEW: Duration = Duration::minutes(5);

/// The operating system a device runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum OsFamily {
    /// Microsoft Windows.
    Windows,
    /// Apple macOS.
    MacOs,
    /// A Linux distribution.
    Linux,
    /// Apple iOS or iPadOS.
    Ios,
    /// Google Android.
    Android,
    /// Google ChromeOS.
    ChromeOs,
}

/// An operating system version, compared part by part, so `14.10` is newer
/// than `14.9`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OsVersion {
    major: u16,
    minor: u16,
    patch: u16,
}

impl OsVersion {
    /// The version `major.minor.patch`.
    #[must_use]
    pub fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

/// The operating system a device reported, with its version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatingSystem {
    family: OsFamily,
    version: OsVersion,
}

impl OperatingSystem {
    /// Version `version` of `family`.
    #[must_use]
    pub fn new(family: OsFamily, version: OsVersion) -> Self {
        Self { family, version }
    }

    /// Which system.
    #[must_use]
    pub fn family(&self) -> OsFamily {
        self.family
    }

    /// The reported release compared with configured minimum operating-system versions.
    #[must_use]
    pub fn version(&self) -> OsVersion {
        self.version
    }
}

/// A protection a device may have switched on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Protection {
    /// The disk is encrypted.
    DiskEncryption,
    /// The screen locks when the device is left.
    ScreenLock,
    /// A host firewall is on.
    Firewall,
    /// The device is enrolled in the organization's device management.
    Managed,
}

/// Whether a reported protection is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionState {
    /// The device reports that the required protection is enabled.
    On,
    /// The device reports that the required protection is disabled.
    Off,
}

/// Which device a report is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportedDevice {
    /// A device a person marked as trusted.
    Trusted(TrustedDeviceId),
    /// A device nobody enrolled.
    Unenrolled,
}

/// What a device agent or device manager reported about a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePosture {
    device: ReportedDevice,
    system: Fact<OperatingSystem>,
    protections: BTreeMap<Protection, ProtectionState>,
    reported_at: OffsetDateTime,
}

/// The facts a [`DevicePosture`] is made from.
pub struct DevicePostureParams {
    /// Which device the report is about.
    pub device: ReportedDevice,
    /// Its operating system, when reported.
    pub system: Fact<OperatingSystem>,
    /// Each protection reported, on or off. One left out is unknown.
    pub protections: BTreeMap<Protection, ProtectionState>,
    /// When the report was made.
    pub reported_at: OffsetDateTime,
}

impl DevicePosture {
    /// A device's posture as it was reported.
    #[must_use]
    pub fn new(params: DevicePostureParams) -> Self {
        Self {
            device: params.device,
            system: params.system,
            protections: params.protections,
            reported_at: params.reported_at,
        }
    }

    /// Which device the report is about.
    #[must_use]
    pub fn device(&self) -> ReportedDevice {
        self.device
    }

    /// The report with its device counted as one nobody enrolled: what a
    /// report naming a trusted device becomes when the person asking does
    /// not trust it, as the device's own record shows. A provider vouching
    /// for Ann's laptop never makes it trusted for Bob, nor once Ann
    /// revoked it.
    #[must_use]
    pub fn untrusted(self) -> Self {
        Self {
            device: ReportedDevice::Unenrolled,
            ..self
        }
    }

    /// The operating system, when reported.
    #[must_use]
    pub fn system(&self) -> Fact<OperatingSystem> {
        self.system
    }

    /// Whether `protection` is on, off, or was not reported.
    #[must_use]
    pub fn protection(&self, protection: Protection) -> Fact<ProtectionState> {
        Fact::from_option(self.protections.get(&protection).copied())
    }

    /// When the report was made.
    #[must_use]
    pub fn reported_at(&self) -> OffsetDateTime {
        self.reported_at
    }
}

/// Whether a rule asks for an enrolled device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum DeviceRequirement {
    /// Any device with a report.
    AnyDevice,
    /// Only a device a person marked as trusted.
    Trusted,
}

/// What a rule does with a system it names no minimum version for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum OtherSystems {
    /// Let it through at any version.
    Allowed,
    /// Refuse it.
    Refused,
}

/// What a posture rule is made from.
pub struct PostureRuleParams {
    /// Whether the device must be a trusted one.
    pub device: DeviceRequirement,
    /// The oldest version allowed of each system named.
    pub minimum_versions: BTreeMap<OsFamily, OsVersion>,
    /// What happens to a system not named in `minimum_versions`.
    pub other_systems: OtherSystems,
    /// The protections that must be on.
    pub required: BTreeSet<Protection>,
    /// How old a report may be and still count.
    pub max_report_age: Seconds,
}

/// What a device must be like for a request from it to pass.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "PostureRuleWire"))]
pub struct PostureRule {
    device: DeviceRequirement,
    minimum_versions: BTreeMap<OsFamily, OsVersion>,
    other_systems: OtherSystems,
    required: BTreeSet<Protection>,
    max_report_age: Seconds,
}

/// A [`PostureRule`] as stored, read back through [`PostureRule::new`].
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct PostureRuleWire {
    device: DeviceRequirement,
    minimum_versions: BTreeMap<OsFamily, OsVersion>,
    other_systems: OtherSystems,
    required: BTreeSet<Protection>,
    max_report_age: Seconds,
}

#[cfg(feature = "serde")]
impl TryFrom<PostureRuleWire> for PostureRule {
    type Error = DomainError;

    fn try_from(wire: PostureRuleWire) -> Result<Self, Self::Error> {
        Self::new(PostureRuleParams {
            device: wire.device,
            minimum_versions: wire.minimum_versions,
            other_systems: wire.other_systems,
            required: wire.required,
            max_report_age: wire.max_report_age,
        })
    }
}

/// Why a device fell short of a posture rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostureGap {
    /// Nothing tells which of the person's trusted devices the request
    /// comes from, so no report can be tied to it.
    DeviceUnknown,
    /// Nothing was reported about the device.
    NoReport,
    /// The report is older than the rule trusts.
    StaleReport,
    /// The report is dated in the future.
    ReportFromTheFuture,
    /// The rule asks for a trusted device, and this one is not.
    DeviceNotTrusted,
    /// The rule asks about the system, and none was reported.
    SystemUnknown,
    /// The system is one the rule does not let through.
    SystemNotAllowed(OsFamily),
    /// The system is older than the rule allows.
    SystemTooOld(OsFamily),
    /// A protection the rule asks for was not reported.
    ProtectionUnknown(Protection),
    /// A protection the rule asks for is off.
    ProtectionOff(Protection),
}

/// What a posture rule decided about a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostureVerdict {
    /// The device meets the rule.
    Meets,
    /// The device falls short, for this reason.
    Fails(PostureGap),
}

impl PostureRule {
    /// A checked posture rule.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] if `max_report_age` is under a minute or
    ///   over a week.
    /// - [`DomainError::Validation`] if the rule asks for nothing at all, so
    ///   a stage holding it would look like a check while checking nothing.
    pub fn new(params: PostureRuleParams) -> Result<Self, DomainError> {
        validate_range(
            "max_report_age",
            params.max_report_age.get(),
            MIN_REPORT_AGE_SECS..=MAX_REPORT_AGE_SECS,
        )?;
        let asks_nothing = params.device == DeviceRequirement::AnyDevice
            && params.minimum_versions.is_empty()
            && params.other_systems == OtherSystems::Allowed
            && params.required.is_empty();
        if asks_nothing {
            return Err(DomainError::invalid(message!(
                "proxy-a-posture-rule-must-ask-for",
                "a posture rule must ask for a trusted device, a system or a protection"
            )));
        }
        Ok(Self {
            device: params.device,
            minimum_versions: params.minimum_versions,
            other_systems: params.other_systems,
            required: params.required,
            max_report_age: params.max_report_age,
        })
    }

    /// Whether the rule asks for a trusted device.
    #[must_use]
    pub fn device(&self) -> DeviceRequirement {
        self.device
    }

    /// The oldest version allowed of each system named.
    #[must_use]
    pub fn minimum_versions(&self) -> &BTreeMap<OsFamily, OsVersion> {
        &self.minimum_versions
    }

    /// What happens to a system the rule names no version for.
    #[must_use]
    pub fn other_systems(&self) -> OtherSystems {
        self.other_systems
    }

    /// The protections that must be on.
    #[must_use]
    pub fn required(&self) -> &BTreeSet<Protection> {
        &self.required
    }

    /// How old a report may be and still count.
    #[must_use]
    pub fn max_report_age(&self) -> Seconds {
        self.max_report_age
    }

    /// Whether the device `posture` describes meets the rule at `now`.
    ///
    /// It denies by default: no report, an old report, or a fact the rule
    /// asks about that nobody reported, each fails.
    #[must_use]
    pub fn evaluate(&self, posture: Fact<&DevicePosture>, now: OffsetDateTime) -> PostureVerdict {
        match self.gap_in(posture, now) {
            Ok(()) => PostureVerdict::Meets,
            Err(gap) => PostureVerdict::Fails(gap),
        }
    }

    /// Whether the request from `device` meets the rule at `now`, by what
    /// `posture` reports about it.
    ///
    /// An unknown device fails every rule: whatever a provider reports
    /// could be about another of the person's devices. When the session's
    /// trusted device names the device, a report about another trusted
    /// device is no report about it.
    #[must_use]
    pub fn evaluate_for(
        &self,
        device: RequestDevice,
        posture: Fact<&DevicePosture>,
        now: OffsetDateTime,
    ) -> PostureVerdict {
        if !device.is_known() {
            return PostureVerdict::Fails(PostureGap::DeviceUnknown);
        }
        if is_about_another(device.session_device(), posture) {
            return PostureVerdict::Fails(PostureGap::NoReport);
        }
        self.evaluate(posture, now)
    }

    /// The first way `posture` falls short of the rule, if any.
    fn gap_in(&self, posture: Fact<&DevicePosture>, now: OffsetDateTime) -> Result<(), PostureGap> {
        let Fact::Known(posture) = posture else {
            return Err(PostureGap::NoReport);
        };
        self.ensure_fresh(posture.reported_at, now)?;
        self.ensure_device(posture.device)?;
        self.ensure_system(posture.system)?;
        self.required
            .iter()
            .try_for_each(|protection| ensure_on(posture, *protection))
    }

    /// Refuses a report older than the rule trusts, or dated ahead of `now`.
    fn ensure_fresh(
        &self,
        reported_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<(), PostureGap> {
        let latest_believable = now.checked_add(REPORT_CLOCK_SKEW).unwrap_or(now);
        if reported_at > latest_believable {
            return Err(PostureGap::ReportFromTheFuture);
        }
        let Some(trusted_until) = reported_at.checked_add(self.max_report_age.duration()) else {
            return Err(PostureGap::StaleReport);
        };
        if now >= trusted_until {
            return Err(PostureGap::StaleReport);
        }
        Ok(())
    }

    /// Refuses an unenrolled device when the rule asks for a trusted one.
    fn ensure_device(&self, device: ReportedDevice) -> Result<(), PostureGap> {
        match (self.device, device) {
            (DeviceRequirement::Trusted, ReportedDevice::Unenrolled) => {
                Err(PostureGap::DeviceNotTrusted)
            }
            (DeviceRequirement::AnyDevice, _)
            | (DeviceRequirement::Trusted, ReportedDevice::Trusted(_)) => Ok(()),
        }
    }

    /// Refuses a system the rule does not let through, or an older version.
    fn ensure_system(&self, system: Fact<OperatingSystem>) -> Result<(), PostureGap> {
        let asks_about_system =
            !self.minimum_versions.is_empty() || self.other_systems == OtherSystems::Refused;
        if !asks_about_system {
            return Ok(());
        }
        let Fact::Known(system) = system else {
            return Err(PostureGap::SystemUnknown);
        };
        match (
            self.minimum_versions.get(&system.family),
            self.other_systems,
        ) {
            (Some(minimum), _) if system.version < *minimum => {
                Err(PostureGap::SystemTooOld(system.family))
            }
            (Some(_), _) | (None, OtherSystems::Allowed) => Ok(()),
            (None, OtherSystems::Refused) => Err(PostureGap::SystemNotAllowed(system.family)),
        }
    }
}

/// Whether `posture` reports on another trusted device than `asked`, the
/// one the session names.
fn is_about_another(asked: Fact<TrustedDeviceId>, posture: Fact<&DevicePosture>) -> bool {
    let (Fact::Known(asked), Fact::Known(report)) = (asked, posture) else {
        return false;
    };
    matches!(report.device, ReportedDevice::Trusted(reported) if reported != asked)
}

/// Refuses a device whose `protection` is off or was not reported.
fn ensure_on(posture: &DevicePosture, protection: Protection) -> Result<(), PostureGap> {
    match posture.protection(protection) {
        Fact::Known(ProtectionState::On) => Ok(()),
        Fact::Known(ProtectionState::Off) => Err(PostureGap::ProtectionOff(protection)),
        Fact::Unknown => Err(PostureGap::ProtectionUnknown(protection)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CertificateFingerprint;

    /// A fixed instant tests measure report ages from.
    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    /// A rule asking for a trusted device on macOS 14 or later, with disk
    /// encryption and a firewall, and a report at most an hour old.
    fn rule() -> PostureRule {
        PostureRule::new(PostureRuleParams {
            device: DeviceRequirement::Trusted,
            minimum_versions: BTreeMap::from([(OsFamily::MacOs, OsVersion::new(14, 0, 0))]),
            other_systems: OtherSystems::Refused,
            required: BTreeSet::from([Protection::DiskEncryption, Protection::Firewall]),
            max_report_age: Seconds::new(3_600),
        })
        .unwrap()
    }

    /// Ann's trusted MacBook on macOS 14.4, encrypted and firewalled,
    /// reported ten minutes ago.
    fn anns_laptop() -> DevicePostureParams {
        DevicePostureParams {
            device: ReportedDevice::Trusted(TrustedDeviceId::new()),
            system: Fact::Known(OperatingSystem {
                family: OsFamily::MacOs,
                version: OsVersion::new(14, 4, 0),
            }),
            protections: BTreeMap::from([
                (Protection::DiskEncryption, ProtectionState::On),
                (Protection::Firewall, ProtectionState::On),
            ]),
            reported_at: now() - Duration::minutes(10),
        }
    }

    /// The verdict of [`rule`] on a device reported as `params` says.
    fn verdict(params: DevicePostureParams) -> PostureVerdict {
        rule().evaluate(Fact::Known(&DevicePosture::new(params)), now())
    }

    /// Ann's laptop, fresh, trusted and protected, meets the rule.
    #[test]
    fn a_device_meeting_every_requirement_passes() {
        assert_eq!(verdict(anns_laptop()), PostureVerdict::Meets);
    }

    /// Evaluating the trusted-device rule without a posture report returns
    /// `NoReport`.
    #[test]
    fn no_report_fails() {
        assert_eq!(
            rule().evaluate(Fact::Unknown, now()),
            PostureVerdict::Fails(PostureGap::NoReport)
        );
    }

    /// Ann's otherwise healthy laptop report fails as stale when it is two
    /// hours old and the rule trusts reports for one hour.
    #[test]
    fn a_stale_report_fails() {
        let old = DevicePostureParams {
            reported_at: now() - Duration::hours(2),
            ..anns_laptop()
        };

        assert_eq!(verdict(old), PostureVerdict::Fails(PostureGap::StaleReport));
    }

    /// An otherwise healthy report dated a year ahead fails with
    /// `ReportFromTheFuture`.
    #[test]
    fn a_report_dated_ahead_fails() {
        let ahead = DevicePostureParams {
            reported_at: now() + Duration::days(365),
            ..anns_laptop()
        };

        assert_eq!(
            verdict(ahead),
            PostureVerdict::Fails(PostureGap::ReportFromTheFuture)
        );
    }

    /// An unenrolled device with otherwise healthy reported facts fails
    /// the trusted-device requirement with `DeviceNotTrusted`.
    #[test]
    fn an_unenrolled_device_fails_a_trusted_device_rule() {
        let bobs = DevicePostureParams {
            device: ReportedDevice::Unenrolled,
            ..anns_laptop()
        };

        assert_eq!(
            verdict(bobs),
            PostureVerdict::Fails(PostureGap::DeviceNotTrusted)
        );
    }

    /// A laptop reporting macOS 13.6 fails with `SystemTooOld` when the rule
    /// requires macOS 14 or later.
    #[test]
    fn an_old_system_fails() {
        let old = DevicePostureParams {
            system: Fact::Known(OperatingSystem {
                family: OsFamily::MacOs,
                version: OsVersion::new(13, 6, 0),
            }),
            ..anns_laptop()
        };

        assert_eq!(
            verdict(old),
            PostureVerdict::Fails(PostureGap::SystemTooOld(OsFamily::MacOs))
        );
    }

    /// The rule names only macOS and refuses other systems. A Windows laptop
    /// fails, and a laptop whose system nobody reported fails too.
    #[test]
    fn a_system_the_rule_does_not_name_or_know_fails() {
        let windows = DevicePostureParams {
            system: Fact::Known(OperatingSystem {
                family: OsFamily::Windows,
                version: OsVersion::new(11, 0, 0),
            }),
            ..anns_laptop()
        };
        let unknown = DevicePostureParams {
            system: Fact::Unknown,
            ..anns_laptop()
        };

        assert_eq!(
            verdict(windows),
            PostureVerdict::Fails(PostureGap::SystemNotAllowed(OsFamily::Windows))
        );
        assert_eq!(
            verdict(unknown),
            PostureVerdict::Fails(PostureGap::SystemUnknown)
        );
    }

    /// A disabled firewall and an unreported firewall both fail the rule,
    /// with distinct `ProtectionOff` and `ProtectionUnknown` gaps.
    #[test]
    fn a_protection_off_or_unreported_fails() {
        let off = DevicePostureParams {
            protections: BTreeMap::from([
                (Protection::DiskEncryption, ProtectionState::On),
                (Protection::Firewall, ProtectionState::Off),
            ]),
            ..anns_laptop()
        };
        let silent = DevicePostureParams {
            protections: BTreeMap::from([(Protection::DiskEncryption, ProtectionState::On)]),
            ..anns_laptop()
        };

        assert_eq!(
            verdict(off),
            PostureVerdict::Fails(PostureGap::ProtectionOff(Protection::Firewall))
        );
        assert_eq!(
            verdict(silent),
            PostureVerdict::Fails(PostureGap::ProtectionUnknown(Protection::Firewall))
        );
    }

    /// macOS 14.10 is newer than 14.9, part by part, not as text.
    #[test]
    fn versions_compare_part_by_part() {
        assert!(OsVersion::new(14, 10, 0) > OsVersion::new(14, 9, 0));
    }

    /// Ann's healthy laptop, reported as `params` says, and the trusted
    /// device it names.
    fn reported(params: DevicePostureParams) -> (DevicePosture, TrustedDeviceId) {
        let ReportedDevice::Trusted(laptop) = params.device else {
            panic!("Ann's laptop is trusted");
        };
        (DevicePosture::new(params), laptop)
    }

    /// An unknown request device fails with `DeviceUnknown` even when
    /// accompanied by Ann's healthy laptop report.
    #[test]
    fn an_unknown_device_fails_every_rule() {
        let (report, _) = reported(anns_laptop());

        let verdict = rule().evaluate_for(RequestDevice::Unknown, Fact::Known(&report), now());

        assert_eq!(verdict, PostureVerdict::Fails(PostureGap::DeviceUnknown));
    }

    /// A request naming Ann's phone as its session device fails with
    /// `NoReport` when supplied with her laptop's report.
    #[test]
    fn a_report_about_another_device_is_no_report() {
        let (report, _) = reported(anns_laptop());
        let phone = RequestDevice::SessionTrusted(TrustedDeviceId::new());

        let verdict = rule().evaluate_for(phone, Fact::Known(&report), now());

        assert_eq!(verdict, PostureVerdict::Fails(PostureGap::NoReport));
    }

    /// Ann's session was signed in from her laptop, and the report is
    /// about it. It is held to the rule, and passes.
    #[test]
    fn a_report_about_the_session_device_is_held_to_the_rule() {
        let (report, laptop) = reported(anns_laptop());
        let device = RequestDevice::SessionTrusted(laptop);

        let verdict = rule().evaluate_for(device, Fact::Known(&report), now());

        assert_eq!(verdict, PostureVerdict::Meets);
    }

    /// Ann's laptop presents its device certificate. The report the
    /// provider gives for that certificate is held to the rule.
    #[test]
    fn a_report_about_a_certified_device_is_held_to_the_rule() {
        let (report, _) = reported(anns_laptop());
        let certified = RequestDevice::Certified(CertificateFingerprint::from_digest([7; 32]));

        let verdict = rule().evaluate_for(certified, Fact::Known(&report), now());

        assert_eq!(verdict, PostureVerdict::Meets);
    }

    /// Marking the matching laptop report untrusted makes it fail the
    /// trusted-device rule with `DeviceNotTrusted`.
    #[test]
    fn an_untrusted_report_fails_a_trusted_device_rule() {
        let (report, laptop) = reported(anns_laptop());
        let device = RequestDevice::SessionTrusted(laptop);

        let verdict = rule().evaluate_for(device, Fact::Known(&report.untrusted()), now());

        assert_eq!(verdict, PostureVerdict::Fails(PostureGap::DeviceNotTrusted));
    }

    /// A rule that asks for nothing, or trusts a report for a month, is
    /// refused.
    #[test]
    fn a_rule_that_checks_nothing_or_trusts_old_reports_is_refused() {
        let nothing = PostureRuleParams {
            device: DeviceRequirement::AnyDevice,
            minimum_versions: BTreeMap::new(),
            other_systems: OtherSystems::Allowed,
            required: BTreeSet::new(),
            max_report_age: Seconds::new(3_600),
        };
        let month = PostureRuleParams {
            device: DeviceRequirement::Trusted,
            minimum_versions: BTreeMap::new(),
            other_systems: OtherSystems::Allowed,
            required: BTreeSet::new(),
            max_report_age: Seconds::new(30 * 86_400),
        };

        assert!(PostureRule::new(nothing).is_err());
        assert!(PostureRule::new(month).is_err());
    }

    /// A stored rule trusting reports for a month is refused on reading,
    /// as building it would be.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_rule_is_held_to_the_same_checks() {
        let mut json = serde_json::to_value(rule()).unwrap();
        assert!(serde_json::from_value::<PostureRule>(json.clone()).is_ok());

        json["max_report_age"] = serde_json::json!(30 * 86_400);

        assert!(serde_json::from_value::<PostureRule>(json).is_err());
    }
}
