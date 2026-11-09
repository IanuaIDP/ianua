//! Check device posture: whether the device a request came from meets a
//! route's posture rule.
//!
//! The gateway's posture stage calls this for each request it sees. The
//! device is what the request names: a verified device certificate first,
//! else the trusted device the person's session was signed in from. The
//! posture provider says what it last heard about the device, the person's
//! own records say whether the device it names is one they trust, and the
//! domain's rule decides.
//!
//! It denies by default. A device nothing names fails every rule, without
//! the provider being asked; a device the provider knows nothing of is
//! unreported, which never meets a rule. A provider that fails, or records
//! that cannot be read, is an error, never a verdict: the gateway answers
//! 503, so an outage is not taken for a device that fell short.

use std::sync::Arc;

use ianua_domain::domains::proxy::stages::posture::{
    DevicePosture, PostureRule, PostureVerdict, ReportedDevice,
};
use ianua_domain::shared::clock;
use ianua_domain::types::{Fact, PrincipalId, TrustedDeviceId};

use crate::error::{AppError, OrInternal};
use crate::ports::proxy::{DeviceInQuestion, DeviceStandings, PostureProvider};
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;

/// Which rule to hold which device to.
pub struct PostureCheck {
    /// The route's posture rule.
    pub rule: PostureRule,
    /// The person and the device the request came from.
    pub device: DeviceInQuestion,
}

/// The ports [`CheckDevicePostureUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CheckDevicePosturePorts {
    /// What a device agent or device manager reported about devices.
    pub posture_provider: Arc<dyn PostureProvider>,
    /// Whose each remembered device is and whether it is still trusted,
    /// which says whether a reported device is one the person trusts.
    pub device_standings: Arc<dyn DeviceStandings>,
}

/// Checks a device against a posture rule.
pub struct CheckDevicePostureUseCase {
    ports: CheckDevicePosturePorts,
}

impl CheckDevicePostureUseCase {
    /// A use case asking through `ports`.
    #[must_use]
    pub fn new(ports: CheckDevicePosturePorts) -> Self {
        Self { ports }
    }

    /// What the provider reported about `device`, or that it knows nothing
    /// of it.
    ///
    /// # Errors
    ///
    /// `AppError::Upstream` when the provider fails, logged with the
    /// person's id and nothing else about the device.
    async fn reported_posture(
        &self,
        tenant: &ScopedTenant,
        device: &DeviceInQuestion,
    ) -> Result<Fact<DevicePosture>, AppError> {
        self.ports
            .posture_provider
            .posture_of(tenant, device)
            .await
            .map_err(|error| {
                tracing::warn!(
                    user_id = %device.person,
                    %error,
                    "device posture provider failed; the request is refused as unavailable"
                );
                AppError::upstream(error)
            })
    }

    /// `posture` as the person's own records stand: a report naming a
    /// trusted device that is not one `person` trusts now counts as about
    /// an unenrolled device.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the device's record cannot be read.
    async fn held_to_records(
        &self,
        tenant: &ScopedTenant,
        person: PrincipalId,
        posture: Fact<DevicePosture>,
    ) -> Result<Fact<DevicePosture>, AppError> {
        let Fact::Known(report) = posture else {
            return Ok(Fact::Unknown);
        };
        let ReportedDevice::Trusted(device) = report.device() else {
            return Ok(Fact::Known(report));
        };
        if self.is_trusted_by(tenant, person, &device).await? {
            return Ok(Fact::Known(report));
        }
        Ok(Fact::Known(report.untrusted()))
    }

    /// Whether `device` is one `person` remembered and still trusts.
    async fn is_trusted_by(
        &self,
        tenant: &ScopedTenant,
        person: PrincipalId,
        device: &TrustedDeviceId,
    ) -> Result<bool, AppError> {
        let standing = self
            .ports
            .device_standings
            .standing_of(tenant, device)
            .await
            .or_internal()?;
        Ok(standing.is_some_and(|standing| standing.is_trusted_by(person)))
    }
}

impl Query for CheckDevicePostureUseCase {
    type Caller = ScopedTenant;
    type Input = PostureCheck;
    type Output = Result<PostureVerdict, AppError>;

    /// Whether the device the request came from meets the rule now.
    ///
    /// A device nothing names fails as
    /// [`PostureGap::DeviceUnknown`](ianua_domain::domains::proxy::stages::posture::PostureGap::DeviceUnknown),
    /// and the provider is not asked.
    ///
    /// # Errors
    ///
    /// - `AppError::Upstream` when the posture provider fails or does not
    ///   answer in time.
    /// - `AppError::Internal` when the person's trusted devices cannot be
    ///   read.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        check: PostureCheck,
    ) -> Result<PostureVerdict, AppError> {
        let device = check.device.device;
        if !device.is_known() {
            return Ok(check.rule.evaluate_for(device, Fact::Unknown, clock::now()));
        }
        let reported = self.reported_posture(tenant, &check.device).await?;
        let person = PrincipalId::from(check.device.person);
        let posture = self.held_to_records(tenant, person, reported).await?;
        Ok(check
            .rule
            .evaluate_for(device, posture.as_ref(), clock::now()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use ianua_domain::domains::authentication::device_status::DeviceStatus;
    use ianua_domain::domains::authentication::device_trust::TrustedDevice;
    use ianua_domain::domains::proxy::request::device::RequestDevice;
    use ianua_domain::domains::proxy::stages::posture::{
        DevicePostureParams, DeviceRequirement, OperatingSystem, OsFamily, OsVersion, OtherSystems,
        PostureGap, PostureRuleParams, Protection, ProtectionState,
    };
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::{CertificateFingerprint, Seconds, UserId};
    use time::Duration;

    use super::*;
    use crate::test_support::authentication::known_device;
    use crate::test_support::proxy::{FakeDeviceStandings, FakePostureProvider};
    use crate::test_support::{block_on, test_ctx};

    /// A rule asking for a trusted device on macOS 14 or later with disk
    /// encryption, reported at most an hour ago.
    fn rule() -> PostureRule {
        PostureRule::new(PostureRuleParams {
            device: DeviceRequirement::Trusted,
            minimum_versions: BTreeMap::from([(OsFamily::MacOs, OsVersion::new(14, 0, 0))]),
            other_systems: OtherSystems::Refused,
            required: BTreeSet::from([Protection::DiskEncryption]),
            max_report_age: Seconds::new(3_600),
        })
        .unwrap()
    }

    /// Ann's MacBook `laptop` on macOS 14.4 with an encrypted disk,
    /// reported `age` ago as the trusted device it is.
    fn report_on(laptop: TrustedDeviceId, age: Duration) -> DevicePosture {
        DevicePosture::new(DevicePostureParams {
            device: ReportedDevice::Trusted(laptop),
            system: Fact::Known(OperatingSystem::new(
                OsFamily::MacOs,
                OsVersion::new(14, 4, 0),
            )),
            protections: BTreeMap::from([(Protection::DiskEncryption, ProtectionState::On)]),
            reported_at: clock::now() - age,
        })
    }

    /// Ann, her laptop as her records keep it, and the checks run against
    /// them.
    struct Fixture {
        ann: UserId,
        laptop: TrustedDevice<ResolvedTenant>,
    }

    impl Fixture {
        /// Ann's laptop, standing in her records as `status` says.
        fn with_laptop(status: DeviceStatus) -> Self {
            let ann = UserId::new();
            Self {
                laptop: known_device(ann, status),
                ann,
            }
        }

        fn laptop_id(&self) -> TrustedDeviceId {
            *self.laptop.id()
        }

        /// The verdict on Ann's request naming `device`, the provider
        /// answering as `provider` says.
        fn check(
            self,
            device: RequestDevice,
            provider: FakePostureProvider,
        ) -> Result<PostureVerdict, AppError> {
            let use_case = CheckDevicePostureUseCase::new(CheckDevicePosturePorts {
                posture_provider: Arc::new(provider),
                device_standings: Arc::new(FakeDeviceStandings::of([&self.laptop])),
            });
            let request = PostureCheck {
                rule: rule(),
                device: DeviceInQuestion {
                    person: self.ann,
                    device,
                },
            };
            block_on(use_case.execute(&test_ctx().tenant(), request))
        }
    }

    /// Ann's session was signed in from her laptop, reported ten minutes
    /// ago. Her request meets the rule.
    #[test]
    fn a_session_device_meeting_the_rule_passes() {
        let f = Fixture::with_laptop(DeviceStatus::Trusted);
        let laptop = f.laptop_id();
        let provider = FakePostureProvider::reporting(report_on(laptop, Duration::minutes(10)));

        let verdict = f.check(RequestDevice::SessionTrusted(laptop), provider);

        assert_eq!(verdict.unwrap(), PostureVerdict::Meets);
    }

    /// Ann's laptop presents its device certificate, and the provider
    /// reports on the laptop it is enrolled as. Her request meets the rule.
    #[test]
    fn a_certified_device_meeting_the_rule_passes() {
        let f = Fixture::with_laptop(DeviceStatus::Trusted);
        let provider =
            FakePostureProvider::reporting(report_on(f.laptop_id(), Duration::minutes(10)));
        let certificate = CertificateFingerprint::from_digest([7; 32]);

        let verdict = f.check(RequestDevice::Certified(certificate), provider);

        assert_eq!(verdict.unwrap(), PostureVerdict::Meets);
    }

    /// A request naming no device fails as unknown even when the provider
    /// has a healthy report about the caller's laptop.
    #[test]
    fn a_request_naming_no_device_is_refused() {
        let f = Fixture::with_laptop(DeviceStatus::Trusted);
        let provider =
            FakePostureProvider::reporting(report_on(f.laptop_id(), Duration::minutes(10)));

        let verdict = f.check(RequestDevice::Unknown, provider);

        assert_eq!(
            verdict.unwrap(),
            PostureVerdict::Fails(PostureGap::DeviceUnknown)
        );
    }

    /// An unreachable posture provider returns an upstream error rather than
    /// a device verdict.
    #[test]
    fn an_unreachable_provider_is_an_error_not_a_verdict() {
        let f = Fixture::with_laptop(DeviceStatus::Trusted);
        let laptop = f.laptop_id();

        let verdict = f.check(
            RequestDevice::SessionTrusted(laptop),
            FakePostureProvider::unreachable(),
        );

        assert!(matches!(verdict, Err(AppError::Upstream(_))));
    }

    /// A remembered device fails for lack of a report when the provider
    /// knows nothing about it.
    #[test]
    fn an_unknown_device_is_refused() {
        let f = Fixture::with_laptop(DeviceStatus::Trusted);
        let laptop = f.laptop_id();

        let verdict = f.check(
            RequestDevice::SessionTrusted(laptop),
            FakePostureProvider::knowing_nothing(),
        );

        assert_eq!(
            verdict.unwrap(),
            PostureVerdict::Fails(PostureGap::NoReport)
        );
    }

    /// A healthy report from two hours ago fails the rule's one-hour freshness
    /// requirement.
    #[test]
    fn a_stale_report_is_refused() {
        let f = Fixture::with_laptop(DeviceStatus::Trusted);
        let laptop = f.laptop_id();
        let provider = FakePostureProvider::reporting(report_on(laptop, Duration::hours(2)));

        let verdict = f.check(RequestDevice::SessionTrusted(laptop), provider);

        assert_eq!(
            verdict.unwrap(),
            PostureVerdict::Fails(PostureGap::StaleReport)
        );
    }

    /// A revoked laptop fails the trusted-device requirement even when its
    /// certificate receives a healthy provider report.
    #[test]
    fn a_revoked_device_fails_a_trusted_device_rule() {
        let f = Fixture::with_laptop(DeviceStatus::Revoked);
        let provider =
            FakePostureProvider::reporting(report_on(f.laptop_id(), Duration::minutes(10)));
        let certificate = CertificateFingerprint::from_digest([7; 32]);

        let verdict = f.check(RequestDevice::Certified(certificate), provider);

        assert_eq!(
            verdict.unwrap(),
            PostureVerdict::Fails(PostureGap::DeviceNotTrusted)
        );
    }

    /// A provider report naming Ann's trusted laptop does not satisfy Bob's
    /// trusted-device requirement.
    #[test]
    fn someone_elses_device_fails_a_trusted_device_rule() {
        let f = Fixture::with_laptop(DeviceStatus::Trusted);
        let provider =
            FakePostureProvider::reporting(report_on(f.laptop_id(), Duration::minutes(10)));
        let bob = Fixture {
            ann: UserId::new(),
            ..f
        };
        let certificate = CertificateFingerprint::from_digest([7; 32]);

        let verdict = bob.check(RequestDevice::Certified(certificate), provider);

        assert_eq!(
            verdict.unwrap(),
            PostureVerdict::Fails(PostureGap::DeviceNotTrusted)
        );
    }
}
