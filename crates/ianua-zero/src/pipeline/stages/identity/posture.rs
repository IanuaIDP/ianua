//! The `DevicePosture` stage: the device a person's request came from held
//! to the route's posture rule by `CheckDevicePostureUseCase`.
//!
//! The rule is the domain's and the report the posture provider's; the
//! stage only asks and enforces. A device is a person's: a request no
//! person was proven for has no device to ask about and is refused. The
//! device is the one the Identity stage named on the context: a verified
//! device certificate, or the trusted device the session was signed in
//! from. A device that fails the rule is a 403 naming the gap; a check
//! that cannot be made is a 503, never a pass.

use ianua_app::ports::proxy::DeviceInQuestion;
use ianua_app::tenancy::ScopedTenant;
use ianua_app::use_case::Query as _;
use ianua_app::use_cases::proxy::PostureCheck;
use ianua_domain::domains::proxy::access::question::PostureFinding;
use ianua_domain::domains::proxy::request::context::{Caller, PipelineContext};
use ianua_domain::domains::proxy::stages::decision::StageDecision;
use ianua_domain::domains::proxy::stages::posture::{PostureGap, PostureRule, PostureVerdict};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DenialStatus, UserId};

use super::{IdentityStages, deny, pass};

/// What the `DevicePosture` stage decided, and what it found for the
/// Policy stage.
#[derive(Debug)]
pub(crate) struct PostureOutcome {
    /// The decision the pipeline enforces.
    pub decision: StageDecision,
    /// What the check found, for a tenant policy that reads it. Not asked
    /// when no person was proven, so there was no device to ask about.
    pub finding: PostureFinding,
}

impl IdentityStages {
    /// The `DevicePosture` stage: a pass when the device the proven person
    /// sent the request from meets `rule`, a 403 otherwise.
    ///
    /// # Errors
    ///
    /// None today; the signature is the group's, so the dispatcher treats
    /// every stage alike. A failed check is a deny, never an error that
    /// could be mistaken for a pass.
    pub(crate) async fn device_posture(
        &self,
        tenant: &ScopedTenant,
        rule: &PostureRule,
        ctx: &PipelineContext,
    ) -> Result<PostureOutcome, DomainError> {
        let Some(person) = person_of(ctx) else {
            return Ok(PostureOutcome {
                decision: deny(DenialStatus::FORBIDDEN, "device_posture_no_person"),
                finding: PostureFinding::NotAsked,
            });
        };
        let check = PostureCheck {
            rule: rule.clone(),
            device: DeviceInQuestion {
                person,
                device: ctx.device,
            },
        };
        let Ok(verdict) = self.posture.execute(tenant, check).await else {
            return Ok(PostureOutcome {
                decision: deny(
                    DenialStatus::SERVICE_UNAVAILABLE,
                    "device_posture_unavailable",
                ),
                finding: PostureFinding::NotAsked,
            });
        };
        Ok(PostureOutcome {
            finding: PostureFinding::Checked(verdict),
            decision: posture_decision(verdict),
        })
    }
}

/// The person the Identity stage proved, when it proved one.
fn person_of(ctx: &PipelineContext) -> Option<UserId> {
    match ctx.authentication().caller()? {
        Caller::User { user_id, .. } => Some(*user_id),
        Caller::Agent { .. } | Caller::Consumer { .. } => None,
    }
}

/// The decision a verdict comes to: a pass when the device meets the rule,
/// a 403 naming the gap when it does not.
fn posture_decision(verdict: PostureVerdict) -> StageDecision {
    let PostureVerdict::Fails(gap) = verdict else {
        return pass("device_posture_met");
    };
    deny(DenialStatus::FORBIDDEN, gap_code(gap))
}

/// The reason code a gap is recorded as.
fn gap_code(gap: PostureGap) -> &'static str {
    match gap {
        PostureGap::DeviceUnknown => "device_unknown",
        PostureGap::NoReport => "device_unreported",
        PostureGap::StaleReport => "device_report_stale",
        PostureGap::ReportFromTheFuture => "device_report_from_the_future",
        PostureGap::DeviceNotTrusted => "device_not_trusted",
        PostureGap::SystemUnknown => "device_system_unknown",
        PostureGap::SystemNotAllowed(_) => "device_system_not_allowed",
        PostureGap::SystemTooOld(_) => "device_system_too_old",
        PostureGap::ProtectionUnknown(_) => "device_protection_unknown",
        PostureGap::ProtectionOff(_) => "device_protection_off",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    use ianua_app::test_support::proxy::FakePostureProvider;
    use ianua_app::test_support::test_ctx;
    use ianua_app::use_cases::proxy::{CheckDevicePosturePorts, CheckDevicePostureUseCase};
    use ianua_domain::domains::proxy::request::context::{
        ConsumerCredential, UserSignIn, Verified,
    };
    use ianua_domain::domains::proxy::request::device::RequestDevice;
    use ianua_domain::domains::proxy::stages::posture::{
        DevicePosture, DevicePostureParams, DeviceRequirement, OperatingSystem, OsFamily,
        OsVersion, OtherSystems, PostureRuleParams, Protection, ProtectionState, ReportedDevice,
    };
    use ianua_domain::shared::clock;
    use ianua_domain::types::{
        CertificateFingerprint, ConsumerId, CorrelationId, Expiry, Fact, PipelineId, Seconds,
    };
    use time::Duration;

    use super::*;
    use crate::pipeline::stages::identity::{IdentityStagesParts, fixtures};

    /// A rule asking for any device with an encrypted disk, reported at
    /// most an hour ago.
    fn rule() -> PostureRule {
        PostureRule::new(PostureRuleParams {
            device: DeviceRequirement::AnyDevice,
            minimum_versions: BTreeMap::new(),
            other_systems: OtherSystems::Allowed,
            required: BTreeSet::from([Protection::DiskEncryption]),
            max_report_age: Seconds::new(3_600),
        })
        .unwrap()
    }

    /// Ann's laptop, its disk encryption `state`, reported ten minutes
    /// ago.
    fn anns_laptop(state: ProtectionState) -> DevicePosture {
        DevicePosture::new(DevicePostureParams {
            device: ReportedDevice::Unenrolled,
            system: Fact::Known(OperatingSystem::new(
                OsFamily::MacOs,
                OsVersion::new(14, 4, 0),
            )),
            protections: BTreeMap::from([(Protection::DiskEncryption, state)]),
            reported_at: clock::now() - Duration::minutes(10),
        })
    }

    fn stages(provider: FakePostureProvider) -> IdentityStages {
        IdentityStages::new(IdentityStagesParts {
            posture: Arc::new(CheckDevicePostureUseCase::new(CheckDevicePosturePorts {
                posture_provider: Arc::new(provider),
                ..CheckDevicePosturePorts::fakes()
            })),
            ..fixtures::parts()
        })
    }

    /// A request proven for `caller`.
    fn proven(caller: Caller) -> PipelineContext {
        let mut ctx = PipelineContext::new(
            test_ctx().tenant_id(),
            PipelineId::new(),
            CorrelationId::new(),
        );
        ctx.authenticate(Verified {
            caller,
            expiry: Expiry::Never,
        })
        .unwrap();
        ctx.device = RequestDevice::Certified(CertificateFingerprint::from_digest([7; 32]));
        ctx
    }

    fn ann() -> Caller {
        Caller::User {
            user_id: UserId::new(),
            sign_in: UserSignIn::Token,
        }
    }

    async fn checked(provider: FakePostureProvider, ctx: &PipelineContext) -> PostureOutcome {
        stages(provider)
            .device_posture(&test_ctx().tenant(), &rule(), ctx)
            .await
            .unwrap()
    }

    async fn check(provider: FakePostureProvider, ctx: &PipelineContext) -> StageDecision {
        checked(provider, ctx).await.decision
    }

    fn assert_refused(decision: &StageDecision, code: &str) {
        let StageDecision::Deny { status, reason } = decision else {
            panic!("expected a deny, got {decision:?}");
        };
        assert_eq!(*status, DenialStatus::FORBIDDEN);
        assert_eq!(reason, code);
    }

    /// Ann's laptop reports an encrypted disk. Her request passes.
    #[tokio::test]
    async fn a_device_meeting_the_rule_passes() {
        let provider = FakePostureProvider::reporting(anns_laptop(ProtectionState::On));

        let decision = check(provider, &proven(ann())).await;

        assert!(matches!(decision, StageDecision::Pass { .. }));
    }

    /// Ann's laptop passes, and what the check found goes on for a tenant
    /// policy that reads it.
    #[tokio::test]
    async fn the_verdict_is_kept_for_the_policy_stage() {
        let provider = FakePostureProvider::reporting(anns_laptop(ProtectionState::On));

        let outcome = checked(provider, &proven(ann())).await;

        assert_eq!(
            outcome.finding,
            PostureFinding::Checked(PostureVerdict::Meets)
        );
    }

    /// An anonymous request records posture as not asked despite a provider
    /// configured to report an encrypted device.
    #[tokio::test]
    async fn no_person_means_no_check_was_made() {
        let ctx = PipelineContext::new(
            test_ctx().tenant_id(),
            PipelineId::new(),
            CorrelationId::new(),
        );
        let provider = FakePostureProvider::reporting(anns_laptop(ProtectionState::On));

        let outcome = checked(provider, &ctx).await;

        assert_eq!(outcome.finding, PostureFinding::NotAsked);
    }

    /// Ann's unencrypted laptop receives 403 with the protection-off reason.
    #[tokio::test]
    async fn a_device_failing_the_rule_is_refused() {
        let provider = FakePostureProvider::reporting(anns_laptop(ProtectionState::Off));

        let decision = check(provider, &proven(ann())).await;

        assert_refused(&decision, "device_protection_off");
    }

    /// An unreachable posture provider yields 503 with the unavailable reason
    /// and leaves the posture finding as not asked.
    #[tokio::test]
    async fn an_unreachable_provider_refuses_the_device() {
        let outcome = checked(FakePostureProvider::unreachable(), &proven(ann())).await;

        let StageDecision::Deny { status, reason } = &outcome.decision else {
            panic!("expected a deny, got {:?}", outcome.decision);
        };
        assert_eq!(*status, DenialStatus::SERVICE_UNAVAILABLE);
        assert_eq!(reason, "device_posture_unavailable");
        assert_eq!(outcome.finding, PostureFinding::NotAsked);
    }

    /// Ann's request without a device receives 403 with the unknown-device reason.
    #[tokio::test]
    async fn a_request_naming_no_device_is_refused() {
        let mut ctx = proven(ann());
        ctx.device = RequestDevice::Unknown;
        let provider = FakePostureProvider::reporting(anns_laptop(ProtectionState::On));

        let decision = check(provider, &ctx).await;

        assert_refused(&decision, "device_unknown");
    }

    /// A provider with no device report yields 403 with the unreported-device reason.
    #[tokio::test]
    async fn an_unknown_device_is_refused() {
        let decision = check(FakePostureProvider::knowing_nothing(), &proven(ann())).await;

        assert_refused(&decision, "device_unreported");
    }

    /// A consumer API key receives 403 for having no person, even when the
    /// provider is configured to report an encrypted device.
    #[tokio::test]
    async fn a_request_without_a_person_is_refused() {
        let consumer = Caller::Consumer {
            consumer_id: ConsumerId::new(),
            credential: ConsumerCredential::ApiKey,
        };
        let provider = FakePostureProvider::reporting(anns_laptop(ProtectionState::On));

        let decision = check(provider, &proven(consumer)).await;

        assert_refused(&decision, "device_posture_no_person");
    }

    /// An anonymous posture check receives 403 with the no-person reason.
    #[tokio::test]
    async fn an_anonymous_request_is_refused() {
        let ctx = PipelineContext::new(
            test_ctx().tenant_id(),
            PipelineId::new(),
            CorrelationId::new(),
        );
        let provider = FakePostureProvider::reporting(anns_laptop(ProtectionState::On));

        let decision = check(provider, &ctx).await;

        assert_refused(&decision, "device_posture_no_person");
    }
}
