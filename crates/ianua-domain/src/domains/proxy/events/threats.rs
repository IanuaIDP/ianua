//! Events about threats the proxy saw: decoys hit, automation, canary tokens.

use time::OffsetDateTime;

use crate::shared::events::data::EventData;
use crate::shared::events::event::{DomainEvent, tenant_event};
use crate::shared::events::raised::scoped;
use crate::types::{CorrelationId, IpAddress, TenantId, UntrustedText};

/// A client requested one of a tenant's decoy paths.
///
/// Almost certainly malicious automation, since no real client requests a
/// decoy path. It carries enough for a tenant's threat dashboard to show
/// what was hit and by whom, without touching the forwarded body.
#[derive(Debug)]
pub struct HoneypotHit {
    /// The address the request came from.
    pub(crate) ip_address: IpAddress,
    /// The decoy path that was requested.
    pub(crate) path: UntrustedText,
    /// The proxied request that hit the decoy.
    pub(crate) correlation_id: CorrelationId,
    /// When the decoy was hit.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    HoneypotHit => crate::types::event_type::ProxyEvent::HoneypotHit,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("ip_address", self.ip_address.as_str())
            .field("path", self.path.as_str())
            .field("correlation_id", self.correlation_id.to_string())
    }
}

impl HoneypotHit {
    /// The record that a client at `ip_address` asked `tenant_id` for the
    /// decoy `path` on the request `correlation_id`.
    ///
    /// The proxy sees this in traffic: no aggregate changes, so nothing
    /// raises it, and the proxy names the tenant whose route was hit.
    #[must_use]
    pub fn observed(
        tenant_id: TenantId,
        ip_address: IpAddress,
        path: UntrustedText,
        correlation_id: CorrelationId,
    ) -> DomainEvent {
        scoped(
            tenant_id,
            Self {
                ip_address,
                path,
                correlation_id,
                occurred_at: crate::shared::clock::now(),
            },
        )
    }
}

/// What the proxy did about an automated threat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatResponse {
    /// The requests were slowed down.
    Tarpit,
    /// The requests were refused.
    Block,
}

impl ThreatResponse {
    /// The name recorded in the audit payload.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tarpit => "tarpit",
            Self::Block => "block",
        }
    }
}

/// What tripped an automated-threat detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatSignal {
    /// Reconnaissance: probing for paths, errors and failed sign-ins.
    Recon,
}

impl ThreatSignal {
    /// The name recorded in the audit payload.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Recon => "recon",
        }
    }
}

/// A stage detected and acted on suspected automated attack behavior.
///
/// Raised by the recon-detection stage. A tenant's threat dashboard uses it
/// to show what was caught and what was done about it, apart from the
/// per-request audit stream.
#[derive(Debug)]
pub struct AutomatedThreatDetected {
    /// The address the suspected automation came from.
    pub(crate) ip_address: IpAddress,
    /// Which detections tripped, such as [`ThreatSignal::Recon`].
    pub(crate) signals: Vec<ThreatSignal>,
    /// What the stage did about it.
    pub(crate) action: ThreatResponse,
    /// The proxied request that tripped the detection.
    pub(crate) correlation_id: CorrelationId,
    /// When the threat was detected.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AutomatedThreatDetected => crate::types::event_type::ProxyEvent::AutomatedThreatDetected,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("ip_address", self.ip_address.as_str())
            .field(
                "signals",
                self.signals
                    .iter()
                    .map(|signal| signal.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            )
            .field("action", self.action.as_str())
            .field("correlation_id", self.correlation_id.to_string())
    }
}

impl AutomatedThreatDetected {
    /// The record that traffic from `ip_address` to `tenant_id` tripped
    /// `signals` on the request `correlation_id`, and the stage answered
    /// with `action`.
    ///
    /// The proxy sees this in traffic: no aggregate changes, so nothing
    /// raises it, and the proxy names the tenant whose route was hit.
    #[must_use]
    pub fn observed(
        tenant_id: TenantId,
        ip_address: IpAddress,
        signals: Vec<ThreatSignal>,
        action: ThreatResponse,
        correlation_id: CorrelationId,
    ) -> DomainEvent {
        scoped(
            tenant_id,
            Self {
                ip_address,
                signals,
                action,
                correlation_id,
                occurred_at: crate::shared::clock::now(),
            },
        )
    }
}

/// A client presented a planted canary credential as a request credential.
///
/// Clear proof of credential theft. The token was never issued to anyone,
/// so whoever presents it found a leaked copy and is replaying it.
#[derive(Debug)]
pub struct CanaryTokenTriggered {
    /// The address that presented the canary.
    pub(crate) ip_address: IpAddress,
    /// The proxied request that carried the canary.
    pub(crate) correlation_id: CorrelationId,
    /// When the canary was presented.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    CanaryTokenTriggered => crate::types::event_type::ProxyEvent::CanaryTokenTriggered,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("ip_address", self.ip_address.as_str())
            .field("correlation_id", self.correlation_id.to_string())
    }
}

impl CanaryTokenTriggered {
    /// The record that a client at `ip_address` presented one of
    /// `tenant_id`'s canary tokens on the request `correlation_id`.
    ///
    /// The proxy sees this in traffic: no aggregate changes, so nothing
    /// raises it, and the proxy names the tenant whose route was hit.
    #[must_use]
    pub fn observed(
        tenant_id: TenantId,
        ip_address: IpAddress,
        correlation_id: CorrelationId,
    ) -> DomainEvent {
        scoped(
            tenant_id,
            Self {
                ip_address,
                correlation_id,
                occurred_at: crate::shared::clock::now(),
            },
        )
    }
}

/// A planted canary credential was found leaking in an upstream response
/// body, and the response was withheld.
///
/// Unlike [`CanaryTokenTriggered`], this is no evidence the *caller* is
/// malicious. It means the tenant's own upstream exposes a secret it should
/// never render, such as in a debug dump, a too-detailed error page or a
/// misconfigured echo endpoint.
#[derive(Debug)]
pub struct CanaryTokenLeaked {
    /// The proxied request whose response was withheld.
    pub(crate) correlation_id: CorrelationId,
    /// When the leak was caught.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    CanaryTokenLeaked => crate::types::event_type::ProxyEvent::CanaryTokenLeaked,
    fn payload(&self) -> EventData {
        EventData::new().field("correlation_id", self.correlation_id.to_string())
    }
}

impl CanaryTokenLeaked {
    /// The record that an upstream of `tenant_id` rendered one of its
    /// canary tokens in the response to `correlation_id`, which was
    /// withheld.
    ///
    /// The proxy sees this in traffic: no aggregate changes, so nothing
    /// raises it, and the proxy names the tenant whose upstream leaked.
    #[must_use]
    pub fn observed(tenant_id: TenantId, correlation_id: CorrelationId) -> DomainEvent {
        scoped(
            tenant_id,
            Self {
                correlation_id,
                occurred_at: crate::shared::clock::now(),
            },
        )
    }
}

/// A tenant generated a new canary decoy token through the generator
/// endpoint.
///
/// It is tied to no stage or pipeline. The token is stored nowhere until
/// the caller adds it to a `CanaryToken` stage's config themselves.
#[derive(Debug)]
pub struct CanaryTokenGenerated {
    /// When the token was generated.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    CanaryTokenGenerated => crate::types::event_type::ProxyEvent::CanaryTokenGenerated,
    fn payload(&self) -> EventData {
        EventData::new()
    }
}
