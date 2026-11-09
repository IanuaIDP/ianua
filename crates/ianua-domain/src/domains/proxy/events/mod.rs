//! Proxy events: pipeline lifecycle, threat and canary detections, and WASM
//! modules.

mod access;
mod log_shipping;
mod pipeline;
mod threats;
mod wasm;

pub use access::*;
pub use log_shipping::*;
pub use pipeline::*;
pub use threats::*;
pub use wasm::*;

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use super::*;
    use crate::domains::proxy::stages::stage::ModuleRef;
    use crate::shared::events::event::{DomainEvent, DomainEventCore};
    use crate::types::{
        CorrelationId, IpAddress, Label, LogShippingTargetId, PipelineId, StageId, TenantId,
        UntrustedText,
    };

    fn now() -> OffsetDateTime {
        crate::shared::clock::now()
    }

    fn ip() -> IpAddress {
        IpAddress::new("10.0.0.1").unwrap()
    }

    /// The name of Ann's SIEM target.
    fn target_name() -> Label {
        Label::new("name", "siem").unwrap()
    }

    /// Every event this module defines.
    // The completeness check requires every event struct in this inventory's body.
    #[allow(clippy::too_many_lines)]
    fn every_event() -> Vec<Box<dyn DomainEventCore>> {
        let pipeline_id = PipelineId::new();
        let stage_id = StageId::new();
        let correlation_id = CorrelationId::new();
        let target_id = LogShippingTargetId::new();

        vec![
            Box::new(PipelineCreated {
                pipeline_id,
                occurred_at: now(),
            }),
            Box::new(PipelineDeleted {
                pipeline_id,
                occurred_at: now(),
            }),
            Box::new(PipelineRenamed {
                pipeline_id,
                previous_name: Label::new("name", "edge").unwrap(),
                current_name: Label::new("name", "edge-eu").unwrap(),
                occurred_at: now(),
            }),
            Box::new(PipelineActivated {
                pipeline_id,
                occurred_at: now(),
            }),
            Box::new(PipelineDisabled {
                pipeline_id,
                occurred_at: now(),
            }),
            Box::new(StageAdded {
                pipeline_id,
                stage_id,
                stage_kind: "waf",
                position: 2,
                occurred_at: now(),
            }),
            Box::new(StageRemoved {
                pipeline_id,
                stage_id,
                occurred_at: now(),
            }),
            Box::new(StageReconfigured {
                pipeline_id,
                stage_id,
                stage_kind: "rate_limit",
                occurred_at: now(),
            }),
            Box::new(StageEnabled {
                pipeline_id,
                stage_id,
                occurred_at: now(),
            }),
            Box::new(StageDisabled {
                pipeline_id,
                stage_id,
                occurred_at: now(),
            }),
            Box::new(PipelineReordered {
                pipeline_id,
                order: vec![stage_id, StageId::new()],
                occurred_at: now(),
            }),
            Box::new(HoneypotHit {
                ip_address: ip(),
                path: UntrustedText::record("/wp-admin"),
                correlation_id,
                occurred_at: now(),
            }),
            Box::new(PersonTurnedAway {
                user_id: crate::types::UserId::new(),
                route_id: crate::types::RouteId::new(),
                route_label: crate::types::EventLabel::of("payroll"),
                reason: "policy_denied",
                correlation_id,
                occurred_at: now(),
            }),
            Box::new(AutomatedThreatDetected {
                ip_address: ip(),
                signals: vec![ThreatSignal::Recon],
                action: ThreatResponse::Block,
                correlation_id,
                occurred_at: now(),
            }),
            Box::new(CanaryTokenTriggered {
                ip_address: ip(),
                correlation_id,
                occurred_at: now(),
            }),
            Box::new(CanaryTokenLeaked {
                correlation_id,
                occurred_at: now(),
            }),
            Box::new(CanaryTokenGenerated { occurred_at: now() }),
            Box::new(WasmModuleUploaded {
                module_ref: ModuleRef::new("sha256:abc").unwrap(),
                byte_len: 4096,
                occurred_at: now(),
            }),
            Box::new(LogTargetCreated {
                target_id,
                name: target_name(),
                destination: "bucket",
                occurred_at: now(),
            }),
            Box::new(LogTargetChanged {
                target_id,
                name: target_name(),
                destination: "datadog",
                records: "denied_only",
                occurred_at: now(),
            }),
            Box::new(LogTargetPaused {
                target_id,
                name: target_name(),
                occurred_at: now(),
            }),
            Box::new(LogTargetResumed {
                target_id,
                name: target_name(),
                occurred_at: now(),
            }),
            Box::new(LogTargetDeleted {
                target_id,
                name: target_name(),
                occurred_at: now(),
            }),
        ]
    }

    /// Events whose payload is empty by design.
    ///
    /// Generating a canary token says everything in the event type, the
    /// tenant and the time. Both are on the envelope. The events for a
    /// canary being triggered or leaked do carry a payload, naming the
    /// request involved.
    const WITHOUT_PAYLOAD: [&str; 1] = ["proxy.canary_token_generated"];

    /// Every proxy event puts its details in the payload. Only the events in
    /// `WITHOUT_PAYLOAD` are empty, and they must stay empty.
    #[test]
    fn every_event_carries_a_payload_unless_it_has_nothing_to_say() {
        for event in every_event() {
            let name = event.event_type().as_str().to_owned();
            let payload = event.payload();

            if WITHOUT_PAYLOAD.contains(&name.as_str()) {
                assert!(payload.is_empty(), "{name} grew a payload");
                continue;
            }

            assert!(!payload.is_empty(), "{name} has an empty payload");
        }
    }

    /// No two proxy events share an event type. Otherwise a subscriber to
    /// one would also get the other.
    #[test]
    fn every_event_names_itself_exactly_once() {
        let mut seen = std::collections::HashSet::new();

        for event in every_event() {
            let name = event.event_type().as_str().to_owned();
            assert!(seen.insert(name.clone()), "{name} listed twice");
        }
    }

    /// Honeypot, automated-threat and canary observations each retain Acme's
    /// supplied tenant ID in their event envelope.
    #[test]
    fn every_observed_threat_names_the_tenant_it_was_seen_for() {
        let acme = TenantId::new();
        let correlation_id = CorrelationId::new();

        let observed = [
            HoneypotHit::observed(
                acme,
                ip(),
                UntrustedText::record("/wp-admin"),
                correlation_id,
            ),
            AutomatedThreatDetected::observed(
                acme,
                ip(),
                vec![ThreatSignal::Recon],
                ThreatResponse::Tarpit,
                correlation_id,
            ),
            CanaryTokenTriggered::observed(acme, ip(), correlation_id),
            CanaryTokenLeaked::observed(acme, correlation_id),
        ];

        for event in &observed {
            assert_eq!(event.tenant_id(), Some(&acme), "{}", event.event_type());
        }
    }

    /// The recon stage tarpits a scanner. The record says what tripped and
    /// what was done, for the threat dashboard.
    #[test]
    fn an_observed_threat_records_what_tripped_and_what_was_done() {
        let event: DomainEvent = AutomatedThreatDetected::observed(
            TenantId::new(),
            ip(),
            vec![ThreatSignal::Recon],
            ThreatResponse::Tarpit,
            CorrelationId::new(),
        );

        let payload = event.payload();
        assert_eq!(payload.get("signals"), Some("recon"));
        assert_eq!(payload.get("action"), Some("tarpit"));
        assert_eq!(payload.get("ip_address"), Some("10.0.0.1"));
    }

    /// A tenant generates a canary token. The token belongs to no pipeline
    /// until the tenant places it in a stage. So the event carries no
    /// payload; the tenant is on the envelope.
    #[test]
    fn generating_a_canary_token_records_no_payload() {
        let event = CanaryTokenGenerated { occurred_at: now() };

        assert!(event.payload().is_empty());
    }
}
