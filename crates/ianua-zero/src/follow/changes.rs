//! What each event changes in the gateway's tables.
//!
//! An event is a notice, never the data: it says which tenant to read
//! again, and the stores say what that tenant is now. A type of event
//! this gateway does not know, as a newer node may raise, is taken to
//! revoke something: its tenant is withdrawn and read again, an
//! organization's reads its tenants again, and the platform's reads
//! everything again.

use ianua_domain::types::event_type::{OrganizationEvent, ProxyEvent, RoutingEvent, TenantEvent};
use ianua_domain::types::{EventType, OrganizationId, TenantId};
use ianua_infra::bus::{EventEnvelope, EventScope};

/// What one heard event asks of the follower.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Effect {
    /// Nothing the gateway holds changed.
    Nothing,
    /// The tenant is read again.
    Tenant(TenantId),
    /// The tenant and every served certificate are read again.
    TenantAndCertificates(TenantId),
    /// The tenant stops being served now, then it and every served
    /// certificate are read again.
    AtOnce(TenantId),
    /// The tenant is read again, and everything with it, since the change
    /// reaches a tenant the event does not name.
    TenantAndEverything(TenantId),
    /// Every tenant of the organization this gateway holds is read again,
    /// and everything with it, for the ones it does not hold yet.
    Organization(OrganizationId),
    /// Anything may have changed: everything is read again.
    Everything,
}

/// How a type of event bears on the tables, whoever it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bearing {
    None,
    Tenant,
    TenantAndCertificates,
    AtOnce,
    Everything,
}

/// What `envelope` asks of the follower.
pub(super) fn effect_of(envelope: &EventEnvelope) -> Effect {
    let bearing = EventType::parse(&envelope.event_type).map_or(Bearing::AtOnce, bearing_of);
    match envelope.scope {
        EventScope::Tenant(tenant) => tenant_effect(TenantId::from_uuid(tenant), bearing),
        EventScope::Organization(organization) => {
            organization_effect(OrganizationId::from_uuid(organization), bearing)
        }
        EventScope::Platform => platform_effect(bearing),
    }
}

fn tenant_effect(tenant: TenantId, bearing: Bearing) -> Effect {
    match bearing {
        Bearing::None => Effect::Nothing,
        Bearing::Tenant => Effect::Tenant(tenant),
        Bearing::TenantAndCertificates => Effect::TenantAndCertificates(tenant),
        Bearing::AtOnce => Effect::AtOnce(tenant),
        Bearing::Everything => Effect::TenantAndEverything(tenant),
    }
}

fn organization_effect(organization: OrganizationId, bearing: Bearing) -> Effect {
    match bearing {
        Bearing::None => Effect::Nothing,
        Bearing::Tenant
        | Bearing::TenantAndCertificates
        | Bearing::AtOnce
        | Bearing::Everything => Effect::Organization(organization),
    }
}

fn platform_effect(bearing: Bearing) -> Effect {
    match bearing {
        Bearing::None => Effect::Nothing,
        Bearing::Tenant
        | Bearing::TenantAndCertificates
        | Bearing::AtOnce
        | Bearing::Everything => Effect::Everything,
    }
}

fn bearing_of(event_type: EventType) -> Bearing {
    match event_type {
        EventType::Tenant(event) => tenant_bearing(event),
        EventType::Routing(event) => routing_bearing(event),
        EventType::Proxy(event) => proxy_bearing(event),
        EventType::Organization(event) => organization_bearing(event),
        EventType::Agents(_)
        | EventType::Authentication(_)
        | EventType::Authorization(_)
        | EventType::Branding(_)
        | EventType::Crypto(_)
        | EventType::Federation(_)
        | EventType::Identity(_)
        | EventType::OAuth(_)
        | EventType::Operator(_)
        | EventType::Signals(_)
        | EventType::Notifications(_)
        | EventType::Messaging(_)
        | EventType::Consumers(_)
        | EventType::Webhooks(_)
        | EventType::Workflows(_) => Bearing::None,
    }
}

/// Maps every tenant event to its table effect; new variants require an explicit decision.
#[allow(clippy::too_many_lines)]
fn tenant_bearing(event: TenantEvent) -> Bearing {
    match event {
        TenantEvent::StatusChanged
        | TenantEvent::ReadableAddressChanged
        | TenantEvent::MtlsConfigUpdated
        | TenantEvent::DomainRemoved
        | TenantEvent::DomainVerificationLost
        | TenantEvent::DomainCertificateRemoved
        | TenantEvent::Deleted
        | TenantEvent::DeletedEarly
        | TenantEvent::TornDown => Bearing::AtOnce,
        TenantEvent::DomainVerified
        | TenantEvent::DomainTlsProvisioned
        | TenantEvent::DomainCertificateUploaded
        | TenantEvent::DomainCertificateReplaced => Bearing::TenantAndCertificates,
        TenantEvent::DomainTransferred => Bearing::Everything,
        TenantEvent::Provisioned
        | TenantEvent::Renamed
        | TenantEvent::DomainRegistered
        | TenantEvent::PrimaryDomainChanged
        | TenantEvent::AuthConfigUpdated
        | TenantEvent::ComplianceChanged
        | TenantEvent::EnvironmentChanged
        | TenantEvent::CloneCompleted => Bearing::Tenant,
        TenantEvent::ContactEmailChanged
        | TenantEvent::TimezoneChanged
        | TenantEvent::LocaleChanged
        | TenantEvent::InfraFailed
        | TenantEvent::DomainHandoverOffered
        | TenantEvent::DnsRecordSetChanged
        | TenantEvent::DnsRecordSetRemoved
        | TenantEvent::TeardownFailed
        | TenantEvent::AuditChainBroken
        | TenantEvent::DomainTlsRequested
        | TenantEvent::DomainCertificateExpiring
        | TenantEvent::CloneStarted
        | TenantEvent::CloneFailed
        | TenantEvent::AuditStreamCreated
        | TenantEvent::AuditStreamChanged
        | TenantEvent::AuditStreamPaused
        | TenantEvent::AuditStreamResumed
        | TenantEvent::AuditStreamRemoved
        | TenantEvent::AuditRecordsPurged
        | TenantEvent::AuditLogExportRequested
        | TenantEvent::AuditLogExportDownloaded => Bearing::None,
    }
}

/// Maps every routing event explicitly so new variants cannot silently skip a reload.
#[allow(clippy::too_many_lines)]
fn routing_bearing(event: RoutingEvent) -> Bearing {
    match event {
        RoutingEvent::RouteCreated
        | RoutingEvent::RouteUpdated
        | RoutingEvent::RouteDeleted
        | RoutingEvent::RouteActivated
        | RoutingEvent::RouteDisabled
        | RoutingEvent::RouteOpenedToWorkflows
        | RoutingEvent::RouteClosedToWorkflows
        | RoutingEvent::RouteAttackModeStarted
        | RoutingEvent::RouteAttackModeEnded
        | RoutingEvent::ServiceCreated
        | RoutingEvent::ServiceUpdated
        | RoutingEvent::ServiceDeleted
        | RoutingEvent::AppSignInChanged
        | RoutingEvent::StreamRouteCreated
        | RoutingEvent::StreamRouteUpdated
        | RoutingEvent::StreamRouteDeleted
        | RoutingEvent::StreamRouteActivated
        | RoutingEvent::StreamRouteDisabled
        | RoutingEvent::GatewayConfigImported
        | RoutingEvent::ConnectorCreated
        | RoutingEvent::ConnectorEnrolled
        | RoutingEvent::ConnectorUpdated
        | RoutingEvent::ConnectorRevoked
        | RoutingEvent::ConnectorDeleted => Bearing::Tenant,
        RoutingEvent::EgressPolicyCreated
        | RoutingEvent::EgressPolicyUpdated
        | RoutingEvent::EgressPolicyDeleted
        | RoutingEvent::StreamRouteOpenedToWorkflows
        | RoutingEvent::StreamRouteClosedToWorkflows
        | RoutingEvent::ConnectorRenewed => Bearing::None,
    }
}

fn proxy_bearing(event: ProxyEvent) -> Bearing {
    match event {
        ProxyEvent::PipelineCreated
        | ProxyEvent::PipelineDeleted
        | ProxyEvent::PipelineRenamed
        | ProxyEvent::PipelineActivated
        | ProxyEvent::PipelineDisabled
        | ProxyEvent::StageAdded
        | ProxyEvent::StageRemoved
        | ProxyEvent::StageEnabled
        | ProxyEvent::StageDisabled
        | ProxyEvent::StageReconfigured
        | ProxyEvent::PipelineReordered => Bearing::Tenant,
        ProxyEvent::HoneypotHit
        | ProxyEvent::PersonTurnedAway
        | ProxyEvent::AutomatedThreatDetected
        | ProxyEvent::CanaryTokenTriggered
        | ProxyEvent::CanaryTokenLeaked
        | ProxyEvent::CanaryTokenGenerated
        | ProxyEvent::WasmModuleUploaded
        | ProxyEvent::ClassificationRuleAdded
        | ProxyEvent::ClassificationRuleRemoved
        | ProxyEvent::ClassificationRuleChanged
        | ProxyEvent::LogTargetCreated
        | ProxyEvent::LogTargetChanged
        | ProxyEvent::LogTargetPaused
        | ProxyEvent::LogTargetResumed
        | ProxyEvent::LogTargetDeleted => Bearing::None,
    }
}

/// An organization's status or name reaches every tenant it owns, and
/// the event names none of them.
fn organization_bearing(event: OrganizationEvent) -> Bearing {
    match event {
        OrganizationEvent::StatusChanged | OrganizationEvent::Renamed => Bearing::Everything,
        _ => Bearing::None,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::*;

    fn envelope(scope: EventScope, event_type: &str) -> EventEnvelope {
        EventEnvelope {
            id: Uuid::now_v7(),
            scope,
            organization_id: None,
            event_type: event_type.to_owned(),
            actor: "system".to_owned(),
            payload: Value::Null,
            occurred_at: OffsetDateTime::UNIX_EPOCH,
            chain_depth: 0,
        }
    }

    fn of_tenant(tenant: Uuid, event_type: &str) -> Effect {
        effect_of(&envelope(EventScope::Tenant(tenant), event_type))
    }

    /// A suspended tenant stops being served before its reload starts.
    #[test]
    fn a_status_change_withdraws_the_tenant_at_once() {
        let acme = Uuid::now_v7();

        let effect = of_tenant(acme, "tenant.status_changed");

        assert_eq!(effect, Effect::AtOnce(TenantId::from_uuid(acme)));
    }

    /// A removed client certificate authority stops being trusted before
    /// the tenant is read again.
    #[test]
    fn an_mtls_change_withdraws_the_tenant_at_once() {
        let acme = Uuid::now_v7();

        let effect = of_tenant(acme, "tenant.mtls_config_updated");

        assert_eq!(effect, Effect::AtOnce(TenantId::from_uuid(acme)));
    }

    #[test]
    fn a_route_change_reloads_its_tenant() {
        let acme = Uuid::now_v7();

        let effect = of_tenant(acme, "routing.route_disabled");

        assert_eq!(effect, Effect::Tenant(TenantId::from_uuid(acme)));
    }

    /// Ann revokes Acme's wiki connector. Acme is read again, and the
    /// connector's live link is closed when its connectors are handed over.
    #[test]
    fn a_connector_revocation_reloads_its_tenant() {
        let acme = Uuid::now_v7();

        let effect = of_tenant(acme, "routing.connector_revoked");

        assert_eq!(effect, Effect::Tenant(TenantId::from_uuid(acme)));
    }

    /// A renewal keeps the connector's key, so nothing the gateway holds
    /// changes.
    #[test]
    fn a_connector_renewal_changes_nothing_held() {
        assert_eq!(
            of_tenant(Uuid::now_v7(), "routing.connector_renewed"),
            Effect::Nothing
        );
    }

    #[test]
    fn a_new_certificate_reloads_the_tenant_and_the_certificates() {
        let acme = Uuid::now_v7();

        let effect = of_tenant(acme, "tenant.domain_tls_provisioned");

        assert_eq!(
            effect,
            Effect::TenantAndCertificates(TenantId::from_uuid(acme))
        );
    }

    /// A transferred domain changes two tenants, and the event names one.
    #[test]
    fn a_transferred_domain_reloads_the_tenant_and_everything() {
        let acme = Uuid::now_v7();

        let effect = of_tenant(acme, "tenant.domain_transferred");

        assert_eq!(
            effect,
            Effect::TenantAndEverything(TenantId::from_uuid(acme))
        );
    }

    /// A suspended organization closes every tenant it owns.
    #[test]
    fn an_organization_status_change_reloads_its_tenants() {
        let acme = Uuid::now_v7();

        let effect = effect_of(&envelope(
            EventScope::Organization(acme),
            "organization.status_changed",
        ));

        assert_eq!(
            effect,
            Effect::Organization(OrganizationId::from_uuid(acme))
        );
    }

    #[test]
    fn a_change_the_gateway_does_not_hold_is_ignored() {
        assert_eq!(
            of_tenant(Uuid::now_v7(), "tenant.contact_email_changed"),
            Effect::Nothing
        );
        assert_eq!(
            of_tenant(Uuid::now_v7(), "identity.user_registered"),
            Effect::Nothing
        );
    }

    /// A newer node's event may revoke something this gateway cannot name,
    /// so its tenant is withdrawn and read again.
    #[test]
    fn an_unknown_tenant_event_withdraws_the_tenant() {
        let acme = Uuid::now_v7();

        let effect = of_tenant(acme, "routing.something_new");

        assert_eq!(effect, Effect::AtOnce(TenantId::from_uuid(acme)));
    }

    #[test]
    fn an_unknown_platform_event_reloads_everything() {
        let effect = effect_of(&envelope(EventScope::Platform, "platform.something_new"));

        assert_eq!(effect, Effect::Everything);
    }
}
