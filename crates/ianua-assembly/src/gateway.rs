//! The gateway use cases the API serves: a tenant's whole gateway
//! configuration, exported as one document and applied back from one.

use std::sync::Arc;

use ianua_app::services::hosts::{PlatformAddressSettings, PlatformAddresses};
use ianua_app::services::issuers::TenantIssuers;
use ianua_app::use_cases::gateway::{
    ExportConfigPorts, ExportConfigUseCase, ImportCheckPorts, ImportConfigPorts,
    ImportConfigUseCase, RecordPorts,
};

use crate::deps::{Adapters, Settings};

/// The gateway configuration use cases.
#[derive(Clone)]
pub struct GatewayState {
    pub export: Arc<ExportConfigUseCase>,
    pub import: Arc<ImportConfigUseCase>,
}

/// Builds the gateway configuration use cases over `a`, with the
/// deployment's upstream networks and address from `s`.
pub fn build(a: &Adapters, s: &Settings) -> GatewayState {
    GatewayState {
        export: Arc::new(ExportConfigUseCase::new(ExportConfigPorts {
            route_store: a.route_store.clone(),
            service_store: a.service_store.clone(),
            pipeline_store: a.pipeline_store.clone(),
            stream_route_store: a.stream_route_store.clone(),
            egress_store: a.egress_policy_store.clone(),
            consumer_store: a.consumer_store.clone(),
            connector_store: a.connector_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        import: Arc::new(
            ImportConfigUseCase::new(ImportConfigPorts {
                tenant_authorities: a.tenant_authorities.clone(),
                unit_of_work: a.unit_of_work.clone(),
                records: records(a),
                checks: checks(a, s),
            })
            .with_platform_addresses(Arc::new(PlatformAddresses::new(
                a.tenant_store.clone(),
                a.organization_store.clone(),
                PlatformAddressSettings {
                    base: s.base_domain.clone(),
                    shape: s.platform_addressing,
                },
            ))),
        ),
    }
}

/// The records replaced together by a gateway configuration import.
fn records(a: &Adapters) -> RecordPorts {
    RecordPorts {
        route_store: a.route_store.clone(),
        service_store: a.service_store.clone(),
        pipeline_store: a.pipeline_store.clone(),
        classification_store: a.classification_store.clone(),
        stream_route_store: a.stream_route_store.clone(),
        egress_store: a.egress_policy_store.clone(),
        consumer_store: a.consumer_store.clone(),
        connector_store: a.connector_store.clone(),
    }
}

/// The tenant and deployment rules checked before imported records are saved.
fn checks(a: &Adapters, s: &Settings) -> ImportCheckPorts {
    ImportCheckPorts {
        issuers: TenantIssuers::new(
            a.tenant_store.clone(),
            a.organization_store.clone(),
            s.app_base_url.clone(),
        ),
        limit_enforcer: a.limit_enforcer.clone(),
        domain_store: a.registered_domain_store.clone(),
        resource_type_store: a.resource_type_store.clone(),
        site_rules: a.site_rules.clone(),
        upstream_networks: s.upstream_networks.clone(),
    }
}
