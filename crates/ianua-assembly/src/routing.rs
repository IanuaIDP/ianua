//! The routing use cases the API serves: a tenant's routes and their
//! traffic, the services they forward to with their sign-in and upstream
//! TLS, the ports it listens on below HTTP, where each service may itself
//! go, and the private-network connectors upstreams are reached through.

use std::sync::Arc;

use ianua_app::services::hosts::{PlatformAddressSettings, PlatformAddresses};
use ianua_app::use_cases::proxy::{DecideAccessPorts, DecideAccessUseCase};
use ianua_app::use_cases::routing::stream_routes::access::StreamAccessPorts;
use ianua_app::use_cases::routing::{connectors, egress, routes, services, stream_routes};

use crate::deps::{Adapters, Settings};

/// The routing use cases.
#[derive(Clone)]
pub struct RoutingState {
    /// Adds a route to the tenant's proxy.
    pub create_route: Arc<routes::CreateUseCase>,
    pub list_routes: Arc<routes::ListUseCase>,
    pub get_route: Arc<routes::GetUseCase>,
    pub update_route: Arc<routes::UpdateUseCase>,
    pub change_route_conditions: Arc<routes::ChangeConditionsUseCase>,
    pub delete_route: Arc<routes::DeleteUseCase>,
    pub activate_route: Arc<routes::ActivateUseCase>,
    pub disable_route: Arc<routes::DisableUseCase>,
    pub set_route_workflow_use: Arc<routes::SetWorkflowUseUseCase>,
    /// Starts or ends a route's attack mode.
    pub set_route_attack_mode: Arc<routes::SetAttackModeUseCase>,
    pub route_traffic: Arc<routes::GetTrafficUseCase>,
    /// The apps the person signed in may open: their start page.
    pub list_openable: Arc<routes::ListOpenableUseCase>,
    /// Adds a backend routes can forward to.
    pub create_service: Arc<services::CreateUseCase>,
    pub list_services: Arc<services::ListUseCase>,
    pub get_service: Arc<services::GetUseCase>,
    pub service_health: Arc<services::HealthUseCase>,
    pub update_service: Arc<services::UpdateUseCase>,
    pub change_service_tls: Arc<services::ChangeTlsUseCase>,
    pub delete_service: Arc<services::DeleteUseCase>,
    pub configure_app_sign_in: Arc<services::ConfigureAppSignInUseCase>,
    pub create_stream_route: Arc<stream_routes::CreateUseCase>,
    pub list_stream_routes: Arc<stream_routes::ListUseCase>,
    pub get_stream_route: Arc<stream_routes::GetUseCase>,
    pub update_stream_route: Arc<stream_routes::UpdateUseCase>,
    pub delete_stream_route: Arc<stream_routes::DeleteUseCase>,
    pub set_stream_route_status: Arc<stream_routes::SetStatusUseCase>,
    pub set_stream_route_workflow_use: Arc<stream_routes::SetStreamWorkflowUseUseCase>,
    pub create_egress_policy: Arc<egress::CreatePolicyUseCase>,
    pub list_egress_policies: Arc<egress::ListPoliciesUseCase>,
    pub get_egress_policy: Arc<egress::GetPolicyUseCase>,
    pub update_egress_policy: Arc<egress::UpdatePolicyUseCase>,
    pub delete_egress_policy: Arc<egress::DeletePolicyUseCase>,
    pub create_connector: Arc<connectors::CreateUseCase>,
    pub list_connectors: Arc<connectors::ListUseCase>,
    pub get_connector: Arc<connectors::GetUseCase>,
    pub change_connector_scope: Arc<connectors::ChangeScopeUseCase>,
    pub revoke_connector: Arc<connectors::RevokeUseCase>,
    pub delete_connector: Arc<connectors::DeleteUseCase>,
    pub enroll_connector: Arc<connectors::EnrollUseCase>,
    pub renew_connector: Arc<connectors::RenewUseCase>,
}

/// Builds the routing use cases over `a`, with the deployment's upstream
/// networks from `s`.
/// The exhaustive public state has 39 fields; its constructors are grouped below.
#[allow(clippy::too_many_lines)]
pub fn build(a: &Adapters, s: &Settings) -> RoutingState {
    let route_cases = route_use_cases(a, s);
    let service_cases = service_use_cases(a, s);
    let stream_cases = stream_route_use_cases(a, s);
    let egress_cases = egress_use_cases(a);
    let connector_cases = connector_use_cases(a);
    RoutingState {
        create_route: route_cases.create,
        list_routes: route_cases.list,
        get_route: route_cases.get,
        update_route: route_cases.update,
        change_route_conditions: route_cases.change_conditions,
        delete_route: route_cases.delete,
        activate_route: route_cases.activate,
        disable_route: route_cases.disable,
        set_route_workflow_use: route_cases.set_workflow_use,
        set_route_attack_mode: route_cases.set_attack_mode,
        route_traffic: route_cases.traffic,
        list_openable: Arc::new(list_openable(a)),
        create_service: service_cases.create,
        list_services: service_cases.list,
        get_service: service_cases.get,
        service_health: service_cases.health,
        update_service: service_cases.update,
        change_service_tls: service_cases.change_tls,
        delete_service: service_cases.delete,
        configure_app_sign_in: service_cases.configure_app_sign_in,
        create_stream_route: stream_cases.create,
        list_stream_routes: stream_cases.list,
        get_stream_route: stream_cases.get,
        update_stream_route: stream_cases.update,
        delete_stream_route: stream_cases.delete,
        set_stream_route_status: stream_cases.set_status,
        set_stream_route_workflow_use: stream_cases.set_workflow_use,
        create_egress_policy: egress_cases.create,
        list_egress_policies: egress_cases.list,
        get_egress_policy: egress_cases.get,
        update_egress_policy: egress_cases.update,
        delete_egress_policy: egress_cases.delete,
        create_connector: connector_cases.create,
        list_connectors: connector_cases.list,
        get_connector: connector_cases.get,
        change_connector_scope: connector_cases.change_scope,
        revoke_connector: connector_cases.revoke,
        delete_connector: connector_cases.delete,
        enroll_connector: connector_cases.enroll,
        renew_connector: connector_cases.renew,
    }
}

/// Commands and queries for HTTP mappings, their policies and observed traffic.
struct RouteUseCases {
    create: Arc<routes::CreateUseCase>,
    list: Arc<routes::ListUseCase>,
    get: Arc<routes::GetUseCase>,
    update: Arc<routes::UpdateUseCase>,
    change_conditions: Arc<routes::ChangeConditionsUseCase>,
    delete: Arc<routes::DeleteUseCase>,
    activate: Arc<routes::ActivateUseCase>,
    disable: Arc<routes::DisableUseCase>,
    set_workflow_use: Arc<routes::SetWorkflowUseUseCase>,
    set_attack_mode: Arc<routes::SetAttackModeUseCase>,
    traffic: Arc<routes::GetTrafficUseCase>,
}

/// Builds the route use cases over `a`.
fn route_use_cases(a: &Adapters, s: &Settings) -> RouteUseCases {
    let platform = platform_addresses(a, s);
    RouteUseCases {
        create: Arc::new(create_route(a, &platform)),
        list: Arc::new(routes::ListUseCase::new(routes::ListPorts {
            route_store: a.route_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        get: Arc::new(routes::GetUseCase::new(routes::GetPorts {
            route_store: a.route_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        update: Arc::new(update_route(a, platform)),
        change_conditions: Arc::new(change_route_conditions(a)),
        delete: Arc::new(delete_route(a)),
        activate: Arc::new(routes::ActivateUseCase::new(routes::ActivatePorts {
            route_store: a.route_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        disable: Arc::new(routes::DisableUseCase::new(routes::DisablePorts {
            route_store: a.route_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        set_workflow_use: Arc::new(set_route_workflow_use(a)),
        set_attack_mode: Arc::new(set_route_attack_mode(a)),
        traffic: Arc::new(routes::GetTrafficUseCase::new(routes::GetTrafficPorts {
            traffic: a.route_traffic_reader.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
    }
}

/// Creates routes with destination checks, plan limits and shared platform ownership rules.
fn create_route(a: &Adapters, platform: &Arc<PlatformAddresses>) -> routes::CreateUseCase {
    routes::CreateUseCase::new(routes::CreatePorts {
        route_store: a.route_store.clone(),
        limit_enforcer: a.limit_enforcer.clone(),
        domain_store: a.registered_domain_store.clone(),
        pipeline_store: a.pipeline_store.clone(),
        service_store: a.service_store.clone(),
        resource_type_store: a.resource_type_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
    .with_platform_addresses(Arc::clone(platform))
}

/// Updates routes against destination records and shared platform ownership rules.
fn update_route(a: &Adapters, platform: Arc<PlatformAddresses>) -> routes::UpdateUseCase {
    routes::UpdateUseCase::new(routes::UpdatePorts {
        route_store: a.route_store.clone(),
        domain_store: a.registered_domain_store.clone(),
        pipeline_store: a.pipeline_store.clone(),
        service_store: a.service_store.clone(),
        resource_type_store: a.resource_type_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
    .with_platform_addresses(platform)
}

/// Changes route conditions under tenant authority.
fn change_route_conditions(a: &Adapters) -> routes::ChangeConditionsUseCase {
    routes::ChangeConditionsUseCase::new(routes::ChangeConditionsPorts {
        route_store: a.route_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Deletes routes through tenant authority checks.
fn delete_route(a: &Adapters) -> routes::DeleteUseCase {
    routes::DeleteUseCase::new(routes::DeletePorts {
        route_store: a.route_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Changes workflow access to routes under tenant authority.
fn set_route_workflow_use(a: &Adapters) -> routes::SetWorkflowUseUseCase {
    routes::SetWorkflowUseUseCase::new(routes::SetWorkflowUsePorts {
        route_store: a.route_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        guard: crate::workflows::change_guard(a),
    })
}

/// Changes route attack mode under tenant authority.
fn set_route_attack_mode(a: &Adapters) -> routes::SetAttackModeUseCase {
    routes::SetAttackModeUseCase::new(routes::SetAttackModePorts {
        route_store: a.route_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Commands and queries for upstream destinations, TLS and app-host sign-in.
struct ServiceUseCases {
    create: Arc<services::CreateUseCase>,
    list: Arc<services::ListUseCase>,
    get: Arc<services::GetUseCase>,
    health: Arc<services::HealthUseCase>,
    update: Arc<services::UpdateUseCase>,
    change_tls: Arc<services::ChangeTlsUseCase>,
    delete: Arc<services::DeleteUseCase>,
    configure_app_sign_in: Arc<services::ConfigureAppSignInUseCase>,
}

/// Builds the service use cases over `a`, with the upstream networks from
/// `s`.
fn service_use_cases(a: &Adapters, s: &Settings) -> ServiceUseCases {
    ServiceUseCases {
        create: Arc::new(create_service(a, s)),
        list: Arc::new(services::ListUseCase::new(services::ListPorts {
            service_store: a.service_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        get: Arc::new(services::GetUseCase::new(services::GetPorts {
            service_store: a.service_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        health: Arc::new(services::HealthUseCase::new(services::HealthPorts {
            service_store: a.service_store.clone(),
            health: a.backend_health_reader.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        update: Arc::new(update_service(a, s)),
        change_tls: Arc::new(change_service_tls(a)),
        delete: Arc::new(services::DeleteUseCase::new(services::DeletePorts {
            service_store: a.service_store.clone(),
            route_store: a.route_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        configure_app_sign_in: Arc::new(configure_app_sign_in(a, s)),
    }
}

/// Creates upstream services with encrypted credentials and allowed network ranges.
fn create_service(a: &Adapters, s: &Settings) -> services::CreateUseCase {
    services::CreateUseCase::new(services::CreatePorts {
        service_store: a.service_store.clone(),
        connector_store: a.connector_store.clone(),
        encryptor: a.secret_encryptor.clone(),
        limit_enforcer: a.limit_enforcer.clone(),
        upstream_networks: s.upstream_networks.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Updates upstreams against their routes, connectors and allowed network ranges.
fn update_service(a: &Adapters, s: &Settings) -> services::UpdateUseCase {
    services::UpdateUseCase::new(services::UpdatePorts {
        service_store: a.service_store.clone(),
        route_store: a.route_store.clone(),
        connector_store: a.connector_store.clone(),
        upstream_networks: s.upstream_networks.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Changes upstream TLS with encrypted credentials and dependent route checks.
fn change_service_tls(a: &Adapters) -> services::ChangeTlsUseCase {
    services::ChangeTlsUseCase::new(services::ChangeTlsPorts {
        service_store: a.service_store.clone(),
        route_store: a.route_store.clone(),
        encryptor: a.secret_encryptor.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Configures application sign-in against site and platform hostname ownership rules.
fn configure_app_sign_in(a: &Adapters, s: &Settings) -> services::ConfigureAppSignInUseCase {
    services::ConfigureAppSignInUseCase::new(services::ConfigureAppSignInPorts {
        service_store: a.service_store.clone(),
        route_store: a.route_store.clone(),
        domain_store: a.registered_domain_store.clone(),
        site_rules: a.site_rules.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
    .with_platform_addresses(platform_addresses(a, s))
}

/// Shares the ownership rules used by route writes and app sign-in configuration.
fn platform_addresses(a: &Adapters, s: &Settings) -> Arc<PlatformAddresses> {
    Arc::new(PlatformAddresses::new(
        a.tenant_store.clone(),
        a.organization_store.clone(),
        PlatformAddressSettings {
            base: s.base_domain.clone(),
            shape: s.platform_addressing,
        },
    ))
}

/// Commands and queries for listeners below HTTP and their workflow access.
struct StreamRouteUseCases {
    create: Arc<stream_routes::CreateUseCase>,
    list: Arc<stream_routes::ListUseCase>,
    get: Arc<stream_routes::GetUseCase>,
    update: Arc<stream_routes::UpdateUseCase>,
    delete: Arc<stream_routes::DeleteUseCase>,
    set_status: Arc<stream_routes::SetStatusUseCase>,
    set_workflow_use: Arc<stream_routes::SetStreamWorkflowUseUseCase>,
}

/// Builds the stream route use cases over `a`, with the upstream networks
/// from `s`.
fn stream_route_use_cases(a: &Adapters, s: &Settings) -> StreamRouteUseCases {
    StreamRouteUseCases {
        create: Arc::new(create_stream_route(a, s)),
        list: Arc::new(stream_routes::ListUseCase::new(stream_routes::ListPorts {
            stream_route_store: a.stream_route_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        get: Arc::new(stream_routes::GetUseCase::new(stream_routes::GetPorts {
            stream_route_store: a.stream_route_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        update: Arc::new(update_stream_route(a, s)),
        delete: Arc::new(stream_routes::DeleteUseCase::new(
            stream_routes::DeletePorts {
                stream_route_store: a.stream_route_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        set_status: Arc::new(stream_routes::SetStatusUseCase::new(
            stream_routes::SetStatusPorts {
                stream_route_store: a.stream_route_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        set_workflow_use: Arc::new(set_stream_workflow_use(a)),
    }
}

/// Creates stream routes with access checks, network restrictions and plan limits.
fn create_stream_route(a: &Adapters, s: &Settings) -> stream_routes::CreateUseCase {
    stream_routes::CreateUseCase::new(stream_routes::CreatePorts {
        stream_route_store: a.stream_route_store.clone(),
        limit_enforcer: a.limit_enforcer.clone(),
        access: stream_access(a),
        upstream_networks: s.upstream_networks.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Updates stream routes against access records and allowed upstream networks.
fn update_stream_route(a: &Adapters, s: &Settings) -> stream_routes::UpdateUseCase {
    stream_routes::UpdateUseCase::new(stream_routes::UpdatePorts {
        stream_route_store: a.stream_route_store.clone(),
        access: stream_access(a),
        upstream_networks: s.upstream_networks.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Changes workflow stream access together with encrypted logins in one unit of work.
fn set_stream_workflow_use(a: &Adapters) -> stream_routes::SetStreamWorkflowUseUseCase {
    stream_routes::SetStreamWorkflowUseUseCase::new(stream_routes::SetStreamWorkflowUsePorts {
        stream_route_store: a.stream_route_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        logins: a.stream_route_logins.clone(),
        encryptor: a.secret_encryptor.clone(),
        unit_of_work: a.unit_of_work.clone(),
    })
}

/// What a stream route's access is checked against.
fn stream_access(a: &Adapters) -> StreamAccessPorts {
    StreamAccessPorts {
        consumer_store: a.consumer_store.clone(),
        resource_type_store: a.resource_type_store.clone(),
    }
}

/// The egress policy use cases.
struct EgressUseCases {
    create: Arc<egress::CreatePolicyUseCase>,
    list: Arc<egress::ListPoliciesUseCase>,
    get: Arc<egress::GetPolicyUseCase>,
    update: Arc<egress::UpdatePolicyUseCase>,
    delete: Arc<egress::DeletePolicyUseCase>,
}

/// Builds the egress policy use cases over `a`.
fn egress_use_cases(a: &Adapters) -> EgressUseCases {
    EgressUseCases {
        create: Arc::new(create_egress_policy(a)),
        list: Arc::new(egress::ListPoliciesUseCase::new(
            egress::ListPoliciesPorts {
                egress_store: a.egress_policy_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        get: Arc::new(egress::GetPolicyUseCase::new(egress::GetPolicyPorts {
            egress_store: a.egress_policy_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        update: Arc::new(egress::UpdatePolicyUseCase::new(
            egress::UpdatePolicyPorts {
                egress_store: a.egress_policy_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        delete: Arc::new(egress::DeletePolicyUseCase::new(
            egress::DeletePolicyPorts {
                egress_store: a.egress_policy_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
    }
}

/// Creates egress policies under tenant authority and plan limits.
fn create_egress_policy(a: &Adapters) -> egress::CreatePolicyUseCase {
    egress::CreatePolicyUseCase::new(egress::CreatePolicyPorts {
        egress_store: a.egress_policy_store.clone(),
        limit_enforcer: a.limit_enforcer.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Enrollment, scope and lifecycle operations for private-network access agents.
struct ConnectorUseCases {
    create: Arc<connectors::CreateUseCase>,
    list: Arc<connectors::ListUseCase>,
    get: Arc<connectors::GetUseCase>,
    change_scope: Arc<connectors::ChangeScopeUseCase>,
    revoke: Arc<connectors::RevokeUseCase>,
    delete: Arc<connectors::DeleteUseCase>,
    enroll: Arc<connectors::EnrollUseCase>,
    renew: Arc<connectors::RenewUseCase>,
}

/// Builds the connector use cases over `a`.
fn connector_use_cases(a: &Adapters) -> ConnectorUseCases {
    ConnectorUseCases {
        create: Arc::new(create_connector(a)),
        list: Arc::new(connectors::ListUseCase::new(connectors::ListPorts {
            connector_store: a.connector_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        get: Arc::new(connectors::GetUseCase::new(connectors::GetPorts {
            connector_store: a.connector_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        change_scope: Arc::new(change_connector_scope(a)),
        revoke: Arc::new(connectors::RevokeUseCase::new(connectors::RevokePorts {
            connector_store: a.connector_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        delete: Arc::new(connectors::DeleteUseCase::new(connectors::DeletePorts {
            connector_store: a.connector_store.clone(),
            service_store: a.service_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        enroll: Arc::new(enroll_connector(a)),
        renew: Arc::new(connectors::RenewUseCase::new(connectors::RenewPorts {
            connector_store: a.connector_store.clone(),
            certificate_signer: a.connector_authority.clone(),
        })),
    }
}

/// Creates connectors with enrollment codes and tenant plan enforcement.
fn create_connector(a: &Adapters) -> connectors::CreateUseCase {
    connectors::CreateUseCase::new(connectors::CreatePorts {
        connector_store: a.connector_store.clone(),
        code_generator: a.connector_code_generator.clone(),
        limit_enforcer: a.limit_enforcer.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Changes connector scope with checks against the services it can reach.
fn change_connector_scope(a: &Adapters) -> connectors::ChangeScopeUseCase {
    connectors::ChangeScopeUseCase::new(connectors::ChangeScopePorts {
        connector_store: a.connector_store.clone(),
        service_store: a.service_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Enrolls connectors with generated codes and signed certificates.
fn enroll_connector(a: &Adapters) -> connectors::EnrollUseCase {
    connectors::EnrollUseCase::new(connectors::EnrollPorts {
        connector_store: a.connector_store.clone(),
        code_generator: a.connector_code_generator.clone(),
        certificate_signer: a.connector_authority.clone(),
    })
}

/// The start page: each active route asked of the gateway's own access
/// decision, built over the same stores the gateway reads.
fn list_openable(a: &Adapters) -> routes::ListOpenableUseCase {
    let decide = DecideAccessUseCase::new(DecideAccessPorts {
        route_store: a.route_store.clone(),
        policy_decisions: a.policy_decisions.clone(),
        access_records: a.access_record_store.clone(),
        member_standings: a.member_standings.clone(),
        policy_store: a.policy_store.clone(),
        time_zones: a.time_zones.clone(),
    });
    routes::ListOpenableUseCase::new(routes::ListOpenablePorts {
        route_store: a.route_store.clone(),
        access_records: a.access_record_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        decide: Arc::new(decide),
    })
}
