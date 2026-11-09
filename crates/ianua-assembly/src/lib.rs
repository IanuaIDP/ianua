//! Every use case, built once from the adapters the server hands in.
//!
//! One group of use cases per app context, each with its builder in
//! `<context>.rs`, and the sets other callers take: the LDAP directory's
//! writes and the actions a workflow's company steps are made through. The
//! API holds the groups in its own state; the LDAP directory and the
//! worker take their sets from here, so no caller borrows another's
//! wiring, and a check added to how an action is built reaches every
//! caller alike.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]

pub mod activity;
pub mod agents;
pub mod audit;
pub mod authentication;
pub mod authorization;
pub mod branding;
pub mod consumers;
pub mod crypto;
pub mod data_classification;
pub mod deps;
pub mod directory;
pub mod domain;
pub mod evaluations;
pub mod federation;
pub mod files;
pub mod gateway;
pub mod identity;
pub mod memories;
pub mod messaging;
pub mod notifications;
pub mod oauth;
pub mod onboarding;
pub mod operator;
pub mod organization;
pub mod proxy;
pub mod realtime;
pub mod routing;
pub mod runtime;
pub mod scim;
pub mod signals;
pub mod tenant;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod tunables;
pub mod webhooks;
pub mod workflows;

use std::sync::Arc;

use ianua_app::use_cases::authentication::sessions::{break_glass, device_trust};
use ianua_app::use_cases::workflows::executions::{
    AccessActions, AgentActions, CompanyActions, PeopleActions, PlatformActions,
};

use crate::deps::{Adapters, Settings};
use crate::directory::{DashboardWrites, LdapUseCases};

/// The LDAP server's use cases, its writes made through the dashboard's own
/// user, address, password and group use cases, so the same rights and
/// domain checks decide them.
#[must_use]
pub fn ldap(adapters: &Adapters, settings: &Settings) -> LdapUseCases {
    let identity = identity::build(adapters, settings);
    let authentication = authentication::build(adapters, settings, &identity);
    let authorization = authorization::build(adapters);
    directory::ldap(
        adapters,
        &DashboardWrites {
            identity: &identity,
            authentication: &authentication,
            authorization: &authorization,
        },
    )
}

/// The dashboard's own actions a workflow's company steps are made
/// through, built as the API's are.
#[must_use]
pub fn company(adapters: &Adapters, settings: &Settings) -> CompanyActions {
    let identity = identity::build(adapters, settings);
    let authentication = authentication::build(adapters, settings, &identity);
    let authorization = authorization::build(adapters);
    let agents = agents::build(adapters, settings);
    let oauth = oauth::build(adapters, settings);
    let routing = routing::build(adapters, settings);
    let audit = audit::build(adapters, settings.tunables.audit_export_limits);
    let classification = data_classification::build(adapters);
    CompanyActions {
        people: company_people(
            adapters,
            identity,
            oauth,
            CompanyDevices {
                list: authentication.sessions.list_devices,
                revoke: authentication.sessions.revoke_device,
            },
        ),
        access: company_access(authorization, authentication.sessions.break_glass_grant),
        agents: company_agents(agents),
        platform: company_platform(adapters, routing, audit, classification),
    }
}

/// The trusted-device actions consumed by workflow people steps.
struct CompanyDevices {
    list: Arc<device_trust::ListDevicesUseCase>,
    revoke: Arc<device_trust::RevokeDeviceUseCase>,
}

/// Selects the dashboard's account actions for workflow people steps.
fn company_people(
    adapters: &Adapters,
    identity: identity::IdentityState,
    oauth: oauth::OAuthState,
    devices: CompanyDevices,
) -> PeopleActions {
    PeopleActions {
        get: identity.users.get,
        list: identity.users.list,
        update_status: identity.users.update_status,
        reset_factors: identity.users.reset_factors,
        sessions: identity.sessions.list,
        revoke_session: identity.sessions.revoke,
        keys: oauth.api_keys.list,
        revoke_key: oauth.api_keys.revoke,
        pause_key: oauth.api_keys.pause,
        resume_key: oauth.api_keys.resume,
        report_signal: signals::report(adapters),
        devices: devices.list,
        forget_device: devices.revoke,
        invite: identity.invitations.invite,
        link_scopes: scim::link_scopes(adapters),
        notify: notifications::send_notice(adapters),
    }
}

/// Selects the dashboard's authorization and emergency-access actions for workflows.
fn company_access(
    authorization: authorization::AuthorizationState,
    break_glass: Arc<break_glass::GrantUseCase>,
) -> AccessActions {
    AccessActions {
        members: authorization.groups.list_members,
        add: authorization.groups.add_member,
        remove: authorization.groups.remove_member,
        approve: authorization.access_requests.approve,
        deny: authorization.access_requests.deny,
        request: authorization.access_requests.get,
        start_review: authorization.access_reviews.start,
        suggest_review: authorization.access_reviews.suggest,
        principal_access: authorization.holdings.principal_access,
        check: authorization.checks.access,
        break_glass,
    }
}

/// Selects the dashboard's agent controls for workflow company steps.
fn company_agents(agents: agents::AgentState) -> AgentActions {
    AgentActions {
        suspend: agents.lifecycle.suspend,
        cancel: agents.runs.cancel,
        runs: agents.runs.list,
        delegations: agents.delegation.list,
        revoke: agents.delegation.revoke,
        revoke_resource: agents.delegation.revoke_resource,
    }
}

/// Selects routing, audit and classification actions for workflow company steps.
fn company_platform(
    adapters: &Adapters,
    routing: routing::RoutingState,
    audit: audit::AuditState,
    classification: data_classification::DataClassificationState,
) -> PlatformActions {
    PlatformActions {
        traffic: routing.route_traffic,
        workflow_use: routing.set_route_workflow_use,
        attack_mode: routing.set_route_attack_mode,
        audit: audit.list_for_tenant,
        pack: audit.exports.request_for_tenant,
        classify: classification.add_rule,
        classification: classification.get,
        digest: adapters.redaction_digest.clone(),
    }
}
