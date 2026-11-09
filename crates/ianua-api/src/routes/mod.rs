//! Where each context's endpoints live: `routes/<context>.rs` gives its
//! router, its paths and its part of the OpenAPI document.

pub mod activity;
pub mod agents;
pub mod audit;
pub mod authentication;
pub mod authorization;
pub mod branding;
pub mod consumers;
pub mod crypto;
pub mod data_classification;
pub mod directory;
pub mod domain;
pub mod federation;
pub mod files;
pub mod gateway;
pub mod identity;
pub mod messaging;
pub mod notifications;
pub mod oauth;
pub mod onboarding;
pub mod operator;
pub mod organization;
pub mod proxy;
pub mod realtime;
pub mod reference;
pub mod routing;
pub mod runtime;
pub mod scim;
pub mod signals;
pub mod tenant;
pub mod webhooks;
pub mod workflows;

use axum::Router;
use utoipa::OpenApi as _;

use crate::state::ApiState;

/// Every context's endpoints.
pub(crate) fn all() -> Router<ApiState> {
    Router::new()
        .merge(notifications::routes())
        .merge(directory::routes())
        .merge(tenant::routes())
        .merge(reference::routes())
        .merge(domain::routes())
        .merge(branding::routes())
        .merge(authorization::routes())
        .merge(audit::routes())
        .merge(activity::routes())
        .merge(agents::routes())
        .merge(realtime::routes())
        .merge(workflows::routes())
        .merge(webhooks::routes())
        .merge(signals::routes())
        .merge(messaging::routes())
        .merge(consumers::routes())
        .merge(federation::routes())
        .merge(oauth::routes())
        .merge(crypto::routes())
        .merge(operator::routes())
        .merge(organization::routes())
        .merge(onboarding::routes())
        .merge(authentication::routes())
        .merge(identity::routes())
        .merge(data_classification::routes())
        .merge(gateway::routes())
        .merge(proxy::routes())
        .merge(routing::routes())
        .merge(runtime::routes())
}

/// Every context's part of the OpenAPI document.
pub(crate) fn documents() -> Vec<utoipa::openapi::OpenApi> {
    let mut documents = vec![
        notifications::Document::openapi(),
        directory::Document::openapi(),
        tenant::Document::openapi(),
        reference::Document::openapi(),
        domain::Document::openapi(),
        branding::Document::openapi(),
        authorization::Document::openapi(),
        audit::Document::openapi(),
        activity::Document::openapi(),
        agents::Document::openapi(),
        onboarding::Document::openapi(),
        realtime::Document::openapi(),
        workflows::Document::openapi(),
        webhooks::Document::openapi(),
        signals::Document::openapi(),
        messaging::Document::openapi(),
        consumers::Document::openapi(),
        scim::Document::openapi(),
    ];
    documents.extend(identity_documents());
    documents
}

/// Identity, organization, and gateway contracts appended to the context documents.
fn identity_documents() -> Vec<utoipa::openapi::OpenApi> {
    vec![
        federation::Document::openapi(),
        files::Document::openapi(),
        oauth::Document::openapi(),
        crypto::Document::openapi(),
        operator::Document::openapi(),
        organization::Document::openapi(),
        authentication::Document::openapi(),
        identity::Document::openapi(),
        data_classification::Document::openapi(),
        gateway::Document::openapi(),
        proxy::Document::openapi(),
        routing::Document::openapi(),
        runtime::Document::openapi(),
    ]
}
