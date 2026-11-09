//! Federation endpoints: a tenant's connections to identity providers and
//! what they let a provider do, an account's links to them, the tenant's
//! SCIM switch, the tenant as identity provider to its SAML apps, single
//! logout both ways, and the SAML metadata documents.

use std::time::Duration;

use axum::Router;
use utoipa::OpenApi;

use crate::dto::federation::connections::{
    AssuranceTrustBody, ConnectionResponse, CreateConnectionBody, CreateConnectionResponse,
    EmailTrustBody, ProvisioningBody, SamlSettingsResponse, UpdateConnectionBody,
};
use crate::dto::federation::discovery::{DiscoverRealmBody, HomeRealmResponse};
use crate::dto::federation::encryption::{EncryptionCertificateResponse, EncryptionKeyBody};
use crate::dto::federation::groups::{GroupMappingBody, GroupRuleBody, MappedGrantBody};
use crate::dto::federation::links::{
    LinkListResponse, LinkResponse, ReconfirmLinkBody, ReenteredProofBody,
};
use crate::dto::federation::messages::{
    LogoutRequestsResponse, SamlForm, SamlFormPost, SamlMessageBody, SamlParameter, SsoAnswerBody,
};
use crate::dto::federation::scim::{
    ScimSettingsBody, ScimSettingsResponse, ScimStatusResponse, ScimTokenResponse,
};
use crate::dto::federation::service_providers::{
    AccountAttributeBody, AttributeNameFormatBody, AttributeStatementBody, CreateSamlAppBody,
    CreateSamlAppResponse, NameIdFormatBody, SamlAppResponse, SignedPartsBody, UpdateSamlAppBody,
};
use crate::handlers::federation::connections::{discover, groups, lifecycle, saml};
use crate::handlers::federation::{idp, links, logout, scim, service_providers};
use crate::method::{delete, get, post, put, shared};
use crate::middleware::ip_rate_limit::{ip_rate_limit, per_address};
use crate::state::ApiState;

/// The tenant's API path every federation route sits under.
const TENANT: &str = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}";

/// What a browser or a peer reaches without a session of its own: the SAML
/// metadata documents, the single sign-on and logout services, the logout
/// answers the dashboard asks for, and home realm discovery. Limited per
/// client address.
pub(crate) fn public_routes(state: &ApiState) -> Router<ApiState> {
    let connection = format!("{TENANT}/federation/connections/{{id}}");
    let limiter = per_address(
        state,
        state.http.rate.api_default_per_minute,
        Duration::from_secs(60),
    );
    Router::new()
        .route(
            &format!("{connection}/saml/metadata"),
            get(saml::sp_metadata),
        )
        .route(
            &format!("{connection}/saml/slo"),
            get(logout::provider_logout_redirect).post(shared(logout::provider_logout_post)),
        )
        .route(
            &format!("{connection}/saml/slo/answer"),
            post(logout::answer_provider_logout),
        )
        .route(
            &format!("{TENANT}/federation/discover"),
            post(discover::discover_home_realm),
        )
        .merge(idp_public_routes())
        .layer(axum::middleware::from_fn_with_state(limiter, ip_rate_limit))
}

/// The tenant's public identity provider endpoints.
fn idp_public_routes() -> Router<ApiState> {
    let saml = format!("{TENANT}/saml");
    Router::new()
        .route(&format!("{saml}/metadata"), get(idp::idp_metadata))
        .route(
            &format!("{saml}/sso"),
            get(idp::sso_redirect).post(shared(idp::sso_post)),
        )
        .route(&format!("{saml}/sso/initiate"), get(idp::sso_initiate))
        .route(
            &format!("{saml}/slo"),
            get(logout::app_logout_redirect).post(shared(logout::app_logout_post)),
        )
        .route(
            &format!("{saml}/slo/answer"),
            post(logout::answer_app_logout),
        )
}

/// The federation endpoints a signed-in caller reaches.
pub(crate) fn routes() -> Router<ApiState> {
    Router::new()
        .merge(connection_routes())
        .merge(link_and_scim_routes())
        .merge(saml_app_routes())
}

/// A tenant's connections and what they let their provider do.
fn connection_routes() -> Router<ApiState> {
    let connections = format!("{TENANT}/federation/connections");
    let connection = format!("{connections}/{{id}}");
    Router::new()
        .route(
            &connections,
            post(lifecycle::create_connection).get(shared(lifecycle::list_connections)),
        )
        .route(
            &connection,
            get(lifecycle::get_connection)
                .patch(shared(lifecycle::update_connection))
                .delete(shared(lifecycle::delete_connection)),
        )
        .route(
            &format!("{connection}/activate"),
            post(lifecycle::activate_connection),
        )
        .route(
            &format!("{connection}/disable"),
            post(lifecycle::disable_connection),
        )
        .merge(connection_settings_routes(&connection))
}

/// Registers provider certificate, encryption and group-mapping settings.
fn connection_settings_routes(connection: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{connection}/certificate/roll-over"),
            post(saml::roll_over_certificate),
        )
        .route(
            &format!("{connection}/encrypted-assertions"),
            put(saml::require_encrypted_assertions)
                .delete(shared(saml::accept_readable_assertions)),
        )
        .route(
            &format!("{connection}/group-mapping"),
            put(groups::map_provider_groups).delete(shared(groups::stop_mapping_provider_groups)),
        )
}

/// An account's links to providers, and the tenant's SCIM switch.
fn link_and_scim_routes() -> Router<ApiState> {
    let federation = format!("{TENANT}/federation");
    let connection = format!("{federation}/connections/{{id}}");
    Router::new()
        .route(&format!("{federation}/links"), get(links::list_my_links))
        .route(
            &format!("{federation}/users/{{user_id}}/links"),
            get(links::list_user_links),
        )
        .route(
            &format!("{connection}/link"),
            delete(links::unlink_own_account),
        )
        .route(
            &format!("{connection}/link/reconfirm"),
            post(links::reconfirm_link),
        )
        .route(
            &format!("{connection}/links/{{user_id}}"),
            delete(links::unlink_user_account),
        )
        .merge(scim_routes(&federation))
}

/// Registers the tenant's SCIM switch, token rotation and settings.
fn scim_routes(federation: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{federation}/scim"),
            get(scim::get_scim_status)
                .post(shared(scim::enable_scim))
                .delete(shared(scim::disable_scim)),
        )
        .route(
            &format!("{federation}/scim/rotate-token"),
            post(scim::rotate_scim_token),
        )
        .route(
            &format!("{federation}/scim/settings"),
            put(scim::update_scim_settings),
        )
}

/// The tenant's SAML apps, signing in to them, and single logout.
fn saml_app_routes() -> Router<ApiState> {
    let saml = format!("{TENANT}/saml");
    let app = format!("{saml}/apps/{{app_id}}");
    Router::new()
        .route(
            &format!("{saml}/apps"),
            post(service_providers::create_saml_app).get(shared(service_providers::list_saml_apps)),
        )
        .route(
            &app,
            get(service_providers::get_saml_app)
                .patch(shared(service_providers::update_saml_app))
                .delete(shared(service_providers::delete_saml_app)),
        )
        .route(
            &format!("{app}/activate"),
            post(service_providers::activate_saml_app),
        )
        .route(
            &format!("{app}/disable"),
            post(service_providers::disable_saml_app),
        )
        .route(&format!("{app}/sign-in"), post(idp::sign_in_to_app))
        .route(&format!("{saml}/sso/answer"), post(idp::answer_sign_in))
        .route(
            &format!("{saml}/slo/start"),
            post(logout::start_single_logout),
        )
}

/// The federation part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        lifecycle::create_connection,
        lifecycle::list_connections,
        lifecycle::get_connection,
        lifecycle::update_connection,
        lifecycle::activate_connection,
        lifecycle::disable_connection,
        lifecycle::delete_connection,
        saml::sp_metadata,
        saml::roll_over_certificate,
        saml::require_encrypted_assertions,
        saml::accept_readable_assertions,
        groups::map_provider_groups,
        groups::stop_mapping_provider_groups,
        discover::discover_home_realm,
        links::list_my_links,
        links::list_user_links,
        links::reconfirm_link,
        links::unlink_own_account,
        links::unlink_user_account,
        scim::get_scim_status,
        scim::enable_scim,
        scim::disable_scim,
        scim::rotate_scim_token,
        scim::update_scim_settings,
        idp::idp_metadata,
        idp::sso_redirect,
        idp::sso_post,
        idp::sso_initiate,
        idp::answer_sign_in,
        idp::sign_in_to_app,
        service_providers::create_saml_app,
        service_providers::list_saml_apps,
        service_providers::get_saml_app,
        service_providers::update_saml_app,
        service_providers::activate_saml_app,
        service_providers::disable_saml_app,
        service_providers::delete_saml_app,
        logout::app_logout_redirect,
        logout::app_logout_post,
        logout::answer_app_logout,
        logout::start_single_logout,
        logout::provider_logout_redirect,
        logout::provider_logout_post,
        logout::answer_provider_logout,
    ),
    components(schemas(
        CreateConnectionBody,
        CreateConnectionResponse,
        UpdateConnectionBody,
        ProvisioningBody,
        EmailTrustBody,
        AssuranceTrustBody,
        ConnectionResponse,
        SamlSettingsResponse,
        EncryptionKeyBody,
        EncryptionCertificateResponse,
        GroupMappingBody,
        GroupRuleBody,
        MappedGrantBody,
        DiscoverRealmBody,
        HomeRealmResponse,
        LinkResponse,
        LinkListResponse,
        ReconfirmLinkBody,
        ReenteredProofBody,
        ScimSettingsBody,
        ScimSettingsResponse,
        ScimStatusResponse,
        ScimTokenResponse,
        SamlForm,
        SamlMessageBody,
        SsoAnswerBody,
        SamlFormPost,
        SamlParameter,
        LogoutRequestsResponse,
        CreateSamlAppBody,
        CreateSamlAppResponse,
        UpdateSamlAppBody,
        SamlAppResponse,
        NameIdFormatBody,
        AccountAttributeBody,
        AttributeNameFormatBody,
        AttributeStatementBody,
        SignedPartsBody,
    ))
)]
pub(crate) struct Document;
