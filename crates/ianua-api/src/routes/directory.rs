//! Directory endpoints: LDAP client certificates and LDAP service accounts.

use axum::Router;
use utoipa::OpenApi;

use crate::dto::directory::{
    CreateServiceAccountBody, CreatedServiceAccountResponse, IssueLdapCertificateBody,
    IssuedLdapCertificateResponse, LdapCertificateEntry, LdapCertificateListResponse,
    ServiceAccountListResponse, ServiceAccountResponse, ServiceAccountScopeBody,
    ServiceAccountSecretResponse,
};
use crate::handlers::directory::{certificates, service_accounts};
use crate::method::{delete, get, post, put, shared};
use crate::state::ApiState;

/// The directory endpoints.
pub(crate) fn routes() -> Router<ApiState> {
    let auth = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth";
    certificate_routes(auth).merge(account_routes(auth))
}

/// Registers issuance, listing and revocation of LDAP client certificates.
fn certificate_routes(auth: &str) -> Router<ApiState> {
    let certificates_path = format!("{auth}/ldap-certificates");
    Router::new()
        .route(
            &certificates_path,
            post(certificates::issue_ldap_certificate)
                .get(shared(certificates::list_ldap_certificates)),
        )
        .route(
            &format!("{certificates_path}/{{certificate_id}}"),
            delete(certificates::revoke_ldap_certificate),
        )
}

/// Registers LDAP account credentials and lifecycle changes.
fn account_routes(auth: &str) -> Router<ApiState> {
    let accounts = format!("{auth}/ldap-service-accounts");
    let account = format!("{accounts}/{{account_id}}");
    Router::new()
        .route(
            &accounts,
            post(service_accounts::create_service_account)
                .get(shared(service_accounts::list_service_accounts)),
        )
        .route(
            &account,
            get(service_accounts::get_service_account)
                .delete(shared(service_accounts::delete_service_account)),
        )
        .route(
            &format!("{account}/scope"),
            put(service_accounts::change_service_account_scope),
        )
        .route(
            &format!("{account}/activate"),
            post(service_accounts::activate_service_account),
        )
        .route(
            &format!("{account}/disable"),
            post(service_accounts::disable_service_account),
        )
        .route(
            &format!("{account}/rotate-secret"),
            post(service_accounts::rotate_service_account_secret),
        )
}

/// The directory part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        certificates::issue_ldap_certificate,
        certificates::list_ldap_certificates,
        certificates::revoke_ldap_certificate,
        service_accounts::create_service_account,
        service_accounts::list_service_accounts,
        service_accounts::get_service_account,
        service_accounts::change_service_account_scope,
        service_accounts::activate_service_account,
        service_accounts::disable_service_account,
        service_accounts::rotate_service_account_secret,
        service_accounts::delete_service_account,
    ),
    components(schemas(
        IssueLdapCertificateBody,
        IssuedLdapCertificateResponse,
        LdapCertificateListResponse,
        LdapCertificateEntry,
        CreateServiceAccountBody,
        CreatedServiceAccountResponse,
        ServiceAccountScopeBody,
        ServiceAccountResponse,
        ServiceAccountListResponse,
        ServiceAccountSecretResponse,
    ))
)]
pub(crate) struct Document;
