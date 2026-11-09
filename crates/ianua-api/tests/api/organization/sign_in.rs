//! Organization sign-in: password login, mailed links, single sign-on,
//! logout, sessions and devices.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{OPERATOR, ORG, ORG_MEMBER, TENANT, adapters, router};
use ianua_app::acting::organization::{OrgActing, OrgActingPorts};
use ianua_app::acting::tenant::{MemberPorts, TenantActing, TenantActingPorts};
use ianua_app::test_support::acting::{FakeOrgActors, Refusal};
use ianua_app::test_support::organization::{
    RecordingOrgSessionStore, org_session_for, org_user_store_with, password_only, stored_caller,
    test_org_session, test_org_session_on_organization,
};
use ianua_app::test_support::{Fake, test_ctx, test_org_caller};
use ianua_domain::domains::authentication::sessions::status::SessionStatus;
use ianua_domain::domains::organization::members::membership::OrgRole;
use ianua_domain::types::SessionId;
use serde_json::{Value, json};

/// The path under the test organization.
fn org_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}{rest}")
}

/// A server whose test member holds one live session besides their own,
/// and the store it is kept in.
fn with_a_second_session() -> (TestServer, Arc<RecordingOrgSessionStore>, SessionId) {
    let member = test_org_caller();
    let session = org_session_for(
        *member.member(),
        member.organization_id(),
        test_ctx().tenant_id(),
        password_only(),
    );
    let id = *session.id();
    let sessions = Arc::new(RecordingOrgSessionStore::holding([
        test_org_session(),
        session,
    ]));
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        org_session_store: sessions.clone(),
        ..adapters()
    }))
    .unwrap();
    (server, sessions, id)
}

/// Whether the session `id` was saved as revoked.
fn ended(sessions: &RecordingOrgSessionStore, id: &SessionId) -> bool {
    sessions
        .saved()
        .iter()
        .any(|session| session.id() == id && session.status() == SessionStatus::Revoked)
}

/// An address nobody signs in with answers as a wrong password does, so
/// the login tells nobody which addresses have accounts.
#[tokio::test]
async fn an_unknown_address_is_invalid_credentials() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post("/api/v1/login")
        .json(&json!({"email": "nobody@acme.test", "password": "whatever"}))
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// The password every member in these tests signs in with.
const PASSPHRASE: &str = "Correct-Horse-Battery-9";

/// Sam accepted his invitation a minute ago, and nobody granted him a
/// tenant yet. He signs in: the session lands on the organization alone,
/// and the answer names no tenant.
#[tokio::test]
async fn a_member_without_a_tenant_signs_in_to_the_organization_alone() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        org_user_store: Arc::new(org_user_store_with([stored_caller(
            OrgRole::Member,
            PASSPHRASE,
        )])),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .post("/api/v1/login")
        .json(&json!({"email": "caller@example.test", "password": PASSPHRASE}))
        .await;

    response.assert_status_ok();
    let signed_in: Value = response.json();
    assert_eq!(signed_in["status"], "authenticated");
    assert!(signed_in["tenant_id"].is_null());
    assert!(signed_in["tenant_slug"].is_null());
}

/// A server where the test member, a plain member with no grant, is
/// signed in to the organization alone, and every caller is worked out
/// from the stored records.
fn signed_in_to_the_organization_alone() -> TestServer {
    let base = adapters();
    let members = Arc::new(org_user_store_with([stored_caller(
        OrgRole::Member,
        PASSPHRASE,
    )]));
    let sessions = Arc::new(RecordingOrgSessionStore::holding([
        test_org_session_on_organization(),
    ]));
    let base = ianua_assembly::deps::Adapters {
        org_user_store: members,
        org_session_store: sessions,
        ..base
    };
    TestServer::new(router(with_stored_callers(base))).unwrap()
}

/// Resolves organization and tenant callers through the supplied membership
/// and session stores.
fn with_stored_callers(base: ianua_assembly::deps::Adapters) -> ianua_assembly::deps::Adapters {
    let org_actors = OrgActing::new(OrgActingPorts {
        organizations: base.organization_store.clone(),
        org_users: base.org_user_store.clone(),
        org_sessions: base.org_session_store.clone(),
        org_api_keys: Fake::fake(),
    });
    let tenant_authorities = TenantActing::new(TenantActingPorts {
        tenants: base.tenant_store.clone(),
        members: MemberPorts {
            organizations: base.organization_store.clone(),
            org_users: base.org_user_store.clone(),
            org_sessions: base.org_session_store.clone(),
            ..MemberPorts::fakes()
        },
        ..TenantActingPorts::fakes()
    });
    ianua_assembly::deps::Adapters {
        org_actors: Arc::new(org_actors),
        tenant_authorities: Arc::new(tenant_authorities),
        ..base
    }
}

/// Sam's session works on the organization alone. He reads what he
/// reaches: his role, and no tenant.
#[tokio::test]
async fn a_session_on_the_organization_alone_reads_the_organization() {
    let server = signed_in_to_the_organization_alone();

    let response = server
        .get(&org_path("/me/access"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status_ok();
    response.assert_json(&json!({"role": "Member", "tenants": []}));
}

/// A session scoped only to the organization receives 403 when listing
/// a tenant's users.
#[tokio::test]
async fn a_session_on_the_organization_alone_is_refused_in_a_tenant() {
    let server = signed_in_to_the_organization_alone();

    let response = server
        .get(&format!(
            "/api/v1/organizations/{ORG}/tenants/{TENANT}/users"
        ))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// Something that is not an address is refused before anything is looked
/// up.
#[tokio::test]
async fn a_malformed_address_is_refused() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post("/api/v1/login")
        .json(&json!({"email": "not an address", "password": "whatever"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Olivia signs out of a session of hers: it ends at once.
#[tokio::test]
async fn a_member_signs_out_of_their_own_session() {
    let (server, sessions, id) = with_a_second_session();

    let response = server
        .post(&org_path("/logout"))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({"session_id": id.as_uuid().to_string()}))
        .await;

    response.assert_status(StatusCode::NO_CONTENT);
    assert!(ended(&sessions, &id));
}

/// A session id that is not hers reads as absent.
#[tokio::test]
async fn signing_out_of_an_unknown_session_is_not_found() {
    let (server, _, _) = with_a_second_session();

    let response = server
        .post(&org_path("/logout"))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({"session_id": uuid::Uuid::now_v7().to_string()}))
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// A session id that is not one is refused.
#[tokio::test]
async fn a_malformed_session_id_is_refused() {
    let (server, _, _) = with_a_second_session();

    let response = server
        .post(&org_path("/logout"))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({"session_id": "not-a-uuid"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// An operator ends a member's session for the platform.
#[tokio::test]
async fn an_operator_ends_a_members_session() {
    let (server, sessions, id) = with_a_second_session();

    let response = server
        .post(&org_path(&format!("/sessions/{}/revoke", id.as_uuid())))
        .authorization_bearer(OPERATOR)
        .await;

    response.assert_status(StatusCode::NO_CONTENT);
    assert!(ended(&sessions, &id));
}

/// The active-session list answers a page.
#[tokio::test]
async fn the_active_sessions_answer_a_page() {
    let (server, _, _) = with_a_second_session();

    let response = server
        .get(&org_path("/sessions/active"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status_ok();
    let page: Value = response.json();
    assert!(page["items"].is_array());
    assert!(page.get("next_cursor").is_some());
}

/// A member with no remembered device sees an empty list, in the shape
/// the dashboard reads.
#[tokio::test]
async fn a_member_lists_their_devices() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .get(&org_path("/devices"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_json(&json!({"devices": []}));
}

/// A signed-out organization session receives 401 when listing devices.
#[tokio::test]
async fn a_session_the_app_no_longer_honours_is_unauthenticated() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        org_actors: Arc::new(FakeOrgActors::refusing(Refusal::SignedOut)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&org_path("/devices"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// A malformed organization slug makes the sign-in request return 422.
#[tokio::test]
async fn a_malformed_organization_choice_is_refused() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post("/api/v1/login")
        .json(&json!({
            "email": "olivia@acme.test",
            "password": "whatever",
            "organization": "Not A Slug!",
        }))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Asking for a sign-in link answers the same for an address nobody holds,
/// so it tells nobody which addresses have accounts.
#[tokio::test]
async fn a_sign_in_link_for_an_unknown_address_answers_the_same() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post("/api/v1/login/magic-link")
        .json(&json!({"email": "nobody@acme.test"}))
        .await;

    response.assert_status(StatusCode::NO_CONTENT);
}

/// An unknown organization sign-in link returns 404.
#[tokio::test]
async fn a_guessed_sign_in_link_opens_nothing() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post("/api/v1/login/magic-link/verify")
        .json(&json!({"token": "a-link-nobody-mailed"}))
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// An organization without an identity provider refuses single sign-on with 403.
#[tokio::test]
async fn single_sign_on_without_a_provider_is_refused() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post("/api/v1/login/sso")
        .json(&json!({"organization": ORG}))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// A SAML answer with empty relay state returns 403.
#[tokio::test]
async fn a_saml_answer_to_no_request_is_refused() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post("/api/v1/login/sso/callback")
        .json(&json!({
            "binding": "browser-secret",
            "answer": {"protocol": "saml", "relay_state": "", "saml_response": "PHNhbWw+"},
        }))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}
