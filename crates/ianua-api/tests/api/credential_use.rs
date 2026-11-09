//! A request marks the credential it came with as used: a member's session
//! stays alive while they work, and a key shows when it last signed in.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{KnownBearers, ORG, ORG_MEMBER, TENANT, adapters, router};
use ianua_app::context::{CallerIdentity, Credential};
use ianua_app::ports::oauth::ApiKeyStore;
use ianua_app::ports::shared::ResolvedCaller;
use ianua_app::test_support::oauth::{FakeApiKeyStore, stored_api_key};
use ianua_app::test_support::organization::{RecordingOrgSessionStore, test_org_session_idle_for};
use ianua_app::test_support::test_ctx;
use ianua_assembly::deps::Adapters;
use ianua_domain::shared::clock;
use ianua_domain::types::{ActorRef, ApiKeyId, Expiry, UserId};

/// The bearer of a tenant API key made by the key's owner.
const CI_KEY: &str = "ci-key-token";

/// The member's notification inbox on the organization.
fn org_inbox() -> String {
    format!("/api/v1/organizations/{ORG}/notifications")
}

/// The notification inbox of the test tenant.
fn tenant_inbox() -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/notifications")
}

/// A server whose member session was last used ten minutes ago.
fn member_idle_ten_minutes() -> (TestServer, Arc<RecordingOrgSessionStore>) {
    let sessions = Arc::new(RecordingOrgSessionStore::holding([
        test_org_session_idle_for(time::Duration::minutes(10)),
    ]));
    let server = TestServer::new(router(Adapters {
        org_session_store: sessions.clone(),
        ..adapters()
    }))
    .unwrap();
    (server, sessions)
}

/// Whether the store's one session was used within the last minute.
fn used_just_now(sessions: &RecordingOrgSessionStore) -> bool {
    sessions
        .saved()
        .iter()
        .all(|session| clock::now() - session.last_active_at() < time::Duration::minutes(1))
}

/// Owen works on his organization's settings all afternoon. Each request
/// marks his session active, so the organization's idle timeout does not
/// sign him out mid-work.
#[tokio::test]
async fn a_member_request_marks_their_session_active() {
    let (server, sessions) = member_idle_ten_minutes();

    server
        .get(&org_inbox())
        .authorization_bearer(ORG_MEMBER)
        .await
        .assert_status_ok();

    assert!(used_just_now(&sessions));
}

/// The same holds when he works inside one of the organization's tenants.
#[tokio::test]
async fn a_member_request_inside_a_tenant_marks_their_session_active() {
    let (server, sessions) = member_idle_ten_minutes();

    server
        .get(&format!(
            "/api/v1/organizations/{ORG}/tenants/{TENANT}/authorization/roles"
        ))
        .authorization_bearer(ORG_MEMBER)
        .await
        .assert_status_ok();

    assert!(used_just_now(&sessions));
}

/// A resolved bearer whose member session is no longer stored returns 401.
#[tokio::test]
async fn a_member_session_no_longer_kept_is_refused() {
    let server = TestServer::new(router(Adapters {
        org_session_store: Arc::new(RecordingOrgSessionStore::new()),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&org_inbox())
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// A server knowing `CI_KEY` as a tenant API key its owner made.
fn with_a_tenant_key() -> (TestServer, Arc<FakeApiKeyStore>, ApiKeyId) {
    let owner = UserId::new();
    let key = stored_api_key("ci", ActorRef::User(owner));
    let key_id = *key.id();
    let ctx = test_ctx();
    let keys = Arc::new(FakeApiKeyStore::holding(&ctx.tenant(), key));
    let bearer = ResolvedCaller {
        identity: CallerIdentity::TenantUser(owner),
        credential: Credential::TenantApiKey(key_id),
        organization_id: Some(ctx.organization_id()),
        tenant_id: Some(ctx.tenant_id()),
        kept_until: Expiry::Never,
    };
    let server = TestServer::new(router(Adapters {
        token_resolver: Arc::new(KnownBearers::of_the_test_callers().and(CI_KEY, bearer)),
        api_key_store: keys.clone(),
        ..adapters()
    }))
    .unwrap();
    (server, keys, key_id)
}

/// Ann's CI job calls the API with her key. The key now shows it was used,
/// so a key that leaked or sits forgotten can be spotted.
#[tokio::test]
async fn a_request_with_a_tenant_key_records_its_use() {
    let (server, keys, key_id) = with_a_tenant_key();

    server
        .get(&tenant_inbox())
        .authorization_bearer(CI_KEY)
        .await
        .assert_status_ok();

    let key = keys
        .find_by_id(&test_ctx().tenant(), &key_id)
        .await
        .unwrap()
        .unwrap();
    assert!(key.last_used_at().is_some());
}
