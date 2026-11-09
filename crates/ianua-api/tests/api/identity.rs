//! The identity endpoints: users, invitations, addresses, custom attributes
//! and privacy, what each answers and in what shape.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, TENANT, TENANT_USER, adapters, router};
use ianua_app::test_support::RejectingLimitEnforcer;
use ianua_app::test_support::acting::{FakeTenantAuthorities, Refusal};
use ianua_app::test_support::authentication::test_caller_id;
use ianua_app::test_support::identity::{FakeUserImportStore, FakeUserStore};
use ianua_app::test_support::scheduling::FakeJobQueue;
use ianua_assembly::deps::Adapters;
use ianua_domain::types::UserId;
use serde_json::{Value, json};

/// The test tenant's address, followed by `rest`.
fn tenant_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}{rest}")
}

/// A server over `adapters`.
fn server_over(adapters: Adapters) -> TestServer {
    TestServer::new(router(adapters)).unwrap()
}

/// A server whose tenant holds Ann, an active user with a confirmed
/// address.
fn with_ann() -> (TestServer, Arc<FakeUserStore>, UserId) {
    let ann = UserId::new();
    let users = Arc::new(FakeUserStore::with_user(ann, "ann@example.test"));
    let server = server_over(Adapters {
        user_store: users.clone(),
        ..adapters()
    });
    (server, users, ann)
}

/// An admin registers Bob without a password: he is created, and the
/// password generated for him comes back this once.
#[tokio::test]
async fn registering_a_user_answers_created_with_the_generated_password() {
    let server = server_over(adapters());

    let response = server
        .post(&tenant_path("/users"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"email": "bob@example.test", "display_name": "Bob"}))
        .await;

    response.assert_status(StatusCode::CREATED);
    let body: Value = response.json();
    assert!(body["id"].is_string());
    assert!(body["generated_password"].is_string());
}

/// An address that is not one is refused before anything is made.
#[tokio::test]
async fn registering_with_an_invalid_address_is_refused() {
    let server = server_over(adapters());

    let response = server
        .post(&tenant_path("/users"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"email": "not-an-address", "display_name": "Bob"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A plan refusal returns 403 and leaves the user store empty.
#[tokio::test]
async fn registering_past_the_plan_limit_is_forbidden() {
    let users = Arc::new(FakeUserStore::empty());
    let server = server_over(Adapters {
        limit_enforcer: Arc::new(RejectingLimitEnforcer),
        user_store: users.clone(),
        ..adapters()
    });

    let response = server
        .post(&tenant_path("/users"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"email": "bob@example.test", "display_name": "Bob"}))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(users.count(), 0);
}

/// The members list answers a page whose rows carry what the dashboard
/// reads: the account, its roles, and no invitation for a joined member.
#[tokio::test]
async fn the_listing_shows_each_user_in_the_dashboards_shape() {
    let (server, _, ann) = with_ann();

    let response = server
        .get(&tenant_path("/users"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let page: Value = response.json();
    assert_eq!(page["items"].as_array().map(Vec::len), Some(1));
    assert!(page["next_cursor"].is_null());
    let row = &page["items"][0];
    assert_eq!(row["id"], ann.as_uuid().to_string());
    assert_eq!(row["email"], "ann@example.test");
    assert_eq!(row["status"], "Active");
    assert_eq!(row["email_verified"], true);
    assert_eq!(row["roles"], json!([]));
    assert_eq!(row["invitation_status"], Value::Null);
    assert!(row.get("attributes").is_none(), "no custom fields declared");
}

/// A custom attribute filter that names no attribute is refused.
#[tokio::test]
async fn a_malformed_attribute_filter_is_refused() {
    let (server, _, _) = with_ann();

    let response = server
        .get(&tenant_path("/users?attr=department"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Listing users without tenant authority returns 403.
#[tokio::test]
async fn a_caller_the_app_refuses_is_forbidden() {
    let server = server_over(Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    });

    let response = server
        .get(&tenant_path("/users"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// One user is read by id; an id nobody has is not found.
#[tokio::test]
async fn a_user_is_read_by_id_and_an_unknown_one_is_not_found() {
    let (server, _, ann) = with_ann();

    let found = server
        .get(&tenant_path(&format!("/users/{}", ann.as_uuid())))
        .authorization_bearer(TENANT_USER)
        .await;
    let missing = server
        .get(&tenant_path(&format!("/users/{}", uuid::Uuid::now_v7())))
        .authorization_bearer(TENANT_USER)
        .await;

    found.assert_status_ok();
    assert_eq!(found.json::<Value>()["display_name"], "Test User");
    missing.assert_status(StatusCode::NOT_FOUND);
}

/// An admin renames Ann through the profile patch.
#[tokio::test]
async fn renaming_a_user_through_the_patch_changes_their_name() {
    let (server, users, ann) = with_ann();

    let response = server
        .patch(&tenant_path(&format!("/users/{}", ann.as_uuid())))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"display_name": "Ann Smith"}))
        .await;

    response.assert_status(StatusCode::NO_CONTENT);
    let name = users.get_display_name(&ann).unwrap();
    assert_eq!(name.as_str(), "Ann Smith");
}

/// A timezone nobody keeps is refused, not stored.
#[tokio::test]
async fn an_unknown_timezone_in_my_preferences_is_refused() {
    let server = server_over(adapters());

    let response = server
        .patch(&tenant_path("/me"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"timezone": "Mars/Olympus_Mons"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// The sign-up form asks whether the tenant takes sign-ups, with no
/// session, and is answered whether or not it does.
#[tokio::test]
async fn the_sign_up_rules_answer_without_a_session() {
    let server = server_over(adapters());

    let response = server.get(&tenant_path("/auth/sign-up")).await;

    response.assert_status_ok();
    let rules: Value = response.json();
    assert!(rules["open"].is_boolean());
}

/// A public link page names a tenant the organization does not hold: not
/// found, before any token is read.
#[tokio::test]
async fn a_public_page_for_an_unknown_tenant_is_not_found() {
    let server = server_over(adapters());

    let response = server
        .post(&format!(
            "/api/v1/organizations/{ORG}/tenants/staging/users/invitation-status"
        ))
        .json(&json!({"token": "never-issued"}))
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// An invitation link this tenant never issued reads as invalid, with no
/// password rules, and with no session.
#[tokio::test]
async fn an_invitation_link_never_issued_reads_invalid() {
    let server = server_over(adapters());

    let response = server
        .post(&tenant_path("/users/invitation-status"))
        .json(&json!({"token": "never-issued"}))
        .await;

    response.assert_json(&json!({"status": "Invalid"}));
}

/// Accepting with a token nobody issued is not found.
#[tokio::test]
async fn accepting_an_unknown_invitation_is_not_found() {
    let server = server_over(adapters());

    let response = server
        .post(&tenant_path("/users/accept-invitation"))
        .json(&json!({"token": "never-issued", "password": "a long enough passphrase"}))
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// Inviting needs a role id that is one.
#[tokio::test]
async fn inviting_with_a_malformed_role_is_refused() {
    let server = server_over(adapters());

    let response = server
        .post(&tenant_path("/users/invite"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "email": "carol@example.test",
            "display_name": "Carol",
            "role_id": "admin"
        }))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Asking to move my address without proving it is me again is refused.
#[tokio::test]
async fn an_email_change_without_proof_is_refused() {
    let server = server_over(adapters());

    let response = server
        .post(&tenant_path("/me/email/request-change"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"new_email": "ann@elsewhere.test"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// An organization member's change link nobody issued reads as invalid,
/// with no session.
#[tokio::test]
async fn an_organization_change_link_never_issued_reads_invalid() {
    let server = server_over(adapters());

    let response = server
        .post(&format!("/api/v1/organizations/{ORG}/email/change-status"))
        .json(&json!({"token": "never-issued"}))
        .await;

    response.assert_json(&json!({"status": "Invalid"}));
}

/// The catalogue of kinds says what each kind implies.
#[tokio::test]
async fn the_attribute_catalogue_says_what_each_kind_implies() {
    let server = server_over(adapters());

    let response = server
        .get(&tenant_path("/user-attributes/kinds"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let kinds: Vec<Value> = response.json();
    let text = kinds.iter().find(|entry| entry["kind"] == "text").unwrap();
    assert_eq!(text["requires_options"], false);
    assert!(text["operators"].is_array());
    assert!(text["default_control"].is_string());
}

/// Declaring a field answers it in the shape a client renders it from, the
/// key derived from the name and nothing exposed that was not asked for.
#[tokio::test]
async fn declaring_an_attribute_answers_it() {
    let server = server_over(adapters());

    let response = server
        .post(&tenant_path("/user-attributes"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"namespace": "app", "kind": "text", "display_name": "Cost Centre"}))
        .await;

    response.assert_status(StatusCode::CREATED);
    let declared: Value = response.json();
    assert_eq!(declared["key"], "cost_centre");
    assert_eq!(declared["namespace"], "app");
    assert_eq!(declared["listed"], false);
    assert_eq!(declared["filterable"], false);
    assert_eq!(declared["archived"], false);
}

/// A namespace that is neither `user` nor `app` is refused.
#[tokio::test]
async fn a_namespace_that_is_neither_is_refused() {
    let (server, _, ann) = with_ann();

    let response = server
        .put(&tenant_path(&format!(
            "/users/{}/attributes/nowhere/department",
            ann.as_uuid()
        )))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"value": "sales"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// No attribute holds an object.
#[tokio::test]
async fn an_object_is_not_something_a_field_can_hold() {
    let (server, _, ann) = with_ann();

    let response = server
        .put(&tenant_path(&format!(
            "/users/{}/attributes/app/department",
            ann.as_uuid()
        )))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"value": {"nested": true}}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Giving consent on another user's behalf returns 403.
#[tokio::test]
async fn consent_given_for_someone_else_is_forbidden() {
    let (server, _, ann) = with_ann();

    let response = server
        .post(&tenant_path(&format!("/users/{}/consent", ann.as_uuid())))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"consent_type": "Marketing", "version": "v1", "granted": true}))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// Cancelling an erasure nobody asked for is not found.
#[tokio::test]
async fn cancelling_an_unknown_erasure_is_not_found() {
    let server = server_over(adapters());

    let response = server
        .post(&tenant_path(&format!(
            "/users/erasure/{}/cancel",
            uuid::Uuid::now_v7()
        )))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// The dashboard reads the signed-in person's own account on every page,
/// with no right to view users needed.
#[tokio::test]
async fn i_read_my_own_account() {
    let server = server_over(Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
        ..adapters()
    });

    let response = server
        .get(&tenant_path("/me"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let me: Value = response.json();
    assert_eq!(me["email"], "caller@example.test");
    assert!(me["profile"].is_object());
}

/// Reading the current user's account without authentication returns 401.
#[tokio::test]
async fn my_account_needs_someone_signed_in() {
    let server = server_over(adapters());

    let response = server.get(&tenant_path("/me")).await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// An admin sets Ann's given name; her account then shows it in its
/// profile.
#[tokio::test]
async fn personal_details_set_show_in_the_profile() {
    let (server, _, ann) = with_ann();
    let user = tenant_path(&format!("/users/{}", ann.as_uuid()));

    let set = server
        .put(&format!("{user}/details"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"given_name": "Ann", "family_name": "Lovelace"}))
        .await;
    let read = server.get(&user).authorization_bearer(TENANT_USER).await;

    set.assert_status(StatusCode::NO_CONTENT);
    let profile = &read.json::<Value>()["profile"];
    assert_eq!(profile["given_name"], "Ann");
    assert_eq!(profile["family_name"], "Lovelace");
    assert_eq!(profile["phone_number"], Value::Null);
}

/// A phone number that is not in international form is refused.
#[tokio::test]
async fn a_phone_number_not_in_international_form_is_refused() {
    let (server, _, ann) = with_ann();

    let response = server
        .put(&tenant_path(&format!("/users/{}/details", ann.as_uuid())))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"phone_number": "030 123456"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Setting directory records with an unknown manager returns 404.
#[tokio::test]
async fn directory_records_naming_an_unknown_manager_are_not_found() {
    let (server, _, ann) = with_ann();

    let response = server
        .put(&tenant_path(&format!("/users/{}/records", ann.as_uuid())))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"department": "Finance", "manager_id": uuid::Uuid::now_v7()}))
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// A server whose imports and job queue the test can look into.
fn with_imports() -> (TestServer, Arc<FakeUserImportStore>, Arc<FakeJobQueue>) {
    let imports = Arc::new(FakeUserImportStore::empty());
    let queue = Arc::new(FakeJobQueue::new());
    let server = server_over(Adapters {
        user_import_store: imports.clone(),
        job_queue: queue.clone(),
        ..adapters()
    });
    (server, imports, queue)
}

/// The import of Bob, with his bcrypt hash.
fn bob_with_a_hash() -> Value {
    json!({"users": [{
        "email": "bob@example.test",
        "display_name": "Bob",
        "password_hash": "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"
    }]})
}

/// An admin brings Bob over from another system with his bcrypt hash. The
/// import is kept and queued for the worker, and answered as accepted with
/// its id; no account is opened in the request.
#[tokio::test]
async fn importing_users_answers_accepted_with_the_import_id() {
    let (server, imports, queue) = with_imports();

    let response = server
        .post(&tenant_path("/users/import"))
        .authorization_bearer(TENANT_USER)
        .json(&bob_with_a_hash())
        .await;

    response.assert_status(StatusCode::ACCEPTED);
    assert!(response.json::<Value>()["import_id"].is_string());
    assert_eq!(imports.count(), 1);
    assert!(queue.holds("identity.import"));
}

/// An unsupported password hash returns 422 and leaves both the import
/// store and job queue empty.
#[tokio::test]
async fn importing_a_hash_in_no_known_form_is_refused() {
    let (server, imports, queue) = with_imports();

    let response = server
        .post(&tenant_path("/users/import"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"users": [{
            "email": "bob@example.test",
            "display_name": "Bob",
            "password_hash": "md5:5f4dcc3b5aa765d61d8327deb882cf99"
        }]}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(imports.count(), 0);
    assert_eq!(queue.count(), 0);
}

/// A plan refusal returns 403 without storing the user import.
#[tokio::test]
async fn importing_past_the_plan_limit_is_forbidden() {
    let imports = Arc::new(FakeUserImportStore::empty());
    let server = server_over(Adapters {
        user_import_store: imports.clone(),
        limit_enforcer: Arc::new(RejectingLimitEnforcer),
        ..adapters()
    });

    let response = server
        .post(&tenant_path("/users/import"))
        .authorization_bearer(TENANT_USER)
        .json(&bob_with_a_hash())
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(imports.count(), 0);
}

/// The admin follows the import she started. It is waiting for the worker,
/// with its one record still to go and nothing set aside.
#[tokio::test]
async fn an_import_shows_where_it_stands() {
    let (server, _, _) = with_imports();
    let started = server
        .post(&tenant_path("/users/import"))
        .authorization_bearer(TENANT_USER)
        .json(&bob_with_a_hash())
        .await
        .json::<Value>();
    let id = started["import_id"].as_str().unwrap();

    let response = server
        .get(&tenant_path(&format!("/users/imports/{id}")))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["status"], "pending");
    assert_eq!(body["total"], 1);
    assert_eq!(body["remaining"], 1);
    assert_eq!(body["errors"], json!([]));
}

/// An import the tenant never had is not found.
#[tokio::test]
async fn an_unknown_import_is_not_found() {
    let (server, _, _) = with_imports();

    let response = server
        .get(&tenant_path(&format!(
            "/users/imports/{}",
            uuid::Uuid::now_v7()
        )))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// An admin mails Ann a reset link instead of choosing her password.
#[tokio::test]
async fn an_admin_mails_a_reset_link() {
    let (server, _, ann) = with_ann();

    let response = server
        .post(&tenant_path(&format!(
            "/users/{}/send-reset-link",
            ann.as_uuid()
        )))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::NO_CONTENT);
}

/// Ann lost her phone and her codes; an admin clears her factors and is
/// told what was taken away.
#[tokio::test]
async fn clearing_a_users_factors_says_what_was_cleared() {
    let (server, _, ann) = with_ann();

    let response = server
        .post(&tenant_path(&format!(
            "/users/{}/reset-factors",
            ann.as_uuid()
        )))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let cleared: Value = response.json();
    assert!(cleared["enrollments_turned_off"].is_u64());
    assert!(cleared["passkeys_removed"].is_u64());
}

/// A time filter that is not RFC 3339 is refused, not ignored.
#[tokio::test]
async fn a_malformed_time_filter_is_refused() {
    let (server, _, _) = with_ann();

    let response = server
        .get(&tenant_path("/users?created_from=yesterday"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Ann lists her own sessions, in the shape the security page reads.
#[tokio::test]
async fn i_list_my_sessions() {
    let server = server_over(Adapters {
        user_store: Arc::new(FakeUserStore::with_user(
            test_caller_id(),
            "ann@example.test",
        )),
        ..adapters()
    });

    let response = server
        .get(&tenant_path("/me/sessions"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    assert!(response.json::<Value>().is_array());
}

/// Ann signs out everywhere else and is told how many sessions ended.
#[tokio::test]
async fn signing_out_everywhere_else_counts_what_ended() {
    let server = server_over(adapters());

    let response = server
        .post(&tenant_path("/me/sessions/sign-out-others"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    assert!(response.json::<Value>()["signed_out"].is_u64());
}

/// Ann reads her own sign-in history as a page.
#[tokio::test]
async fn i_read_my_sign_in_history() {
    let server = server_over(Adapters {
        user_store: Arc::new(FakeUserStore::with_user(test_caller_id(), "ann@acme.test")),
        ..adapters()
    });

    let response = server
        .get(&tenant_path("/me/sign-ins"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let page: Value = response.json();
    assert!(page["items"].is_array());
    assert!(page.get("next_cursor").is_some());
}

/// Reading another user's sign-ins without tenant authority returns 403.
#[tokio::test]
async fn another_users_sign_ins_need_the_app_to_allow_it() {
    let ann = UserId::new();
    let server = server_over(Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    });

    let response = server
        .get(&tenant_path(&format!("/users/{}/sign-ins", ann.as_uuid())))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// An admin reads Ann's consent history.
#[tokio::test]
async fn a_users_consent_history_is_read() {
    let (server, _, ann) = with_ann();

    let response = server
        .get(&tenant_path(&format!("/users/{}/consent", ann.as_uuid())))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    assert!(response.json::<Value>().is_array());
}

/// Staff ask for a copy of Ann's data under the right of access; the
/// export's id comes back.
#[tokio::test]
async fn asking_for_a_data_export_answers_its_id() {
    let (server, _, ann) = with_ann();

    let response = server
        .post(&tenant_path(&format!("/users/{}/exports", ann.as_uuid())))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"scope": "access"}))
        .await;

    response.assert_status(StatusCode::CREATED);
    assert!(response.json::<Value>()["id"].is_string());
}

/// Downloading an export nobody asked for is not found.
#[tokio::test]
async fn downloading_an_unknown_export_is_not_found() {
    let server = server_over(adapters());

    let response = server
        .post(&tenant_path(&format!(
            "/users/exports/{}/download",
            uuid::Uuid::now_v7()
        )))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// A one-minute impersonation window falls below the allowed duration and returns 422.
#[tokio::test]
async fn an_impersonation_window_outside_the_rules_is_refused() {
    let (server, _, ann) = with_ann();

    let response = server
        .post(&tenant_path(&format!(
            "/users/{}/impersonations",
            ann.as_uuid()
        )))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"reason": "ticket 42", "minutes": 1}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A person lists the impersonations naming them, and has none.
#[tokio::test]
async fn i_list_the_impersonations_naming_me() {
    let server = server_over(adapters());

    let response = server
        .get(&tenant_path("/impersonations"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_json(&json!([]));
}

/// A user-list request naming an unknown impersonation returns 404.
#[tokio::test]
async fn acting_through_an_unknown_impersonation_is_not_found() {
    let server = server_over(adapters());

    let response = server
        .get(&tenant_path("/users"))
        .authorization_bearer(TENANT_USER)
        .add_header(
            "ianua-support-impersonation",
            uuid::Uuid::now_v7().to_string(),
        )
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// A malformed impersonation header makes the user-list request return 422.
#[tokio::test]
async fn a_garbled_impersonation_header_is_refused() {
    let server = server_over(adapters());

    let response = server
        .get(&tenant_path("/users"))
        .authorization_bearer(TENANT_USER)
        .add_header("ianua-support-impersonation", "someone")
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}
