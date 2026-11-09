//! The SCIM service: what a tenant's directory is answered, in SCIM's own
//! format.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::http::header::{CONTENT_TYPE, ETAG, IF_NONE_MATCH};
use axum_test::TestServer;
use ianua_api::test_support::{ORG, TENANT, adapters, router};
use ianua_app::test_support::federation::FakeScimUserQueries;
use ianua_app::test_support::identity::{FakeUserStore, user_with_profile};
use ianua_app::test_support::scim::{SCIM_TOKEN, signed_in};
use ianua_app::test_support::test_ctx;
use ianua_assembly::deps::Adapters;
use ianua_domain::domains::identity::account::profile_values::{
    Department, EmployeeNumber, ExternalId, FamilyName, GivenName,
};
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::identity::account::user_profile::{
    DirectoryRecords, PersonalDetails, UserProfile,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{Setting, UserId};
use serde_json::{Value, json};

const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const ENTERPRISE_SCHEMA: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
const LIMITS_SCHEMA: &str =
    "urn:ianua:params:scim:schemas:extension:limits:2.0:ServiceProviderConfig";

/// The test tenant's SCIM address, followed by `rest`.
fn scim_path(rest: &str) -> String {
    format!("/scim/v2/organizations/{ORG}/tenants/{TENANT}{rest}")
}

/// A server whose test tenant has SCIM switched on, signing in
/// [`SCIM_TOKEN`].
fn switched_on() -> TestServer {
    TestServer::new(router(Adapters {
        scim_authorities: signed_in(),
        ..adapters()
    }))
    .unwrap()
}

/// A person the directory sent with every profile field it keeps.
fn person(email: &str, given: &str, family: &str, external_id: &str) -> User<ResolvedTenant> {
    user_with_profile(
        UserId::from_uuid(uuid::Uuid::now_v7()),
        email,
        UserProfile {
            details: PersonalDetails {
                given_name: Setting::Set(GivenName::new(given).unwrap()),
                family_name: Setting::Set(FamilyName::new(family).unwrap()),
                ..PersonalDetails::default()
            },
            records: DirectoryRecords {
                external_id: Setting::Set(ExternalId::new(external_id).unwrap()),
                department: Setting::Set(Department::new("Research").unwrap()),
                employee_number: Setting::Set(EmployeeNumber::new(external_id).unwrap()),
                manager: Setting::Unset,
            },
        },
    )
}

/// A server whose directory sees Ada Lovelace (`00u1`) and Grace Hopper
/// (`00u2`).
fn with_people() -> TestServer {
    let people = [
        person("ada@acme.com", "Ada", "Lovelace", "00u1"),
        person("grace@acme.com", "Grace", "Hopper", "00u2"),
    ];
    TestServer::new(router(Adapters {
        scim_authorities: signed_in(),
        scim_user_queries: Arc::new(FakeScimUserQueries::holding(&test_ctx().tenant(), people)),
        ..adapters()
    }))
    .unwrap()
}

/// The `userName`s of a list response, in order.
fn user_names(body: &Value) -> Vec<String> {
    body["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|user| user["userName"].as_str().unwrap().to_owned())
        .collect()
}

/// A provider setting up a connection reads what the service supports, as
/// SCIM JSON: patch, filters, sorting and ETags, and no bulk.
#[tokio::test]
async fn the_service_provider_config_is_scim_json() {
    let server = switched_on();

    let response = server.get(&scim_path("/ServiceProviderConfig")).await;

    response.assert_status_ok();
    assert_eq!(
        response.headers().get(CONTENT_TYPE).unwrap(),
        "application/scim+json"
    );
    let body: Value = response.json();
    assert_eq!(body["patch"]["supported"], true);
    assert_eq!(body["sort"]["supported"], true);
    assert_eq!(body["etag"]["supported"], true);
    assert_eq!(body["bulk"]["supported"], false);
}

/// A provider setting up a connection reads how many members one group
/// write may name, in the service's own extension of the configuration.
#[tokio::test]
async fn the_service_provider_config_gives_the_member_cap() {
    let server = switched_on();

    let response = server.get(&scim_path("/ServiceProviderConfig")).await;

    let body: Value = response.json();
    let limits = &body[LIMITS_SCHEMA];
    assert_eq!(limits["maxMembersPerOperation"], 1_000);
    assert!(
        body["schemas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|schema| schema == LIMITS_SCHEMA)
    );
}

/// A group write with 1,001 members returns 400 with the SCIM tooMany error.
#[tokio::test]
async fn a_group_write_naming_too_many_members_is_too_many() {
    let server = switched_on();
    let members: Vec<Value> = (0..1_001)
        .map(|_| json!({"value": uuid::Uuid::now_v7().to_string()}))
        .collect();

    let response = server
        .post(&scim_path("/Groups"))
        .authorization_bearer(SCIM_TOKEN)
        .json(&json!({"displayName": "Engineering", "members": members}))
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(body["scimType"], "tooMany");
    assert_eq!(body["status"], "400");
}

/// The directory lists the users with its token and gets a SCIM list
/// response.
#[tokio::test]
async fn the_directory_lists_users() {
    let server = switched_on();

    let response = server
        .get(&scim_path("/Users"))
        .authorization_bearer(SCIM_TOKEN)
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(
        body["schemas"],
        json!(["urn:ietf:params:scim:api:messages:2.0:ListResponse"])
    );
    assert_eq!(body["totalResults"], 0);
    assert_eq!(body["startIndex"], 1);
    assert_eq!(body["Resources"], json!([]));
}

/// A user is answered with the profile fields the directory sent: its
/// `externalId`, the name's parts, and the enterprise extension.
#[tokio::test]
async fn a_listed_user_carries_its_profile_fields() {
    let server = with_people();

    let response = server
        .get(&scim_path("/Users"))
        .add_query_param("filter", "externalId eq \"00u1\"")
        .authorization_bearer(SCIM_TOKEN)
        .await;

    response.assert_status_ok();
    let ada = &response.json::<Value>()["Resources"][0];
    assert_eq!(ada["externalId"], "00u1");
    assert_eq!(ada["name"]["givenName"], "Ada");
    assert_eq!(ada["name"]["familyName"], "Lovelace");
    assert_eq!(ada[ENTERPRISE_SCHEMA]["department"], "Research");
    assert_eq!(ada[ENTERPRISE_SCHEMA]["employeeNumber"], "00u1");
    assert!(
        ada["schemas"]
            .as_array()
            .unwrap()
            .contains(&json!(ENTERPRISE_SCHEMA))
    );
    assert!(ada["meta"]["version"].as_str().unwrap().starts_with("W/\""));
}

/// Entra ID finds people with `co`, `sw` and `or`: each filter picks the
/// people it names.
#[tokio::test]
async fn filters_compare_with_co_sw_and_or() {
    let server = with_people();

    let either = server
        .get(&scim_path("/Users"))
        .add_query_param(
            "filter",
            "name.familyName sw \"hop\" or userName co \"ada@\"",
        )
        .authorization_bearer(SCIM_TOKEN)
        .await;
    let both = server
        .get(&scim_path("/Users"))
        .add_query_param(
            "filter",
            "(department eq \"research\") and displayName co \"test\" and externalId eq \"00u2\"",
        )
        .authorization_bearer(SCIM_TOKEN)
        .await;

    assert_eq!(either.json::<Value>()["totalResults"], 2);
    assert_eq!(user_names(&both.json()), ["grace@acme.com"]);
}

/// `sortBy` with `sortOrder=descending` lists Grace before Ada.
#[tokio::test]
async fn users_are_sorted_as_asked() {
    let server = with_people();

    let response = server
        .get(&scim_path("/Users"))
        .add_query_param("sortBy", "name.givenName")
        .add_query_param("sortOrder", "descending")
        .authorization_bearer(SCIM_TOKEN)
        .await;

    response.assert_status_ok();
    assert_eq!(
        user_names(&response.json()),
        ["grace@acme.com", "ada@acme.com"]
    );
}

/// A `sortBy` naming an attribute the service does not keep is an
/// `invalidValue`.
#[tokio::test]
async fn sorting_by_an_unkept_attribute_is_an_invalid_value() {
    let server = with_people();

    let response = server
        .get(&scim_path("/Users"))
        .add_query_param("sortBy", "title")
        .authorization_bearer(SCIM_TOKEN)
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(response.json::<Value>()["scimType"], "invalidValue");
}

/// Groups are listed in one order, so a `sortBy` on them is refused.
#[tokio::test]
async fn groups_are_not_sorted() {
    let server = switched_on();

    let response = server
        .get(&scim_path("/Groups"))
        .add_query_param("sortBy", "displayName")
        .authorization_bearer(SCIM_TOKEN)
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(response.json::<Value>()["scimType"], "invalidValue");
}

/// A lookup by an attribute the service does not keep matches nobody, so
/// the provider goes on to create the user.
#[tokio::test]
async fn a_filter_on_an_unkept_attribute_matches_nobody() {
    let server = with_people();

    let response = server
        .get(&scim_path("/Users"))
        .add_query_param("filter", "title eq \"Engineer\"")
        .authorization_bearer(SCIM_TOKEN)
        .await;

    response.assert_status_ok();
    assert_eq!(response.json::<Value>()["totalResults"], 0);
}

/// A user is answered with its version as the `ETag`; sent back in
/// `If-None-Match`, the answer is `304` with no body.
#[tokio::test]
async fn a_user_the_directory_holds_already_is_not_modified() {
    let id = UserId::from_uuid(uuid::Uuid::now_v7());
    let server = TestServer::new(router(Adapters {
        scim_authorities: signed_in(),
        user_store: Arc::new(FakeUserStore::with_user(id, "ada@acme.com")),
        ..adapters()
    }))
    .unwrap();
    let path = scim_path(&format!("/Users/{id}"));

    let first = server.get(&path).authorization_bearer(SCIM_TOKEN).await;
    let etag = first.header(ETAG).to_str().unwrap().to_owned();
    let again = server
        .get(&path)
        .authorization_bearer(SCIM_TOKEN)
        .add_header(IF_NONE_MATCH, etag.as_str())
        .await;
    let stale = server
        .get(&path)
        .authorization_bearer(SCIM_TOKEN)
        .add_header(IF_NONE_MATCH, "W/\"0000000000000000\"")
        .await;

    first.assert_status_ok();
    assert_eq!(first.json::<Value>()["meta"]["version"], etag);
    again.assert_status(StatusCode::NOT_MODIFIED);
    assert!(again.text().is_empty());
    stale.assert_status_ok();
}

/// `/Me` is not offered: every method is answered `501` in SCIM's error
/// format.
#[tokio::test]
async fn me_is_not_implemented() {
    let server = switched_on();

    let read = server.get(&scim_path("/Me")).await;
    let write = server
        .post(&scim_path("/Me"))
        .authorization_bearer(SCIM_TOKEN)
        .json(&json!({"userName": "ada@acme.com"}))
        .await;

    read.assert_status(StatusCode::NOT_IMPLEMENTED);
    write.assert_status(StatusCode::NOT_IMPLEMENTED);
    let body: Value = read.json();
    assert_eq!(body["schemas"], json!([ERROR_SCHEMA]));
    assert_eq!(body["status"], "501");
}

/// Listing users without a token returns 401 in the SCIM error schema.
#[tokio::test]
async fn a_request_without_the_token_is_unauthenticated() {
    let server = switched_on();

    let response = server.get(&scim_path("/Users")).await;

    response.assert_status(StatusCode::UNAUTHORIZED);
    let body: Value = response.json();
    assert_eq!(body["schemas"], json!([ERROR_SCHEMA]));
    assert_eq!(body["status"], "401");
}

/// A filter on an unkept attribute still requires a token and otherwise returns 401.
#[tokio::test]
async fn a_filter_matching_nobody_still_needs_the_token() {
    let server = switched_on();

    let response = server
        .get(&scim_path("/Users"))
        .add_query_param("filter", "title eq \"x-1\"")
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// Listing groups with a guessed token returns 401.
#[tokio::test]
async fn a_guessed_token_is_unauthenticated() {
    let server = switched_on();

    let response = server
        .get(&scim_path("/Groups"))
        .authorization_bearer("guessed")
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// A user whose `userName` is no address, with no email to fall back on, is
/// an `invalidValue`.
#[tokio::test]
async fn a_user_without_an_address_is_an_invalid_value() {
    let server = switched_on();

    let response = server
        .post(&scim_path("/Users"))
        .authorization_bearer(SCIM_TOKEN)
        .json(&json!({"userName": "ada"}))
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(body["scimType"], "invalidValue");
    assert_eq!(body["status"], "400");
}

/// A filter in a form the service does not read is an `invalidFilter`.
#[tokio::test]
async fn an_unsupported_filter_is_an_invalid_filter() {
    let server = switched_on();

    let response = server
        .get(&scim_path("/Users"))
        .add_query_param("filter", "userName ne \"ada\"")
        .authorization_bearer(SCIM_TOKEN)
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(response.json::<Value>()["scimType"], "invalidFilter");
}

/// A user the tenant does not have is not found.
#[tokio::test]
async fn an_unknown_user_is_not_found() {
    let server = switched_on();

    let response = server
        .get(&scim_path(&format!("/Users/{}", uuid::Uuid::now_v7())))
        .authorization_bearer(SCIM_TOKEN)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
    assert_eq!(response.json::<Value>()["schemas"], json!([ERROR_SCHEMA]));
}

/// A guessed token receives identical 401 bodies for known and unknown tenants.
#[tokio::test]
async fn an_unknown_tenant_answers_like_a_wrong_token() {
    let server = switched_on();

    let unknown = server
        .get(&format!(
            "/scim/v2/organizations/{ORG}/tenants/nobody/Users"
        ))
        .authorization_bearer("guess")
        .await;
    let wrong = server
        .get(&scim_path("/Users"))
        .authorization_bearer("guess")
        .await;

    unknown.assert_status(StatusCode::UNAUTHORIZED);
    wrong.assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(unknown.text(), wrong.text());
}

/// Repeated SCIM requests with a guessed token exhaust the address allowance
/// and receive 429.
#[tokio::test]
async fn the_scim_service_is_limited_per_address() {
    let server = switched_on();
    let mut last = StatusCode::OK;

    for _ in 0..610 {
        last = server
            .get(&scim_path("/Users"))
            .authorization_bearer("guess")
            .await
            .status_code();
    }

    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}
