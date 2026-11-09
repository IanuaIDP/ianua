//! A member's sign-in that waits for its second factor: answering it with a
//! code or a recovery code, and setting up the first factor it owes, each
//! with the waiting sign-in's own refresh token as the bearer. Until it is
//! answered, the sign-in reaches nothing else of the organization.
//!
//! The bearers are resolved from the stored sessions, as the platform's
//! lookup resolves them, and every caller is worked out from the stored
//! records, so a session still waiting is treated here as it is in a
//! deployment.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::{TestResponse, TestServer};
use ianua_api::test_support::{ORG, StoredOrgSessions, adapters, router};
use ianua_app::acting::organization::{OrgActing, OrgActingPorts};
use ianua_app::ports::organization::OrgSessionStore as _;
use ianua_app::test_support::authentication::{FakeMfaEnrollmentStore, Holder};
use ianua_app::test_support::organization::{
    FakeOrgRecoveryCodeStore, RecordingOrgSessionStore, org_user_store_with, stored_caller,
};
use ianua_app::test_support::{Fake, test_org_caller};
use ianua_assembly::deps::Adapters;
use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::sessions::mfa_factor::{FactorProved, MfaFactor};
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
use ianua_domain::domains::authentication::sessions::status::SessionStatus;
use ianua_domain::domains::organization::access::session::{
    OrgSession, OrgSessionRow, SessionPlace,
};
use ianua_domain::domains::organization::members::membership::OrgRole;
use ianua_domain::shared::clock;
use ianua_domain::types::{
    CredentialChange, Fact, OrgUserId, OrganizationId, SessionId, TokenHash,
};
use serde_json::{Value, json};

/// The password the owner signs in with.
const PASSPHRASE: &str = "Correct-Horse-Battery-9";

/// The code the test authenticator shows.
const RIGHT_CODE: &str = "123456";

/// The recovery code the owner kept, as the fake generator hashes it.
const RECOVERY_CODE: &str = "code_0";

/// The path under the test organization.
fn org_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}{rest}")
}

/// Whether the owner has set up an authenticator app.
#[derive(Clone, Copy)]
enum Authenticator {
    /// Set up, with one unused recovery code kept beside it.
    SetUp,
    /// Never set up.
    None,
}

/// Acme, whose owner Olivia signs in with a password, and the sessions
/// kept for its members.
struct Acme {
    server: TestServer,
    sessions: Arc<RecordingOrgSessionStore>,
    olivia: OrgUserId,
}

/// A sign-in the login answered: its session and refresh token.
struct SignIn {
    session_id: String,
    bearer: String,
}

impl Acme {
    /// Acme with Olivia's authenticator as `authenticator` says.
    fn with(authenticator: Authenticator) -> Self {
        let base = adapters();
        let owner = stored_caller(OrgRole::Owner, PASSPHRASE);
        let olivia = *owner.id();
        let members = Arc::new(org_user_store_with([owner]));
        let sessions = Arc::new(RecordingOrgSessionStore::new());
        let org_actors = OrgActing::new(OrgActingPorts {
            organizations: base.organization_store.clone(),
            org_users: members.clone(),
            org_sessions: sessions.clone(),
            org_api_keys: Fake::fake(),
        });
        let (enrollments, recovery_codes) = factors_of(olivia, authenticator);
        let server = TestServer::new(router(Adapters {
            org_user_store: members,
            org_session_store: sessions.clone(),
            org_mfa_enrollment_store: Arc::new(enrollments),
            org_recovery_code_store: Arc::new(recovery_codes),
            token_resolver: Arc::new(StoredOrgSessions::over(sessions.clone())),
            org_actors: Arc::new(org_actors),
            ..base
        }))
        .unwrap();
        Self {
            server,
            sessions,
            olivia,
        }
    }

    /// Olivia signs in with her password. The answer says her sign-in owes
    /// a code from her authenticator.
    async fn sign_in(&self) -> SignIn {
        let response = self
            .server
            .post("/api/v1/login")
            .json(&json!({"email": "caller@example.test", "password": PASSPHRASE}))
            .await;
        response.assert_status_ok();
        let answer: Value = response.json();
        assert_eq!(answer["mfa_required"], true);
        assert_eq!(answer["mfa_enrollment_required"], false);
        SignIn {
            session_id: answer["session_id"].as_str().unwrap().to_owned(),
            bearer: answer["refresh_token"].as_str().unwrap().to_owned(),
        }
    }

    /// A session of `member` of `organization`, signed in as `progress`
    /// says, kept under the refresh token it returns.
    async fn session_of(
        &self,
        member: OrgUserId,
        organization: OrganizationId,
        progress: SignInProgressRow,
    ) -> SignIn {
        let id = SessionId::new();
        let token = id.as_uuid().simple().to_string();
        let now = clock::now();
        let session = OrgSession::reconstitute(OrgSessionRow {
            id,
            org_user_id: member,
            organization_id: organization,
            place: SessionPlace::Organization,
            refresh_token_hash: TokenHash::from_stored(format!("fake_hash_{token}")),
            progress,
            ip_address: Fact::Unknown,
            user_agent: Fact::Unknown,
            status: SessionStatus::Active,
            created_at: now,
            last_active_at: now,
            expires_at: now + time::Duration::hours(8),
            kept_through: CredentialChange::Never,
        })
        .unwrap();
        self.sessions.save(&session).await.unwrap();
        SignIn {
            session_id: id.as_uuid().to_string(),
            bearer: format!("fake_refresh_{token}"),
        }
    }

    /// One of Olivia's sessions, signed in as `progress` says.
    async fn olivias_session(&self, progress: SignInProgressRow) -> SignIn {
        let organization = test_org_caller().organization_id();
        self.session_of(self.olivia, organization, progress).await
    }

    /// `bearer` answers its sign-in with `code` from the authenticator.
    async fn verify(&self, bearer: &str, code: &str) -> TestResponse {
        self.server
            .post(&org_path("/mfa/verify"))
            .authorization_bearer(bearer)
            .json(&json!({"code": code}))
            .await
    }

    /// `bearer` reads who they are in the organization.
    async fn me(&self, bearer: &str) -> TestResponse {
        self.server
            .get(&org_path("/me"))
            .authorization_bearer(bearer)
            .await
    }
}

/// Olivia's authenticator and recovery codes, as `authenticator` says.
fn factors_of(
    olivia: OrgUserId,
    authenticator: Authenticator,
) -> (FakeMfaEnrollmentStore, FakeOrgRecoveryCodeStore) {
    let organization = test_org_caller().organization_id();
    match authenticator {
        Authenticator::SetUp => (
            FakeMfaEnrollmentStore::active_for(Holder::member_of(organization, olivia)),
            FakeOrgRecoveryCodeStore::with_codes(olivia, &["hash_0"]),
        ),
        Authenticator::None => (
            FakeMfaEnrollmentStore::empty(),
            FakeOrgRecoveryCodeStore::new(),
        ),
    }
}

/// A password sign-in that owes `owed` and proved no second factor yet.
fn owing(owed: SecondFactor) -> SignInProgressRow {
    SignInProgressRow {
        method: AuthMethod::Password,
        factor: FactorProved::NoneYet,
        owed,
    }
}

/// A password sign-in that answered its code and owes nothing more.
fn finished() -> SignInProgressRow {
    SignInProgressRow {
        method: AuthMethod::Password,
        factor: FactorProved::Proved(MfaFactor::Totp),
        owed: SecondFactor::NotOwed,
    }
}

/// Olivia set up an authenticator app. She signs in with her password,
/// owes a code, and answers it with the refresh token of that sign-in.
/// The sign-in is complete, and her session now reads who she is.
#[tokio::test]
async fn an_owner_answers_their_sign_in_with_a_code_from_their_authenticator() {
    let acme = Acme::with(Authenticator::SetUp);
    let sign_in = acme.sign_in().await;

    let response = acme.verify(&sign_in.bearer, RIGHT_CODE).await;

    response.assert_status(StatusCode::NO_CONTENT);
    acme.me(&sign_in.bearer).await.assert_status_ok();
}

/// A session awaiting its second factor receives 401 from both the member
/// profile and organization-access endpoints.
#[tokio::test]
async fn a_sign_in_waiting_for_its_code_reads_nothing_of_the_organization() {
    let acme = Acme::with(Authenticator::SetUp);
    let sign_in = acme.sign_in().await;

    let me = acme.me(&sign_in.bearer).await;
    let access = acme
        .server
        .get(&org_path("/me/access"))
        .authorization_bearer(&sign_in.bearer)
        .await;

    me.assert_status(StatusCode::UNAUTHORIZED);
    access.assert_status(StatusCode::UNAUTHORIZED);
}

/// An incorrect second-factor code returns 403 and leaves the session
/// unable to read the member profile.
#[tokio::test]
async fn a_wrong_code_is_refused_and_the_sign_in_still_waits() {
    let acme = Acme::with(Authenticator::SetUp);
    let sign_in = acme.sign_in().await;

    let response = acme.verify(&sign_in.bearer, "000000").await;

    response.assert_status(StatusCode::FORBIDDEN);
    acme.me(&sign_in.bearer)
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

/// Completing another organization's waiting sign-in on Acme's route returns 403.
#[tokio::test]
async fn another_organizations_waiting_sign_in_is_refused() {
    let acme = Acme::with(Authenticator::SetUp);
    let mallorys = acme
        .session_of(
            OrgUserId::new(),
            OrganizationId::new(),
            owing(SecondFactor::Verify),
        )
        .await;

    let response = acme.verify(&mallorys.bearer, RIGHT_CODE).await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// Repeating verification after a session proves its second factor returns 409.
#[tokio::test]
async fn a_finished_session_answers_no_code() {
    let acme = Acme::with(Authenticator::SetUp);
    let session = acme.olivias_session(finished()).await;

    let response = acme.verify(&session.bearer, RIGHT_CODE).await;

    response.assert_status(StatusCode::CONFLICT);
}

/// Olivia lost her phone. She signs in with her password and answers the
/// code her sign-in owes with a recovery code she kept, with the refresh
/// token of that sign-in. The sign-in is complete.
#[tokio::test]
async fn a_waiting_sign_in_is_answered_with_a_recovery_code() {
    let acme = Acme::with(Authenticator::SetUp);
    let sign_in = acme.sign_in().await;

    let response = acme
        .server
        .post(&org_path("/mfa/recovery"))
        .authorization_bearer(&sign_in.bearer)
        .json(&json!({"code": RECOVERY_CODE}))
        .await;

    response.assert_status_ok();
    response.assert_json(&json!({"mfa_enrollment_required": false}));
    acme.me(&sign_in.bearer).await.assert_status_ok();
}

/// An unknown mailbox-confirmation link returns 404, and the waiting
/// session still receives 401 from the member profile endpoint.
#[tokio::test]
async fn a_mailed_confirmation_with_a_guessed_link_is_refused() {
    let acme = Acme::with(Authenticator::None);
    let sign_in = acme
        .olivias_session(owing(SecondFactor::ConfirmByEmail))
        .await;

    let response = acme
        .server
        .post("/api/v1/login/confirm")
        .json(&json!({"token": "a-link-nobody-mailed", "refresh_token": sign_in.bearer}))
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
    acme.me(&sign_in.bearer)
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

/// Olivia's organization asks every member for a second factor, and she
/// has none yet, so her sign-in waits for her to set one up. With that
/// sign-in's refresh token she begins an authenticator, confirms it with a
/// code naming the sign-in, and the sign-in is complete.
#[tokio::test]
async fn a_sign_in_that_owes_its_first_factor_sets_it_up() {
    let acme = Acme::with(Authenticator::None);
    let sign_in = acme.olivias_session(owing(SecondFactor::Enrol)).await;

    let begun = acme
        .server
        .post(&org_path("/mfa/begin"))
        .authorization_bearer(&sign_in.bearer)
        .await;
    let confirmed = acme
        .server
        .post(&org_path("/mfa/confirm"))
        .authorization_bearer(&sign_in.bearer)
        .json(&json!({"code": RIGHT_CODE, "session_id": sign_in.session_id}))
        .await;

    begun.assert_status_ok();
    confirmed.assert_status_ok();
    acme.me(&sign_in.bearer).await.assert_status_ok();
}

/// One waiting session's bearer cannot confirm an authenticator for another;
/// the response is 403.
#[tokio::test]
async fn confirming_names_only_the_sign_in_of_the_bearer() {
    let acme = Acme::with(Authenticator::None);
    let mallorys = acme.olivias_session(owing(SecondFactor::Enrol)).await;
    let other = acme.olivias_session(owing(SecondFactor::Enrol)).await;

    let response = acme
        .server
        .post(&org_path("/mfa/confirm"))
        .authorization_bearer(&mallorys.bearer)
        .json(&json!({"code": RIGHT_CODE, "session_id": other.session_id}))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}
