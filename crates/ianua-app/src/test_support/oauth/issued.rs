//! What the OAuth flows hand out, as a test seeds it: an authorization code
//! for a client, a device request, the session a person consents in, and
//! the access and refresh tokens a client holds.

use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::sessions::channel::SessionChannel;
use ianua_domain::domains::authentication::sessions::mfa_factor::FactorProved;
use ianua_domain::domains::authentication::sessions::session::{
    Session, SessionOrigin, SessionRow,
};
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
use ianua_domain::domains::authentication::sessions::status::SessionStatus;
use ianua_domain::domains::oauth::clients::client::OAuthClient;
use ianua_domain::domains::oauth::grants::access_token::{
    AccessAudience, AccessToken, AccessTokenRow, TokenSubject,
};
use ianua_domain::domains::oauth::grants::authorization_code::{
    AuthCodeRow, AuthorizationCode, CodeChallenge, CodeChallengeMethod, NonceSent,
};
use ianua_domain::domains::oauth::grants::device_authorization::{
    DeviceAuthRow, DeviceAuthState, LastPoll, PollInterval,
};
use ianua_domain::domains::oauth::grants::refresh_token::{
    GrantedIn, OAuthRefreshTokenRow, RefreshState,
};
use ianua_domain::domains::oauth::grants::token_binding::SenderBinding;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::types::{
    CredentialChange, DeviceUserCode, Fact, RefreshFamilyId, Revocation, Scope, SessionId,
    TokenHash, Usage, UserId,
};
use time::Duration;

use crate::test_support::oauth::codes::hash_of;
use crate::test_support::test_session_id;

/// The raw authorization code every seeded code is redeemed with.
pub const TEST_RAW_CODE: &str = "code_raw";

/// The PKCE verifier every seeded code is made for. The fake PKCE port
/// makes a verifier's challenge from its own text, so the code keeps this
/// as its challenge.
pub const TEST_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

/// The raw device code every seeded device request is polled with.
pub const TEST_DEVICE_CODE: &str = "device_raw";

/// The user code every seeded device request shows.
pub const TEST_USER_CODE: &str = "ABCD-1234";

/// An unused code `client` was issued for `user_id`, to its first redirect,
/// for `openid` and `read`, consented in the test session after a password
/// sign-in a minute ago, as storage keeps it.
#[must_use]
pub fn code_row(client: &OAuthClient<ResolvedTenant>, user_id: UserId) -> AuthCodeRow {
    let now = clock::now();
    AuthCodeRow {
        code_hash: hash_of(TEST_RAW_CODE),
        client_id: *client.id(),
        user_id,
        redirect_uri: client.redirect_uris()[0].clone(),
        scopes: vec![
            Scope::new("openid").expect("a valid scope"),
            Scope::new("read").expect("a valid scope"),
        ],
        code_challenge: CodeChallenge::new(TEST_VERIFIER).expect("a valid challenge"),
        code_challenge_method: CodeChallengeMethod::S256,
        nonce: NonceSent::NotSent,
        session_id: test_session_id(),
        auth_method: AuthMethod::Password,
        second_factor: FactorProved::NoneYet,
        authenticated_at: now - Duration::minutes(1),
        created_at: now,
        expires_at: now + Duration::minutes(1),
        usage: Usage::Unused,
    }
}

/// The code [`code_row`] describes.
#[must_use]
pub fn issued_code(
    client: &OAuthClient<ResolvedTenant>,
    user_id: UserId,
) -> AuthorizationCode<ResolvedTenant> {
    AuthorizationCode::reconstitute(code_row(client, user_id)).expect("a consistent code row")
}

/// A device request `client` started for `read`, in `state`, polled with
/// [`TEST_DEVICE_CODE`] and showing [`TEST_USER_CODE`], with ten minutes
/// left, as storage keeps it.
#[must_use]
pub fn device_row(client: &OAuthClient<ResolvedTenant>, state: DeviceAuthState) -> DeviceAuthRow {
    let now = clock::now();
    DeviceAuthRow {
        device_code_hash: hash_of(TEST_DEVICE_CODE),
        user_code: DeviceUserCode::new(TEST_USER_CODE).expect("a valid user code"),
        client_id: *client.id(),
        scopes: vec![Scope::new("read").expect("a valid scope")],
        state,
        interval: PollInterval::DEFAULT,
        last_poll: LastPoll::Never,
        created_at: now - Duration::minutes(1),
        expires_at: now + Duration::minutes(10),
    }
}

/// `user_id` signed in with a password a minute ago to session `id`, which
/// is active and finished.
#[must_use]
pub fn signed_in_session(id: SessionId, user_id: UserId) -> Session<ResolvedTenant> {
    let now = clock::now();
    let started = now - Duration::minutes(1);
    Session::reconstitute(SessionRow {
        id,
        user_id,
        refresh_token_hash: TokenHash::from_stored("refresh".to_owned()),
        parent_id: SessionOrigin::SignIn,
        ip_address: Fact::Unknown,
        user_agent: Fact::Unknown,
        signed_in_from: Fact::Unknown,
        progress: SignInProgressRow {
            method: AuthMethod::Password,
            factor: FactorProved::NoneYet,
            owed: SecondFactor::NotOwed,
        },
        status: SessionStatus::Active,
        channel: SessionChannel::Dashboard,
        signed_in_at: started,
        created_at: started,
        last_active_at: now,
        expires_at: now + Duration::hours(1),
        kept_through: CredentialChange::Never,
        last_use: Fact::Unknown,
    })
    .expect("a fresh, finished session is a consistent row")
}

/// The raw refresh token every seeded refresh token is used with.
pub const TEST_REFRESH_TOKEN: &str = "refresh_raw";

/// The raw access token every seeded access token is presented with.
pub const TEST_ACCESS_TOKEN: &str = "access_raw";

/// An active bearer refresh token `client` holds for `user_id`, for
/// `openid` and `read`, granted in the test session, issued a minute ago,
/// with a day to run and thirty in its family, as storage keeps it.
#[must_use]
pub fn refresh_row(client: &OAuthClient<ResolvedTenant>, user_id: UserId) -> OAuthRefreshTokenRow {
    let now = clock::now();
    OAuthRefreshTokenRow {
        token_hash: hash_of(TEST_REFRESH_TOKEN),
        family: RefreshFamilyId::new(),
        client_id: *client.id(),
        user_id,
        scopes: vec![
            Scope::new("openid").expect("a valid scope"),
            Scope::new("read").expect("a valid scope"),
        ],
        granted_in: GrantedIn::Session(test_session_id()),
        binding: SenderBinding::Bearer,
        issued_at: now - Duration::minutes(1),
        expires_at: now + Duration::days(1),
        family_expires_at: now + Duration::days(30),
        state: RefreshState::Active,
    }
}

/// A live bearer access token `client` holds, acting for `subject`, for
/// `openid` and `read`, issued a minute ago with an hour to run, presented
/// as [`TEST_ACCESS_TOKEN`], as storage keeps it.
#[must_use]
pub fn access_row(client: &OAuthClient<ResolvedTenant>, subject: TokenSubject) -> AccessTokenRow {
    let now = clock::now();
    AccessTokenRow {
        token_hash: hash_of(TEST_ACCESS_TOKEN),
        client_id: *client.id(),
        subject,
        scopes: vec![
            Scope::new("openid").expect("a valid scope"),
            Scope::new("read").expect("a valid scope"),
        ],
        audience: AccessAudience::Holder,
        delegation: Vec::new(),
        binding: SenderBinding::Bearer,
        created_at: now - Duration::minutes(1),
        expires_at: now + Duration::hours(1),
        revocation: Revocation::InForce,
    }
}

/// The token [`access_row`] describes.
#[must_use]
pub fn access_token(
    client: &OAuthClient<ResolvedTenant>,
    subject: TokenSubject,
) -> AccessToken<ResolvedTenant> {
    AccessToken::reconstitute(access_row(client, subject)).expect("a consistent token row")
}
