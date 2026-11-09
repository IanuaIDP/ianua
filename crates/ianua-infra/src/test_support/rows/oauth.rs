//! Rows of the OAuth context, and the people and clients its stores' rows
//! point at, saved through their own stores.

use std::sync::Arc;

use ianua_app::ports::identity::UserStore;
use ianua_app::ports::oauth::OAuthClientStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::sessions::mfa_factor::FactorProved;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::oauth::clients::api_key::{ApiKeyRow, KeyStanding};
use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClient, OAuthClientRow};
use ianua_domain::domains::oauth::clients::consent::OAuthConsentRow;
use ianua_domain::domains::oauth::clients::credential::ClientCredential;
use ianua_domain::domains::oauth::clients::registration::{
    ClientManagement, InitialAccessTokenRow,
};
use ianua_domain::domains::oauth::clients::settings::ClientSettings;
use ianua_domain::domains::oauth::clients::status::OAuthClientStatus;
use ianua_domain::domains::oauth::grants::access_token::{
    AccessAudience, AccessTokenRow, TokenSubject,
};
use ianua_domain::domains::oauth::grants::authorization_code::{
    AuthCodeRow, CodeChallenge, CodeChallengeMethod, NonceSent,
};
use ianua_domain::domains::oauth::grants::authorization_request::{
    AskedFlow, AskedPrompts, AskedRequest, AskedScopes, MaxAge, RequestedAcr, ResponseMode,
};
use ianua_domain::domains::oauth::grants::device_authorization::{
    DeviceAuthRow, DeviceAuthState, LastPoll, PollInterval,
};
use ianua_domain::domains::oauth::grants::pushed_request::{
    PushedParameters, PushedRequestRow, StateSent,
};
use ianua_domain::domains::oauth::grants::refresh_token::{
    GrantedIn, OAuthRefreshTokenRow, RefreshState,
};
use ianua_domain::domains::oauth::grants::token_binding::SenderBinding;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::types::{
    ActorRef, ApiKeyId, ClientId, DeviceUserCode, Expiry, InitialAccessTokenId, KeyPrefix, Label,
    OAuthClientId, PushedRequestId, RedirectUri, RefreshFamilyId, Revocation, Scope, SessionId,
    TokenHash, Usage, UserId,
};

use crate::postgres::identity::PgUserStore;
use crate::postgres::oauth::PgOAuthClientStore;
use crate::test_support::TestDb;
use crate::test_support::rows::at;
use crate::test_support::rows::identity::user_row;

/// Where every test client sends its codes.
pub const REDIRECT: &str = "https://app.example.com/callback";

/// The PKCE challenge every test code and pushed request carries.
pub const CHALLENGE: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

/// `names` as scopes.
///
/// # Panics
///
/// When a name is not a scope, which is a mistake in the test.
#[must_use]
pub fn scopes(names: &[&str]) -> Vec<Scope> {
    names
        .iter()
        .map(|name| Scope::new(*name).expect("a valid scope"))
        .collect()
}

/// `raw` as the hash a store keeps for it.
#[must_use]
pub fn hash(raw: &str) -> TokenHash {
    TokenHash::from_stored(format!("hash:{raw}"))
}

/// An active client named `name` the admins manage, that may use `grants`,
/// signs in with a secret, sends codes to [`REDIRECT`], may ask for
/// `openid`, `read` and `write`, and keeps the platform's settings, made at
/// the fixed moment.
///
/// # Panics
///
/// When `name` is not a label, which is a mistake in the test.
#[must_use]
pub fn oauth_client_row(name: &str, grants: &[GrantType]) -> OAuthClientRow {
    let id = OAuthClientId::new();
    OAuthClientRow {
        id,
        client_id_value: ClientId::new(format!("client_{}", id.as_uuid().simple()))
            .expect("a valid client id"),
        credential: ClientCredential::secret(hash("secret")),
        name: Label::new("name", name).expect("a valid name"),
        redirect_uris: vec![RedirectUri::new(REDIRECT).expect("a valid redirect")],
        post_logout_redirect_uris: vec![
            RedirectUri::new("https://app.example.com/signed-out").expect("a valid address"),
        ],
        grant_types: grants.to_vec(),
        scopes: scopes(&["openid", "read", "write"]),
        settings: ClientSettings::platform_defaults(),
        management: ClientManagement::ByAdmins,
        status: OAuthClientStatus::Active,
        created_at: at(0),
    }
}

/// An unrevoked initial access token named `name`, its hash made from the
/// name, with five uses, issued at the fixed moment for an hour.
///
/// # Panics
///
/// When `name` is not a label, which is a mistake in the test.
#[must_use]
pub fn initial_access_token_row(name: &str) -> InitialAccessTokenRow {
    InitialAccessTokenRow {
        id: InitialAccessTokenId::new(),
        name: Label::new("name", name).expect("a valid name"),
        token_hash: hash(&format!("iat-{name}")),
        uses_left: 5,
        created_at: at(0),
        expires_at: at(3600),
        revocation: Revocation::InForce,
    }
}

/// An unused code `client` was issued for `person`, kept as the hash of
/// `raw`, for `openid` and `read`, consented in `session` after a password
/// sign-in, issued a second after the fixed moment for a minute.
#[must_use]
pub fn code_row(
    client: &OAuthClient<ResolvedTenant>,
    person: UserId,
    session: SessionId,
    raw: &str,
) -> AuthCodeRow {
    AuthCodeRow {
        code_hash: hash(raw),
        client_id: *client.id(),
        user_id: person,
        redirect_uri: RedirectUri::new(REDIRECT).expect("a valid redirect"),
        scopes: scopes(&["openid", "read"]),
        code_challenge: CodeChallenge::new(CHALLENGE).expect("a valid challenge"),
        code_challenge_method: CodeChallengeMethod::S256,
        nonce: NonceSent::NotSent,
        session_id: session,
        auth_method: AuthMethod::Password,
        second_factor: FactorProved::NoneYet,
        authenticated_at: at(0),
        created_at: at(1),
        expires_at: at(61),
        usage: Usage::Unused,
    }
}

/// `person`'s consent to `client` for `openid`, given at `granted`.
#[must_use]
pub fn consent_row(
    person: UserId,
    client: &OAuthClient<ResolvedTenant>,
    granted: i64,
) -> OAuthConsentRow {
    OAuthConsentRow {
        user_id: person,
        client_id: *client.id(),
        scopes: scopes(&["openid"]),
        granted_at: at(granted),
    }
}

/// An unused request `client` pushed at the fixed moment, for a code for
/// `openid`, living sixty seconds.
#[must_use]
pub fn pushed_row(client: &OAuthClient<ResolvedTenant>) -> PushedRequestRow {
    PushedRequestRow {
        id: PushedRequestId::new(),
        client_id: *client.id(),
        parameters: PushedParameters {
            redirect_uri: RedirectUri::new(REDIRECT).expect("a valid redirect"),
            asked: AskedRequest {
                flow: AskedFlow::CodeWithS256Challenge,
                scopes: AskedScopes::Named(scopes(&["openid"])),
                prompts: AskedPrompts::Named(Vec::new()),
                response_mode: ResponseMode::Query,
            },
            max_age: MaxAge::Any,
            acr: RequestedAcr::Any,
            code_challenge: CodeChallenge::new(CHALLENGE).expect("a valid challenge"),
            nonce: NonceSent::NotSent,
            state: StateSent::NotSent,
        },
        created_at: at(0),
        expires_at: at(60),
        usage: Usage::Unused,
    }
}

/// An unrevoked bearer access token `client` holds for `subject`, kept as
/// the hash of `raw`, for `openid` and `read`, issued at the fixed moment
/// for an hour.
#[must_use]
pub fn access_row(
    client: &OAuthClient<ResolvedTenant>,
    subject: TokenSubject,
    raw: &str,
) -> AccessTokenRow {
    AccessTokenRow {
        token_hash: hash(raw),
        client_id: *client.id(),
        subject,
        scopes: scopes(&["openid", "read"]),
        audience: AccessAudience::Holder,
        delegation: Vec::new(),
        binding: SenderBinding::Bearer,
        created_at: at(0),
        expires_at: at(3600),
        revocation: Revocation::InForce,
    }
}

/// The first, active, bearer refresh token of a new family `client` holds
/// for `person`, kept as the hash of `raw`, granted in `session`, issued at
/// the fixed moment for a day, its family for thirty.
#[must_use]
pub fn refresh_row(
    client: &OAuthClient<ResolvedTenant>,
    person: UserId,
    session: SessionId,
    raw: &str,
) -> OAuthRefreshTokenRow {
    OAuthRefreshTokenRow {
        token_hash: hash(raw),
        family: RefreshFamilyId::new(),
        client_id: *client.id(),
        user_id: person,
        scopes: scopes(&["openid", "read"]),
        granted_in: GrantedIn::Session(session),
        binding: SenderBinding::Bearer,
        issued_at: at(0),
        expires_at: at(86_400),
        family_expires_at: at(2_592_000),
        state: RefreshState::Active,
    }
}

/// A pending device request `client` started for `read`, polled with the
/// device code `raw` and showing `user_code`, started at the fixed moment
/// for ten minutes.
///
/// # Panics
///
/// When `user_code` is not one, which is a mistake in the test.
#[must_use]
pub fn device_row(
    client: &OAuthClient<ResolvedTenant>,
    raw: &str,
    user_code: &str,
) -> DeviceAuthRow {
    DeviceAuthRow {
        device_code_hash: hash(raw),
        user_code: DeviceUserCode::new(user_code).expect("a valid user code"),
        client_id: *client.id(),
        scopes: scopes(&["read"]),
        state: DeviceAuthState::Pending,
        interval: PollInterval::DEFAULT,
        last_poll: LastPoll::Never,
        created_at: at(0),
        expires_at: at(600),
    }
}

/// A key named `name` that `maker` made at the fixed moment, which may view
/// routing and never expires, its prefix and hash made from the name.
///
/// # Panics
///
/// When `name` is not a label or a prefix, which is a mistake in the test.
#[must_use]
pub fn api_key_row(name: &str, maker: ActorRef) -> ApiKeyRow {
    ApiKeyRow {
        id: ApiKeyId::new(),
        name: Label::new("api_key_name", name).expect("a valid name"),
        key_prefix: KeyPrefix::new(format!("ik_live_acme_{name}")).expect("a valid prefix"),
        key_hash: hash(&format!("key-{name}")),
        scopes: scopes(&["idp:routing:view"]),
        created_by: maker,
        expires_at: Expiry::Never,
        last_used_at: None,
        last_used_ip: None,
        seen_countries: Vec::new(),
        created_at: at(0),
        standing: KeyStanding::Working,
    }
}

/// An active person at `email` saved in `tenant` through the user store,
/// for the rows that point at a person.
///
/// # Panics
///
/// When the person cannot be saved, which is a mistake in the test.
pub async fn a_person(db: &TestDb, tenant: &ScopedTenant, email: &str) -> UserId {
    let person: User<ResolvedTenant> =
        User::reconstitute(user_row(email)).expect("a consistent user row");
    PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
        .save(tenant, &person)
        .await
        .expect("the person is saved");
    *person.id()
}

/// The client `row` describes, saved in `tenant` through the client store,
/// for the rows that point at a client.
///
/// # Panics
///
/// When the row is inconsistent or cannot be saved, which is a mistake in
/// the test.
pub async fn a_client(
    db: &TestDb,
    tenant: &ScopedTenant,
    row: OAuthClientRow,
) -> OAuthClient<ResolvedTenant> {
    let client = OAuthClient::reconstitute(row).expect("a consistent client row");
    PgOAuthClientStore::new(Arc::clone(&db.databases))
        .save(tenant, &client)
        .await
        .expect("the client is saved");
    client
}
