//! An application of the company's own signs Pat in over OpenID Connect:
//! Tess registers it as a public client, Pat consents, and the application
//! redeems its code with PKCE, verifies her ID token against the keys the
//! tenant publishes, reads who she is, trades its refresh token and gives
//! its access up. A code is redeemed once; an unregistered callback or a
//! wrong verifier gets nothing, and Pat's own session is untouched. A
//! refresh token used twice takes its successor down with it, and Pat
//! signing out through the application ends her session and its tokens.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{oauth, people};
use ianua_scenarios::expect::verified_rs256;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::oauth::{
    Authorized, ClientRegistered, Consent, EndSession, NewClient, Revocation, TokenRequest, Tokens,
};
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::world::{MEMBER_ROLE, World};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use url::Url;

/// The PKCE verifier the application keeps to itself: longer than the
/// forty-three characters the standard asks for at least.
const VERIFIER: &str = "a_client_owned_random_verifier_with_more_than_forty_three_characters_9471";

/// Another verifier of the same shape, whose challenge no code was bound
/// to.
const OTHER_VERIFIER: &str =
    "a_different_random_verifier_with_more_than_forty_three_characters_1234";

/// The state the application sends with its request and expects back.
const STATE: &str = "client-owned-state";

/// The nonce the application binds into Pat's ID token.
const NONCE: &str = "client-owned-nonce";

/// The scopes the application asks for.
const SCOPE: &str = "openid email profile offline_access";

/// The claims of an ID token the application relies on.
#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: serde_json::Value,
    sub: String,
    nonce: String,
    exp: i64,
}

/// The application, registered by Tess as a public client with `callback`
/// as its only callback and the code and refresh grants.
async fn registered(world: &World<'_>, callback: &str) -> ClientRegistered {
    let client = NewClient {
        name: "Independent application".to_owned(),
        redirect_uris: vec![callback.to_owned()],
        grant_types: vec!["AuthorizationCode".to_owned(), "RefreshToken".to_owned()],
        scopes: SCOPE.split(' ').map(str::to_owned).collect(),
        token_endpoint_auth_method: "none".to_owned(),
        post_logout_redirect_uris: vec![signed_out_page(callback)],
    };
    oauth::register_client(world.tenant(), &client)
        .send(world.admin().client())
        .await
        .ok()
}

/// Pat, invited by Tess into the tenant, who accepted from the mailed link
/// and signed in.
async fn pat_signed_in(world: &World<'_>) -> Person {
    let mut pat = world.newcomer("pat", "Pat Holder");
    let invitation = people::invite(
        world.tenant(),
        &InviteUser {
            email: pat.email().to_owned(),
            display_name: pat.account().display_name.clone(),
            role_id: world.role_id(MEMBER_ROLE).await,
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    pat.record_invitation(&invitation.id);
    pat.accept_invitation(world.stack()).await;
    pat.sign_in(world.stack()).await;
    pat
}

/// Pat's consent to `client`'s request for a code sent to `callback`,
/// bound to the S256 challenge of `verifier`.
fn consent(client: &ClientRegistered, callback: &str, verifier: &str) -> Consent {
    Consent {
        client_id: client.client_id.clone(),
        redirect_uri: callback.to_owned(),
        response_type: "code".to_owned(),
        scope: SCOPE.to_owned(),
        state: STATE.to_owned(),
        nonce: NONCE.to_owned(),
        code_challenge: URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
        code_challenge_method: "S256".to_owned(),
        consent: "given".to_owned(),
    }
}

/// The code grant redeeming `code` for `client` at `callback` with
/// `verifier`.
fn code_grant(
    client: &ClientRegistered,
    code: &str,
    callback: &str,
    verifier: &str,
) -> TokenRequest {
    TokenRequest::AuthorizationCode {
        client_id: client.client_id.clone(),
        code: code.to_owned(),
        redirect_uri: callback.to_owned(),
        code_verifier: verifier.to_owned(),
    }
}

/// The code `authorized` issued.
fn code_of(authorized: &Authorized) -> &str {
    assert_eq!(authorized.outcome, "issued", "consent given issues a code");
    authorized
        .code
        .as_deref()
        .expect("a code comes with the issued outcome")
}

/// Checks `token`, Pat's ID token, as the application does: the signature
/// with the RSA key the tenant publishes under the header's key id, then
/// the issuer, the audience, the subject `pat_id`, the nonce and the
/// expiry, trusting nothing the token says of itself.
async fn verified(world: &World<'_>, client: &ClientRegistered, token: &str, pat_id: &str) {
    let discovery = oauth::discovery(world.tenant())
        .send(world.anonymous().client())
        .await
        .ok();
    let published = oauth::keys(&discovery.jwks_uri)
        .send(world.anonymous().client())
        .await
        .ok();
    let claims =
        verified_rs256(&published, token, "JWT").expect("the published key verifies the ID token");
    check_claims(claims, &discovery.issuer, client, pat_id);
}

/// Verified claims name this issuer, client and person, with the expected nonce and a future expiry.
fn check_claims(claims: serde_json::Value, issuer: &str, client: &ClientRegistered, pat_id: &str) {
    let claims: Claims = serde_json::from_value(claims).expect("OIDC claims");
    assert_eq!(claims.iss, issuer, "the token names the issuer");
    assert!(
        claims.aud == client.client_id
            || claims.aud.as_array().is_some_and(|audiences| audiences
                .iter()
                .any(|audience| audience == &client.client_id)),
        "the token is for the application"
    );
    assert_eq!(claims.sub, pat_id, "the token names Pat");
    assert_eq!(
        claims.nonce, NONCE,
        "the token carries the application's nonce"
    );
    assert!(
        claims.exp > time::OffsetDateTime::now_utc().unix_timestamp(),
        "the token has not expired"
    );
}

/// Pat consents to the application's request: a code goes to its exact
/// callback with its state. The application redeems the code with its
/// verifier, verifies Pat's ID token against the tenant's published keys,
/// reads who she is, trades its refresh token for a new one, and finds the
/// code spent when it tries it again. It gives its access up, and the
/// token reads nothing any more.
#[tokio::test]
async fn an_application_signs_pat_in_with_a_code_and_pkce_and_gives_its_access_up() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = pat_signed_in(&world).await;
    let callback = format!("https://relying-party.{}/callback", stack.customer_domain());
    let client = registered(&world, &callback).await;

    let authorized = oauth::authorize(world.tenant(), &consent(&client, &callback, VERIFIER))
        .send(pat.client())
        .await
        .ok();
    let code = code_of(&authorized);
    check_callback(&authorized, &callback);
    let application = Client::new(&stack, "the application").expect("a client");
    let grant = code_grant(&client, code, &callback, VERIFIER);
    let tokens = oauth::token(world.tenant(), &grant)
        .send(&application)
        .await
        .ok();
    verify_identity(&world, &pat, &client, &tokens).await;
    check_user_info(&world, &application, &pat, &tokens).await;
    let refreshed = refresh_tokens(&world, &application, &client, &tokens).await;
    oauth::token(world.tenant(), &grant)
        .send(&application)
        .await
        .refused(Status::BAD_REQUEST, "invalid_grant");
    revoke_access(&world, &application, &client, &refreshed).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// The authorization sends its code to the registered callback with the application's state.
fn check_callback(authorized: &Authorized, callback: &str) {
    let redirect = Url::parse(authorized.redirect_to.as_deref().expect("the callback"))
        .expect("a callback URL");
    assert_eq!(
        redirect.host_str(),
        Url::parse(callback)
            .expect("the registered callback")
            .host_str(),
        "the code goes to the registered callback"
    );
    assert!(
        redirect
            .query_pairs()
            .any(|(name, value)| name == "state" && value == STATE),
        "the application's state comes back with the code"
    );
}

/// The OpenID grant includes an ID token that independently verifies as Pat's.
async fn verify_identity(
    world: &World<'_>,
    pat: &Person,
    client: &ClientRegistered,
    tokens: &Tokens,
) {
    let id_token = tokens
        .id_token
        .as_deref()
        .expect("openid issues an ID token");
    verified(world, client, id_token, pat.id()).await;
}

/// The access token exposes Pat's subject and email through user info.
async fn check_user_info(world: &World<'_>, application: &Client, pat: &Person, tokens: &Tokens) {
    let info = oauth::user_info(world.tenant(), &tokens.access_token)
        .send(application)
        .await
        .ok();
    assert_eq!(info.sub, pat.id(), "user info names Pat");
    assert_eq!(
        info.email.as_deref(),
        Some(pat.email()),
        "user info gives Pat's address"
    );
}

/// Trading the offline grant rotates its refresh token.
async fn refresh_tokens(
    world: &World<'_>,
    application: &Client,
    client: &ClientRegistered,
    tokens: &Tokens,
) -> Tokens {
    let refresh = TokenRequest::RefreshToken {
        client_id: client.client_id.clone(),
        refresh_token: tokens
            .refresh_token
            .clone()
            .expect("offline access issues a refresh token"),
    };
    let refreshed = oauth::token(world.tenant(), &refresh)
        .send(application)
        .await
        .ok();
    assert!(
        refreshed.refresh_token != tokens.refresh_token,
        "a refresh hands out a new refresh token"
    );
    refreshed
}

/// Revoking the refreshed access token makes its next user-info request unauthorized.
async fn revoke_access(
    world: &World<'_>,
    application: &Client,
    client: &ClientRegistered,
    refreshed: &Tokens,
) {
    let revocation = Revocation {
        client_id: client.client_id.clone(),
        token: refreshed.access_token.clone(),
    };
    oauth::revoke(world.tenant(), &revocation)
        .send(application)
        .await
        .ok();
    let after = oauth::user_info(world.tenant(), &refreshed.access_token)
        .send(application)
        .await;
    assert_eq!(
        after.status(),
        Status::UNAUTHORIZED,
        "a revoked token reads nothing: {}",
        after.summary()
    );
}

/// An unregistered callback cannot receive a code, and a code cannot be
/// redeemed with a verifier other than the one it was bound to.
/// Both requests are refused, Pat's own session reads on, and a fresh consent
/// still redeems with the right verifier.
#[tokio::test]
async fn an_unregistered_callback_or_a_wrong_verifier_gets_no_tokens() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = pat_signed_in(&world).await;
    let callback = format!("https://relying-party.{}/callback", stack.customer_domain());
    let client = registered(&world, &callback).await;

    refuse_wrong_callback(&world, &pat, &client).await;
    refuse_wrong_verifier(&world, &pat, &client, &callback).await;
    people::me(world.tenant()).send(pat.client()).await.ok();

    let fresh = oauth::authorize(world.tenant(), &consent(&client, &callback, VERIFIER))
        .send(pat.client())
        .await
        .ok();
    let right_verifier = code_grant(&client, code_of(&fresh), &callback, VERIFIER);
    oauth::token(world.tenant(), &right_verifier)
        .send(world.anonymous().client())
        .await
        .ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// Consent cannot send a code to an address outside the client's registered callbacks.
async fn refuse_wrong_callback(world: &World<'_>, pat: &Person, client: &ClientRegistered) {
    let elsewhere = consent(client, "https://unregistered.example/callback", VERIFIER);
    oauth::authorize(world.tenant(), &elsewhere)
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// A code bound to the original challenge cannot be redeemed with another verifier.
async fn refuse_wrong_verifier(
    world: &World<'_>,
    pat: &Person,
    client: &ClientRegistered,
    callback: &str,
) {
    let authorized = oauth::authorize(world.tenant(), &consent(client, callback, VERIFIER))
        .send(pat.client())
        .await
        .ok();
    let wrong_verifier = code_grant(client, code_of(&authorized), callback, OTHER_VERIFIER);
    oauth::token(world.tenant(), &wrong_verifier)
        .send(world.anonymous().client())
        .await
        .refused(Status::BAD_REQUEST, "invalid_grant");
}

/// The application trades its refresh token for a new one. Someone then
/// presents the old one again: it is refused, and the new one dies with
/// it, since only a copy explains a second use.
#[tokio::test]
async fn a_refresh_token_used_twice_takes_its_successor_down_with_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = pat_signed_in(&world).await;
    let callback = format!("https://relying-party.{}/callback", stack.customer_domain());
    let client = registered(&world, &callback).await;
    let application = Client::new(&stack, "the application").expect("a client");
    let tokens = issued(&world, &pat, &client, &callback).await;

    let first = refresh_with(&client, &tokens);
    let refreshed = oauth::token(world.tenant(), &first)
        .send(&application)
        .await
        .ok();
    oauth::token(world.tenant(), &first)
        .send(&application)
        .await
        .refused(Status::BAD_REQUEST, "invalid_grant");
    oauth::token(world.tenant(), &refresh_with(&client, &refreshed))
        .send(&application)
        .await
        .refused(Status::BAD_REQUEST, "invalid_grant");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat signs in to the application, which later asks the tenant to sign
/// her out. A request naming nobody only asks her to confirm and ends
/// nothing. The application then sends her browser to the tenant's
/// sign-out address with the ID token naming her; the platform sends it
/// on to the dashboard's sign-out page, which hands the request back
/// with her session. Her session ends, the application's refresh token
/// with it, and she goes back to the application's signed-out page with
/// its state.
#[tokio::test]
async fn pat_signing_out_through_the_application_ends_her_session_and_its_tokens() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = pat_signed_in(&world).await;
    let callback = format!("https://relying-party.{}/callback", stack.customer_domain());
    let client = registered(&world, &callback).await;
    let application = Client::new(&stack, "the application").expect("a client");
    let tokens = issued(&world, &pat, &client, &callback).await;
    let id_token = tokens.id_token.clone().expect("openid issues an ID token");
    let unnamed = request_sign_out(&world, &pat, &client, &callback).await;
    visit_sign_out(&world, &pat, &unnamed, &id_token).await;
    confirm_sign_out(&world, &pat, unnamed, id_token).await;
    people::me(world.tenant())
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    oauth::token(world.tenant(), &refresh_with(&client, &tokens))
        .send(&application)
        .await
        .refused(Status::BAD_REQUEST, "invalid_grant");

    stack.stop().await.expect("the stack stops cleanly");
}

/// An unnamed sign-out request asks for confirmation and leaves Pat's session usable.
async fn request_sign_out(
    world: &World<'_>,
    pat: &Person,
    client: &ClientRegistered,
    callback: &str,
) -> EndSession {
    let unnamed = EndSession {
        id_token_hint: None,
        client_id: client.client_id.clone(),
        post_logout_redirect_uri: signed_out_page(callback),
        state: STATE.to_owned(),
        confirmed: false,
    };

    let asked = oauth::end_session(world.tenant(), &unnamed)
        .send(pat.client())
        .await
        .ok();
    assert_eq!(
        asked.outcome, "confirm",
        "a request naming nobody asks first"
    );
    people::me(world.tenant()).send(pat.client()).await.ok();
    unnamed
}

/// The browser's token-bearing logout request redirects to the dashboard.
async fn visit_sign_out(world: &World<'_>, pat: &Person, unnamed: &EndSession, id_token: &str) {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("id_token_hint", id_token)
        .append_pair("client_id", &unnamed.client_id)
        .append_pair(
            "post_logout_redirect_uri",
            &unnamed.post_logout_redirect_uri,
        )
        .append_pair("state", STATE)
        .finish();
    let sent = oauth::logout(world.tenant(), &query)
        .send(pat.client())
        .await;
    assert_eq!(
        sent.status(),
        Status::FOUND,
        "the browser goes on to the dashboard: {}",
        sent.summary()
    );
}

/// Naming Pat signs her out and returns her browser to the application with its state.
async fn confirm_sign_out(world: &World<'_>, pat: &Person, unnamed: EndSession, id_token: String) {
    let signed_out = unnamed.post_logout_redirect_uri.clone();
    let named = EndSession {
        id_token_hint: Some(id_token),
        ..unnamed
    };
    let ended = oauth::end_session(world.tenant(), &named)
        .send(pat.client())
        .await
        .ok();
    assert_eq!(ended.outcome, "signed_out");
    let back = Url::parse(
        ended
            .redirect_to
            .as_deref()
            .expect("back to the application"),
    )
    .expect("an address");
    assert!(
        back.as_str().starts_with(&signed_out),
        "Pat goes back to the application's signed-out page: {back}"
    );
    assert!(
        back.query_pairs()
            .any(|(name, value)| name == "state" && value == STATE),
        "the application's state comes back"
    );
}

/// The tokens the application holds once Pat consented and it redeemed
/// the code with its verifier.
async fn issued(
    world: &World<'_>,
    pat: &Person,
    client: &ClientRegistered,
    callback: &str,
) -> Tokens {
    let authorized = oauth::authorize(world.tenant(), &consent(client, callback, VERIFIER))
        .send(pat.client())
        .await
        .ok();
    oauth::token(
        world.tenant(),
        &code_grant(client, code_of(&authorized), callback, VERIFIER),
    )
    .send(world.anonymous().client())
    .await
    .ok()
}

/// The refresh grant trading the refresh token in `tokens`.
fn refresh_with(client: &ClientRegistered, tokens: &Tokens) -> TokenRequest {
    TokenRequest::RefreshToken {
        client_id: client.client_id.clone(),
        refresh_token: tokens
            .refresh_token
            .clone()
            .expect("offline access issues a refresh token"),
    }
}

/// The application's page for a person who signed out, beside its
/// `callback`.
fn signed_out_page(callback: &str) -> String {
    callback.replace("/callback", "/signed-out")
}
