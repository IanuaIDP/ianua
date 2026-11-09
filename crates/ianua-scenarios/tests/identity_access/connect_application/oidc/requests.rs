//! Requests for a code the platform must not answer with one: a request
//! that drops PKCE or asks for tokens in the address, one that goes
//! beyond what the app registered, and a code carried off to another app
//! or address. The app is told what is wrong, with its own state and the
//! issuer's name; an address never registered is told nothing.

use ianua_scenarios::api::oauth;
use ianua_scenarios::providers::parameter;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::oauth::{Authorized, ClientSettings, Consent};
use ianua_scenarios::world::World;
use url::form_urlencoded;

use crate::clients::{
    NONCE, SIGN_IN_SCOPES, STATE, VERIFIER, callback, challenge, code_for, code_grant, consent,
    provider, public_app, registered,
};
use crate::support::pat;

/// An address nobody registered.
const ELSEWHERE: &str = "https://elsewhere.example/callback";

/// What one authorization request asks for, as the browser carries it.
struct Asked<'a> {
    client: &'a str,
    redirect: &'a str,
    response_type: &'a str,
    method: &'a str,
}

impl Asked<'_> {
    /// The query the browser carries the request in.
    fn query(&self) -> String {
        form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", self.client)
            .append_pair("redirect_uri", self.redirect)
            .append_pair("response_type", self.response_type)
            .append_pair("scope", SIGN_IN_SCOPES)
            .append_pair("state", STATE)
            .append_pair("nonce", NONCE)
            .append_pair("code_challenge", &challenge(VERIFIER))
            .append_pair("code_challenge_method", self.method)
            .finish()
    }
}

/// Ledger sends Pat's browser with a proper request, and the platform
/// sends it on to the dashboard's consent page. Mallory, in the middle,
/// strips the request down: a challenge sent in the clear, or tokens
/// asked for in the address. Each goes back to Ledger's own address with
/// what is wrong, Ledger's state and the name of the issuer that answered,
/// so Ledger can tell it from another provider's answer. A request naming
/// an address Tess never registered is told nothing at that address.
#[tokio::test]
async fn a_request_that_weakens_the_flow_gets_no_code() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let at = callback(&stack, "ledger");
    let ledger = registered(
        &world,
        &public_app("Ledger", &at, ClientSettings::default()),
    )
    .await;
    let tenant = provider(&world).await;

    let proper = Asked {
        client: &ledger.client_id,
        redirect: &at,
        response_type: "code",
        method: "S256",
    };
    let onward = sent_on(&world, &proper).await;
    assert!(
        !onward.starts_with(&at),
        "a proper request goes on to the consent page first: {onward}"
    );
    assert!(
        onward.contains("/oauth/authorize"),
        "to the consent page: {onward}"
    );

    let cleartext = Asked {
        method: "plain",
        ..proper
    };
    let implicit = Asked {
        response_type: "token",
        ..proper
    };
    for (asked, error, why) in [
        (
            &cleartext,
            "invalid_request",
            "a challenge sent in the clear",
        ),
        (
            &implicit,
            "unsupported_response_type",
            "tokens in the address",
        ),
    ] {
        let back = sent_on(&world, asked).await;
        assert!(back.starts_with(&at), "{why} is told to Ledger: {back}");
        assert_eq!(parameter(&back, "error"), error, "{why}");
        assert_eq!(
            parameter(&back, "state"),
            STATE,
            "{why} keeps Ledger's state"
        );
        assert_eq!(
            parameter(&back, "iss"),
            tenant.discovery.issuer,
            "{why} names the issuer"
        );
    }

    let misdirected = Asked {
        redirect: ELSEWHERE,
        ..proper
    };
    let refused = oauth::browser_authorize(world.tenant(), &misdirected.query())
        .send(world.anonymous().client())
        .await;
    assert_eq!(
        refused.header("location"),
        None,
        "nothing goes to that address"
    );
    refused.refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Where the platform sends the browser carrying `asked`.
async fn sent_on(world: &World<'_>, asked: &Asked<'_>) -> String {
    let answer = oauth::browser_authorize(world.tenant(), &asked.query())
        .send(world.anonymous().client())
        .await;
    assert!(
        answer.status().is_redirection(),
        "the browser is sent on: {}",
        answer.summary()
    );
    answer
        .header("location")
        .expect("a redirect says where")
        .to_owned()
}

/// Ledger registered the sign-in scopes only. Asked for more on Pat's
/// consent page, the platform tells Ledger the scope is refused and
/// issues no code. Nobody signed in, and Sam from the other company, get
/// no code for Pat's tenant either.
#[tokio::test]
async fn nobody_gets_a_code_beyond_what_the_app_registered_or_for_someone_elses_tenant() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = pat(&world).await;
    let at = callback(&stack, "ledger");
    let ledger = registered(
        &world,
        &public_app("Ledger", &at, ClientSettings::default()),
    )
    .await;

    let wider = Consent {
        scope: format!("{SIGN_IN_SCOPES} admin"),
        ..consent(&ledger.client_id, &at, SIGN_IN_SCOPES)
    };
    let answered: Authorized = oauth::authorize(world.tenant(), &wider)
        .send(pat.client())
        .await
        .ok();
    assert_eq!(
        answered.outcome, "refused",
        "no code for what was not registered"
    );
    assert_eq!(answered.error.as_deref(), Some("invalid_scope"));
    assert!(answered.code.is_none(), "no code comes with a refusal");

    let asked = consent(&ledger.client_id, &at, SIGN_IN_SCOPES);
    oauth::authorize(world.tenant(), &asked)
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    oauth::authorize(world.tenant(), &asked)
        .send(world.stranger().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat consents to Ledger. Mallory carries the code off: Shadow, the app
/// she registered in the same tenant, cannot redeem it, nor can anyone
/// send it to any address but the one it was issued for.
#[tokio::test]
async fn a_code_redeems_only_for_its_app_at_its_address() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = pat(&world).await;
    let at = callback(&stack, "ledger");
    let ledger = registered(
        &world,
        &public_app("Ledger", &at, ClientSettings::default()),
    )
    .await;
    let shadow_at = callback(&stack, "shadow");
    let shadow = registered(
        &world,
        &public_app("Shadow", &shadow_at, ClientSettings::default()),
    )
    .await;

    let stolen = code_for(&world, &pat, &ledger.client_id, &at).await;
    oauth::token(
        world.tenant(),
        &code_grant(&shadow.client_id, &stolen, &shadow_at),
    )
    .send(world.anonymous().client())
    .await
    .refused(Status::BAD_REQUEST, "invalid_grant");

    let redirected = code_for(&world, &pat, &ledger.client_id, &at).await;
    oauth::token(
        world.tenant(),
        &code_grant(&ledger.client_id, &redirected, &shadow_at),
    )
    .send(world.anonymous().client())
    .await
    .refused(Status::BAD_REQUEST, "invalid_grant");

    let kept = code_for(&world, &pat, &ledger.client_id, &at).await;
    oauth::token(world.tenant(), &code_grant(&ledger.client_id, &kept, &at))
        .send(world.anonymous().client())
        .await
        .ok();
    stack.stop().await.expect("the stack stops cleanly");
}
