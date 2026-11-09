//! Pat's consent to Ledger: asked once, shown back to her on her list of
//! apps, and withdrawn, which ends what Ledger holds for her and makes it
//! ask again.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{oauth, people};
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::oauth::{ClientSettings, Consent, RegisteredClient, Tokens};
use ianua_scenarios::world::World;

use crate::clients::{
    SIGN_IN_SCOPES, callback, code_for, code_grant, consent, person, public_app, refresh_grant,
    registered,
};
use crate::support::pat;

/// The answer of a consent page that has not asked yet.
const NOT_ASKED_YET: &str = "not_asked_yet";

/// The record of a person withdrawing consent.
const WITHDRAWN: &str = "oauth.consent_revoked";

/// Ledger and the address it takes codes at.
struct Ledger {
    client: RegisteredClient,
    at: String,
}

impl Ledger {
    /// Ledger's request as the consent page first shows it, before Pat
    /// has answered.
    fn unanswered(&self) -> Consent {
        Consent {
            consent: NOT_ASKED_YET.to_owned(),
            ..consent(&self.client.client_id, &self.at, SIGN_IN_SCOPES)
        }
    }

    /// Ledger's tokens for `pat`, once she consented and it redeemed the
    /// code.
    async fn tokens_for(&self, world: &World<'_>, pat: &Person) -> Tokens {
        let code = code_for(world, pat, &self.client.client_id, &self.at).await;
        oauth::token(
            world.tenant(),
            &code_grant(&self.client.client_id, &code, &self.at),
        )
        .send(world.anonymous().client())
        .await
        .ok()
    }
}

/// Pat signs in to Ledger for the first time and is asked to consent to
/// what it wants. Once she has agreed, Ledger appears on her list of apps
/// with those scopes and she is not asked again on its next visit. Quinn,
/// who gave Ledger nothing, cannot withdraw anything, and nobody signed
/// in can either; Ledger still reads Pat through all of it. Pat withdraws
/// her consent: the access token Ledger holds reads nothing, its refresh
/// token is dead, Ledger is off her list, its next visit asks her again,
/// and withdrawing twice finds nothing. One record says what she did and
/// shows neither token. She stays signed in throughout, and if she agrees
/// again Ledger gets fresh tokens that work while the old ones stay dead.
#[tokio::test]
async fn pat_is_asked_once_and_withdrawing_ends_what_ledger_holds_for_her() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = pat(&world).await;
    let at = callback(&stack, "ledger");
    let client = registered(
        &world,
        &public_app("Ledger", &at, ClientSettings::default()),
    )
    .await;
    let ledger = Ledger { client, at };

    assert_asked_first(&world, &pat, &ledger).await;
    let tokens = ledger.tokens_for(&world, &pat).await;
    assert_listed_and_not_asked_again(&world, &pat, &ledger).await;
    refuse_outsiders(&world, &ledger).await;
    oauth::user_info(world.tenant(), &tokens.access_token)
        .send(world.anonymous().client())
        .await
        .ok();

    withdraw(&world, &pat, &ledger, &tokens).await;
    assert_asked_again(&world, &pat, &ledger, &tokens).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Before Pat answers, the page is told to ask her about the scopes, and
/// Ledger is on no list of hers.
async fn assert_asked_first(world: &World<'_>, pat: &Person, ledger: &Ledger) {
    let asked = oauth::authorize(world.tenant(), &ledger.unanswered())
        .send(pat.client())
        .await
        .ok();
    assert_eq!(asked.outcome, "consent", "Pat is asked first");
    assert!(asked.code.is_none(), "no code before she answers");
    let scopes = asked.scopes.expect("the page is told what to ask about");
    assert!(
        scopes.iter().any(|scope| scope == "email"),
        "she sees what Ledger wants"
    );

    let apps = oauth::my_apps(world.tenant()).send(pat.client()).await.ok();
    assert!(apps.is_empty(), "Ledger is on no list of Pat's yet");
}

/// Once Pat agreed, Ledger is on her list with its scopes, and its next
/// visit issues a code without asking.
async fn assert_listed_and_not_asked_again(world: &World<'_>, pat: &Person, ledger: &Ledger) {
    let apps = oauth::my_apps(world.tenant()).send(pat.client()).await.ok();
    let [app] = apps.as_slice() else {
        panic!("Ledger alone is on Pat's list: {apps:?}");
    };
    assert_eq!(app.client_id, ledger.client.client_id);
    assert_eq!(app.name, "Ledger");
    assert!(app.scopes.iter().any(|scope| scope == "email"));

    let again = oauth::authorize(world.tenant(), &ledger.unanswered())
        .send(pat.client())
        .await
        .ok();
    assert_eq!(again.outcome, "issued", "Pat is not asked twice");
    assert_eq!(again.consent_granted, Some(false), "nothing new was given");
}

/// Quinn, who consented to nothing, and nobody signed in withdraw nothing.
async fn refuse_outsiders(world: &World<'_>, ledger: &Ledger) {
    let quinn = person(world, "quinn", "Quinn Member").await;
    oauth::withdraw_consent(world.tenant(), &ledger.client.id)
        .send(quinn.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    oauth::withdraw_consent(world.tenant(), &ledger.client.id)
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Pat withdraws: both tokens die at once, she stays signed in and off
/// goes Ledger from her list, and the one record shows no token.
async fn withdraw(world: &World<'_>, pat: &Person, ledger: &Ledger, tokens: &Tokens) {
    oauth::withdraw_consent(world.tenant(), &ledger.client.id)
        .send(pat.client())
        .await
        .ok();
    oauth::user_info(world.tenant(), &tokens.access_token)
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "invalid_token");
    let refresh = tokens
        .refresh_token
        .as_deref()
        .expect("offline access issues one");
    oauth::token(
        world.tenant(),
        &refresh_grant(&ledger.client.client_id, refresh),
    )
    .send(world.anonymous().client())
    .await
    .refused(Status::BAD_REQUEST, "invalid_grant");
    people::me(world.tenant()).send(pat.client()).await.ok();
    let apps = oauth::my_apps(world.tenant()).send(pat.client()).await.ok();
    assert!(apps.is_empty(), "Ledger is off Pat's list");

    let record = world.trail().recorded(WITHDRAWN).await;
    assert_eq!(
        world.trail().count(WITHDRAWN).await,
        1,
        "one withdrawal is on record"
    );
    no_secret_leaked(
        &record.details.to_string(),
        &[tokens.access_token.as_str(), refresh],
    );
}

/// Ledger must ask again, there is nothing left to withdraw, and a new
/// consent gives fresh tokens that work while the old ones stay dead.
async fn assert_asked_again(world: &World<'_>, pat: &Person, ledger: &Ledger, old: &Tokens) {
    let asked = oauth::authorize(world.tenant(), &ledger.unanswered())
        .send(pat.client())
        .await
        .ok();
    assert_eq!(asked.outcome, "consent", "Ledger must ask again");
    oauth::withdraw_consent(world.tenant(), &ledger.client.id)
        .send(pat.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");

    let fresh = ledger.tokens_for(world, pat).await;
    oauth::user_info(world.tenant(), &fresh.access_token)
        .send(world.anonymous().client())
        .await
        .ok();
    oauth::user_info(world.tenant(), &old.access_token)
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "invalid_token");
}
