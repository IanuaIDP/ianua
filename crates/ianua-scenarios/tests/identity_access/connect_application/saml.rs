//! Ledger, an outside SAML app, signing Pat in with the tenant as its
//! identity provider. Ledger trusts only what the tenant publishes and
//! checks every answer itself; the platform answers only the apps and
//! addresses Tess registered, each request once, for the person signed in.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{audit, saml_apps};
use ianua_scenarios::providers::parameter;
use ianua_scenarios::services::saml::signature::Broken;
use ianua_scenarios::services::saml::{App, IdentityProvider, PERSISTENT, Refusal, Sent};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::saml_apps::{AnswerSignIn, FormPost};
use ianua_scenarios::world::World;

use crate::support::{carried, pat, registered, the_tenant};

/// The page of Ledger Pat was on when it sent her to sign in, which the
/// answer must bring back.
const REPORTS: &str = "/reports/q3";

/// The record an answer to an app leaves.
const ISSUED: &str = "federation.saml_assertion_issued";

/// A sign-in request and the signed form returned for that request.
struct IssuedAnswer<'a> {
    request: &'a Sent,
    answer: &'a FormPost,
}

/// The registered app and the tenant metadata it trusts during status changes.
struct RegisteredApp<'a> {
    app: &'a App,
    id: &'a str,
    provider: &'a IdentityProvider,
}

/// Tess registers Ledger, which reads the tenant's published metadata.
/// Ledger sends Pat's browser to the tenant's sign-in service with its
/// request, and the platform holds it and sends her on to the dashboard.
/// Nobody signed in gets no answer to it. The dashboard, as Pat, asks for
/// the answer: it goes to Ledger's own address, bringing back the page
/// Pat was on. Ledger refuses the answer once a word of it is changed,
/// and accepts it as sent: signed by the tenant's published key, issued
/// by the tenant, meant for Ledger, answering its own request, naming Pat
/// by a lasting id and giving her address. The request is answered only
/// once, and the answer is on the tenant's record.
#[tokio::test]
async fn ledger_accepts_the_platforms_signed_answer_for_pat_once() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let ledger = App::at("ledger.example");
    registered(&world, &ledger, "Ledger").await;
    let tenant = the_tenant(&world).await;
    let pat = pat(&world).await;

    let request = ledger.sign_in_request(&tenant, REPORTS);
    let held = AnswerSignIn {
        request: carried(&pat, &ledger, &tenant, &request).await,
    };
    saml_apps::answer(world.tenant(), &held)
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let answer = saml_apps::answer(world.tenant(), &held)
        .send(pat.client())
        .await
        .ok();
    let issued = IssuedAnswer {
        request: &request,
        answer: &answer,
    };
    assert_signed_answer(&pat, &ledger, &tenant, &issued);
    assert_single_answer(&world, &pat, &held).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Replaying the request yields no answer and leaves exactly one issuance record.
async fn assert_single_answer(world: &World<'_>, pat: &Person, held: &AnswerSignIn) {
    saml_apps::answer(world.tenant(), held)
        .send(pat.client())
        .await
        .refused(Status::GONE, "link_expired");
    let issued = audit::tenant_log(world.tenant(), ISSUED)
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(issued.items.len(), 1, "one answer is on record");
}

/// Ledger accepts the intended signed answer and refuses a changed address.
fn assert_signed_answer(
    pat: &Person,
    ledger: &App,
    tenant: &IdentityProvider,
    issued: &IssuedAnswer<'_>,
) {
    let IssuedAnswer { request, answer } = *issued;
    assert_eq!(answer.destination, ledger.acs_url(), "posted to Ledger");
    assert_eq!(answer.parameter, "SAMLResponse");
    assert_eq!(answer.relay_state.as_deref(), Some(REPORTS));

    let changed = changed(&answer.message, pat.email(), "mallory@ledger.example");
    assert_eq!(
        ledger.accepted(tenant, request, &changed).map(|_| ()),
        Err(Refusal::Signature(Broken::DigestDiffers)),
        "Ledger refuses an answer with Pat's address changed"
    );
    let accepted = ledger
        .accepted(tenant, request, &answer.message)
        .expect("Ledger accepts the platform's answer");
    assert_eq!(accepted.name_id_format, PERSISTENT);
    assert!(!accepted.name_id.is_empty(), "Pat is named by a lasting id");
    assert_eq!(
        accepted.attributes.get("email"),
        Some(&vec![pat.email().to_owned()]),
        "Ledger learns Pat's address"
    );
}

/// Shadow, an app Tess never registered, sends Pat to sign in, and gets
/// no answer. Ledger asking for its answer at an address Tess never
/// allowed gets none either. Once Tess switches Ledger off, its own
/// request is refused too, and once she switches it on again, answered.
#[tokio::test]
async fn only_the_apps_and_addresses_tess_allowed_are_answered() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let ledger = App::at("ledger.example");
    let made = registered(&world, &ledger, "Ledger").await;
    let tenant = the_tenant(&world).await;
    let pat = pat(&world).await;
    refuse_unregistered_targets(&world, &pat, &ledger, &tenant).await;
    let registered = RegisteredApp {
        app: &ledger,
        id: &made.id,
        provider: &tenant,
    };
    assert_app_status(&world, &pat, &registered).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Unregistered apps and unapproved return addresses receive no sign-in answer.
async fn refuse_unregistered_targets(
    world: &World<'_>,
    pat: &Person,
    ledger: &App,
    tenant: &IdentityProvider,
) {
    let shadow = App::at("shadow.example");
    let unknown = shadow.sign_in_request(tenant, REPORTS);
    let elsewhere = ledger.request_to(tenant, "https://elsewhere.example/saml/acs", REPORTS);
    for (app, request, why) in [
        (&shadow, &unknown, "an app Tess never registered"),
        (ledger, &elsewhere, "an address Tess never allowed"),
    ] {
        let held = AnswerSignIn {
            request: carried(pat, app, tenant, request).await,
        };
        let answer = saml_apps::answer(world.tenant(), &held)
            .send(pat.client())
            .await;
        assert_eq!(
            answer.status(),
            Status::FORBIDDEN,
            "{why} gets no answer: {}",
            answer.summary()
        );
    }
}

/// Disabling Ledger refuses its request; reactivation permits a fresh request.
async fn assert_app_status(world: &World<'_>, pat: &Person, registered: &RegisteredApp<'_>) {
    let ledger = registered.app;
    let id = registered.id;
    let tenant = registered.provider;
    saml_apps::disable(world.tenant(), id)
        .send(world.admin().client())
        .await
        .ok();
    let while_off = ledger.sign_in_request(tenant, REPORTS);
    let held = AnswerSignIn {
        request: carried(pat, ledger, tenant, &while_off).await,
    };
    saml_apps::answer(world.tenant(), &held)
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    assert_reactivated_app(world, pat, registered).await;
}

/// Reactivating Ledger lets it accept the answer to a fresh request.
async fn assert_reactivated_app(world: &World<'_>, pat: &Person, registered: &RegisteredApp<'_>) {
    let ledger = registered.app;
    let tenant = registered.provider;
    let id = registered.id;
    saml_apps::activate(world.tenant(), id)
        .send(world.admin().client())
        .await
        .ok();
    let again = ledger.sign_in_request(tenant, REPORTS);
    let held = AnswerSignIn {
        request: carried(pat, ledger, tenant, &again).await,
    };
    let answer = saml_apps::answer(world.tenant(), &held)
        .send(pat.client())
        .await
        .ok();
    ledger
        .accepted(tenant, &again, &answer.message)
        .expect("Ledger, switched on again, accepts its answer");
}

/// Tess registers Ledger with the certificate its requests are signed
/// with. A request in Ledger's name carrying no signature, as an impostor
/// sends it, gets no answer for Pat, and neither does one signed with
/// another key. Ledger's own signed request is answered, and the answer
/// passes Ledger's check.
#[tokio::test]
async fn once_ledger_signs_its_requests_no_unsigned_or_foreign_one_is_answered() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let ledger = App::signing_at("ledger.example");
    registered(&world, &ledger, "Ledger").await;
    let tenant = the_tenant(&world).await;
    let pat = pat(&world).await;

    let impostor = App::at("ledger.example");
    let stranger = App::signing_at("ledger.example");
    for (app, why) in [
        (&impostor, "an unsigned request"),
        (&stranger, "a request signed with another key"),
    ] {
        let request = app.sign_in_request(&tenant, REPORTS);
        let status = answer_status(&world, &pat, app, &request).await;
        assert_eq!(status, Status::FORBIDDEN, "{why} gets no answer");
    }

    let request = ledger.sign_in_request(&tenant, REPORTS);
    let held = AnswerSignIn {
        request: carried(&pat, &ledger, &tenant, &request).await,
    };
    let answer = saml_apps::answer(world.tenant(), &held)
        .send(pat.client())
        .await
        .ok();
    ledger
        .accepted(&tenant, &request, &answer.message)
        .expect("Ledger accepts the answer to its signed request");
    stack.stop().await.expect("the stack stops cleanly");
}

/// The status the platform refuses or answers `request` with, whether it
/// refuses it as `person`'s browser carries it from `app` or only when the
/// dashboard asks for the answer.
async fn answer_status(world: &World<'_>, person: &Person, app: &App, request: &Sent) -> Status {
    let tenant = the_tenant(world).await;
    let carried = saml_apps::carry(tenant.sso_url(), request.form(), &app.site())
        .send(person.client())
        .await;
    if carried.status() != Status::FOUND {
        return carried.status();
    }
    let onward = carried.header("location").unwrap_or_default().to_owned();
    let held = AnswerSignIn {
        request: parameter(&onward, "request"),
    };
    saml_apps::answer(world.tenant(), &held)
        .send(person.client())
        .await
        .status()
}

/// The base64 answer `message` with `from` written as `to` in it, as
/// someone between the platform and the app might change it.
pub(crate) fn changed(message: &str, from: &str, to: &str) -> String {
    let xml = String::from_utf8(STANDARD.decode(message).expect("base64")).expect("text");
    assert!(xml.contains(from), "the answer carries {from}");
    STANDARD.encode(xml.replace(from, to))
}
