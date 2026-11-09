//! Single logout between Ledger and the tenant, either way. Ledger asking
//! ends Pat's session on the platform only when it names her as Ledger
//! knows her; Pat signing out at the platform sends Ledger a signed
//! request naming her, and Ledger's answer is taken.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::account::{self, Plane};
use ianua_scenarios::api::{audit, saml_apps};
use ianua_scenarios::providers::parameter;
use ianua_scenarios::services::saml::logout::{LoggedOut, LogoutAsked};
use ianua_scenarios::services::saml::sign_in::Accepted;
use ianua_scenarios::services::saml::{App, IdentityProvider, Refusal, Sent};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::saml_apps::{AnswerLogout, FormPost};
use ianua_scenarios::world::World;

use crate::support::{pat, registered, sent_on, signed_in_to, the_tenant};

/// The page of Ledger Pat logs out from, which every answer brings back.
const GOODBYE: &str = "/goodbye";

/// The record of a logout request sent to an app.
const REQUEST_SENT: &str = "federation.logout_request_sent";

/// The record of an app's answer to it.
const ANSWER_TAKEN: &str = "federation.logout_response_taken";

/// Ledger and the tenant whose signed logout messages it exchanges.
struct LogoutPeers<'a> {
    app: &'a App,
    provider: &'a IdentityProvider,
}

/// Pat signs in to Ledger through the tenant. A logout request naming
/// someone Ledger never signed in, carried by Pat's browser, is answered
/// as failed, and Pat is still signed in. Ledger's own request for her is
/// answered with a signed success sent to Ledger's logout address,
/// bringing back the page she left from, and her session on the platform
/// is over. The same request handed in again is refused.
#[tokio::test]
async fn ledger_logging_pat_out_ends_her_session_only_when_it_names_her() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let ledger = App::at("ledger.example");
    registered(&world, &ledger, "Ledger").await;
    let tenant = the_tenant(&world).await;
    let pat = pat(&world).await;
    let known = signed_in_to(&world, &pat, &ledger, &tenant).await;
    let peers = LogoutPeers {
        app: &ledger,
        provider: &tenant,
    };
    refuse_other_person(&world, &pat, &peers, &known).await;
    logout_pat_once(&world, &pat, &peers, &known).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// A logout naming someone Ledger never saw fails and preserves Pat's session.
async fn refuse_other_person(
    world: &World<'_>,
    pat: &Person,
    peers: &LogoutPeers<'_>,
    known: &Accepted,
) {
    let LogoutPeers {
        app: ledger,
        provider: tenant,
    } = *peers;
    let somebody_else = Accepted {
        name_id: "somebody-ledger-never-saw".to_owned(),
        ..known.clone()
    };
    let forged = ledger.logout_request(tenant, &somebody_else, GOODBYE);
    let answer = logout_answered(world, pat, peers, &forged).await;
    let outcome = ledger.logout_answered(tenant, &forged, &answer.message);
    assert!(
        matches!(outcome, Ok(LoggedOut::Failed(_))),
        "a logout naming somebody else fails: {outcome:?}"
    );
    account::me(Plane::Tenant(world.tenant()))
        .send(pat.client())
        .await
        .ok();
}

/// Ledger's logout for Pat ends her session and cannot be replayed.
async fn logout_pat_once(
    world: &World<'_>,
    pat: &Person,
    peers: &LogoutPeers<'_>,
    known: &Accepted,
) {
    let LogoutPeers {
        app: ledger,
        provider: tenant,
    } = *peers;
    let request = ledger.logout_request(tenant, known, GOODBYE);
    let answer = logout_answered(world, pat, peers, &request).await;
    assert_eq!(answer.destination, ledger.logout_url());
    assert_eq!(answer.parameter, "SAMLResponse");
    assert_eq!(answer.relay_state.as_deref(), Some(GOODBYE));
    assert_eq!(
        ledger.logout_answered(tenant, &request, &answer.message),
        Ok(LoggedOut::Success),
        "Ledger takes the platform's signed answer"
    );
    account::me(Plane::Tenant(world.tenant()))
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    let again = handed_back(pat, ledger, tenant, &request).await;
    saml_apps::answer_logout(world.tenant(), &again)
        .send(world.anonymous().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// Pat signs in to Ledger, then signs out at the platform. The platform
/// hands her browser one signed logout request, for Ledger's logout
/// address, naming her and her session as Ledger knows them; Ledger
/// refuses the same request for anybody else it knows. Ledger's answer,
/// posted back to the tenant, is taken: the browser goes on to the
/// sign-in page with the logout a success, and both steps are on record.
#[tokio::test]
async fn pat_signing_out_at_the_platform_logs_her_out_of_ledger() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let ledger = App::at("ledger.example");
    registered(&world, &ledger, "Ledger").await;
    let tenant = the_tenant(&world).await;
    let pat = pat(&world).await;
    let known = signed_in_to(&world, &pat, &ledger, &tenant).await;
    let peers = LogoutPeers {
        app: &ledger,
        provider: &tenant,
    };
    answer_platform_logout(&world, &pat, &peers, &known).await;
    assert_logout_records(&world).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ledger checks the single request for Pat and sends its successful answer back.
async fn answer_platform_logout(
    world: &World<'_>,
    pat: &Person,
    peers: &LogoutPeers<'_>,
    known: &Accepted,
) {
    let LogoutPeers {
        app: ledger,
        provider: tenant,
    } = *peers;
    let owed = saml_apps::start_logout(world.tenant())
        .send(pat.client())
        .await
        .ok();
    let [to_ledger] = owed.messages.as_slice() else {
        panic!("one logout is owed, to Ledger");
    };
    let asked = check_logout_request(peers, known, to_ledger);
    let relay_state = to_ledger.relay_state.as_deref().unwrap_or_default();
    let answer = ledger.logged_out(tenant, &asked, relay_state);
    let slo = tenant.slo_url().expect("the tenant takes logouts");
    let onward = sent_on(pat, ledger, slo, &answer).await;
    assert_eq!(
        parameter(&onward, "logout"),
        "success",
        "the browser goes on to the sign-in page"
    );
}

/// The signed request targets Ledger and identifies Pat rather than another person.
fn check_logout_request(
    peers: &LogoutPeers<'_>,
    known: &Accepted,
    to_ledger: &FormPost,
) -> LogoutAsked {
    let LogoutPeers {
        app: ledger,
        provider: tenant,
    } = *peers;
    assert_eq!(to_ledger.destination, ledger.logout_url());
    assert_eq!(to_ledger.parameter, "SAMLRequest");
    let somebody_else = Accepted {
        name_id: "somebody-ledger-signed-in".to_owned(),
        ..known.clone()
    };
    assert_eq!(
        ledger
            .logout_asked(tenant, &to_ledger.message, &somebody_else)
            .map(|_| ()),
        Err(Refusal::Person),
        "the request names Pat, not anybody else Ledger knows"
    );
    ledger
        .logout_asked(tenant, &to_ledger.message, known)
        .expect("Ledger takes the platform's signed request for Pat")
}

/// The request to Ledger and its accepted answer each appear once on the trail.
async fn assert_logout_records(world: &World<'_>) {
    for (event, why) in [
        (REQUEST_SENT, "the request to Ledger"),
        (ANSWER_TAKEN, "Ledger's answer"),
    ] {
        let recorded = audit::tenant_log(world.tenant(), event)
            .send(world.owner().client())
            .await
            .ok();
        assert_eq!(recorded.items.len(), 1, "{why} is on record");
    }
}

/// The platform's answer to `request`, once `person`'s browser carried it
/// from the app to the tenant's logout service and the dashboard handed it
/// back with their session.
async fn logout_answered(
    world: &World<'_>,
    person: &Person,
    peers: &LogoutPeers<'_>,
    request: &Sent,
) -> FormPost {
    let handed = handed_back(person, peers.app, peers.provider, request).await;
    saml_apps::answer_logout(world.tenant(), &handed)
        .send(person.client())
        .await
        .ok()
}

/// `request` as the dashboard hands it back, read from where the platform
/// sent `person`'s browser once it carried it from `app` to the tenant's
/// logout service.
async fn handed_back(
    person: &Person,
    app: &App,
    provider: &IdentityProvider,
    request: &Sent,
) -> AnswerLogout {
    let slo = provider.slo_url().expect("the tenant takes logouts");
    let onward = sent_on(person, app, slo, request).await;
    assert_eq!(parameter(&onward, "binding"), "post");
    AnswerLogout {
        message: parameter(&onward, "message"),
        relay_state: Some(parameter(&onward, "relay_state")),
    }
}
