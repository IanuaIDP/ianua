//! Single logout between the tenant and Acme's provider, either way, for
//! a session Pat opened through the provider.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::account::{self, Plane};
use ianua_scenarios::api::{Request, Text, saml_apps};
use ianua_scenarios::net::Call;
use ianua_scenarios::providers::parameter;
use ianua_scenarios::providers::saml::{Claim, Provider};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::saml_apps::{AnswerLogout, FormPost};
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;

use crate::support::{
    Outcome, PROVIDER_SITE, SamlAnswer, Settings, begun, connected, owned_domain, pat, signed_in,
};

/// The parts of the tenant's link to the provider a logout goes through.
struct Linked {
    /// The connection's id.
    connection: String,
    /// The connection's published metadata, naming the certificate the
    /// platform signs with.
    metadata: String,
    /// Where the connection takes the provider's logouts.
    slo_url: String,
}

/// Pat signs in through Acme's provider. The provider asks the tenant to
/// log her out, and her browser carries the request to the connection's
/// logout address; the dashboard hands it back with her session. The
/// answer, signed with the connection's published certificate, goes to
/// the provider's logout address and answers its request with success,
/// and Pat's session on the platform is over.
#[tokio::test]
async fn acmes_provider_logging_pat_out_ends_her_session() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let provider = Provider::new();
    let (linked, pat) = signed_in_through(&world, &provider).await;

    let asked = provider.logout_request(&linked.slo_url);
    let handed = carry_request(&pat, &linked, &asked.message).await;
    let answer_at = world.tenant().at(&format!(
        "/federation/connections/{}/saml/slo/answer",
        linked.connection
    ));
    let answer = Request::<FormPost>::of(Call::post(answer_at).json(&handed))
        .send(pat.client())
        .await
        .ok();
    assert_eq!(answer.destination, provider.slo_url());
    assert_eq!(answer.parameter, "SAMLResponse");
    provider
        .logout_answered(&answer.message, &linked.metadata, &asked)
        .expect("the provider takes the platform's signed answer");
    account::me(Plane::Tenant(world.tenant()))
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat's browser carries the provider request and hands its redirected message back.
async fn carry_request(pat: &Person, linked: &Linked, message: &str) -> AnswerLogout {
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("SAMLRequest", message)
        .finish();
    let carried = pat
        .client()
        .send::<IgnoredAny>(
            Call::post(&linked.slo_url)
                .raw("application/x-www-form-urlencoded", form)
                .header("origin", PROVIDER_SITE)
                .header("sec-fetch-site", "cross-site"),
        )
        .await;
    assert_eq!(carried.status(), Status::FOUND, "{}", carried.summary());
    let onward = carried.header("location").unwrap_or_default().to_owned();
    AnswerLogout {
        message: parameter(&onward, "message"),
        relay_state: None,
    }
}

/// Pat signs in through Acme's provider, then signs out at the platform.
/// The platform hands her browser one logout request, for the provider's
/// logout address, signed with the connection's published certificate
/// and naming her subject and session at the provider. The provider's
/// signed answer, posted back to the connection, is taken: the browser
/// goes on to the sign-in page with the logout a success.
#[tokio::test]
async fn pat_signing_out_at_the_platform_logs_her_out_at_acmes_provider() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let provider = Provider::new();
    let (linked, pat) = signed_in_through(&world, &provider).await;

    let owed = saml_apps::start_logout(world.tenant())
        .send(pat.client())
        .await
        .ok();
    let [to_provider] = owed.messages.as_slice() else {
        panic!("one logout is owed, to the provider");
    };
    answer_platform_request(&pat, &linked, &provider, to_provider).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// The provider accepts the signed request and its answer returns logout success.
async fn answer_platform_request(
    pat: &Person,
    linked: &Linked,
    provider: &Provider,
    to_provider: &FormPost,
) {
    assert_eq!(to_provider.destination, provider.slo_url());
    let asked = provider
        .logout_asked(&to_provider.message, &linked.metadata)
        .expect("the provider takes the platform's signed request");

    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair(
        "SAMLResponse",
        &provider.logged_out(&asked, &linked.slo_url),
    );
    if let Some(relay_state) = &to_provider.relay_state {
        form.append_pair("RelayState", relay_state);
    }
    let taken = pat
        .client()
        .send::<IgnoredAny>(
            Call::post(&linked.slo_url)
                .raw("application/x-www-form-urlencoded", form.finish())
                .header("origin", PROVIDER_SITE)
                .header("sec-fetch-site", "cross-site"),
        )
        .await;
    let onward = taken.header("location").unwrap_or_default().to_owned();
    assert_eq!(
        parameter(&onward, "logout"),
        "success",
        "the browser goes on to the sign-in page: {}",
        taken.summary()
    );
}

/// The tenant's link to `provider`, signing the messages it sends, and
/// Pat signed in on the dashboard through it.
async fn signed_in_through(world: &World<'_>, provider: &Provider) -> (Linked, Person) {
    let domain = owned_domain(world).await;
    let settings = Settings {
        provider,
        next: None,
        sign_requests: true,
    };
    let connection = connected(world, &domain, &settings).await;
    let mut pat = pat(world, &domain).await;
    let redirect = begun(world, &pat, &connection).await;
    let answer = SamlAnswer {
        provider,
        redirect,
        claim: Claim::Correct,
    };
    let outcome = signed_in(world, &mut pat, answer).await;
    assert!(
        matches!(outcome, Outcome::SignedIn),
        "Pat signs in through the provider: {outcome:?}"
    );
    let linked = read_link(world, connection).await;
    (linked, pat)
}

/// Reads the connection's signing metadata and constructs its logout address.
async fn read_link(world: &World<'_>, connection: String) -> Linked {
    let at = |rest: &str| {
        world
            .tenant()
            .at(&format!("/federation/connections/{connection}{rest}"))
    };
    let metadata = Request::<Text>::text(Call::get(at("/saml/metadata")))
        .send_text(world.anonymous().client())
        .await
        .ok();
    let base = world
        .stack()
        .app_url()
        .as_str()
        .trim_end_matches('/')
        .to_owned();
    let slo_url = format!("{base}{}", at("/saml/slo"));
    Linked {
        connection,
        metadata,
        slo_url,
    }
}
