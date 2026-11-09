//! The gateway restarts alone, as its process does during a deploy, while
//! the control plane keeps running. Pat, signed in at Acme's orders app,
//! is still signed in after it; while it is down nothing reaches the app;
//! as it comes back every request is decided before anything is passed
//! on, and nobody without a session gets through; a request already in
//! flight when it stops is ended by the gateway, never sent again.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{app_sign_in, people, routing};
use ianua_scenarios::expect::{Matrix, Records, eventually};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::routes::{Placement, RouteSpec, domain};
use ianua_scenarios::stack::{Profile, Stack, StackError};
use ianua_scenarios::upstreams::{AssertionCheck, Echo, Hanging};
use ianua_scenarios::wire::app_sign_in::{AppLogIn, AppSignInSettings, ConfigureAppSignIn};
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::routing::RoutePolicy;
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::{MEMBER_ROLE, World};
use serde::de::IgnoredAny;

/// How long the slow report's route gives its app, in seconds: long
/// enough to stop the gateway while the request waits, short enough for
/// the stop to wait it out.
const SLOW_TIMEOUT_SECS: u32 = 3;

/// Pat's account page in the orders app.
const ACCOUNT_PAGE: &str = "/account/orders";

/// The slow report, behind a route to an app that never answers.
const SLOW_REPORT: &str = "/slow/report";

/// How many letters of a random id tell this app's names apart.
const WORD_LENGTH: usize = 8;

/// Acme's orders app behind the gateway on a domain of Acme's own: its
/// account pages for signed-in people, and a slow report whose app never
/// answers.
struct OrdersApp {
    host: String,
    app: Echo,
    slow: Hanging,
}

impl OrdersApp {
    /// `path` on the app's host.
    fn page(&self, path: &str) -> String {
        format!("https://{}{path}", self.host)
    }
}

/// Pat signs in at Acme's orders app and reads her account page. A slow
/// report is in flight when the gateway stops: the stop waits for it, the
/// gateway answers it as timed out, and it reached the app once. While the
/// gateway is down neither Pat nor anybody else gets an answer, and the
/// app sees nothing. The moment it is back, every answer is a decision:
/// Pat is let in or told to wait, nobody signed in is refused or told to
/// wait, and the app sees Pat's next request alone. Pat's session cookie,
/// kept from before, still lets her in; the report was not sent again; and
/// the gateway records Pat's request as allowed.
#[tokio::test]
async fn a_gateway_restart_keeps_pat_signed_in_and_lets_nothing_through_undecided() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let orders = orders_app(&world).await;
    let pat = customer(&world).await;
    signed_in_at(&orders, &pat).await;
    pat.client()
        .get::<IgnoredAny>(&orders.page(ACCOUNT_PAGE))
        .await
        .ok();
    let reached = orders.slow.connections();
    let arrived = orders.app.arrivals().len();

    let (in_flight, stopped) = tokio::join!(
        pat.client()
            .attempt::<IgnoredAny>(Call::get(orders.page(SLOW_REPORT))),
        stop_once_reached(&stack, &orders, reached),
    );
    stopped.expect("the gateway stops");
    assert_ended_by_the_gateway(&in_flight);
    assert_eq!(
        orders.slow.connections(),
        reached + 1,
        "the report in flight reached its app once"
    );
    assert_nothing_answers_while_down(&world, &orders, &pat).await;
    assert_eq!(
        orders.app.arrivals().len(),
        arrived,
        "nothing reached the app while the gateway was down"
    );

    stack
        .start_gateway()
        .await
        .expect("the gateway starts again");
    every_answer_decided_until_pat_is_in(&world, &orders, &pat).await;
    assert_eq!(
        orders.app.arrivals().len(),
        arrived + 1,
        "the app saw Pat's one request let in, and nothing while the gateway came back"
    );
    assert_pat_alone_reaches_the_app(&world, &orders, &pat).await;
    assert_allowed_record(&world, &pat).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Stops the gateway once the slow report reached its app, so the stop
/// comes while the request is in flight.
async fn stop_once_reached(
    stack: &Stack,
    orders: &OrdersApp,
    reached: usize,
) -> Result<(), StackError> {
    eventually("the slow report to reach its app", || async {
        (orders.slow.connections() > reached).then_some(())
    })
    .await;
    stack.stop_gateway().await
}

/// The report in flight when the gateway stopped was ended by the
/// gateway: answered as timed out at its route's timeout, or its
/// connection closed unanswered. The app it waited on never answers, so
/// nothing else could have been passed back.
fn assert_ended_by_the_gateway(in_flight: &Result<Answer<IgnoredAny>, String>) {
    let Ok(answer) = in_flight else {
        return;
    };
    assert_eq!(
        answer.status(),
        Status::GATEWAY_TIMEOUT,
        "the stopping gateway ends the report at its timeout: {}",
        answer.summary()
    );
}

/// While the gateway is down, neither Pat nor a visitor nobody signed in
/// gets any answer from the app's host.
async fn assert_nothing_answers_while_down(world: &World<'_>, orders: &OrdersApp, pat: &Person) {
    for (who, client) in [
        ("Pat", pat.client()),
        ("a visitor", world.anonymous().client()),
    ] {
        let answer = client
            .attempt::<IgnoredAny>(Call::get(orders.page(ACCOUNT_PAGE)))
            .await;
        assert!(
            answer.is_err(),
            "{who} got an answer while the gateway was down: {:?}",
            answer.map(|answered| answered.summary())
        );
    }
}

/// Asks for Pat's account page as Pat and as a visitor nobody signed in,
/// again and again, from the moment the gateway is back until Pat is let
/// in: Pat is only ever let in or told to wait, the visitor only ever
/// refused or told to wait.
async fn every_answer_decided_until_pat_is_in(world: &World<'_>, orders: &OrdersApp, pat: &Person) {
    let page = orders.page(ACCOUNT_PAGE);
    eventually("Pat to be let in again", || async {
        let visitor = world
            .anonymous()
            .client()
            .attempt::<IgnoredAny>(Call::get(page.as_str()))
            .await
            .ok()?;
        assert!(
            [Status::UNAUTHORIZED, Status::SERVICE_UNAVAILABLE].contains(&visitor.status()),
            "a visitor is refused or told to wait while the gateway comes back: {}",
            visitor.summary()
        );
        let answer = pat
            .client()
            .attempt::<IgnoredAny>(Call::get(page.as_str()))
            .await
            .ok()?;
        assert!(
            [Status::OK, Status::SERVICE_UNAVAILABLE].contains(&answer.status()),
            "Pat is let in or told to wait while the gateway comes back: {}",
            answer.summary()
        );
        (answer.status() == Status::OK).then_some(())
    })
    .await;
}

/// After the restart Pat, with the session cookie she held before it, is
/// let in and the app sees the gateway's signed assertion naming her;
/// nobody signed in is refused and the app sees nothing of them.
async fn assert_pat_alone_reaches_the_app(world: &World<'_>, orders: &OrdersApp, pat: &Person) {
    let before = orders.app.arrivals().len();
    Matrix::new(
        "reading Pat's account page after the gateway restarted",
        Call::get(orders.page(ACCOUNT_PAGE)),
    )
    .allowed(pat.client())
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
    let arrivals = orders.app.arrivals();
    assert_eq!(arrivals.len(), before + 1, "only Pat reached the app");
    for arrival in &arrivals {
        let AssertionCheck::Verified { caller } = &arrival.assertion else {
            panic!("a request reached the app without the gateway's assertion: {arrival:?}");
        };
        assert_eq!(caller.sub, pat.id(), "every request let in was Pat's");
        assert!(
            !arrival.has_header("cookie"),
            "Pat's cookie reached the app"
        );
    }
}

/// The gateway's records hold Pat's request to her account page as an
/// allowed request of a tenant user.
async fn assert_allowed_record(world: &World<'_>, pat: &Person) {
    let record = Records::of_tenant(world.admin().client(), world.tenant())
        .recorded_where(ACCOUNT_PAGE, "Pat's", |record| {
            record.subject.id.as_deref() == Some(pat.id())
        })
        .await;
    assert_eq!(record.decision, "allowed", "Pat's request is allowed");
}

/// Tess puts Acme's orders app behind the gateway on a domain of Acme's
/// own: its account pages for signed-in people, signing them in on that
/// host, and a slow report, open to anyone, whose app never answers and
/// whose route gives it a few seconds.
async fn orders_app(world: &World<'_>) -> OrdersApp {
    let stack = world.stack();
    let admin = world.admin().client();
    let word = uuid::Uuid::new_v4().simple().to_string()[..WORD_LENGTH].to_owned();
    let host = domain::brought(
        stack,
        admin,
        world.tenant(),
        &format!("orders-{word}.{}", stack.customer_domain()),
    )
    .await;
    let app = Echo::start(stack, &host)
        .await
        .expect("the orders app starts");
    let slow = Hanging::start()
        .await
        .expect("the slow report's app starts");
    let probe = Client::new(stack, "a probe").expect("a client for the probe");
    let hosts = std::slice::from_ref(&host);
    let account = RouteSpec::public(&format!("orders-{word}"), "/account/*")
        .asking(RoutePolicy::Authenticated)
        .pinned(&format!("orders-{word}"))
        .on_hosts(hosts)
        .applied(
            admin,
            &probe,
            Placement {
                tenant: world.tenant(),
                upstream: &app.url(),
                host: &host,
            },
        )
        .await;
    RouteSpec::public(&format!("orders-slow-{word}"), "/slow/*")
        .timing_out_after(SLOW_TIMEOUT_SECS)
        .on_hosts(hosts)
        .applied(
            admin,
            &probe,
            Placement {
                tenant: world.tenant(),
                upstream: &slow.url(),
                host: &host,
            },
        )
        .await;
    let signing_in = ConfigureAppSignIn {
        app_sign_in: Some(AppSignInSettings {
            hosts: vec![host.clone()],
            signed_out_browsers: "refuse".to_owned(),
        }),
        accepts_app_sign_in_of: None,
        delivery: None,
    };
    routing::configure_app_sign_in(world.tenant(), &account.service_id, &signing_in)
        .send(admin)
        .await
        .ok();
    let orders = OrdersApp { host, app, slow };
    signs_in(&orders, &probe).await;
    orders
}

/// Waits until the gateway answers the orders app's sign-in address.
async fn signs_in(orders: &OrdersApp, probe: &Client) {
    let login = orders.page("/.ianua/login");
    eventually(
        "the gateway to answer the orders app's sign-in address",
        || async {
            let answer = probe.send::<IgnoredAny>(Call::get(login.as_str())).await;
            (answer.status() == Status::OK).then_some(())
        },
    )
    .await;
}

/// Pat, invited by Tess into the tenant with its `Member` role, who joined
/// from the mailed link with a password of her own.
async fn customer(world: &World<'_>) -> Person {
    let mut pat = world.newcomer("pat", "Pat Customer");
    let invitation = InviteUser {
        email: pat.email().to_owned(),
        display_name: pat.account().display_name.clone(),
        role_id: world.role_id(MEMBER_ROLE).await,
    };
    let made = people::invite(world.tenant(), &invitation)
        .send(world.admin().client())
        .await
        .ok();
    pat.record_invitation(&made.id);
    pat.accept_invitation(world.stack()).await;
    pat
}

/// Pat signed in on the orders app's own host, holding its session cookie.
async fn signed_in_at(orders: &OrdersApp, pat: &Person) {
    let log_in = AppLogIn {
        email: pat.email().to_owned(),
        password: pat.password().to_owned(),
    };
    let signed_in = app_sign_in::log_in(&orders.host, &log_in)
        .send(pat.client())
        .await
        .ok();
    assert!(
        signed_in.signed_in && !signed_in.mfa_required,
        "Pat is signed in at the orders app"
    );
}
