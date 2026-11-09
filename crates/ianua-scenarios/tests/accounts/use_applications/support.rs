//! What the application scenarios share: an app published behind the
//! gateway with a real upstream that sees every request forwarded to it,
//! a person invited into the tenant, their sign-in on the app's own host,
//! the moves of a route through its life, and waiting for the gateway to
//! answer a changed route as it now should.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{Request, app_sign_in, people, routing};
use ianua_scenarios::expect::eventually;
use ianua_scenarios::net::Client;
use ianua_scenarios::routes::{self, AppliedRoute, Placement, RouteSpec, domain};
use ianua_scenarios::upstreams::{Arrival, Echo};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::app_sign_in::{AppLogIn, AppSignInSettings, ConfigureAppSignIn};
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::routing::{RouteChange, RoutePolicy};
use ianua_scenarios::world::{MEMBER_ROLE, World};

/// An app published behind the gateway, and the upstream behind it that
/// keeps every request forwarded to it.
pub(crate) struct Application {
    /// The host the gateway serves it on.
    pub(crate) host: String,
    /// The service, pipeline and route that publish it.
    pub(crate) route: AppliedRoute,
    /// The upstream every allowed request reaches.
    pub(crate) upstream: Echo,
}

impl Application {
    /// An app anyone may reach, published by Tess under `/app/*` on the
    /// tenant's own platform name.
    pub(crate) async fn public(world: &World<'_>) -> Self {
        let names = routing::hostnames(world.tenant())
            .send(world.admin().client())
            .await
            .ok();
        let host = names.slug_subdomain.unwrap_or(names.uuid_subdomain);
        let upstream = Echo::start(world.stack(), &host)
            .await
            .expect("the app starts");
        let probe = Client::new(world.stack(), "a visitor of the app").expect("a client");
        let route = RouteSpec::public("published-app", "/app/*")
            .applied(
                world.admin().client(),
                &probe,
                Placement {
                    tenant: world.tenant(),
                    upstream: &upstream.url(),
                    host: &host,
                },
            )
            .await;
        Self {
            host,
            route,
            upstream,
        }
    }

    /// An app only signed-in people reach, published by Tess under
    /// `/app/*` on a domain the tenant proved, with sign-in on that same
    /// host, waited for until the gateway serves its sign-in page.
    pub(crate) async fn protected(world: &World<'_>) -> Self {
        let name = format!("managed-app.{}", world.stack().customer_domain());
        let host =
            domain::brought(world.stack(), world.admin().client(), world.tenant(), &name).await;
        let upstream = Echo::start(world.stack(), &host)
            .await
            .expect("the protected app starts");
        let probe = Client::new(world.stack(), "a visitor of the app").expect("a client");
        let route = RouteSpec::public("protected-app", "/app/*")
            .asking(RoutePolicy::Authenticated)
            .pinned("managed-application")
            .on_hosts(std::slice::from_ref(&host))
            .applied(
                world.admin().client(),
                &probe,
                Placement {
                    tenant: world.tenant(),
                    upstream: &upstream.url(),
                    host: &host,
                },
            )
            .await;
        configure_app(world, &route, &host).await;
        await_app_sign_in(&host, &probe).await;
        Self {
            host,
            route,
            upstream,
        }
    }

    /// A visit to `path` on the app's host, answered by what the upstream
    /// saw when the gateway forwarded it.
    pub(crate) fn visit(&self, path: &str) -> Request<Arrival> {
        routes::visit(&self.host, path)
    }

    /// The route pointed at `service_id` and answering `path_pattern`
    /// instead.
    pub(crate) fn route_moved(
        &self,
        world: &World<'_>,
        service_id: &str,
        path_pattern: &str,
    ) -> Request<()> {
        let change = RouteChange {
            service_id: Some(service_id.to_owned()),
            path_pattern: Some(path_pattern.to_owned()),
        };
        routing::change_route(world.tenant(), &self.route.route_id, &change)
    }

    /// The route taken down, kept.
    pub(crate) fn route_disabled(&self, world: &World<'_>) -> Request<()> {
        routing::disable_route(world.tenant(), &self.route.route_id)
    }

    /// A disabled route back up.
    pub(crate) fn route_activated(&self, world: &World<'_>) -> Request<()> {
        routing::activate_route(world.tenant(), &self.route.route_id)
    }

    /// The route removed for good.
    pub(crate) fn route_removed(&self, world: &World<'_>) -> Request<()> {
        routing::remove_route(world.tenant(), &self.route.route_id)
    }
}

/// Enables sign-in on the app host while refusing signed-out browsers.
async fn configure_app(world: &World<'_>, route: &AppliedRoute, host: &str) {
    routing::configure_app_sign_in(
        world.tenant(),
        &route.service_id,
        &ConfigureAppSignIn {
            app_sign_in: Some(AppSignInSettings {
                hosts: vec![host.to_owned()],
                signed_out_browsers: "refuse".to_owned(),
            }),
            accepts_app_sign_in_of: None,
            delivery: None,
        },
    )
    .send(world.admin().client())
    .await
    .ok();
}

/// Waits until gateway configuration makes the app's sign-in page available.
async fn await_app_sign_in(host: &str, probe: &Client) {
    eventually("the gateway to serve the app's sign-in page", || async {
        let answer = app_sign_in::sign_in_page(host).send(probe).await;
        (answer.status() == Status::OK).then_some(())
    })
    .await;
}

/// Someone named `name`, invited by Tess into the tenant as a member, who
/// accepted from the mailed link; not signed in anywhere yet.
pub(crate) async fn invited(world: &World<'_>, name: &str, display_name: &str) -> Person {
    let mut person = world.newcomer(name, display_name);
    let invitation = people::invite(
        world.tenant(),
        &InviteUser {
            email: person.email().to_owned(),
            display_name: person.account().display_name.clone(),
            role_id: world.role_id(MEMBER_ROLE).await,
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    person.record_invitation(&invitation.id);
    person.accept_invitation(world.stack()).await;
    person
}

/// `person` signs in on `app`'s own host with their password, keeping the
/// cookie in their own jar, and owes nothing more.
pub(crate) async fn signed_in_at(app: &Application, person: &Person) {
    let log_in = AppLogIn {
        email: person.email().to_owned(),
        password: person.password().to_owned(),
    };
    let answer = app_sign_in::log_in(&app.host, &log_in)
        .send(person.client())
        .await
        .ok();
    assert!(
        answer.signed_in,
        "{} is signed in at the app",
        person.email()
    );
    assert!(
        !answer.mfa_required,
        "{} owes no second factor at the app",
        person.email()
    );
}

/// Waits until the gateway answers `visit` as `client` with `expected`:
/// a changed route takes a moment to reach the gateway.
pub(crate) async fn once_answering(client: &Client, visit: Request<Arrival>, expected: Status) {
    eventually("the gateway to answer the changed route", || async {
        let answer = visit.clone().send(client).await;
        (answer.status() == expected).then_some(())
    })
    .await;
}
