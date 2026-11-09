//! What the gateway scenarios share: the deployment they run, the tenant's
//! app host, a client nobody signed in on for probing routes, a word that
//! tells one shop from another, a shop a tenant sets up behind the gateway,
//! its customers, and a customer signed in at it.

use ianua_scenarios::actors::{Person, PersonAccount};
use ianua_scenarios::api::{TenantPath, app_sign_in, control_access, people, roles, routing};
use ianua_scenarios::expect::{eventually, eventually_within};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::routes::{AppliedRoute, Placement, RouteSpec, domain};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{AssertedCaller, AssertionCheck, Echo};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::app_sign_in::{
    AppLogIn, AppSignInSettings, ConfigureAppSignIn, Delivery, TokenFor,
};
use ianua_scenarios::wire::control_access::{NewAction, NewResourceType};
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::routing::RoutePolicy;
use ianua_scenarios::world::{MEMBER_ROLE, World};
use serde::de::IgnoredAny;

/// The password the twin tenant's customer chooses: a sentence, so no
/// scanner takes it for a key.
const TWIN_CUSTOMER_PASSWORD: &str = "Scenario lantern meadow copper 7314";

/// How many letters of a random id tell one shop's names from another's:
/// enough that two shops in one run never share them.
const WORD_LENGTH: usize = 8;

/// How long the gateway is given to pick up an app's sign-in setting.
const SIGN_IN_PATIENCE: std::time::Duration = std::time::Duration::from_secs(30);

/// The deployment the gateway scenarios run against: the standard one.
pub(crate) fn profile() -> Profile {
    Profile::standard()
}

/// Tess declares the tenant's own `resource` with the one action `action`,
/// which a role or a route must find in the catalogue before naming it.
pub(crate) async fn declared_permission(world: &World<'_>, resource: &str, action: &str) {
    let declared = NewResourceType {
        key: resource.to_owned(),
        display_name: resource.to_owned(),
        actions: vec![NewAction {
            key: action.to_owned(),
            display_name: action.to_owned(),
            implies: Vec::new(),
        }],
        data_class: "Internal".to_owned(),
    };
    control_access::declare_resource_type(world.tenant(), &declared)
        .send(world.admin().client())
        .await
        .ok();
}

/// The random root, or explicitly enabled readable root, as the tenant's
/// administrator reads it from the API.
pub(crate) async fn app_host(world: &World<'_>) -> String {
    let names = routing::hostnames(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    names.slug_subdomain.unwrap_or(names.uuid_subdomain)
}

/// A client that has signed in nowhere, for asking after routes.
pub(crate) fn probe(stack: &Stack) -> Client {
    Client::new(stack, "a probe").expect("a client for the probe")
}

/// A word unique to one shop, route or domain, so two of them made in the
/// same run never share a name.
pub(crate) fn word() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..WORD_LENGTH].to_owned()
}

/// A tenant's shop as a customer sets one up behind the gateway: the shop
/// app on a domain of the tenant's own, signing people in there, with its
/// account pages for signed-in people alone; and its API on the tenant's
/// apps host, taking short-lived tokens the shop's pages fetch for it.
pub(crate) struct Shop {
    /// The service owning the shop's app sign-in, for explicit acceptance.
    pub(crate) app_service_id: String,
    /// The shop's own domain.
    pub(crate) host: String,
    /// The tenant's host under the apps domain, where the API is reached.
    /// Its route names no host, so it answers on every host of the tenant:
    /// a route may name only the tenant's platform hosts or verified domains.
    pub(crate) api_host: String,
    /// The audience the API's tokens are made for.
    pub(crate) api_audience: String,
    /// The shop app.
    pub(crate) app: Echo,
    /// The shop's API.
    pub(crate) api: Echo,
}

/// What a [`Shop`] is opened in: the tenant, its administrator, and a word
/// telling its names apart from every other shop's.
pub(crate) struct ShopOwner<'a> {
    /// The tenant.
    pub(crate) tenant: &'a TenantPath,
    /// Its administrator.
    pub(crate) admin: &'a Client,
    /// A word unique to this shop.
    pub(crate) word: &'a str,
}

impl Shop {
    /// The shop `owner` opens on `stack`, served once this returns.
    pub(crate) async fn opened(stack: &Stack, owner: &ShopOwner<'_>) -> Self {
        let host = domain::brought(
            stack,
            owner.admin,
            owner.tenant,
            &format!("shop-{}.{}", owner.word, stack.customer_domain()),
        )
        .await;
        let names = routing::hostnames(owner.tenant)
            .send(owner.admin)
            .await
            .ok();
        let api_host = names.slug_subdomain.unwrap_or(names.uuid_subdomain);
        let audience = format!("shop-{}", owner.word);
        let api_audience = format!("shop-api-{}", owner.word);
        let app = Echo::start(stack, &host)
            .await
            .expect("the shop app starts");
        let api = Echo::start(stack, &api_host)
            .await
            .expect("the shop's API starts");
        let probe = probe(stack);
        let account = RouteSpec::public(&format!("shop-{}", owner.word), "/account/*")
            .asking(RoutePolicy::Authenticated)
            .pinned(&audience)
            .on_hosts(std::slice::from_ref(&host))
            .applied(
                owner.admin,
                &probe,
                Placement {
                    tenant: owner.tenant,
                    upstream: &app.url(),
                    host: &host,
                },
            )
            .await;
        let orders = RouteSpec::public(&format!("shop-api-{}", owner.word), "/orders/*")
            .asking(RoutePolicy::Authenticated)
            .pinned(&api_audience)
            .applied(
                owner.admin,
                &probe,
                Placement {
                    tenant: owner.tenant,
                    upstream: &api.url(),
                    host: &api_host,
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
        routing::configure_app_sign_in(owner.tenant, &account.service_id, &signing_in)
            .send(owner.admin)
            .await
            .ok();
        let accepting = ConfigureAppSignIn {
            app_sign_in: None,
            accepts_app_sign_in_of: Some(account.service_id.clone()),
            delivery: Some(Delivery::Tokens),
        };
        routing::configure_app_sign_in(owner.tenant, &orders.service_id, &accepting)
            .send(owner.admin)
            .await
            .ok();
        let shop = Self {
            app_service_id: account.service_id,
            host,
            api_host,
            api_audience,
            app,
            api,
        };
        shop.signs_in(&probe).await;
        shop
    }

    /// Waits until the gateway answers the shop's sign-in address.
    async fn signs_in(&self, probe: &Client) {
        let login = format!("https://{}/.ianua/login", self.host);
        eventually(
            "the gateway to answer the shop's sign-in address",
            || async {
                let answer = probe.send::<IgnoredAny>(Call::get(login.as_str())).await;
                (answer.status() == Status::OK).then_some(())
            },
        )
        .await;
    }

    /// `path` on the shop's host.
    pub(crate) fn page(&self, path: &str) -> String {
        format!("https://{}{path}", self.host)
    }

    /// `path` on the shop's API host.
    pub(crate) fn endpoint(&self, path: &str) -> String {
        format!("https://{}{path}", self.api_host)
    }
}

/// One app of the tenant's behind one route, on a host of its own under
/// the tenant's random label, signing people in on that host.
pub(crate) struct HostedApp {
    /// The host it answers on.
    pub(crate) host: String,
    /// The service, pipeline and route that publish it.
    pub(crate) route: AppliedRoute,
}

impl HostedApp {
    /// Tess puts `spec` on a host beginning `name`, forwarding to
    /// `upstream`, its tokens pinned to `name`, and signing people in
    /// there; served once this returns.
    pub(crate) async fn opened(
        world: &World<'_>,
        name: &str,
        spec: RouteSpec,
        upstream: &str,
    ) -> Self {
        let admin = world.admin().client();
        let names = routing::hostnames(world.tenant()).send(admin).await.ok();
        let host = format!("{name}-{}", names.uuid_subdomain);
        let visitor = probe(world.stack());
        let route = spec
            .pinned(name)
            .on_hosts(std::slice::from_ref(&host))
            .applied(
                admin,
                &visitor,
                Placement {
                    tenant: world.tenant(),
                    upstream,
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
        routing::configure_app_sign_in(world.tenant(), &route.service_id, &signing_in)
            .send(admin)
            .await
            .ok();
        let login = format!("https://{host}/.ianua/login");
        eventually_within("the app to accept sign-ins", SIGN_IN_PATIENCE, || async {
            let answer = visitor.send::<IgnoredAny>(Call::get(login.as_str())).await;
            (answer.status() == Status::OK).then_some(())
        })
        .await;
        Self { host, route }
    }

    /// `path` on the app's host.
    pub(crate) fn page(&self, path: &str) -> String {
        format!("https://{}{path}", self.host)
    }
}

/// `person` signed in on `host`, holding its session cookie.
pub(crate) async fn signed_in_on(host: &str, person: &Person) {
    let log_in = AppLogIn {
        email: person.email().to_owned(),
        password: person.password().to_owned(),
    };
    let signed_in = app_sign_in::log_in(host, &log_in)
        .send(person.client())
        .await
        .ok();
    assert!(
        signed_in.signed_in && !signed_in.mfa_required,
        "{} is signed in on {host}",
        person.email()
    );
}

/// Someone Tess invites into the world's tenant, who joins from the mailed
/// link with a password of their own.
pub(crate) async fn customer(world: &World<'_>, name: &str, display_name: &str) -> Person {
    let person = world.newcomer(name, display_name);
    joined(world, person, world.tenant(), world.admin().client()).await
}

/// Someone Sam invites into the twin tenant, who joins from the mailed link
/// with a password of their own.
pub(crate) async fn twin_customer(world: &World<'_>, name: &str, display_name: &str) -> Person {
    let account = PersonAccount {
        email: world.address(name),
        display_name: display_name.to_owned(),
        tenant: world.twin().clone(),
    };
    let client = Client::new(world.stack(), display_name).expect("a client for the customer");
    let person = Person::new(client, account, TWIN_CUSTOMER_PASSWORD);
    joined(world, person, world.twin(), world.stranger().client()).await
}

/// `person`, invited into `tenant` by `admin` with its `Member` role, once
/// they accepted from the mailed link.
async fn joined(
    world: &World<'_>,
    mut person: Person,
    tenant: &TenantPath,
    admin: &Client,
) -> Person {
    let roles = roles::list(tenant).send(admin).await.ok();
    let Some(member) = roles
        .items
        .into_iter()
        .find(|role| role.name == MEMBER_ROLE)
    else {
        panic!("the tenant has no {MEMBER_ROLE} role");
    };
    let invitation = InviteUser {
        email: person.email().to_owned(),
        display_name: person.account().display_name.clone(),
        role_id: member.id,
    };
    let made = people::invite(tenant, &invitation).send(admin).await.ok();
    person.record_invitation(&made.id);
    person.accept_invitation(world.stack()).await;
    person
}

/// `person` signed in on `shop`'s own host, holding its session cookie.
pub(crate) async fn signed_in_at(shop: &Shop, person: &Person) {
    signed_in_on(&shop.host, person).await;
}

/// The token the shop's page fetches for `person`, for the shop's API.
pub(crate) async fn api_token(shop: &Shop, person: &Person) -> String {
    let wanted = TokenFor {
        audience: shop.api_audience.clone(),
    };
    app_sign_in::token(&shop.host, &wanted)
        .send(person.client())
        .await
        .ok()
        .access_token
}

/// Who the gateway vouched for on the last request `app` got, once the
/// app checked the assertion against the tenant's published keys and no
/// credential of the caller's arrived with it.
pub(crate) fn last_caller(app: &Echo) -> AssertedCaller {
    let arrived = app.arrivals();
    let Some(last) = arrived.last() else {
        panic!("nothing reached the app");
    };
    let AssertionCheck::Verified { caller } = &last.assertion else {
        panic!("the app could not check the gateway's assertion: {last:?}");
    };
    for credential in ["authorization", "cookie"] {
        assert!(
            !last.has_header(credential),
            "the caller's {credential} reached the app"
        );
    }
    (**caller).clone()
}
