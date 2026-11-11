//! The start page: the apps a person may open, asked of the gateway's own
//! decision before they open any. What it lists, the gateway lets them
//! open, and what it leaves out, the gateway refuses. A role taken back
//! leaves the page at once, and nobody signed in has a page at all.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{roles, routing};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::net::Call;
use ianua_scenarios::routes::RouteSpec;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::upstreams::Echo;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::roles::{AssignRole, NewAppRole};
use ianua_scenarios::wire::routing::{CustomPermission, OpenableApp, RoutePolicy};
use ianua_scenarios::world::World;

use crate::support::{HostedApp, app_host, customer, declared_permission, profile, signed_in_on};

/// What the reports app asks for.
fn reading_reports() -> CustomPermission {
    CustomPermission {
        resource: "reports".to_owned(),
        action: "read".to_owned(),
    }
}

/// Tess publishes the wiki for anyone signed in, the reports app for
/// those who may read reports, and the archive, which she then takes
/// down. Pat may read reports; Quinn may not. Pat's start page lists the
/// wiki and the reports app, each opening now at its own path, and
/// Quinn's only the wiki; neither lists the archive, and nobody signed in
/// is told to sign in. The gateway agrees: both open the wiki, Pat opens
/// the reports app, and Quinn is forbidden there. Tess takes Pat's role
/// back, and his start page drops the reports app.
#[tokio::test]
async fn the_start_page_lists_what_the_gateway_lets_each_person_open() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let echo = Echo::start(&stack, &app_host(&world).await)
        .await
        .expect("the apps start");
    declared_permission(&world, "reports", "read").await;
    let wiki = HostedApp::opened(&world, "wiki", signed_in_only("wiki"), &echo.url()).await;
    let reports = HostedApp::opened(&world, "reports", report_readers_only(), &echo.url()).await;
    let archive =
        HostedApp::opened(&world, "archive", signed_in_only("archive"), &echo.url()).await;
    routing::disable_route(world.tenant(), &archive.route.route_id)
        .send(world.admin().client())
        .await
        .ok();
    let mut pat = customer(&world, "pat", "Pat Customer").await;
    let mut quinn = customer(&world, "quinn", "Quinn Contractor").await;
    let role = report_reader(&world, &pat).await;
    pat.sign_in(world.stack()).await;
    quinn.sign_in(world.stack()).await;

    let pat_s = start_page(&world, &pat).await;
    let quinn_s = start_page(&world, &quinn).await;
    routing::my_apps(world.tenant())
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    assert_eq!(names(&pat_s), ["reports", "wiki"]);
    assert_eq!(names(&quinn_s), ["wiki"]);
    let listed = opening(&pat_s, "wiki");
    assert_eq!(
        (listed.path.as_str(), listed.opens.as_str()),
        ("/wiki", "now")
    );
    assert_eq!(listed.route_id, wiki.route.route_id);
    assert_eq!(listed.hosts, std::slice::from_ref(&wiki.host));
    assert_eq!(opening(&pat_s, "reports").opens, "now");
    gateway_agrees(&wiki, &reports, &pat, &quinn).await;

    roles::unassign(world.tenant(), &role, pat.id())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(names(&start_page(&world, &pat).await), ["wiki"]);
    stack.stop().await.expect("the stack stops cleanly");
}

/// A route named `name` under `/{name}/*` for anyone signed in.
fn signed_in_only(name: &str) -> RouteSpec {
    RouteSpec::public(name, &format!("/{name}/*")).asking(RoutePolicy::Authenticated)
}

/// The reports route, for those who may read reports.
fn report_readers_only() -> RouteSpec {
    RouteSpec::public("reports", "/reports/*").asking(RoutePolicy::RequireCustomPermission(vec![
        reading_reports(),
    ]))
}

/// Tess makes a role granting `reports:read` and gives it to Pat; its id.
async fn report_reader(world: &World<'_>, pat: &Person) -> String {
    let role = roles::create_for_app(
        world.tenant(),
        &NewAppRole {
            name: "Report readers".to_owned(),
            custom_permissions: vec![reading_reports()],
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    let assigned = AssignRole {
        user_id: pat.id().to_owned(),
    };
    roles::assign(world.tenant(), &role.id, &assigned)
        .send(world.admin().client())
        .await
        .ok();
    role.id
}

/// `person`'s start page.
async fn start_page(world: &World<'_>, person: &Person) -> Vec<OpenableApp> {
    routing::my_apps(world.tenant())
        .send(person.client())
        .await
        .ok()
}

/// The names of the apps on `page`, sorted.
fn names(page: &[OpenableApp]) -> Vec<&str> {
    let mut names: Vec<&str> = page.iter().map(|app| app.name.as_str()).collect();
    names.sort_unstable();
    names
}

/// The app named `name` on `page`.
fn opening<'a>(page: &'a [OpenableApp], name: &str) -> &'a OpenableApp {
    page.iter()
        .find(|app| app.name == name)
        .unwrap_or_else(|| panic!("{name} is on the page"))
}

/// Pat and Quinn sign in on both apps' hosts and open each at the path
/// their start pages gave: the gateway lets both into the wiki, Pat into
/// the reports app, and forbids Quinn there.
async fn gateway_agrees(wiki: &HostedApp, reports: &HostedApp, pat: &Person, quinn: &Person) {
    for host in [&wiki.host, &reports.host] {
        signed_in_on(host, pat).await;
        signed_in_on(host, quinn).await;
    }
    Matrix::new("opening the wiki", Call::get(wiki.page("/wiki").as_str()))
        .allowed(pat.client())
        .allowed(quinn.client())
        .run()
        .await;
    Matrix::new(
        "opening the reports app",
        Call::get(reports.page("/reports").as_str()),
    )
    .allowed(pat.client())
    .refused(quinn.client(), Status::FORBIDDEN, "forbidden")
    .run()
    .await;
}
