//! Keeping agents in check where they act: the tenant's apps behind the
//! gateway, which an agent reaches with its task token bound to its key
//! and a fresh proof of that key on every request. Each scenario reads
//! what the app saw arrive, what the gateway recorded and what the audit
//! trail holds.
//!
//! - `tools`: Reporter calling outside tools over MCP through the gateway,
//!   held to the tools Ann granted it by name, and the grants Ann may not
//!   make.
//! - `containment`: fencing a misbehaving agent in: suspending and resuming
//!   it, stopping every agent at once, the kill switch, its person losing
//!   their standing, and Mallory with a stolen token or a replayed proof.
//! - `budgets`: the request budget Ann's grant sets, spent, shared by every
//!   grant the agent holds, and absent for an agent with none.
//! - `held_calls`: a delegation whose every call waits for a person, held
//!   at the gateway until Tess approves exactly that call once, or denies
//!   it.
//! - `payments`: a payment held for two different people, Bea and Cal,
//!   each answering a fresh authenticator code, released once.
//! - `recording`: a request refused while the gateway cannot record the
//!   agent's action, and recorded once when it can again.
//! - `lineage`: whose authority an agent acts on, from Ann through Reporter
//!   to Helper, as the app, the gateway, the API and the trail tell it.
//! - `reviews`: Watcher, set by Tess to watch Reporter, reading its evidence
//!   and giving a verdict, and every way that watch is refused.

mod budgets;
mod containment;
mod held_calls;
mod lineage;
mod payments;
mod recording;
mod reviews;
mod tools;

use ianua_scenarios::actors::Member;
use ianua_scenarios::agent::external::dpop::ProvenRequest;
use ianua_scenarios::agent::external::{ExternalAgent, IssuedToken};
use ianua_scenarios::api::agents::delegation;
use ianua_scenarios::api::{members, roles, routing};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::routes::{AppliedRoute, Placement, RouteSpec};
use ianua_scenarios::stack::Stack;
use ianua_scenarios::upstreams::Echo;
use ianua_scenarios::wire::agents::Principal;
use ianua_scenarios::wire::agents::authority::{Attenuation, Capabilities, Grant, Limits};
use ianua_scenarios::wire::audit::AuditEntry;
use ianua_scenarios::wire::organization::{OrgRole, TenantRoles};
use ianua_scenarios::wire::roles::{NewRole, SystemPermission};
use ianua_scenarios::wire::routing::RoutePolicy;
use ianua_scenarios::world::World;
use serde_json::Value;

/// The permission Ann hands her agents, which she holds as the owner.
const VIEW_USERS: &str = "idp:users:view";

/// How long the grants last, in seconds: long enough for a scenario,
/// short enough to be a task's.
const GRANT_SECONDS: u32 = 600;

/// How long the part Reporter hands on to Helper lasts, in seconds: inside
/// Ann's grant.
const HANDED_ON_SECONDS: u32 = 300;

/// How many letters of a random id tell one app's names from another's.
const WORD_LENGTH: usize = 8;

/// An app of the tenant behind the gateway, and the route in front of it.
struct App {
    /// What reached the app.
    echo: Echo,
    /// The tenant's host the app answers on.
    host: String,
    /// What the route made: its service, which a grant names, and the
    /// route itself, which a tool is registered over.
    route: AppliedRoute,
}

impl App {
    /// The address of `path` on the app.
    fn url(&self, path: &str) -> String {
        format!("https://{}{path}", self.host)
    }

    /// The service a grant names to let an agent reach the app.
    fn service_id(&self) -> &str {
        &self.route.service_id
    }
}

/// An app answering at `pattern`, such as `/reports/*`, open to anyone
/// signed in, with `stages` added to its pipeline, made by Tess and served
/// once this returns.
async fn opened(stack: &Stack, world: &World<'_>, pattern: &str, stages: Vec<Value>) -> App {
    let host = app_host(world).await;
    let echo = Echo::start(stack, &host).await.expect("the app starts");
    let word = word();
    let spec = stages.into_iter().fold(
        RouteSpec::public(&format!("app-{word}"), pattern)
            .asking(RoutePolicy::Authenticated)
            .pinned(&format!("app-{word}")),
        RouteSpec::with_stage,
    );
    let probe = Client::new(stack, "a probe").expect("a client for the probe");
    let route = spec
        .applied(
            world.admin().client(),
            &probe,
            Placement {
                tenant: world.tenant(),
                upstream: &echo.url(),
                host: &host,
            },
        )
        .await;
    echo.forget();
    App { echo, host, route }
}

/// The reports app, answering at `/reports/*`.
async fn reports_app(stack: &Stack, world: &World<'_>) -> App {
    opened(stack, world, "/reports/*", Vec::new()).await
}

/// The tenant's random host, or its readable one where turned on, as Tess
/// reads it.
async fn app_host(world: &World<'_>) -> String {
    let names = routing::hostnames(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    names.slug_subdomain.unwrap_or(names.uuid_subdomain)
}

/// A word unique to one app, so two apps made in one run never share a
/// name.
fn word() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..WORD_LENGTH].to_owned()
}

/// A grant of `granted` and the app `service_id`, its tokens bound to the
/// agent's key, named `name`.
fn bound_grant(service_id: &str, name: &str, granted: Capabilities) -> Grant {
    Grant {
        granted,
        limits: Limits {
            ttl_seconds: GRANT_SECONDS,
            sender_constrained: true,
            apps: vec![service_id.to_owned()],
            ..Limits::default()
        },
        name: Some(name.to_owned()),
    }
}

/// The agent `name`, made by Ann with its own key, holding the task token
/// of `grant` she makes it.
async fn granted_agent(
    stack: &Stack,
    world: &World<'_>,
    name: &str,
    grant: &Grant,
) -> ExternalAgent {
    let ann = world.owner().client();
    let mut agent = ExternalAgent::enrolled(stack, world.tenant(), ann, name).await;
    let granted = delegation::grant(world.tenant(), agent.id(), grant)
        .send(ann)
        .await
        .ok();
    agent.hold(IssuedToken::of(granted));
    agent
}

/// Helper, and whom the part of Reporter's grant it was handed acts for.
struct HandedOn {
    /// Helper, holding the part's task token.
    helper: ExternalAgent,
    /// Whom the part acts for, nearest first, as the API answered it.
    on_behalf_of: Vec<Principal>,
}

/// Helper, made by Ann, holding the part of Reporter's grant that Reporter
/// hands on: reading reports on the same app, for less time, its tokens
/// bound to Helper's own key.
async fn handed_on(
    stack: &Stack,
    world: &World<'_>,
    reporter: &ExternalAgent,
    app: &App,
) -> HandedOn {
    let ann = world.owner().client();
    let mut helper = ExternalAgent::enrolled(stack, world.tenant(), ann, "Helper").await;
    let Some(held) = reporter.token() else {
        panic!("Reporter holds Ann's token");
    };
    let part = Attenuation {
        delegate: helper.id().to_owned(),
        granted: Capabilities::http(&[VIEW_USERS]),
        limits: Limits {
            ttl_seconds: HANDED_ON_SECONDS,
            sender_constrained: true,
            apps: vec![app.service_id().to_owned()],
            ..Limits::default()
        },
    };
    let granted = reporter.pass_on(held.delegation_id(), &part).await.ok();
    let on_behalf_of = granted.on_behalf_of.clone();
    helper.hold(IssuedToken::of(granted));
    HandedOn {
        helper,
        on_behalf_of,
    }
}

/// Pat, a member of Ann's organization reaching the tenant with a role
/// Tess made for viewing people and making and empowering agents, signed
/// in.
async fn steward(stack: &Stack, world: &World<'_>) -> Member {
    let role_name = format!("Agent stewards {}", word());
    roles::create(
        world.tenant(),
        &NewRole {
            name: role_name.clone(),
            system_permissions: vec![
                SystemPermission::new("Users", "View"),
                SystemPermission::new("Agents", "Create"),
                SystemPermission::new("Agents", "Delegate"),
            ],
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    let mut pat = world.colleague("pat", "Pat Steward", OrgRole::Member).await;
    members::set_tenant_roles(
        world.org(),
        pat.id(),
        world.tenant().slug(),
        &TenantRoles {
            roles: vec![role_name],
        },
    )
    .send(world.owner().client())
    .await
    .ok();
    pat.sign_in(stack).await;
    pat
}

/// `call` as `agent` sends it to an app: its task token under the `DPoP`
/// scheme with a fresh proof of its key made for `method` at `url`.
fn proven(agent: &ExternalAgent, call: Call, method: &str, url: &str) -> Call {
    let proof = agent.dpop_proof(ProvenRequest { method, url });
    bare(agent, call).header("dpop", &proof)
}

/// `call` carrying `agent`'s task token under the `DPoP` scheme and no
/// proof at all, as a thief holding only the token sends it.
fn bare(agent: &ExternalAgent, call: Call) -> Call {
    let Some(issued) = agent.token() else {
        panic!("{} holds a token", agent.name());
    };
    call.header("authorization", &format!("DPoP {}", issued.token()))
}

/// A `GET` of `url` as `agent` sends it, proven by its key.
fn proven_get(agent: &ExternalAgent, url: &str) -> Call {
    proven(agent, Call::get(url), "GET", url)
}

/// Whether `entry` names `id`: as what it happened to, who did it, or in
/// what it says happened.
fn names(entry: &AuditEntry, id: &str) -> bool {
    entry.target_id.as_deref() == Some(id)
        || entry.actor.contains(id)
        || entry.details.to_string().contains(id)
}
