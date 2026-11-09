//! The demo seeder: a demonstration organization, seeded through the use
//! cases the API serves and nothing else. Development only; the
//! configuration refuses it in production.
//!
//! The organization is founded with its first tenant and owner through the
//! install use case, so it lands on a plan with no limits, and the owner
//! signs in with their password. The seeder reads no mailbox, so that
//! sign-in owes an authenticator app, which the owner sets up through the
//! enrolment use cases; its link is shown once. Everything else is made as
//! the owner: two more tenants, the roles and teams of each, its people, a
//! pipeline with services and routes, a webhook, a model provider and
//! agents, and a place the organization's notifications are posted. Every
//! record of it is one a use case raised while doing it, so the audit trail
//! tells the demo's history as it happened; no event or row is built here.
//!
//! Every step looks first and makes only what is missing, so the seeder
//! runs again safely: a run that finds everything signs nobody in and adds
//! nothing. The tenants stay in setup until a server's worker runs it.

mod access;
mod agents;
mod catalog;
mod notifications;
mod owner;
mod people;
mod routing;
mod seeder;
mod tenants;
mod webhooks;

use std::sync::Arc;

use ianua_api::state::Deps;
use ianua_app::error::AppError;
use ianua_app::ports::shared::MailSetup;
use ianua_assembly::deps::Adapters;
use ianua_domain::domains::identity::account::address::MailReach;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::validation::ValidationError;
use ianua_domain::types::{GroupId, OtpauthUrl, RoleId};

pub use self::seeder::Tally;
use self::seeder::{DemoTenant, Seeder};
use crate::api;
use crate::config::Config;
use crate::error::ServerError;
use crate::platform::Platform;

/// Why the demo could not be seeded.
#[derive(Debug, thiserror::Error)]
pub enum DemoError {
    /// The platform holds an organization that is not the demo's, and the
    /// install use case founds one only on an empty platform.
    #[error(
        "the platform holds another organization; the demo seeds an empty database, \
         so run it against a fresh one"
    )]
    Occupied,
    /// The owner's sign-in opened no session that may act.
    #[error("the demo owner's sign-in {0}")]
    SignIn(&'static str),
    /// A use case refused or failed.
    #[error("{what} could not be made")]
    Refused {
        /// What was being made.
        what: &'static str,
        /// Why.
        #[source]
        cause: AppError,
    },
    /// What a use case just made could not be found again.
    #[error("{0} could not be found again")]
    Vanished(&'static str),
    /// A store could not be read.
    #[error("a store could not be read")]
    Lookup(#[from] DomainError),
    /// A value of the demo's own catalogue does not read.
    #[error("a value of the demo's own does not read")]
    Catalog(#[from] ValidationError),
    /// No code could be read from the authenticator app the owner's sign-in
    /// set up.
    #[error("the owner's authenticator app shows no code")]
    Authenticator(#[source] DomainError),
}

/// What a run seeded.
#[derive(Debug)]
pub struct Seeded {
    /// How much was made and how much found.
    pub tally: Tally,
    /// The link of the authenticator app the owner set up as this run
    /// signed them in, shown once so a developer can add it to their own
    /// app. None when nobody signed in.
    pub authenticator: Option<OtpauthUrl>,
}

/// The seeder reads no mailbox, so to its sign-ins no mail ever arrives,
/// whatever mail server the deployment has.
struct NoMailbox;

impl MailSetup for NoMailbox {
    fn reach(&self) -> MailReach {
        MailReach::NotSetUp
    }
}

/// Seeds the demonstration organization and says on standard output what
/// was made and how to sign in.
///
/// # Errors
///
/// [`ServerError`] when the adapters cannot be built or a step fails.
pub async fn run(platform: &Platform, config: &Config) -> Result<(), ServerError> {
    let deps = api::deps(platform, config)?;
    let seeded = seed(&deps).await?;
    report(&seeded);
    Ok(())
}

/// Seeds whatever of the demonstration organization is missing, and
/// answers how much was made and how much found.
///
/// The owner signs in as on a deployment with no mail server, since the
/// seeder could never follow a mailed link: the sign-in owes an
/// authenticator app, which the owner sets up there and then.
///
/// # Errors
///
/// [`DemoError`] for the first step that failed. What the steps before it
/// made is kept, and a second run carries on from there.
pub async fn seed(deps: &Deps) -> Result<Seeded, DemoError> {
    let deps = without_mailbox(deps);
    let state = ianua_api::state::build(&deps);
    let mut tally = Tally::default();
    let organization = tally.count(owner::organization(&deps, &state).await?);
    let seeder = Seeder::new(&deps, state, organization)?;
    for seed in &catalog::TENANTS {
        let tenant = tally.count(tenants::tenant(&seeder, seed).await?);
        seed_tenant(&seeder, &mut tally, &tenant, seed).await?;
    }
    tally.count(notifications::destination(&seeder).await?);
    Ok(Seeded {
        tally,
        authenticator: seeder.into_authenticator(),
    })
}

/// `deps` as the seeder's sign-ins see them, with no mail reaching anyone.
fn without_mailbox(deps: &Deps) -> Deps {
    Deps {
        adapters: Adapters {
            mail_setup: Arc::new(NoMailbox),
            ..deps.adapters.clone()
        },
        ..deps.clone()
    }
}

/// Seeds what one tenant holds.
async fn seed_tenant(
    seeder: &Seeder<'_>,
    tally: &mut Tally,
    tenant: &DemoTenant,
    seed: &catalog::TenantSeed,
) -> Result<(), DemoError> {
    let teams = seed_teams(seeder, tally, tenant).await?;
    for person in seed.people {
        let team = teams[person.team];
        let user = tally.count(people::person(seeder, tenant, person, team.role).await?);
        tally.count(access::member(seeder, tenant, team.group, user).await?);
    }
    seed_routing(seeder, tally, tenant).await?;
    tally.count(webhooks::webhook(seeder, tenant).await?);
    tally.count(agents::model_provider(seeder, tenant).await?);
    for agent in &catalog::AGENTS {
        tally.count(agents::agent(seeder, tenant, agent).await?);
    }
    Ok(())
}

/// A team of a tenant: its group, and the role it carries.
#[derive(Clone, Copy)]
struct Team {
    group: GroupId,
    role: RoleId,
}

/// Seeds the tenant's roles and the teams carrying them, and answers the
/// teams in the order of [`catalog::TEAMS`].
async fn seed_teams(
    seeder: &Seeder<'_>,
    tally: &mut Tally,
    tenant: &DemoTenant,
) -> Result<Vec<Team>, DemoError> {
    let mut teams = Vec::with_capacity(catalog::TEAMS.len());
    for (role, team) in catalog::ROLES.iter().zip(catalog::TEAMS) {
        let role = tally.count(access::role(seeder, tenant, role).await?);
        let group = tally.count(access::team(seeder, tenant, team).await?);
        tally.count(access::team_role(seeder, tenant, group, role).await?);
        teams.push(Team { group, role });
    }
    Ok(teams)
}

/// Seeds the tenant's pipeline and the services and routes on it, then
/// puts the pipeline in force.
async fn seed_routing(
    seeder: &Seeder<'_>,
    tally: &mut Tally,
    tenant: &DemoTenant,
) -> Result<(), DemoError> {
    let pipeline = tally.count(routing::pipeline(seeder, tenant).await?);
    for seed in &catalog::SERVICES {
        let service = tally.count(routing::service(seeder, tenant, seed).await?);
        let placement = routing::RoutePlacement { service, pipeline };
        tally.count(routing::route(seeder, tenant, seed, &placement).await?);
    }
    tally.count(routing::in_force(seeder, tenant, pipeline).await?);
    Ok(())
}

/// Says on standard output what the run did, and how to sign in.
fn report(seeded: &Seeded) {
    println!(
        "Demo organization '{}': made {} pieces, found {} there already.",
        catalog::ORGANIZATION_SLUG,
        seeded.tally.made,
        seeded.tally.found
    );
    if let Some(link) = &seeded.authenticator {
        println!();
        println!("The owner's sign-in set up an authenticator app. Add it to yours with");
        println!("this link, which is shown only now:");
        println!("  {}", link.as_str());
    }
    println!();
    println!(
        "Every demo account signs in with the password {}.",
        catalog::PASSWORD
    );
    println!(
        "The owner, {}, signs in at POST /api/v1/login and reaches every tenant.",
        catalog::OWNER_EMAIL
    );
    println!(
        "Tenant users sign in at POST /api/v1/organizations/{}/tenants/{{tenant}}/login, \
         such as liam.becker@{} in 'production'.",
        catalog::ORGANIZATION_SLUG,
        catalog::MAIL_DOMAIN
    );
    println!();
    println!("Start the server next: its worker finishes the tenants' setup and delivers");
    println!("the seeded events, which fill the activity feeds and notifications.");
}
