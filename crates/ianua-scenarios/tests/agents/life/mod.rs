//! The life of Reporter, an external agent, from the key it enrols to the
//! key Ann revokes: made with its own key, handed part of Ann's authority,
//! asking for tokens of its own, reporting through the relay and passing
//! part of its authority on to Helper, waiting on Tess for three calls,
//! spending what the relay allows, and refused everywhere once its key is
//! gone. At every step the whole cast tries the step's endpoints, and the
//! audit trail is read for what the step recorded and for what a refusal
//! must not have.
//!
//! - `authority`: Ann's grant, the tokens Reporter takes under it, and
//!   the part it passes on to Helper.
//! - `relay`: Reporter reporting through the relay, who else may not, and
//!   the relay's allowance for one address spent.
//! - `approvals`: three calls Reporter needs a person's say for, decided
//!   by Tess or lapsed.
//! - `revoked`: Ann revokes Reporter's key, and nothing signs it in again.

mod approvals;
mod authority;
mod relay;
mod revoked;

use ianua_scenarios::agent::external::{ExternalAgent, IssuedToken};
use ianua_scenarios::api::agents::{credentials, lifecycle};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::wire::agents::authority::{Capabilities, Granted};
use ianua_scenarios::wire::agents::token::TokenAsk;
use ianua_scenarios::world::World;

use crate::support::{Witness, hidden_from_the_rest, profile, reports_topic};

/// The requests Ann's grant lets Reporter make in a window: more than the
/// relay's allowance for one address, so the relay is what stops a burst.
const BUDGET: u32 = 50;

/// That window, in seconds: an hour.
const WINDOW: u32 = 3600;

/// How long the tokens Reporter asks for last, in seconds: ten minutes,
/// inside Ann's grant.
const TOKEN_SECONDS: u32 = 600;

/// The acting agent and the other agent whose independent rights are checked.
struct Agents<'a> {
    reporter: &'a ExternalAgent,
    helper: &'a ExternalAgent,
}

/// Ann's grant and the topic and alternative token used throughout Reporter's life.
struct Authority {
    topic: String,
    grant: Granted,
    bound: IssuedToken,
}

/// Reporter is made with its own key and handed part of Ann's authority;
/// it takes a bearer token and a key-bound one, reports through the relay,
/// passes part of the grant on to Helper, waits on Tess for three calls,
/// spends what the relay allows an address, and is refused everywhere
/// once Ann revokes its key. Nothing secret reaches the trail.
#[tokio::test]
async fn an_agent_lives_from_its_key_to_its_revocation() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let mut witness = Witness::of(&world).await;
    let mut reporter = created(&stack, &world, &mut witness, "Reporter").await;
    let mut helper = created(&stack, &world, &mut witness, "Helper").await;
    read_by_the_cast(&world, &reporter, &[&reporter, &helper]).await;

    let authority = grant_authority(&world, &mut witness, &mut reporter, &mut helper).await;
    let access = relay::RelayAccess {
        helper: &helper,
        topic: &authority.topic,
        bound: &authority.bound,
    };
    relay::relayed(&world, &mut witness, &mut reporter, access).await;
    read_by_the_cast(&world, &reporter, &[&reporter, &helper]).await;
    let agents = Agents {
        reporter: &reporter,
        helper: &helper,
    };
    finish_reporting(&world, &mut witness, &agents, &authority).await;
    let mut kept = secrets_of(&[&reporter, &helper]);
    kept.push(authority.bound.token().to_owned());
    kept.extend(world.cast_secrets());
    let kept: Vec<&str> = kept.iter().map(String::as_str).collect();
    witness.holds_none_of(&kept).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann delegates publishing, Reporter takes both token forms and hands part to Helper.
async fn grant_authority(
    world: &World<'_>,
    witness: &mut Witness<'_>,
    reporter: &mut ExternalAgent,
    helper: &mut ExternalAgent,
) -> Authority {
    let topic = reports_topic(world, reporter).await;
    let agents = Agents { reporter, helper };
    let grant = authority::delegated(world, witness, &agents, &topic).await;
    let bound = authority::tokens_taken(witness, reporter, &topic).await;
    let hand_on = authority::HandOn {
        reporter,
        grant: &grant,
    };
    authority::passed_on(world, witness, helper, hand_on).await;
    Authority {
        topic,
        grant,
        bound,
    }
}

/// Reporter waits for approval, spends the relay allowance and loses access after revocation.
async fn finish_reporting(
    world: &World<'_>,
    witness: &mut Witness<'_>,
    agents: &Agents<'_>,
    authority: &Authority,
) {
    approvals::waited_on_people(world, witness, agents, &authority.grant).await;
    relay::allowance_spent(world, agents.reporter, &authority.topic, &authority.grant).await;
    revoked::key_revoked(world, witness, agents, &authority.topic).await;
}

/// `name`, made by Ann with the key it made for itself. The agent is on
/// record, and the key Ann's API keeps for it is the agent's own public
/// half, active.
async fn created(
    stack: &Stack,
    world: &World<'_>,
    witness: &mut Witness<'_>,
    name: &str,
) -> ExternalAgent {
    let agent = ExternalAgent::enrolled(stack, world.tenant(), world.owner().client(), name).await;
    witness.recorded("agents.agent_created").await;
    let keys = credentials::list(world.tenant(), agent.id())
        .send(world.owner().client())
        .await
        .ok();
    let Some(enrolled) = keys.iter().find(|key| key.kid == agent.key_id()) else {
        panic!("{name}'s key is not among its credentials");
    };
    assert_eq!(enrolled.status, "active", "{name}'s key is active");
    assert_eq!(
        enrolled.public_key.trim(),
        agent.key().public_pem().trim(),
        "the platform keeps {name}'s own public key"
    );
    agent
}

/// Reporter and its keys, read by the whole cast: Ann, who owns it, and
/// Tess, the tenant's administrator, may; nobody else. Reporter and its
/// keys are hidden from Max as if it did not exist.
async fn read_by_the_cast(world: &World<'_>, reporter: &ExternalAgent, agents: &[&ExternalAgent]) {
    let reading = Matrix::new(
        "reading Reporter",
        lifecycle::get(world.tenant(), reporter.id()).call(),
    )
    .allowed(world.owner().client())
    .allowed(world.admin().client());
    hidden_from_the_rest(reading, world, agents).run().await;
    let listing = Matrix::new(
        "listing Reporter's keys",
        credentials::list(world.tenant(), reporter.id()).call(),
    )
    .allowed(world.owner().client())
    .allowed(world.admin().client());
    hidden_from_the_rest(listing, world, agents).run().await;
}

/// What Reporter asks for to report: publishing to its topic, for ten
/// minutes.
fn reporting(topic: &str) -> TokenAsk {
    TokenAsk::bearer(Capabilities::default().publishing_to(topic), TOKEN_SECONDS)
}

/// The tokens `agents` hold now.
fn secrets_of(agents: &[&ExternalAgent]) -> Vec<String> {
    agents
        .iter()
        .filter_map(|agent| agent.token())
        .map(|token| token.token().to_owned())
        .collect()
}
