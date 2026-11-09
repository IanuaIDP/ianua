//! What the agent scenarios share: the deployment they run, the witness of
//! the audit trail, the cast's refusals, and the setup steps a scenario
//! needs before its agent acts.

use std::collections::HashSet;

use ianua_scenarios::agent::external::ExternalAgent;
use ianua_scenarios::agent::model::ModelBackend;
use ianua_scenarios::agent::tool_upstream::ToolUpstream;
use ianua_scenarios::api::agents::{delegation, messaging};
use ianua_scenarios::expect::{Matrix, Trail, eventually, no_secret_leaked};
use ianua_scenarios::stack::Profile;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::agents::authority::{Grant, Granted};
use ianua_scenarios::wire::agents::messaging::{NewTopic, Retention, area_topic};
use ianua_scenarios::wire::audit::AuditEntry;
use ianua_scenarios::world::World;
use serde_json::{Value, json};

/// The relay requests one address may make a minute here: few enough that
/// an agent meets its `Status::TOO_MANY_REQUESTS` in a few dozen messages.
pub(crate) const RELAY_PER_MINUTE: u32 = 30;

/// The schema every report an agent publishes must match.
const REPORT_SCHEMA: &str = r#"{
    "type": "object",
    "properties": {"summary": {"type": "string", "maxLength": 500}},
    "required": ["summary"],
    "additionalProperties": false
}"#;

/// The deployment agents run against: the standard one, with the relay
/// held to [`RELAY_PER_MINUTE`] an address, and agents' own sign-ins
/// allowed often enough for every misstep a scenario tries.
pub(crate) fn profile() -> Profile {
    Profile::standard()
        .with(
            "RATE_LIMIT_AGENT_RELAY_PER_MINUTE",
            &RELAY_PER_MINUTE.to_string(),
        )
        .with("RATE_LIMIT_LOGIN_PER_MINUTE", "600")
}

/// `profile` with the platform's model providers let into the networks
/// `backend` listens in, so a tenant's provider can point at it.
pub(crate) fn with_model(profile: Profile, backend: &ModelBackend) -> Profile {
    let Some(networks) = backend.private_networks() else {
        return profile;
    };
    profile.with("ALLOW_PRIVATE_MODEL_ENDPOINTS", networks)
}

/// `profile` with platform-run agents' tool calls sent to `upstream`,
/// which listens on loopback.
pub(crate) fn with_tools(profile: Profile, upstream: &ToolUpstream) -> Profile {
    profile
        .with("UPSTREAM_NETWORKS", "127.0.0.0/8")
        .with("AGENT_PROXY_BASE_URL", &upstream.base_url())
}

/// The audit records a scenario's steps raised, read from the first
/// organization's trail by its owner, each record counted once.
pub(crate) struct Witness<'w> {
    trail: Trail<'w>,
    seen: HashSet<String>,
}

impl<'w> Witness<'w> {
    /// A witness of `world`'s trail, every record made before now already
    /// seen.
    pub(crate) async fn of(world: &'w World<'_>) -> Self {
        let trail = world.trail();
        let seen = trail
            .entries("")
            .await
            .into_iter()
            .map(|entry| entry.id)
            .collect();
        Self { trail, seen }
    }

    /// The record of `event_type` a step raised, once the trail holds one
    /// not seen before.
    pub(crate) async fn recorded(&mut self, event_type: &str) -> AuditEntry {
        let what = format!("a new {event_type} in the audit trail");
        let trail = &self.trail;
        let seen = &self.seen;
        let entry = eventually(&what, || async move {
            trail
                .entries(event_type)
                .await
                .into_iter()
                .find(|entry| entry.event_type == event_type && !seen.contains(&entry.id))
        })
        .await;
        self.seen.insert(entry.id.clone());
        entry
    }

    /// Fails when the trail holds a record of `event_type` not seen
    /// before: a refused step records nothing it refused.
    pub(crate) async fn nothing_new(&self, event_type: &str) {
        let fresh = self
            .trail
            .entries(event_type)
            .await
            .into_iter()
            .any(|entry| entry.event_type == event_type && !self.seen.contains(&entry.id));
        assert!(!fresh, "a refused step recorded {event_type}");
    }

    /// Every record of exactly `event_type` the trail holds that was not
    /// seen before, newest first.
    pub(crate) async fn fresh(&self, event_type: &str) -> Vec<AuditEntry> {
        self.trail
            .entries(event_type)
            .await
            .into_iter()
            .filter(|entry| entry.event_type == event_type && !self.seen.contains(&entry.id))
            .collect()
    }

    /// Counts every record the trail holds now as seen, so what a later
    /// step raises is told apart from what came before.
    pub(crate) async fn caught_up(&mut self) {
        let entries = self.trail.entries("").await;
        self.seen.extend(entries.into_iter().map(|entry| entry.id));
    }

    /// Fails when any of `secrets` appears in any agent record the trail
    /// holds.
    pub(crate) async fn holds_none_of(&self, secrets: &[&str]) {
        for entry in self.trail.entries("agents.").await {
            no_secret_leaked(&entry.details.to_string(), secrets);
            no_secret_leaked(&entry.actor, secrets);
        }
    }
}

/// `matrix` with the refusals an agent endpoint gives the rest of the cast
/// when the right it needs is checked before any record is read, such as
/// deciding an approval: Max, with no administrator's rights, and Sam, from
/// another organization, are forbidden; nobody signed in, and every agent
/// in `agents` with its task token, is not known as anyone.
pub(crate) fn refused_to_the_rest<'a>(
    matrix: Matrix<'a>,
    world: &'a World<'_>,
    agents: &[&'a ExternalAgent],
) -> Matrix<'a> {
    let matrix = matrix
        .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
        .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
        .refused(
            world.anonymous().client(),
            Status::UNAUTHORIZED,
            "unauthenticated",
        );
    agents.iter().fold(matrix, |matrix, agent| {
        matrix.refused(agent.client(), Status::UNAUTHORIZED, "unauthenticated")
    })
}

/// [`refused_to_the_rest`] for a step under the owner rule, which hides an
/// agent the member may not act on: Max is told it does not exist, so an id
/// he names tells him nothing about whose agents there are.
pub(crate) fn hidden_from_the_rest<'a>(
    matrix: Matrix<'a>,
    world: &'a World<'_>,
    agents: &[&'a ExternalAgent],
) -> Matrix<'a> {
    let matrix = matrix
        .refused(world.member().client(), Status::NOT_FOUND, "not_found")
        .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
        .refused(
            world.anonymous().client(),
            Status::UNAUTHORIZED,
            "unauthenticated",
        );
    agents.iter().fold(matrix, |matrix, agent| {
        matrix.refused(agent.client(), Status::UNAUTHORIZED, "unauthenticated")
    })
}

/// The topic `agent` reports to, in its own area, made by the owner with
/// the report schema.
///
/// # Panics
///
/// When the topic is refused.
pub(crate) async fn reports_topic(world: &World<'_>, agent: &ExternalAgent) -> String {
    let topic_name = area_topic(agent.id(), "reports");
    let topic = NewTopic {
        name: format!("{}'s reports", agent.name()),
        topic_name: topic_name.clone(),
        schema: REPORT_SCHEMA.to_owned(),
        retention: Retention::Duration(3600),
    };
    messaging::create_topic(world.tenant(), &topic)
        .send(world.owner().client())
        .await
        .ok();
    topic_name
}

/// The delegation the owner grants `agent`.
///
/// # Panics
///
/// When the grant is refused.
pub(crate) async fn granted_by_owner(
    world: &World<'_>,
    agent: &ExternalAgent,
    grant: &Grant,
) -> Granted {
    delegation::grant(world.tenant(), agent.id(), grant)
        .send(world.owner().client())
        .await
        .ok()
}

/// A report saying `summary`, as the topic's schema takes it.
pub(crate) fn report(summary: &str) -> Value {
    json!({ "summary": summary })
}
