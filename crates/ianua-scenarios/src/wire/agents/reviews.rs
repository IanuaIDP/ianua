//! An agent set to watch another: the assignment a person makes, the
//! evidence the watcher reads at its review desk, and the verdict it
//! gives.

use serde::{Deserialize, Serialize};

use super::Principal;

/// `POST …/agents/{id}/reviewers`: the agent that will watch the one in
/// the path.
#[derive(Debug, Clone, Serialize)]
pub struct AssignReviewer {
    /// The watching agent.
    pub reviewer_agent_id: String,
}

/// Who watches whom, and since when.
#[derive(Debug, Clone, Deserialize)]
pub struct ReviewAssignment {
    /// The handle a person ends the review by.
    pub id: String,
    /// The watching agent.
    pub reviewer_agent_id: String,
    /// The agent watched.
    pub reviewed_agent_id: String,
    /// The person who set it up.
    pub assigned_by: Principal,
    /// When a person ended it, once someone did.
    #[serde(default)]
    pub ended_at: Option<String>,
}

/// One record of an agent's evidence, with its place in the tenant's
/// chain.
#[derive(Debug, Clone, Deserialize)]
pub struct EvidenceRecord {
    /// Its place in the chain: what a verdict cites.
    pub seq: i64,
    /// What happened, such as `agents.token_issued`.
    pub event_type: String,
}

/// A page of an agent's evidence, oldest first.
#[derive(Debug, Clone, Deserialize)]
pub struct EvidencePage {
    /// The audit records the watcher may rest a verdict on.
    pub records: Vec<EvidenceRecord>,
}

/// `POST …/agents/review-desk/{id}/verdicts`: what the watcher concluded,
/// resting on records it read.
#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    /// `concern` or `containment_requested`.
    pub kind: String,
    /// What it concluded, in its own words.
    pub note: String,
    /// The evidence records it rests on, at least one.
    pub cited_seqs: Vec<i64>,
}
