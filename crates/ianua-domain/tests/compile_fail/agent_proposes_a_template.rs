//! A task template's proposer is the person whose sign-in proposes it, so
//! no caller names an agent, or another person, as its proposer.

use ianua_domain::domains::agents::authority::task_template::ProposeTaskTemplateParams;
use ianua_domain::types::{AgentId, Initiator};

fn propose(base: ProposeTaskTemplateParams) -> ProposeTaskTemplateParams {
    ProposeTaskTemplateParams {
        proposed_by: Initiator::Agent(AgentId::new()),
        ..base
    }
}

fn main() {}
