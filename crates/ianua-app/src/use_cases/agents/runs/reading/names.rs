//! The names a run's records give its agent and model provider, as the
//! audit trail knows them.

use ianua_domain::domains::agents::execution::run::{AgentRun, RunNames};
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::ports::shared::AuditLabelResolver;
use crate::tenancy::ScopedTenant;
use crate::use_cases::agents::audit_labels::{agent_label, provider_label};

/// The agent and model provider of `run`, named as `resolver` names them,
/// for the record that hands the run to a worker.
pub(crate) async fn run_names(
    resolver: &dyn AuditLabelResolver,
    tenant: &ScopedTenant,
    run: &AgentRun<ResolvedTenant>,
) -> RunNames {
    RunNames::new(
        agent_label(resolver, tenant, run.agent_id()).await,
        provider_label(resolver, tenant, run.provider_id()).await,
    )
}
