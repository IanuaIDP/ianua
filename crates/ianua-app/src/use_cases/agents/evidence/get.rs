//! Agent evidence: what ianua recorded about an agent, located in the chain.
//!
//! The answer to "what did this agent do?" that does not come from the agent:
//! its audit records, each with its place and hash in the tenant's chain, and
//! the scheduled sweep's last verdict on that chain. A record from a chain
//! that does not verify proves nothing, so the two travel together. The
//! verdict is the one the sweep kept, so reading a page never walks a chain
//! of millions of records inside the request.

use std::sync::Arc;

use ianua_domain::domains::audit::evidence::EvidenceRecord;
use ianua_domain::domains::audit::verdict::ChainVerdict;
use ianua_domain::types::AgentId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::AgentStore;
use crate::ports::audit::{AuditChainVerdictStore, EvidenceStore};
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::agents::evidence::watching::watched_agent;

/// The most records one page returns.
pub(crate) const MAX_EVIDENCE_PAGE: u32 = 200;

/// A page of an agent's evidence and the state of the chain it sits in.
pub struct EvidencePage {
    /// The records, oldest first.
    pub records: Vec<EvidenceRecord>,
    /// The sweep's last verdict on the tenant's chain, or `None` before
    /// the first sweep walked it.
    pub chain: Option<ChainVerdict>,
}

/// Where a page of evidence starts and how long it is.
pub(in crate::use_cases::agents) struct EvidenceCursor {
    /// The last sequence number already seen.
    pub(in crate::use_cases::agents) after_seq: i64,
    /// How many records to return at most.
    pub(in crate::use_cases::agents) limit: u32,
}

/// Where an agent's evidence and the verdict on its chain are read from.
pub(in crate::use_cases::agents) struct EvidenceSources<'a> {
    /// Reads the evidence records.
    pub(in crate::use_cases::agents) store: &'a dyn EvidenceStore,
    /// The sweep's kept verdicts on the audit chain they hang off.
    pub(in crate::use_cases::agents) verdicts: &'a dyn AuditChainVerdictStore,
}

/// The ports [`GetAgentUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetAgentPorts {
    /// The agents, to find whose evidence it is.
    pub agent_store: Arc<dyn AgentStore>,
    /// The records.
    pub evidence_store: Arc<dyn EvidenceStore>,
    /// The sweep's kept verdicts on the chain.
    pub chain_verdicts: Arc<dyn AuditChainVerdictStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads an agent's evidence for a person.
pub struct GetAgentUseCase {
    ports: GetAgentPorts,
}

impl GetAgentUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetAgentPorts) -> Self {
        Self { ports }
    }
}

/// Whose evidence to read, and which page of it.
pub struct GetAgentRequest {
    /// The agent the evidence is about.
    pub agent_id: AgentId,
    /// The last sequence number already seen.
    pub after_seq: i64,
    /// How many records to return at most.
    pub limit: u32,
}

impl Query for GetAgentUseCase {
    type Caller = CallerContext;
    type Input = GetAgentRequest;
    type Output = Result<EvidencePage, AppError>;

    /// One page of the agent's evidence after `after_seq`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such agent, or the
    ///   caller neither owns it nor may view agents, so that an agent of
    ///   someone else's answers as one that does not exist.
    /// - `AppError::Internal` when the records or the chain's verdict cannot
    ///   be read.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: GetAgentRequest,
    ) -> Result<EvidencePage, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        watched_agent(
            self.ports.agent_store.as_ref(),
            &authority,
            &tenant,
            &request.agent_id,
        )
        .await?;
        evidence_page(
            EvidenceSources {
                store: self.ports.evidence_store.as_ref(),
                verdicts: self.ports.chain_verdicts.as_ref(),
            },
            &tenant,
            &request.agent_id,
            EvidenceCursor {
                after_seq: request.after_seq,
                limit: request.limit,
            },
        )
        .await
    }
}

/// Reads one page of `agent`'s evidence with the sweep's last verdict on
/// the chain.
///
/// # Errors
///
/// Returns `AppError::Internal` when the records or the verdict cannot be
/// read.
pub(in crate::use_cases::agents) async fn evidence_page(
    sources: EvidenceSources<'_>,
    tenant_id: &ScopedTenant,
    agent: &AgentId,
    cursor: EvidenceCursor,
) -> Result<EvidencePage, AppError> {
    let EvidenceSources { store, verdicts } = sources;
    let EvidenceCursor { after_seq, limit } = cursor;
    let records = store
        .agent_records(
            tenant_id,
            agent,
            after_seq,
            limit.clamp(1, MAX_EVIDENCE_PAGE),
        )
        .await
        .or_internal()?;
    let chain = verdicts.find(tenant_id).await.or_internal()?;
    Ok(EvidencePage { records, chain })
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::walk::ChainStanding;
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{FakeAgentStore, callers_agent};
    use crate::test_support::audit::{FakeChainVerdictStore, FakeEvidenceStore};
    use crate::test_support::{block_on, test_ctx};

    fn read(ports: GetAgentPorts, agent_id: AgentId) -> Result<EvidencePage, AppError> {
        block_on(GetAgentUseCase::new(ports).execute(
            &test_ctx(),
            GetAgentRequest {
                agent_id,
                after_seq: 0,
                limit: 10,
            },
        ))
    }

    fn ports_for(
        agents: FakeAgentStore,
        agent: AgentId,
        authorities: FakeTenantAuthorities,
    ) -> GetAgentPorts {
        GetAgentPorts {
            agent_store: Arc::new(agents),
            evidence_store: Arc::new(FakeEvidenceStore(agent)),
            tenant_authorities: Arc::new(authorities),
            ..GetAgentPorts::fakes()
        }
    }

    /// The verdict last night's sweep kept on the test tenant's chain.
    fn kept(standing: ChainStanding) -> Arc<FakeChainVerdictStore> {
        Arc::new(FakeChainVerdictStore::holding(
            test_ctx().tenant_id(),
            standing,
        ))
    }

    /// Ann reads the evidence of her own agent, though she holds no agent
    /// permission. She gets its records and the verdict last night's sweep
    /// kept on the chain.
    #[test]
    fn an_owner_reads_their_agents_evidence() {
        let agent = AgentId::new();
        let ports = GetAgentPorts {
            chain_verdicts: kept(ChainStanding::Intact),
            ..ports_for(
                callers_agent(agent),
                agent,
                FakeTenantAuthorities::holding(&[]),
            )
        };

        let page = read(ports, agent).unwrap();

        assert_eq!(page.records.len(), 3);
        let verdict = page.chain.unwrap();
        assert_eq!(verdict.standing(), ChainStanding::Intact);
    }

    /// Someone rewrote record 7 and the sweep found it. Ann reads her
    /// agent's evidence and is told where the chain breaks, so she knows
    /// the records prove nothing.
    #[test]
    fn the_sweeps_break_travels_with_the_evidence() {
        let agent = AgentId::new();
        let ports = GetAgentPorts {
            chain_verdicts: kept(ChainStanding::BrokenAt(7)),
            ..ports_for(
                callers_agent(agent),
                agent,
                FakeTenantAuthorities::holding(&[]),
            )
        };

        let verdict = read(ports, agent).unwrap().chain.unwrap();

        assert_eq!(verdict.standing(), ChainStanding::BrokenAt(7));
    }

    /// Ann reads her agent's evidence before the first sweep walked the
    /// chain. She hears it is not verified yet, never that it is intact.
    #[test]
    fn evidence_before_the_first_sweep_is_not_verified_yet() {
        let agent = AgentId::new();
        let ports = ports_for(
            callers_agent(agent),
            agent,
            FakeTenantAuthorities::holding(&[]),
        );

        let page = read(ports, agent).unwrap();

        assert!(page.chain.is_none());
    }

    /// Bob may view agents. He reads the evidence of an agent someone else
    /// owns.
    #[test]
    fn a_viewer_reads_another_persons_agent() {
        let agent = AgentId::new();
        let ports = ports_for(
            FakeAgentStore::with_active(agent),
            agent,
            FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::View)]),
        );

        assert_eq!(read(ports, agent).unwrap().records.len(), 3);
    }

    /// A caller who neither owns the agent nor may view agents receives
    /// the same missing-agent response as for an unknown agent.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let agent = AgentId::new();
        let ports = ports_for(
            FakeAgentStore::with_active(agent),
            agent,
            FakeTenantAuthorities::holding(&[]),
        );

        assert!(matches!(read(ports, agent), Err(AppError::NotFound(_))));
    }

    /// An agent absent from the tenant's store is reported as missing,
    /// even to a caller with every permission.
    #[test]
    fn an_agent_of_another_tenant_is_not_found() {
        let agent = AgentId::new();
        let ports = ports_for(
            FakeAgentStore::empty(),
            agent,
            FakeTenantAuthorities::holding_everything(),
        );

        assert!(matches!(read(ports, agent), Err(AppError::NotFound(_))));
    }

    /// A signed-out caller cannot read evidence even for their own agent.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let agent = AgentId::new();
        let ports = ports_for(
            callers_agent(agent),
            agent,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        assert!(matches!(read(ports, agent), Err(AppError::Unauthenticated)));
    }
}
