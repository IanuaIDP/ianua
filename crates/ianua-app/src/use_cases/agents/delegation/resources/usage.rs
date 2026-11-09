//! Who may spend a tenant's model providers and tools through agent runs,
//! and what the relationship graph says a person holds.
//!
//! A provider carries a team's API key and quota, and a tool its calls. They
//! belong to the tenant, but using one is held per person: the one who
//! connected it holds use of it, can share that use through the resource
//! graph, and an agent administrator may use them all. Holding
//! `Agents(Delegate)` alone is not enough.

use ianua_domain::domains::agents::authority::capability::{CapabilitySet, ResourceCapability};
use ianua_domain::domains::agents::authority::delegation::HeldResources;
use ianua_domain::domains::agents::execution::tool::AgentTool;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::permission::AgentAction;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::PrincipalRef;

use crate::error::{AppError, OrInternal};
use crate::ports::agents::{RelationshipResolver, ResourceGrantStore};
use crate::tenancy::ScopedTenant;

/// Answers whether a person may use a resource, in one tenant.
pub(in crate::use_cases::agents) struct UseCheck<'a> {
    /// The resource graph.
    pub(in crate::use_cases::agents) resolver: &'a dyn RelationshipResolver,
    /// The tenant the person acts in.
    pub(in crate::use_cases::agents) tenant: &'a ScopedTenant,
}

impl UseCheck<'_> {
    /// The part of `wanted` the person `control` names may use: all of it
    /// for an agent administrator, otherwise what the graph says they hold.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the graph cannot be read.
    pub(in crate::use_cases::agents) async fn usable(
        &self,
        control: &AgentControl<'_>,
        wanted: Vec<ResourceCapability>,
    ) -> Result<Vec<ResourceCapability>, AppError> {
        if control.holds_agent(AgentAction::Manage) {
            return Ok(wanted);
        }
        self.resolver
            .held_subset(self.tenant, &control.by().principal(), &wanted)
            .await
            .or_internal()
    }

    /// Refuses a person who may not use `resource`.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when they hold no use of it.
    /// - `AppError::Internal` when the graph cannot be read.
    pub(in crate::use_cases::agents) async fn require(
        &self,
        control: &AgentControl<'_>,
        resource: ResourceCapability,
    ) -> Result<(), AppError> {
        let usable = self.usable(control, vec![resource]).await?;
        if usable.is_empty() {
            return Err(AppError::Forbidden(message!(
                "agents-you-have-not-been-given-use",
                "you have not been given use of this resource"
            )));
        }
        Ok(())
    }
}

/// The graph's answer for `holder`, as the domain takes it when it works out
/// what someone may grant: which of the resources `wanted` names, and of
/// the use of each tool in `registry`, they hold.
///
/// # Errors
///
/// - `AppError::Internal` when the graph cannot be read.
pub(in crate::use_cases::agents) async fn held_resources(
    resolver: &dyn RelationshipResolver,
    tenant: &ScopedTenant,
    holder: PrincipalRef,
    wanted: &CapabilitySet,
    registry: &[AgentTool<ResolvedTenant>],
) -> Result<HeldResources, AppError> {
    let asked: Vec<ResourceCapability> = wanted
        .resources()
        .iter()
        .cloned()
        .chain(
            registry
                .iter()
                .map(|tool| ResourceCapability::use_of_tool(tool.id())),
        )
        .collect();
    let held = resolver
        .held_subset(tenant, &holder, &asked)
        .await
        .or_internal()?;
    Ok(HeldResources::answered(holder, held))
}

/// Gives the person who connected a provider or registered a tool use of it.
///
/// # Errors
///
/// - `AppError::Internal` when the grant cannot be written.
pub(in crate::use_cases::agents) async fn grant_use_to_creator(
    grants: &dyn ResourceGrantStore,
    tenant: &ScopedTenant,
    creator: &TenantAuthority,
    resource: &ResourceCapability,
) -> Result<(), AppError> {
    let creator = creator.who().principal();
    grants
        .grant(tenant, &creator, resource, &creator)
        .await
        .or_internal()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::types::{Human, ModelProviderId};

    use super::*;
    use crate::test_support::agents::{FakeResourceGraph, caller_person};
    use crate::test_support::{block_on, test_ctx};

    fn authority(holding: &[SystemPermission]) -> TenantAuthority {
        TenantAuthority::assumed(caller_person(), test_ctx().tenant_id(), holding, &[])
    }

    fn delegator() -> TenantAuthority {
        authority(&[SystemPermission::Agents(AgentAction::Delegate)])
    }

    fn may_use(
        graph: &FakeResourceGraph,
        authority: &TenantAuthority,
        resource: ResourceCapability,
    ) -> Result<(), AppError> {
        let tenant = test_ctx().tenant();
        let check = UseCheck {
            resolver: graph,
            tenant: &tenant,
        };
        block_on(check.require(&AgentControl::new(authority), resource))
    }

    fn me() -> Human {
        caller_person()
    }

    /// Agent-delegation permission alone does not grant use of a provider.
    #[test]
    fn delegating_alone_gives_no_use_of_a_provider() {
        let result = may_use(
            &FakeResourceGraph::empty(),
            &delegator(),
            ResourceCapability::use_of_provider(&ModelProviderId::new()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann was given use of the finance provider. She may use it.
    #[test]
    fn a_person_given_use_of_a_provider_may_use_it() {
        let graph = FakeResourceGraph::empty();
        let provider = ResourceCapability::use_of_provider(&ModelProviderId::new());
        graph.insert(&test_ctx().tenant(), me().principal(), provider.clone());

        let result = may_use(&graph, &delegator(), provider);

        assert!(result.is_ok());
    }

    /// Use of one provider cannot authorize use of a different provider.
    #[test]
    fn use_of_one_provider_is_not_use_of_another() {
        let graph = FakeResourceGraph::empty();
        graph.insert(
            &test_ctx().tenant(),
            me().principal(),
            ResourceCapability::use_of_provider(&ModelProviderId::new()),
        );

        let result = may_use(
            &graph,
            &delegator(),
            ResourceCapability::use_of_provider(&ModelProviderId::new()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Bob manages agents. He may use every provider without being given
    /// each one.
    #[test]
    fn an_agent_administrator_may_use_every_provider() {
        let admin = authority(&[SystemPermission::Agents(AgentAction::Manage)]);

        let result = may_use(
            &FakeResourceGraph::empty(),
            &admin,
            ResourceCapability::use_of_provider(&ModelProviderId::new()),
        );

        assert!(result.is_ok());
    }

    /// Ann connects a provider. She is given use of it.
    #[test]
    fn the_creator_is_given_use() {
        let graph = FakeResourceGraph::empty();
        let provider = ResourceCapability::use_of_provider(&ModelProviderId::new());

        block_on(grant_use_to_creator(
            &graph,
            &test_ctx().tenant(),
            &delegator(),
            &provider,
        ))
        .unwrap();

        assert!(may_use(&graph, &delegator(), provider).is_ok());
    }

    /// Ann asks to hand on the ledger and holds it. The graph's answer names
    /// her and the ledger, and not the use of a tool she was never given.
    #[test]
    fn the_graphs_answer_names_the_holder_and_only_what_they_hold() {
        let graph = FakeResourceGraph::empty();
        let ledger = ResourceCapability::use_of_provider(&ModelProviderId::new());
        graph.insert(&test_ctx().tenant(), me().principal(), ledger.clone());
        let wanted = CapabilitySet::empty().with_resources(vec![ledger.clone()]);

        let held = block_on(held_resources(
            &graph,
            &test_ctx().tenant(),
            me().principal(),
            &wanted,
            &[],
        ))
        .unwrap();

        assert_eq!(
            held,
            HeldResources::answered(me().principal(), vec![ledger])
        );
    }
}
