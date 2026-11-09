//! List credentials: the keys an agent signs in with.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::agents::identity::credential::AgentCredential;
use ianua_domain::domains::authorization::permission::AgentAction;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::AgentId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentCredentialStore, AgentStore};
use crate::use_case::Query;
use crate::use_cases::agents::lookup::{AgentReach, owned_agent};

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Loads the agent whose keys are listed.
    pub agent_store: Arc<dyn AgentStore>,
    /// Reads credentials.
    pub credential_store: Arc<dyn AgentCredentialStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists an agent's keys.
pub struct ListUseCase {
    ports: ListPorts,
}

impl ListUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListUseCase {
    type Caller = CallerContext;
    type Input = AgentId;
    type Output = Result<Vec<AgentCredential<ResolvedTenant>>, AppError>;

    /// The keys `agent_id` holds, active, rotated and revoked.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` if the agent doesn't exist, or the caller
    ///   neither owns it nor may view agents, so that an agent of someone
    ///   else's answers as one that does not exist.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        agent_id: AgentId,
    ) -> Result<Vec<AgentCredential<ResolvedTenant>>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let store = self.ports.agent_store.as_ref();
        let reach = AgentReach::Acting(AgentAction::View);
        owned_agent(store, &tenant, &agent_id, &control, reach).await?;
        self.ports
            .credential_store
            .list_for_agent(&tenant, &agent_id)
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::agent::AgentIdentity;
    use ianua_domain::types::Human;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentCredentialStore, FakeAgentStore, agent_row, caller_person, key_row, someone_else,
    };
    use crate::test_support::{block_on, test_ctx};

    struct Bench {
        agents: Arc<FakeAgentStore>,
        credentials: Arc<FakeAgentCredentialStore>,
    }

    impl Bench {
        fn new() -> Self {
            Self {
                agents: Arc::new(FakeAgentStore::empty()),
                credentials: Arc::new(FakeAgentCredentialStore::empty()),
            }
        }

        fn agent_of(&self, owner: Human, keys: usize) -> AgentId {
            let tenant = test_ctx().tenant();
            let id = AgentId::new();
            let agent = AgentIdentity::reconstitute(agent_row(id, owner)).unwrap();
            block_on(self.agents.save(&tenant, &agent)).unwrap();
            for _ in 0..keys {
                let key = AgentCredential::reconstitute(key_row(id, "kid")).unwrap();
                block_on(self.credentials.save(&tenant, &key)).unwrap();
            }
            id
        }

        fn list(
            &self,
            people: FakeTenantAuthorities,
            agent: AgentId,
        ) -> Result<Vec<AgentCredential<ResolvedTenant>>, AppError> {
            let use_case = ListUseCase::new(ListPorts {
                agent_store: self.agents.clone(),
                credential_store: self.credentials.clone(),
                tenant_authorities: Arc::new(people),
            });
            block_on(use_case.execute(&test_ctx(), agent))
        }
    }

    /// Ann lists her agent's keys. She sees its two, and none of another
    /// agent's.
    #[test]
    fn lists_only_the_agents_own_credentials() {
        let bench = Bench::new();
        let agent = bench.agent_of(caller_person(), 2);
        bench.agent_of(caller_person(), 1);

        let keys = bench
            .list(FakeTenantAuthorities::holding(&[]), agent)
            .unwrap();

        assert_eq!(keys.len(), 2);
        assert!(keys.iter().all(|key| *key.agent_id() == agent));
    }

    /// Without ownership or the view right, listing a real agent's keys
    /// returns the same missing response as an unknown agent.
    #[test]
    fn a_caller_who_neither_owns_nor_may_view_the_agent_is_refused() {
        let bench = Bench::new();
        let agent = bench.agent_of(someone_else(), 1);

        let result = bench.list(FakeTenantAuthorities::holding(&[]), agent);
        let unknown = bench.list(FakeTenantAuthorities::holding(&[]), AgentId::new());

        let refusal = |listed: Result<_, AppError>| listed.err().map(|error| error.to_string());
        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(refusal(result), refusal(unknown));
    }

    /// A signed-out caller cannot list even their own agent's keys.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let bench = Bench::new();
        let agent = bench.agent_of(caller_person(), 1);

        let result = bench.list(FakeTenantAuthorities::refusing(Refusal::SignedOut), agent);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Ann lists the keys of an agent the tenant does not have. It is not
    /// found.
    #[test]
    fn an_unknown_agent_is_not_found() {
        let bench = Bench::new();

        let result = bench.list(FakeTenantAuthorities::holding_everything(), AgentId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
