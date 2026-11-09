//! Revoke credential: retire an agent's key for good.
//!
//! The agent's owner may revoke one of its keys, and so may someone allowed
//! to delete agents. A revoked key verifies nothing again, and every task
//! token the agent minted with it is refused from the next request on: the
//! token's delegation names the key, and the check of a presented token
//! reads the key's status beside the delegation chain.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::permission::AgentAction;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AgentCredentialId, AgentId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentCredentialStore, AgentStore};
use crate::use_case::Command;
use crate::use_cases::agents::lookup::{AgentReach, owned_agent, owned_credential};

/// Request to revoke a credential.
pub struct RevokeRequest {
    /// The agent the credential must belong to.
    pub agent_id: AgentId,
    /// The credential to revoke.
    pub credential_id: AgentCredentialId,
}

/// The ports [`RevokeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokePorts {
    /// Loads the agent the credential signs in.
    pub agent_store: Arc<dyn AgentStore>,
    /// Loads and keeps credentials.
    pub credential_store: Arc<dyn AgentCredentialStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Revokes an agent's key.
pub struct RevokeUseCase {
    ports: RevokePorts,
}

impl RevokeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RevokePorts) -> Self {
        Self { ports }
    }
}

impl Command for RevokeUseCase {
    type Caller = CallerContext;
    type Input = RevokeRequest;
    type Output = Result<(), AppError>;

    /// Revokes the credential for good, saved and then recorded.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` if the credential or its agent doesn't exist,
    ///   the credential belongs to a different agent, or the caller neither
    ///   owns the agent nor may delete agents, so that an agent of someone
    ///   else's answers as one that does not exist.
    /// - `AppError::Domain` if the credential is already revoked.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        req: RevokeRequest,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let store = self.ports.agent_store.as_ref();
        let reach = AgentReach::Acting(AgentAction::Delete);
        let agent = owned_agent(store, &tenant, &req.agent_id, &control, reach).await?;
        let mut credential = owned_credential(
            self.ports.credential_store.as_ref(),
            &tenant,
            &req.agent_id,
            &req.credential_id,
        )
        .await?;
        credential
            .revoke(&control, &agent)
            .map_err(AppError::from_domain)?;
        self.ports
            .credential_store
            .save(&tenant, &credential)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), credential.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::agent::AgentIdentity;
    use ianua_domain::domains::agents::identity::credential::AgentCredential;
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::crypto::key_status::KeyStatus;
    use ianua_domain::types::Human;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentCredentialStore, FakeAgentStore, agent_row, caller_person, key_row, someone_else,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Bench {
        agent: AgentId,
        key: AgentCredentialId,
        agents: Arc<FakeAgentStore>,
        credentials: Arc<FakeAgentCredentialStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Bench {
        fn owned_by(owner: Human) -> Self {
            let tenant = test_ctx().tenant();
            let agent = AgentId::new();
            let agents = Arc::new(FakeAgentStore::empty());
            block_on(agents.save(
                &tenant,
                &AgentIdentity::reconstitute(agent_row(agent, owner)).unwrap(),
            ))
            .unwrap();
            let credentials = Arc::new(FakeAgentCredentialStore::empty());
            let credential = AgentCredential::reconstitute(key_row(agent, "kid-seed")).unwrap();
            block_on(credentials.save(&tenant, &credential)).unwrap();
            Self {
                agent,
                key: *credential.id(),
                agents,
                credentials,
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn revoke_as(
            &self,
            people: FakeTenantAuthorities,
            agent_id: AgentId,
        ) -> Result<(), AppError> {
            let use_case = RevokeUseCase::new(RevokePorts {
                agent_store: self.agents.clone(),
                credential_store: self.credentials.clone(),
                tenant_authorities: Arc::new(people),
            });
            block_on(use_case.execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                RevokeRequest {
                    agent_id,
                    credential_id: self.key,
                },
            ))
        }

        fn revoke(&self, people: FakeTenantAuthorities) -> Result<(), AppError> {
            self.revoke_as(people, self.agent)
        }

        fn status(&self) -> KeyStatus {
            self.credentials.status_of(&self.key).unwrap()
        }
    }

    /// Ann revokes a key of her agent. It is revoked, and the revoke is
    /// recorded under the agent's name.
    #[test]
    fn the_owner_revokes_a_key_and_it_is_recorded() {
        let bench = Bench::owned_by(caller_person());

        bench.revoke(FakeTenantAuthorities::holding(&[])).unwrap();

        assert_eq!(bench.status(), KeyStatus::Revoked);
        assert_eq!(
            bench.sink.records.lock().unwrap().as_slice(),
            ["agents.credential_revoked"]
        );
        assert_eq!(
            bench.sink.label_of("agents.credential_revoked", "agent"),
            Some("ledger-bot".to_owned())
        );
    }

    /// Bob may delete agents. He revokes a key of Ann's agent after a leak,
    /// and it is revoked.
    #[test]
    fn someone_allowed_to_delete_agents_revokes_a_key() {
        let bench = Bench::owned_by(someone_else());

        bench
            .revoke(FakeTenantAuthorities::holding(&[SystemPermission::Agents(
                AgentAction::Delete,
            )]))
            .unwrap();

        assert_eq!(bench.status(), KeyStatus::Revoked);
    }

    /// A viewer cannot revoke another person's agent key; the agent appears
    /// missing, the key stays active, and no revocation is recorded.
    #[test]
    fn a_caller_who_neither_owns_nor_may_delete_the_agent_is_refused() {
        let bench = Bench::owned_by(someone_else());

        let result = bench.revoke(FakeTenantAuthorities::holding(&[SystemPermission::Agents(
            AgentAction::View,
        )]));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(bench.status(), KeyStatus::Active);
        assert!(bench.sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out caller cannot revoke the key, which remains active.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let bench = Bench::owned_by(caller_person());

        let result = bench.revoke(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(bench.status(), KeyStatus::Active);
    }

    /// Ann revokes a key twice. The second revoke is refused: a revoke is
    /// final.
    #[test]
    fn revoking_twice_is_refused() {
        let bench = Bench::owned_by(caller_person());
        bench.revoke(FakeTenantAuthorities::holding(&[])).unwrap();

        let second = bench.revoke(FakeTenantAuthorities::holding(&[]));

        assert!(matches!(second, Err(AppError::Domain(_))));
    }

    /// Naming an unknown parent agent yields a missing response and leaves
    /// the existing agent's key active.
    #[test]
    fn a_key_of_another_agent_is_not_found() {
        let bench = Bench::owned_by(caller_person());

        let result = bench.revoke_as(FakeTenantAuthorities::holding_everything(), AgentId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(bench.status(), KeyStatus::Active);
    }

    /// Ann revokes a key the tenant does not have. It is not found.
    #[test]
    fn an_unknown_credential_is_not_found() {
        let use_case = RevokeUseCase::new(RevokePorts::fakes());

        let result = block_on(use_case.execute(
            &test_ctx(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            RevokeRequest {
                agent_id: AgentId::new(),
                credential_id: AgentCredentialId::new(),
            },
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
