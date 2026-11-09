//! Update agent: change an agent's name, description and attestation
//! policy.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::identity::attestation::AttestationPolicy;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::permission::AgentAction;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AgentId, Label};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::input::FieldUpdate;
use crate::ports::agents::{AgentStore, AgentVersion};
use crate::use_case::Command;
use crate::use_cases::agents::lookup::{AgentReach, owned_agent};

/// Request to update an agent's details.
pub struct UpdateAgentRequest {
    /// The agent to update.
    pub agent_id: AgentId,
    /// New display name.
    pub name: Label,
    /// New description (cleared when `None`).
    pub description: Option<Label>,
    /// The attestation policy: left alone, cleared, or replaced whole. Its
    /// methods, interval and origins make one policy together, so one of
    /// them is never changed alone.
    pub attestation_policy: FieldUpdate<AttestationPolicy>,
}

/// The ports [`UpdateAgentUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdateAgentPorts {
    /// Loads and saves agents.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Updates one agent of the caller's tenant.
pub struct UpdateAgentUseCase {
    ports: UpdateAgentPorts,
}

impl UpdateAgentUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: UpdateAgentPorts) -> Self {
        Self { ports }
    }
}

impl Command for UpdateAgentUseCase {
    type Caller = CallerContext;
    type Input = UpdateAgentRequest;
    type Output = Result<(), AppError>;

    /// Changes the agent's name and description, and sets, clears or keeps
    /// its attestation policy.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such agent, or the
    ///   caller neither owns it nor may update agents, so that an agent of
    ///   someone else's answers as one that does not exist.
    /// - `AppError::Conflict` when the agent changed since it was read, as
    ///   when a fleet stop suspended it meanwhile, or another agent of the
    ///   tenant has the new name.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        req: UpdateAgentRequest,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let store = self.ports.agent_store.as_ref();
        let reach = AgentReach::Acting(AgentAction::Update);
        let mut agent = owned_agent(store, &tenant, &req.agent_id, &control, reach).await?;
        let read = AgentVersion::of(&agent);
        update(&mut agent, &control, req).map_err(AppError::from_domain)?;
        self.ports
            .agent_store
            .save_unchanged_since(&tenant, &agent, read)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&ctx.actor(), agent.take_events(&tenant))
            .await
            .or_internal()
    }
}

/// Applies `req` to `agent`, as `control` may.
fn update(
    agent: &mut AgentIdentity<ResolvedTenant>,
    control: &AgentControl<'_>,
    req: UpdateAgentRequest,
) -> Result<(), DomainError> {
    agent.update_details(control, req.name, req.description)?;
    match req.attestation_policy {
        FieldUpdate::Keep => Ok(()),
        FieldUpdate::Clear => agent.clear_attestation_policy(control),
        FieldUpdate::Set(policy) => agent.trust_attestation(control, policy),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::attestation::{AttestationMethod, AttestedOrigin};
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::types::Seconds;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{FakeAgentStore, caller_person, callers_agent};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn policy(method: AttestationMethod) -> AttestationPolicy {
        AttestationPolicy::new(
            vec![method],
            Seconds::new(3600),
            vec![AttestedOrigin::new("spiffe://cluster").unwrap()],
        )
        .unwrap()
    }

    fn renamed(
        id: AgentId,
        attestation_policy: FieldUpdate<AttestationPolicy>,
    ) -> UpdateAgentRequest {
        UpdateAgentRequest {
            agent_id: id,
            name: Label::new("name", "nightly-report").unwrap(),
            description: Some(Label::new("description", "renamed").unwrap()),
            attestation_policy,
        }
    }

    fn update(
        store: &Arc<FakeAgentStore>,
        authorities: FakeTenantAuthorities,
        sink: &Arc<FakeEventDispatcher>,
        req: UpdateAgentRequest,
    ) -> Result<(), AppError> {
        let use_case = UpdateAgentUseCase::new(UpdateAgentPorts {
            agent_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(sink.clone()), req))
    }

    fn owner() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[])
    }

    fn quiet() -> Arc<FakeEventDispatcher> {
        Arc::new(FakeEventDispatcher::new())
    }

    /// Ann renames her agent. The new name and description are kept and the
    /// change is recorded.
    #[test]
    fn the_owner_renames_their_agent_and_it_is_recorded() {
        let id = AgentId::new();
        let store = Arc::new(callers_agent(id));
        let sink = quiet();

        update(&store, owner(), &sink, renamed(id, FieldUpdate::Keep)).unwrap();

        let saved = store.find_by_id_direct(&id).unwrap();
        assert_eq!(saved.name().as_str(), "nightly-report");
        assert_eq!(saved.description().map(Label::as_str), Some("renamed"));
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.agent_updated"]
        );
    }

    /// Ann moves her agent onto attestation with a TPM policy. The agent
    /// keeps that policy.
    #[test]
    fn a_given_policy_replaces_the_old_one() {
        let id = AgentId::new();
        let store = Arc::new(callers_agent(id));
        let tpm = policy(AttestationMethod::Tpm);

        update(
            &store,
            owner(),
            &quiet(),
            renamed(id, FieldUpdate::Set(tpm.clone())),
        )
        .unwrap();

        assert_eq!(
            store.find_by_id_direct(&id).unwrap().attestation_policy(),
            Some(&tpm)
        );
    }

    /// Ann renames an agent that attests under SPIFFE, saying nothing about
    /// the policy. The policy stays.
    #[test]
    fn a_rename_alone_keeps_the_policy() {
        let id = AgentId::new();
        let store = Arc::new(callers_agent(id));
        let spiffe = policy(AttestationMethod::Spiffe);
        update(
            &store,
            owner(),
            &quiet(),
            renamed(id, FieldUpdate::Set(spiffe.clone())),
        )
        .unwrap();

        update(&store, owner(), &quiet(), renamed(id, FieldUpdate::Keep)).unwrap();

        assert_eq!(
            store.find_by_id_direct(&id).unwrap().attestation_policy(),
            Some(&spiffe)
        );
    }

    /// Ann clears her agent's attestation policy. It proves itself with an
    /// enrolled key again.
    #[test]
    fn the_policy_can_be_cleared() {
        let id = AgentId::new();
        let store = Arc::new(callers_agent(id));
        let spiffe = policy(AttestationMethod::Spiffe);
        update(
            &store,
            owner(),
            &quiet(),
            renamed(id, FieldUpdate::Set(spiffe)),
        )
        .unwrap();

        update(&store, owner(), &quiet(), renamed(id, FieldUpdate::Clear)).unwrap();

        assert_eq!(
            store.find_by_id_direct(&id).unwrap().attestation_policy(),
            None
        );
    }

    /// Bob, who may update agents, renames Ann's agent. The new name is kept.
    #[test]
    fn someone_allowed_to_update_agents_renames_anothers() {
        let id = AgentId::new();
        let store = Arc::new(FakeAgentStore::with_active(id));
        let bob = FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::Update)]);

        update(&store, bob, &quiet(), renamed(id, FieldUpdate::Keep)).unwrap();

        assert_eq!(
            store.find_by_id_direct(&id).unwrap().name().as_str(),
            "nightly-report"
        );
    }

    /// A viewer cannot update another person's agent; it appears missing,
    /// retains its stored name, and produces no update record.
    #[test]
    fn a_viewer_cannot_change_anothers_agent() {
        let id = AgentId::new();
        let store = Arc::new(FakeAgentStore::with_active(id));
        let sam = FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::View)]);
        let sink = quiet();

        let result = update(&store, sam, &sink, renamed(id, FieldUpdate::Clear));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(
            store.find_by_id_direct(&id).unwrap().name().as_str(),
            "fake-agent"
        );
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out caller cannot update their agent's details.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let id = AgentId::new();
        let store = Arc::new(callers_agent(id));

        let result = update(
            &store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &quiet(),
            renamed(id, FieldUpdate::Keep),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// A rename racing a fleet stop returns a conflict; the agent stays
    /// inactive with its original name and no update record is emitted.
    #[test]
    fn an_edit_read_before_a_fleet_stop_does_not_undo_it() {
        let id = AgentId::new();
        let store = Arc::new(callers_agent(id));
        store.stops_the_fleet_before_each_save();
        let sink = quiet();

        let result = update(&store, owner(), &sink, renamed(id, FieldUpdate::Keep));

        assert!(matches!(result, Err(AppError::Conflict(_))), "{result:?}");
        let kept = store.find_by_id_direct(&id).unwrap();
        assert!(!kept.is_active());
        assert_eq!(kept.name().as_str(), "fake-agent");
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Renaming an agent to another agent's name returns a conflict;
    /// the original name remains stored and no update is recorded.
    #[test]
    fn a_rename_onto_a_name_another_agent_holds_is_a_conflict() {
        let id = AgentId::new();
        let other = AgentId::new();
        let store = Arc::new(callers_agent(id));
        store.add_owned_by(other, caller_person());
        store.keeps_names_unique();
        update(&store, owner(), &quiet(), renamed(other, FieldUpdate::Keep)).unwrap();
        let sink = quiet();

        let result = update(&store, owner(), &sink, renamed(id, FieldUpdate::Keep));

        assert!(matches!(result, Err(AppError::Conflict(_))), "{result:?}");
        assert_eq!(
            store.find_by_id_direct(&id).unwrap().name().as_str(),
            "fake-agent"
        );
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann updates an agent the tenant does not have. It is not found.
    #[test]
    fn an_unknown_agent_is_not_found() {
        let result = update(
            &Arc::new(FakeAgentStore::empty()),
            FakeTenantAuthorities::holding_everything(),
            &quiet(),
            renamed(AgentId::new(), FieldUpdate::Keep),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A viewer's update attempts return identical responses for another
    /// person's agent and an unknown id.
    #[test]
    fn anothers_agent_answers_as_an_unknown_one() {
        let id = AgentId::new();
        let store = Arc::new(FakeAgentStore::with_active(id));
        let sam = || FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::View)]);

        let anothers = update(&store, sam(), &quiet(), renamed(id, FieldUpdate::Keep));
        let unknown = update(
            &store,
            sam(),
            &quiet(),
            renamed(AgentId::new(), FieldUpdate::Keep),
        );

        assert_eq!(format!("{anothers:?}"), format!("{unknown:?}"));
    }
}
