event_types! {
    /// The events the agents context publishes.
    pub enum AgentsEvent {
        /// A new agent identity was created.
        AgentCreated => "agents.agent_created",
        /// An agent's details were updated.
        AgentUpdated => "agents.agent_updated",
        /// An agent was suspended.
        AgentSuspended => "agents.agent_suspended",
        /// Every active agent of the tenant was suspended in one step.
        AllAgentsSuspended => "agents.all_agents_suspended",
        /// A suspended agent was resumed.
        AgentResumed => "agents.agent_resumed",
        /// An agent was revoked.
        AgentRevoked => "agents.agent_revoked",
        /// An agent identity was permanently deleted.
        AgentDeleted => "agents.agent_deleted",
        /// An agent was contained in one action. The agent, its credentials,
        /// every delegation it holds and every one made from those were
        /// revoked.
        AgentContained => "agents.agent_contained",
        /// An agent was required to re-attest before acting again.
        ReattestationRequired => "agents.reattestation_required",
        /// A delegation was granted to an agent.
        DelegationGranted => "agents.delegation_granted",
        /// A delegation was revoked.
        DelegationRevoked => "agents.delegation_revoked",
        /// A resource-scoped capability was granted onto an existing delegation.
        DelegationResourceGranted => "agents.delegation_resource_granted",
        /// A resource-scoped capability was revoked from an existing delegation.
        DelegationResourceRevoked => "agents.delegation_resource_revoked",
        /// A task token was issued for a delegation.
        TokenIssued => "agents.token_issued",
        /// A durable identity credential was minted for an agent.
        CredentialMinted => "agents.credential_minted",
        /// An agent credential was rotated.
        CredentialRotated => "agents.credential_rotated",
        /// An agent credential was revoked.
        CredentialRevoked => "agents.credential_revoked",
        /// An agent proved what it is with a verified attestation and got a
        /// short-lived credential.
        AgentBootstrapped => "agents.agent_bootstrapped",
        /// A paused action requested human approval.
        ApprovalRequested => "agents.approval_requested",
        /// A human approved a paused agent action.
        ApprovalGranted => "agents.approval_granted",
        /// The first of two approvals a high-risk action needs was given.
        ApprovalSigned => "agents.approval_signed",
        /// A person assigned one agent to review another.
        ReviewerAssigned => "agents.reviewer_assigned",
        /// A person ended a review assignment.
        ReviewEnded => "agents.review_ended",
        /// A reviewer agent reached an advisory verdict.
        ReviewVerdict => "agents.review_verdict",
        /// A service an agent called was refused a way out.
        EgressDenied => "agents.egress_denied",
        /// A person lowered a stopped agent's data mark.
        ExposureReset => "agents.exposure_reset",
        /// A person proposed a task template.
        TaskTemplateProposed => "agents.task_template_proposed",
        /// A second person approved a task template.
        TaskTemplateApproved => "agents.task_template_approved",
        /// A person retired a task template.
        TaskTemplateRetired => "agents.task_template_retired",
        /// A human denied a paused agent action.
        ApprovalDenied => "agents.approval_denied",
        /// A paused agent action's request was taken back, undecided,
        /// because a person stopped the run that raised it or changed the
        /// call it was about.
        ApprovalWithdrawn => "agents.approval_withdrawn",
        /// Policy allowed an agent's HTTP request.
        ActionAuthorized => "agents.action_authorized",
        /// Policy refused an agent's HTTP request.
        ActionDenied => "agents.action_denied",
        /// An agent's message on the message bus was allowed.
        MessageAuthorized => "agents.message_authorized",
        /// An agent's message on the message bus was refused.
        MessageDenied => "agents.message_denied",
        /// An agent's actions drifted from its declared intent.
        IntentDrift => "agents.intent_drift",
        /// Two agents met at one path: one wrote, the other read, within the
        /// window.
        Converged => "agents.converged",
        /// A bring-your-own model provider was connected.
        ModelProviderConnected => "agents.model_provider_connected",
        /// A tool was registered for agents to call.
        ToolRegistered => "agents.tool_registered",
        /// A tool was enabled or disabled.
        ToolStatusChanged => "agents.tool_status_changed",
        /// A tool was permanently deleted.
        ToolDeleted => "agents.tool_deleted",
        /// A model provider was enabled or disabled.
        ModelProviderStatusChanged => "agents.model_provider_status_changed",
        /// A model provider was permanently deleted.
        ModelProviderDeleted => "agents.model_provider_deleted",
        /// A model provider was sent a test request.
        ModelProviderTested => "agents.model_provider_tested",
        /// A principal was given a relation on a resource.
        ResourceRelationGranted => "agents.resource_relation_granted",
        /// A principal's relation on a resource was taken away.
        ResourceRelationRevoked => "agents.resource_relation_revoked",
        /// An agent was issued an attestation challenge to answer.
        AttestationChallengeIssued => "agents.attestation_challenge_issued",
        /// An orchestration run was accepted and started.
        RunStarted => "agents.run_started",
        /// An orchestration run paused for human approval.
        RunAwaitingApproval => "agents.run_awaiting_approval",
        /// An orchestration run finished.
        RunFinished => "agents.run_finished",
        /// A human asked an in-flight run to stop.
        RunCancelRequested => "agents.run_cancel_requested",
        /// An agent's ownership moved to another person.
        AgentOwnershipTransferred => "agents.agent_ownership_transferred",
        /// An agent's owner offered it to another person, who may accept it.
        AgentOwnershipOffered => "agents.agent_ownership_offered",
        /// An offer of an agent was withdrawn by its owner or declined by
        /// the person it was made to.
        AgentOwnershipOfferWithdrawn => "agents.agent_ownership_offer_withdrawn",
        /// A model provider was cleared for more or less sensitive data.
        ModelProviderClearanceChanged => "agents.model_provider_clearance_changed",
        /// A person renewed a delegation they granted, for another lifetime.
        DelegationRenewed => "agents.delegation_renewed",
        /// An agent asked a person for a delegation.
        DelegationRequested => "agents.delegation_requested",
        /// A person granted the delegation an agent asked them for.
        DelegationRequestApproved => "agents.delegation_request_approved",
        /// A person refused the delegation an agent asked them for.
        DelegationRequestDenied => "agents.delegation_request_denied",
        /// A model provider was given a new API key.
        ModelProviderKeyRotated => "agents.model_provider_key_rotated",
        /// A model provider was switched to another model or price.
        ModelProviderModelChanged => "agents.model_provider_model_changed",
        /// A model provider started or stopped offering an embedding model,
        /// or switched to another.
        ModelProviderEmbeddingsChanged => "agents.model_provider_embeddings_changed",
        /// A tool's definition was edited.
        ToolEdited => "agents.tool_edited",
        /// A person paused a run between its steps.
        RunPaused => "agents.run_paused",
        /// A person resumed a paused run.
        RunResumed => "agents.run_resumed",
        /// A run paused itself before spending more, until a person lets
        /// it go on.
        RunHeldAtSpend => "agents.run_held_at_spend",
        /// A run spent its limit, or could not tell what it spent, and
        /// stopped as over budget.
        RunStoppedOverBudget => "agents.run_stopped_over_budget",
        /// A person changed the arguments of the call a run holds for
        /// approval.
        HeldCallRevised => "agents.held_call_revised",
        /// An agent nobody registered was seen for the first time.
        AgentSighted => "agents.agent_sighted",
        /// A person registered an agent that was seen unregistered.
        AgentSightingRegistered => "agents.agent_sighting_registered",
        /// A person dismissed a sighting of an unregistered agent.
        AgentSightingDismissed => "agents.agent_sighting_dismissed",
        /// An agent's sign-in was refused in a way that looks like an
        /// attack: a replayed or forged assertion, one naming another
        /// agent, or a key-bound token without its key's proof.
        TokenAttackRefused => "agents.token_attack_refused",
    }
}

impl AgentsEvent {
    /// Whether other members hear about this event.
    ///
    /// Attestation challenges and model provider tests change nothing. Each
    /// allowed or refused action or message, each refused egress and each
    /// token issued fires on every request an agent makes. All of these go in
    /// the audit trail but not in colleagues' feeds. A converged flow is
    /// still told, since it is worth a look.
    ///
    /// A refused egress fires each time a service an agent called tries a way
    /// out. If it were told, Mallory's service could fill every feed by
    /// trying a thousand times. A sign-in refused as an attack fires as
    /// often as Mallory tries; it is a security alert instead, held back to
    /// one an hour.
    #[must_use]
    pub fn is_notifiable(&self) -> bool {
        !matches!(
            self,
            Self::AttestationChallengeIssued
                | Self::ModelProviderTested
                | Self::ActionAuthorized
                | Self::ActionDenied
                | Self::MessageAuthorized
                | Self::MessageDenied
                | Self::EgressDenied
                | Self::TokenIssued
                | Self::TokenAttackRefused
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An agent's allowed and refused actions and messages, and its issued
    /// tokens, fire on every request it makes. None of them reach a
    /// colleague's feed.
    #[test]
    fn per_request_agent_events_are_not_notified() {
        for event in [
            AgentsEvent::ActionAuthorized,
            AgentsEvent::ActionDenied,
            AgentsEvent::MessageAuthorized,
            AgentsEvent::MessageDenied,
            AgentsEvent::TokenIssued,
        ] {
            assert!(!event.is_notifiable(), "{event:?}");
        }
    }

    /// An egress refusal is excluded from feed notifications so repeated
    /// attempts cannot create a notice for every request.
    #[test]
    fn a_refused_egress_is_not_notified() {
        assert!(!AgentsEvent::EgressDenied.is_notifiable());
    }

    /// Agent sign-in attack refusals do not produce feed notices that repeated
    /// attempts could use to overwhelm colleagues.
    #[test]
    fn a_sign_in_refused_as_an_attack_is_not_notified() {
        assert!(!AgentsEvent::TokenAttackRefused.is_notifiable());
    }

    /// Two agents meet at one path. That is rare and worth a look, so
    /// colleagues are told.
    #[test]
    fn a_converged_flow_is_notified() {
        assert!(AgentsEvent::Converged.is_notifiable());
    }

    /// An admin deletes an agent. Colleagues are notified.
    #[test]
    fn a_change_to_an_agent_is_notified() {
        assert!(AgentsEvent::AgentDeleted.is_notifiable());
    }
}
