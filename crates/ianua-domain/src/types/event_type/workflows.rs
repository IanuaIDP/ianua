event_types! {
    /// The events the workflows context publishes.
    pub enum WorkflowsEvent {
        /// A workflow's first version was drafted.
        WorkflowCreated => "workflows.workflow_created",
        /// A workflow's next version was drafted.
        VersionDrafted => "workflows.version_drafted",
        /// A draft was renamed.
        DraftRenamed => "workflows.draft_renamed",
        /// A draft's steps and edges were replaced.
        DraftStepsReplaced => "workflows.draft_steps_replaced",
        /// What starts a draft was changed.
        DraftTriggerChanged => "workflows.draft_trigger_changed",
        /// How long a draft's executions may run was changed.
        DraftRunLimitChanged => "workflows.draft_run_limit_changed",
        /// What a draft does was described, or its description taken away.
        DraftDescribed => "workflows.draft_described",
        /// Who is told when a run of a draft fails was changed.
        DraftFailureAlertChanged => "workflows.draft_failure_alert_changed",
        /// A version was published. Its trigger now starts it.
        VersionPublished => "workflows.version_published",
        /// A version was taken out of service.
        VersionArchived => "workflows.version_archived",
        /// A version in service was held: an account it acts through can no
        /// longer be used for its publisher, so nothing starts it until a
        /// next version is published.
        VersionHeld => "workflows.version_held",
        /// An execution started.
        ExecutionStarted => "workflows.execution_started",
        /// A schedule, webhook or event did not start a version, because the
        /// person it would act for may not have it run.
        StartRefused => "workflows.start_refused",
        /// A step's work started.
        StepStarted => "workflows.step_started",
        /// A step finished.
        StepSucceeded => "workflows.step_succeeded",
        /// A step failed.
        StepFailed => "workflows.step_failed",
        /// An integration turned a step's call away, and the call is made
        /// again.
        StepCallTurnedAway => "workflows.step_call_turned_away",
        /// An agent run step was put off while the tenant's plan had no room
        /// for another run in flight, and is tried again.
        StepDeferred => "workflows.step_deferred",
        /// No path reached a step.
        StepSkipped => "workflows.step_skipped",
        /// An execution ended while a step was ready or under way.
        StepAbandoned => "workflows.step_abandoned",
        /// In a test, a step stood in instead of doing its work.
        StepStoodIn => "workflows.step_stood_in",
        /// In a test, a step that ran for real failed.
        TestStepFailed => "workflows.test_step_failed",
        /// A guardrail step found personal data, an attempt to trick a model
        /// or a banned word in the text it checked, named by kind and place.
        GuardrailFound => "workflows.guardrail_found",
        /// A person approved an approval step.
        ApprovalGranted => "workflows.approval_granted",
        /// An execution ended.
        ExecutionEnded => "workflows.execution_ended",
        /// A test of a workflow ended.
        TestEnded => "workflows.test_ended",
        /// A workflow's evaluation set was saved: its sample cases and
        /// whether publishing needs the draft's last evaluation to pass.
        EvaluationSetSaved => "workflows.evaluation_set_saved",
        /// A person started an evaluation of a workflow version against its
        /// sample cases.
        EvaluationStarted => "workflows.evaluation_started",
        /// An evaluation ended: every case passed, failed or could not run.
        EvaluationEnded => "workflows.evaluation_ended",
        /// A loop step started one pass, for one item of its list.
        PassStarted => "workflows.pass_started",
        /// One pass of a loop ended.
        PassEnded => "workflows.pass_ended",
        /// A sandbox was made: a named recipe of code, pinned packages and
        /// limits.
        SandboxCreated => "workflows.sandbox_created",
        /// A version of a sandbox was saved, and its bundle is being built.
        SandboxVersionSaved => "workflows.sandbox_version_saved",
        /// A version's bundle was built and stored.
        SandboxVersionBuilt => "workflows.sandbox_version_built",
        /// A version's bundle could not be built.
        SandboxVersionFailed => "workflows.sandbox_version_failed",
        /// A sandbox was archived.
        SandboxArchived => "workflows.sandbox_archived",
        /// A person started a trial of a sandbox version on sample input.
        SandboxTrialStarted => "workflows.sandbox_trial_started",
        /// A copy of a sandbox version was pushed to a company's repository.
        SandboxVersionPushed => "workflows.sandbox_version_pushed",
        /// An administrator allowed an image registry, which sandbox
        /// versions may pull the company's own images from.
        ImageRegistryAllowed => "workflows.image_registry_allowed",
        /// An image registry was taken off the tenant's list: versions
        /// whose image it keeps no longer run.
        ImageRegistryRemoved => "workflows.image_registry_removed",
        /// A memory was made: a named store of texts and their vectors.
        MemoryCreated => "workflows.memory_created",
        /// A memory was set to be deleted after its waiting period.
        MemoryDeletionRequested => "workflows.memory_deletion_requested",
        /// A memory set to be deleted was brought back.
        MemoryRestored => "workflows.memory_restored",
        /// A memory and every text it kept were deleted, its waiting period
        /// over.
        MemoryPurged => "workflows.memory_purged",
        /// An integration account was connected.
        AccountConnected => "workflows.account_connected",
        /// An integration account's sharing, scope, name or credential changed.
        AccountChanged => "workflows.account_changed",
        /// An integration account was disabled.
        AccountDisabled => "workflows.account_disabled",
        /// An integration account was enabled again.
        AccountEnabled => "workflows.account_enabled",
        /// The service renewed an integration account's credential as it was
        /// used, and the renewed one was kept.
        AccountCredentialRenewed => "workflows.account_credential_renewed",
        /// A person began connecting an account by signing in at the
        /// integration's service.
        AccountConnectionStarted => "workflows.account_connection_started",
        /// Someone other than the person who began a connection tried to
        /// finish it, and was refused.
        AccountConnectionRefused => "workflows.account_connection_refused",
        /// A workflow was registered at an integration's service, which now
        /// sends it the events it starts on.
        SubscriptionRegistered => "workflows.subscription_registered",
        /// A workflow's registration at a service lapsed or could not be
        /// made, so the service's events no longer start it.
        SubscriptionLapsed => "workflows.subscription_lapsed",
        /// A workflow's registration at a service was removed, as its version
        /// left service.
        SubscriptionRemoved => "workflows.subscription_removed",
        /// An account's address for a service's events began taking them.
        ChannelReady => "workflows.channel_ready",
        /// An account's address for a service's events lapsed, so the
        /// service's events no longer start its workflows.
        ChannelLapsed => "workflows.channel_lapsed",
        /// An account's address for a service's events, which no workflow
        /// used any more, was closed.
        ChannelClosed => "workflows.channel_closed",
        /// The token a service sent an account's address was shown to the
        /// account's owner, to paste back at the service.
        ChannelTokenShown => "workflows.channel_token_shown",
        /// A tenant raised how risky an integration operation counts as.
        OperationRiskRaised => "workflows.operation_risk_raised",
        /// A tenant dropped its raised view of an operation, which counts as
        /// its integration declares again.
        OperationRiskOverrideRemoved => "workflows.operation_risk_override_removed",
        /// A person made an agent flow: stages of agent runs, published and
        /// started at once.
        FlowCreated => "workflows.flow_created",
        /// A flow whose run had ended was deleted.
        FlowDeleted => "workflows.flow_deleted",
        /// A secret was issued for a workflow's webhook.
        TriggerSecretIssued => "workflows.trigger_secret_issued",
        /// A workflow's webhook secret was replaced. The old one starts
        /// nothing more.
        TriggerSecretRotated => "workflows.trigger_secret_rotated",
        /// A workflow's webhook secret was revoked. Its webhook starts
        /// nothing until a new one is issued.
        TriggerSecretRevoked => "workflows.trigger_secret_revoked",
    }
}

impl WorkflowsEvent {
    /// Selects events for colleagues' feeds; every event still reaches the audit trail.
    /// Routine execution/step progress, draft edits, loop passes, sandbox saves/builds/trials,
    /// test and evaluation activity, personal flow creation/deletion, credential renewal and subscription
    /// registration/removal stay quiet. Failures, approvals, execution outcomes, published
    /// version and account changes, sandbox creation/archive/build failure, webhook-secret
    /// changes, lapsed registrations and refused connections notify.
    #[must_use]
    pub fn is_notifiable(&self) -> bool {
        !self.is_routine_setup() && !self.is_routine_run()
    }

    /// Edits, flows, sandbox versions, connections begun and registrations
    /// made or removed: routine work on what runs.
    fn is_routine_setup(&self) -> bool {
        matches!(
            self,
            Self::FlowCreated
                | Self::FlowDeleted
                | Self::AccountCredentialRenewed
                | Self::AccountConnectionStarted
                | Self::AccountConnectionRefused
                | Self::SubscriptionRegistered
                | Self::SubscriptionRemoved
                | Self::ChannelReady
                | Self::ChannelClosed
                | Self::ChannelTokenShown
                | Self::DraftRenamed
                | Self::DraftStepsReplaced
                | Self::DraftTriggerChanged
                | Self::DraftRunLimitChanged
                | Self::DraftDescribed
                | Self::DraftFailureAlertChanged
                | Self::SandboxVersionSaved
                | Self::SandboxVersionBuilt
                | Self::SandboxVersionPushed
                | Self::SandboxTrialStarted
                | Self::EvaluationSetSaved
        )
    }

    /// The moves of a run that fire many times over, and everything in a
    /// test.
    fn is_routine_run(&self) -> bool {
        matches!(
            self,
            Self::ExecutionStarted
                | Self::PassStarted
                | Self::PassEnded
                | Self::StepStarted
                | Self::StepSucceeded
                | Self::StepCallTurnedAway
                | Self::StepDeferred
                | Self::StepSkipped
                | Self::StepAbandoned
                | Self::StepStoodIn
                | Self::TestStepFailed
                | Self::TestEnded
                | Self::GuardrailFound
                | Self::EvaluationStarted
                | Self::EvaluationEnded
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A workflow step starts and succeeds. Neither notifies anyone. A
    /// failed step, an ended execution and a connected account do.
    #[test]
    fn routine_step_progress_is_audited_but_not_notified() {
        assert!(!WorkflowsEvent::StepSucceeded.is_notifiable());
        assert!(!WorkflowsEvent::StepStarted.is_notifiable());
        assert!(!WorkflowsEvent::StepCallTurnedAway.is_notifiable());
        assert!(!WorkflowsEvent::StepDeferred.is_notifiable());
        assert!(WorkflowsEvent::StepFailed.is_notifiable());
        assert!(WorkflowsEvent::ExecutionEnded.is_notifiable());
        assert!(WorkflowsEvent::AccountConnected.is_notifiable());
    }

    /// Pat's guardrail finds a card number in every reply it checks. The
    /// findings reach the audit trail but no one's feed; a guardrail that
    /// stops the run fails its step, and that failure is heard.
    #[test]
    fn guardrail_findings_are_audited_but_not_notified() {
        assert!(!WorkflowsEvent::GuardrailFound.is_notifiable());
        assert!(WorkflowsEvent::StepFailed.is_notifiable());
    }

    /// Ann renames her draft, replaces its steps, changes its trigger and its
    /// run limit, describes it and chooses who hears of its failures. None of
    /// it notifies anyone. Publishing it does.
    #[test]
    fn edits_to_a_draft_are_audited_but_not_notified() {
        for edit in [
            WorkflowsEvent::DraftRenamed,
            WorkflowsEvent::DraftStepsReplaced,
            WorkflowsEvent::DraftTriggerChanged,
            WorkflowsEvent::DraftRunLimitChanged,
            WorkflowsEvent::DraftDescribed,
            WorkflowsEvent::DraftFailureAlertChanged,
        ] {
            assert!(!edit.is_notifiable(), "{edit:?}");
        }
        assert!(WorkflowsEvent::VersionPublished.is_notifiable());
    }

    /// Ann tests her draft and a step fails, ending the test. Nobody is
    /// told; the same failure in a real run is heard.
    #[test]
    fn a_test_failing_tells_nobody() {
        for quiet in [
            WorkflowsEvent::StepStoodIn,
            WorkflowsEvent::TestStepFailed,
            WorkflowsEvent::TestEnded,
        ] {
            assert!(!quiet.is_notifiable(), "{quiet:?}");
        }
        assert!(WorkflowsEvent::StepFailed.is_notifiable());
    }

    /// Ann saves sample cases for her draft and evaluates it; the
    /// evaluation fails. All of it is her own work on the draft, so none
    /// of it reaches her colleagues' feeds.
    #[test]
    fn evaluating_a_draft_tells_nobody() {
        for quiet in [
            WorkflowsEvent::EvaluationSetSaved,
            WorkflowsEvent::EvaluationStarted,
            WorkflowsEvent::EvaluationEnded,
        ] {
            assert!(!quiet.is_notifiable(), "{quiet:?}");
        }
    }

    /// Ann makes a flow and later deletes it. Neither reaches her
    /// colleagues' feeds. Bob issuing, replacing or revoking a webhook
    /// secret does.
    #[test]
    fn flows_stay_out_of_feeds_and_secret_changes_do_not() {
        assert!(!WorkflowsEvent::FlowCreated.is_notifiable());
        assert!(!WorkflowsEvent::FlowDeleted.is_notifiable());
        for change in [
            WorkflowsEvent::TriggerSecretIssued,
            WorkflowsEvent::TriggerSecretRotated,
            WorkflowsEvent::TriggerSecretRevoked,
        ] {
            assert!(change.is_notifiable(), "{change:?}");
        }
    }

    /// Tess begins signing in at GitHub and GitHub refuses her code. Both
    /// are her own attempt, so neither reaches her colleagues. The account
    /// she connects does, and so does a version held for an account it can
    /// no longer use.
    #[test]
    fn signing_in_at_a_service_stays_out_of_feeds() {
        assert!(!WorkflowsEvent::AccountConnectionStarted.is_notifiable());
        assert!(!WorkflowsEvent::AccountConnectionRefused.is_notifiable());
        assert!(WorkflowsEvent::AccountConnected.is_notifiable());
        assert!(WorkflowsEvent::VersionHeld.is_notifiable());
    }
}
