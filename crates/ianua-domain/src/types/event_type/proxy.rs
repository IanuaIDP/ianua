event_types! {
    /// The events the proxy pipeline context publishes.
    pub enum ProxyEvent {
        /// A pipeline was created for a tenant.
        PipelineCreated => "proxy.pipeline_created",
        /// A pipeline was deleted.
        PipelineDeleted => "proxy.pipeline_deleted",
        /// A pipeline was renamed.
        PipelineRenamed => "proxy.pipeline_renamed",
        /// A pipeline started running on live traffic.
        PipelineActivated => "proxy.pipeline_activated",
        /// A pipeline stopped running on live traffic.
        PipelineDisabled => "proxy.pipeline_disabled",
        /// A stage was added to a pipeline.
        StageAdded => "proxy.stage_added",
        /// A stage was removed from a pipeline.
        StageRemoved => "proxy.stage_removed",
        /// A stage was enabled.
        StageEnabled => "proxy.stage_enabled",
        /// A stage was disabled.
        StageDisabled => "proxy.stage_disabled",
        /// A stage's settings were changed in place.
        StageReconfigured => "proxy.stage_reconfigured",
        /// A pipeline's stage order was changed.
        PipelineReordered => "proxy.pipeline_reordered",
        /// A client requested a configured decoy path.
        HoneypotHit => "proxy.honeypot_hit",
        /// The gateway turned a signed-in person away from an app.
        PersonTurnedAway => "proxy.person_turned_away",
        /// A stage detected and acted on suspected automated attack behavior.
        AutomatedThreatDetected => "proxy.automated_threat_detected",
        /// A client presented a planted canary credential.
        CanaryTokenTriggered => "proxy.canary_token_triggered",
        /// A planted canary credential was found leaking in an upstream
        /// response body.
        CanaryTokenLeaked => "proxy.canary_token_leaked",
        /// A tenant generated a new canary decoy token.
        CanaryTokenGenerated => "proxy.canary_token_generated",
        /// A tenant uploaded a WASM module for a `Custom` stage.
        WasmModuleUploaded => "proxy.wasm_module_uploaded",
        /// A tenant classified a field for redaction.
        ClassificationRuleAdded => "proxy.classification_rule_added",
        /// A tenant removed a field classification.
        ClassificationRuleRemoved => "proxy.classification_rule_removed",
        /// A tenant changed the level or redaction of a field classification.
        ClassificationRuleChanged => "proxy.classification_rule_changed",
        /// A tenant added a place its request records are shipped to.
        LogTargetCreated => "proxy.log_target_created",
        /// A tenant changed where or what its records are shipped.
        LogTargetChanged => "proxy.log_target_changed",
        /// A tenant stopped shipping records to a target for now.
        LogTargetPaused => "proxy.log_target_paused",
        /// A tenant started shipping records to a paused target again.
        LogTargetResumed => "proxy.log_target_resumed",
        /// A tenant removed a place its records were shipped to.
        LogTargetDeleted => "proxy.log_target_deleted",
    }
}

impl ProxyEvent {
    /// Whether other members hear about this event.
    ///
    /// A honeypot hit, a detected automated attack and a planted canary
    /// credential, presented or leaked, fire on a single request. Whoever
    /// sends the request decides how often. They go in the audit trail but
    /// not in colleagues' feeds. Mallory requests the decoy path a thousand
    /// times. If each hit were told, every feed would fill with her noise.
    #[must_use]
    pub fn is_notifiable(&self) -> bool {
        !matches!(
            self,
            Self::HoneypotHit
                | Self::PersonTurnedAway
                | Self::AutomatedThreatDetected
                | Self::CanaryTokenTriggered
                | Self::CanaryTokenLeaked
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decoy hits, automated threats and triggered or leaked canaries are
    /// excluded from notifications that could otherwise flood colleagues' feeds.
    #[test]
    fn per_request_threat_events_are_not_notified() {
        for event in [
            ProxyEvent::HoneypotHit,
            ProxyEvent::AutomatedThreatDetected,
            ProxyEvent::CanaryTokenTriggered,
            ProxyEvent::CanaryTokenLeaked,
        ] {
            assert!(!event.is_notifiable(), "{event:?}");
        }
    }

    /// An admin disables a pipeline. Colleagues are notified.
    #[test]
    fn a_change_to_a_pipeline_is_notified() {
        assert!(ProxyEvent::PipelineDisabled.is_notifiable());
    }
}
