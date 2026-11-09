event_types! {
    /// The events the signals context publishes.
    pub enum SignalsEvent {
        /// A signal stream receiver was registered.
        StreamRegistered => "signals.stream_registered",
        /// A signal stream was paused.
        StreamPaused => "signals.stream_paused",
        /// A signal stream was resumed.
        StreamResumed => "signals.stream_resumed",
        /// A signal stream was permanently disabled.
        StreamDisabled => "signals.stream_disabled",
        /// A signal stream's configuration was updated.
        StreamUpdated => "signals.stream_updated",
        /// A disabled signal stream was permanently deleted.
        StreamDeleted => "signals.stream_deleted",
        /// A user or agent was added to what a signal stream hears about.
        SubjectAdded => "signals.subject_added",
        /// A user or agent was removed from what a signal stream hears about.
        SubjectRemoved => "signals.subject_removed",
        /// A verification event was asked for and sent down a stream.
        VerificationRequested => "signals.verification_requested",
        /// A signal about a person was reported by hand or by a workflow:
        /// a risk level, a compromised credential or device.
        SignalReported => "signals.signal_reported",
    }
}

impl SignalsEvent {
    /// Whether the tenant's members hear about this event.
    ///
    /// A receiver adds and removes subjects one at a time, often one per
    /// user it signs in, and asks for verification events to check its
    /// stream works. That goes in the audit trail but not in anybody's
    /// feed, which it would flood.
    #[must_use]
    pub fn is_notifiable(&self) -> bool {
        !matches!(
            self,
            Self::SubjectAdded | Self::SubjectRemoved | Self::VerificationRequested
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The payroll app adds a hundred users to its stream. None of that
    /// reaches a colleague's feed, while a disabled stream does.
    #[test]
    fn subject_changes_reach_nobodys_feed() {
        assert!(!SignalsEvent::SubjectAdded.is_notifiable());
        assert!(!SignalsEvent::SubjectRemoved.is_notifiable());
        assert!(!SignalsEvent::VerificationRequested.is_notifiable());
        assert!(SignalsEvent::StreamDisabled.is_notifiable());
    }
}
