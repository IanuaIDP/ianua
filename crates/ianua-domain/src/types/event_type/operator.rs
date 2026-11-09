event_types! {
    /// The events the operator context publishes.
    pub enum OperatorEvent {
        /// An operator account was created.
        OperatorCreated => "operator.operator_created",
        /// An operator account was disabled.
        OperatorDisabled => "operator.operator_disabled",
        /// An operator account was re-enabled.
        OperatorEnabled => "operator.operator_enabled",
        /// An impersonation grant was created.
        ImpersonationGranted => "operator.impersonation_granted",
        /// An impersonation grant was revoked.
        ImpersonationRevoked => "operator.impersonation_revoked",
        /// An operator API key was created.
        OperatorApiKeyCreated => "operator.operator_api_key_created",
        /// An operator API key was revoked.
        OperatorApiKeyRevoked => "operator.operator_api_key_revoked",
        /// Someone tried to sign in as an operator and was refused.
        OperatorSignInFailed => "operator.operator_sign_in_failed",
        /// An export of the platform's audit log was asked for.
        AuditLogExportRequested => "operator.audit_log_export_requested",
        /// The file of an export of the platform's audit log was handed out.
        AuditLogExportDownloaded => "operator.audit_log_export_downloaded",
        /// A job that used up its attempts was given one more by an operator.
        DeadJobRetried => "operator.dead_job_retried",
    }
}

impl OperatorEvent {
    /// Whether other operators hear about this event.
    ///
    /// Exporting the audit log and a refused sign-in are an operator's own
    /// activity: the trail records them, colleagues' feeds do not.
    #[must_use]
    pub fn is_notifiable(&self) -> bool {
        !matches!(
            self,
            Self::AuditLogExportRequested
                | Self::AuditLogExportDownloaded
                | Self::OperatorSignInFailed
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An operator exports the platform's log. Nobody else is told; a new
    /// operator account still is.
    #[test]
    fn an_export_is_not_notified_but_a_new_operator_is() {
        assert!(!OperatorEvent::AuditLogExportRequested.is_notifiable());
        assert!(!OperatorEvent::AuditLogExportDownloaded.is_notifiable());
        assert!(OperatorEvent::OperatorCreated.is_notifiable());
    }

    /// Bob retries a dead job. The other operators hear of it, since the
    /// work runs again on the platform they share.
    #[test]
    fn a_retried_dead_job_is_notified() {
        assert!(OperatorEvent::DeadJobRetried.is_notifiable());
    }

    /// Someone guesses an operator's password. The trail holds the
    /// refusal; no operator's feed is told of every guess.
    #[test]
    fn a_refused_sign_in_is_not_notified() {
        assert!(!OperatorEvent::OperatorSignInFailed.is_notifiable());
    }
}
