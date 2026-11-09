event_types! {
    /// The events the tenant context publishes.
    pub enum TenantEvent {
        /// A new tenant was provisioned.
        Provisioned => "tenant.provisioned",
        /// A tenant's status changed.
        StatusChanged => "tenant.status_changed",
        /// A tenant was renamed.
        Renamed => "tenant.renamed",
        /// A tenant's contact email was changed.
        ContactEmailChanged => "tenant.contact_email_changed",
        /// A tenant's timezone was changed.
        TimezoneChanged => "tenant.timezone_changed",
        /// A tenant's locale was changed.
        LocaleChanged => "tenant.locale_changed",
        /// A custom domain was registered for a tenant.
        DomainRegistered => "tenant.domain_registered",
        /// A custom domain was removed from a tenant.
        DomainRemoved => "tenant.domain_removed",
        /// A custom domain's DNS verification succeeded.
        DomainVerified => "tenant.domain_verified",
        /// A verified custom domain stopped resolving.
        DomainVerificationLost => "tenant.domain_verification_lost",
        /// A tenant's primary domain was changed.
        PrimaryDomainChanged => "tenant.primary_domain_changed",
        /// A tenant's authentication configuration was updated.
        AuthConfigUpdated => "tenant.auth_config_updated",
        /// A tenant's mTLS trust anchor was changed.
        MtlsConfigUpdated => "tenant.mtls_config_updated",
        /// The tenant's compliance posture changed.
        ComplianceChanged => "tenant.compliance_changed",
        /// Infrastructure provisioning failed.
        InfraFailed => "tenant.infra_failed",
        /// A custom domain's TLS certificate was provisioned.
        DomainTlsProvisioned => "tenant.domain_tls_provisioned",
        /// A tenant offered one of its custom domains to another tenant.
        DomainHandoverOffered => "tenant.domain_handover_offered",
        /// A custom domain was transferred between tenants.
        DomainTransferred => "tenant.domain_transferred",
        /// A record set in a delegated zone was written or replaced.
        DnsRecordSetChanged => "tenant.dns_record_set_changed",
        /// A record set in a delegated zone was removed.
        DnsRecordSetRemoved => "tenant.dns_record_set_removed",
        /// A tenant was permanently deleted.
        Deleted => "tenant.deleted",
        /// The platform deleted a tenant before its archive grace had run.
        DeletedEarly => "tenant.deleted_early",
        /// Everything a deleted tenant held was removed.
        TornDown => "tenant.torn_down",
        /// A step of a deleted tenant's teardown failed for good.
        TeardownFailed => "tenant.teardown_failed",
        /// A scheduled check found the tenant's audit chain broken.
        AuditChainBroken => "tenant.audit_chain_broken",
        /// A TLS certificate was requested for a domain.
        DomainTlsRequested => "tenant.domain_tls_requested",
        /// A tenant uploaded its own certificate for a domain.
        DomainCertificateUploaded => "tenant.domain_certificate_uploaded",
        /// A tenant replaced the certificate it uploaded for a domain.
        DomainCertificateReplaced => "tenant.domain_certificate_replaced",
        /// A tenant removed the certificate it uploaded for a domain.
        DomainCertificateRemoved => "tenant.domain_certificate_removed",
        /// A certificate the tenant uploaded is close to running out.
        DomainCertificateExpiring => "tenant.domain_certificate_expiring",
        /// A tenant was relabelled as serving another stage of its product.
        EnvironmentChanged => "tenant.environment_changed",
        /// A tenant enabled or disabled its public readable platform address.
        ReadableAddressChanged => "tenant.readable_address_changed",
        /// Copying another tenant's setup into this one started.
        CloneStarted => "tenant.clone_started",
        /// Every part of a clone was copied.
        CloneCompleted => "tenant.clone_completed",
        /// A clone stopped before every part was copied.
        CloneFailed => "tenant.clone_failed",
        /// A tenant started streaming its audit records to a SIEM.
        AuditStreamCreated => "tenant.audit_stream_created",
        /// An audit stream's destination, name or filter changed.
        AuditStreamChanged => "tenant.audit_stream_changed",
        /// An audit stream stopped sending, by hand or after failing.
        AuditStreamPaused => "tenant.audit_stream_paused",
        /// A paused audit stream started sending again.
        AuditStreamResumed => "tenant.audit_stream_resumed",
        /// An audit stream was removed.
        AuditStreamRemoved => "tenant.audit_stream_removed",
        /// Audit records past the tenant's retention were removed.
        AuditRecordsPurged => "tenant.audit_records_purged",
        /// An export of the tenant's audit log was asked for.
        AuditLogExportRequested => "tenant.audit_log_export_requested",
        /// The file of an export of the tenant's audit log was handed out.
        AuditLogExportDownloaded => "tenant.audit_log_export_downloaded",
    }
}

impl TenantEvent {
    /// Whether other members hear about this event.
    ///
    /// A retention purge carries out the posture the tenant chose, which
    /// was told when it was chosen, and runs on a schedule. Only the audit
    /// trail needs each one. An export of the audit log is the reader's own
    /// activity: the trail records who took the records out, colleagues'
    /// feeds do not.
    #[must_use]
    pub fn is_notifiable(&self) -> bool {
        !matches!(
            self,
            Self::AuditRecordsPurged
                | Self::AuditLogExportRequested
                | Self::AuditLogExportDownloaded
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The nightly purge removes Acme's old records, and Fay shortens the
    /// retention. Colleagues hear of the shorter retention, not of each
    /// purge it leads to.
    #[test]
    fn a_purge_is_not_notified_but_a_posture_change_is() {
        assert!(!TenantEvent::AuditRecordsPurged.is_notifiable());
        assert!(TenantEvent::ComplianceChanged.is_notifiable());
    }
}
