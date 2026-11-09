//! The sweeps that keep records in shape: retention of the audit trail,
//! of notifications, of the gateway's request and stream records and of
//! sessions long over, the audit chain, signing
//! and assertion keys, certificates and domains, and SAML metadata.

use std::sync::Arc;
use std::time::Duration;

use ianua_app::ports::authentication::SecretEncryptor;
use ianua_app::ports::domain::PlatformZoneSettings;
use ianua_app::use_cases::audit::exports::{ExpirePorts, ExpireUseCase};
use ianua_app::use_cases::audit::{
    PurgeExpiredRecordsPorts, PurgeExpiredRecordsUseCase, SweepChainsPorts, SweepChainsUseCase,
};
use ianua_app::use_cases::authentication::sessions::{PurgeEndedPorts, PurgeEndedUseCase};
use ianua_app::use_cases::crypto::assertions;
use ianua_app::use_cases::crypto::keys::{
    RevokeAfterGracePorts, RevokeAfterGraceUseCase, RotateByAgePorts, RotateByAgeUseCase,
};
use ianua_app::use_cases::domain::certificates::{
    ProvisionPendingTlsPorts, ProvisionPendingTlsUseCase, ProvisionTlsPorts, ProvisionTlsUseCase,
    RenewPorts, RenewUseCase,
};
use ianua_app::use_cases::domain::verification::proof::ProofRules;
use ianua_app::use_cases::domain::verification::verified::CertificateQueue;
use ianua_app::use_cases::domain::verification::{
    DomainHealthCheckPorts, DomainHealthCheckUseCase, RetryPorts, RetryUseCase,
};
use ianua_app::use_cases::federation::connections::{RefreshMetadataPorts, RefreshMetadataUseCase};
use ianua_app::use_cases::notifications::{PurgeOldPorts, PurgeOldUseCase};
use ianua_app::use_cases::proxy::{ForgetOldRecordsPorts, ForgetOldRecordsUseCase};
use ianua_app::use_cases::tenant::certificates::{
    MaintainPlatformCertificatesPorts, MaintainPlatformCertificatesUseCase,
    PlatformCertificateSettings,
};
use ianua_app::use_cases::workflows::evaluations;
use ianua_app::use_cases::workflows::executions::{PurgeEndedRunsPorts, PurgeEndedRunsUseCase};
use ianua_app::use_cases::workflows::sandboxes::trying::{
    PurgeEndedTrialsPorts, PurgeEndedTrialsUseCase,
};
use ianua_domain::domains::crypto::rotation::KeyRotationSchedule;
use ianua_domain::domains::tenant::hosts::PlatformAddressing;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::types::Lifetime;
use ianua_infra::crypto::{Pkcs8KeyGenerator, X509CertificateParser};
use ianua_infra::files::FileAuditExportFiles;
use ianua_infra::postgres::audit::{
    PgAuditChainVerdictStore, PgAuditChainVerifier, PgAuditExportStore, PgAuditRetentionStore,
};
use ianua_infra::postgres::crypto::{
    PgAssertionKeyStore, PgCrossTenantAssertionKeys, PgCrossTenantKeySets, PgMigrationStore,
};
use ianua_infra::postgres::domain::{
    PgCertificateStore, PgCrossTenantCertificateStore, PgCrossTenantDomainStore,
    PgPlatformCertificateStore, PgRegisteredDomainStore,
};
use ianua_infra::postgres::federation::{PgConnectionStore, PgMetadataFollowers};
use ianua_infra::postgres::notifications::{
    PgOrgNotificationStore, PgPlatformNotificationStore, PgTenantNotificationStore,
};
use ianua_infra::postgres::organization::PgOrgSessionStore;
use ianua_infra::postgres::proxy::{PgCrossTenantHosts, PgRequestRecordRetention};
use ianua_infra::postgres::routing::PgStreamRecordRetention;
use ianua_infra::postgres::shared::PgSessionStore;
use ianua_infra::postgres::workflows::{
    PgEvaluationStore, PgSandboxTrialStore, PgWorkflowExecutionStore,
};

use crate::error::{PlatformError, ServerError};
use crate::worker::parts::Parts;
use crate::worker::sweeps::{SweepRun, Swept};

/// The longest a tenant's signing key signs before the platform rotates
/// it. No setting names it; a quarter keeps a stolen key's worth short
/// while leaving relying parties' caches of the JWKS far behind.
const SIGNING_KEY_MAX_AGE: Duration = Duration::from_secs(90 * 86_400);

/// Why an upkeep sweep cannot be built.
#[derive(Debug, thiserror::Error)]
enum UpkeepError {
    /// This node holds no audit purge login, which a worker always does.
    #[error("the audit retention needs AUDIT_PURGE_DATABASE_URL, which this node does not hold")]
    NoAuditPurge,
}

/// The upkeep sweeps' runners.
///
/// # Errors
///
/// [`ServerError`] when a use case cannot be built.
pub(super) fn runners(parts: &Parts<'_>) -> Result<Vec<Arc<dyn SweepRun>>, ServerError> {
    Ok(vec![
        purge_expired_records(parts)?,
        sweep_chains(parts),
        purge_old_notifications(parts),
        purge_ended_trials(parts),
        purge_ended_evaluations(parts),
        purge_ended_runs(parts),
        forget_old_records(parts),
        purge_ended_sessions(parts),
        expire_audit_exports(parts),
        rotate_keys_by_age(parts)?,
        revoke_keys_after_grace(parts)?,
        rotate_assertion_keys_by_age(parts),
        retire_assertion_keys_after_overlap(parts),
        provision_pending_tls(parts),
        renew_certificates(parts),
        platform_certificates(parts),
        health_check(parts),
        retry_verification(parts),
        refresh_saml_metadata(parts),
    ])
}

/// Reconciles platform pairs from live tenant state, independent of event delivery.
fn platform_certificates(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    let platform = parts.platform;
    let config = parts.config;
    let settings = match (
        config.deployment.platform_addressing,
        config.domains.proxy_address.as_ref(),
    ) {
        (PlatformAddressing::Nested, Some(address)) => Some(PlatformCertificateSettings {
            base_domain: config.deployment.base_domain.clone(),
            zones: PlatformZoneSettings {
                nameservers: config.domains.nameservers.clone(),
                address: address.clone(),
            },
        }),
        _ => None,
    };
    Swept::of(MaintainPlatformCertificatesUseCase::new(
        MaintainPlatformCertificatesPorts {
            hosts: Arc::new(PgCrossTenantHosts::new(
                Arc::clone(&platform.databases),
                DomainLimits::default(),
            )),
            certificates: Arc::new(PgPlatformCertificateStore::new(
                Arc::clone(&platform.databases),
                platform.secrets.encryptor.clone(),
            )),
            provisioner: Arc::clone(&parts.platform_tls),
            parser: Arc::new(X509CertificateParser),
        },
        settings,
    ))
}

/// The tenants' audit records past their retention, removed through the
/// audit purge's own login, never the app's.
fn purge_expired_records(parts: &Parts<'_>) -> Result<Arc<dyn SweepRun>, ServerError> {
    let platform = parts.platform;
    let purge = platform
        .audit_purge
        .as_ref()
        .ok_or(UpkeepError::NoAuditPurge)
        .map_err(PlatformError::of("the audit retention"))?;
    Ok(Swept::of(PurgeExpiredRecordsUseCase::new(
        PurgeExpiredRecordsPorts {
            tenant_store: Arc::clone(&parts.tenants),
            retention: Arc::new(PgAuditRetentionStore::new(
                Arc::clone(purge),
                platform.keys.audit_chain_seals.clone(),
            )),
            unit_of_work: Arc::clone(&platform.unit_of_work),
        },
    )))
}

/// Every tenant's audit chain checked from its last checkpoint, under the
/// seals of the chain's heads and verdicts.
fn sweep_chains(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    let platform = parts.platform;
    let seals = &platform.keys.audit_chain_seals;
    Swept::of(SweepChainsUseCase::new(SweepChainsPorts {
        tenant_store: Arc::clone(&parts.tenants),
        verifier: Arc::new(PgAuditChainVerifier::new(
            Arc::clone(&platform.databases),
            seals.clone(),
        )),
        verdicts: Arc::new(PgAuditChainVerdictStore::new(
            Arc::clone(&platform.databases),
            seals.clone(),
        )),
    }))
}

/// The notifications of operators, members and tenant users past their
/// keeping, removed.
fn purge_old_notifications(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    let databases = &parts.platform.databases;
    Swept::of(PurgeOldUseCase::new(PurgeOldPorts {
        platform_store: Arc::new(PgPlatformNotificationStore::new(Arc::clone(databases))),
        org_store: Arc::new(PgOrgNotificationStore::new(Arc::clone(databases))),
        tenant_store: Arc::new(PgTenantNotificationStore::new(Arc::clone(databases))),
        tenants: Arc::clone(&parts.tenants),
    }))
}

/// Every tenant's sandbox trials past their keeping, removed.
fn purge_ended_trials(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    Swept::of(PurgeEndedTrialsUseCase::new(PurgeEndedTrialsPorts {
        trials: Arc::new(PgSandboxTrialStore::new(Arc::clone(
            &parts.platform.databases,
        ))),
        tenants: Arc::clone(&parts.tenants),
    }))
}

/// Every tenant's evaluations past their keeping, removed.
fn purge_ended_evaluations(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    Swept::of(evaluations::PurgeEndedUseCase::new(
        evaluations::PurgeEndedPorts {
            evaluations: Arc::new(PgEvaluationStore::new(Arc::clone(
                &parts.platform.databases,
            ))),
            tenants: Arc::clone(&parts.tenants),
        },
    ))
}

/// Every tenant's ended workflow runs past their keeping, removed.
fn purge_ended_runs(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    Swept::of(PurgeEndedRunsUseCase::new(
        PurgeEndedRunsPorts {
            executions: Arc::new(PgWorkflowExecutionStore::new(Arc::clone(
                &parts.platform.databases,
            ))),
            tenants: Arc::clone(&parts.tenants),
        },
        parts.config.worker.workflow_runs_kept,
    ))
}

/// The gateway's request and stream records past each tenant's retention,
/// removed.
fn forget_old_records(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    let databases = &parts.platform.databases;
    Swept::of(ForgetOldRecordsUseCase::new(ForgetOldRecordsPorts {
        tenant_store: Arc::clone(&parts.tenants),
        requests: Arc::new(PgRequestRecordRetention::new(Arc::clone(databases))),
        streams: Arc::new(PgStreamRecordRetention::new(Arc::clone(databases))),
    }))
}

/// The sessions of tenant users and members long over, removed.
fn purge_ended_sessions(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    let databases = &parts.platform.databases;
    Swept::of(PurgeEndedUseCase::new(PurgeEndedPorts {
        session_store: Arc::new(PgSessionStore::new(Arc::clone(databases))),
        org_session_store: Arc::new(PgOrgSessionStore::new(Arc::clone(databases))),
        tenants: Arc::clone(&parts.tenants),
    }))
}

/// The audit log exports past their keeping, their files deleted.
fn expire_audit_exports(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    let platform = parts.platform;
    Swept::of(ExpireUseCase::new(ExpirePorts {
        exports: Arc::new(PgAuditExportStore::new(Arc::clone(&platform.databases))),
        files: Arc::new(FileAuditExportFiles::new(
            Arc::clone(&platform.files),
            parts.platform.file_links.clone(),
        )),
    }))
}

/// The tenants' signing keys older than a quarter, rotated, the old one
/// kept published for the JWKS grace.
fn rotate_keys_by_age(parts: &Parts<'_>) -> Result<Arc<dyn SweepRun>, ServerError> {
    let platform = parts.platform;
    let schedule = KeyRotationSchedule::new(
        lifetime(SIGNING_KEY_MAX_AGE, "the signing keys' rotation")?,
        jwks_grace(parts)?,
    )
    .map_err(PlatformError::of("the signing keys' rotation"))?;
    Ok(Swept::of(RotateByAgeUseCase::new(
        RotateByAgePorts {
            key_store: parts.signing_keys(),
            key_sets: Arc::new(PgCrossTenantKeySets::new(Arc::clone(&platform.databases))),
            key_generator: Arc::new(Pkcs8KeyGenerator),
            migration_store: Arc::new(PgMigrationStore::new(Arc::clone(&platform.databases))),
            unit_of_work: Arc::clone(&platform.unit_of_work),
        },
        schedule,
    )))
}

/// The signing keys rotated out longer than the JWKS grace ago, revoked:
/// the same grace the JWKS keeps them published for.
fn revoke_keys_after_grace(parts: &Parts<'_>) -> Result<Arc<dyn SweepRun>, ServerError> {
    let platform = parts.platform;
    Ok(Swept::of(RevokeAfterGraceUseCase::new(
        RevokeAfterGracePorts {
            key_store: parts.signing_keys(),
            key_sets: Arc::new(PgCrossTenantKeySets::new(Arc::clone(&platform.databases))),
            unit_of_work: Arc::clone(&platform.unit_of_work),
        },
        jwks_grace(parts)?,
    )))
}

/// The assertion keys, each new private half sealed at rest under the
/// platform's sealer.
fn assertion_keys(parts: &Parts<'_>) -> Arc<PgAssertionKeyStore> {
    let platform = parts.platform;
    let sealer: Arc<dyn SecretEncryptor> = platform.secrets.encryptor.clone();
    Arc::new(PgAssertionKeyStore::new(
        Arc::clone(&platform.databases),
        sealer,
    ))
}

/// The tenants' assertion keys older than the domain's fixed schedule, or
/// with nothing signing, rotated onto a new key; the old one kept
/// published for the schedule's overlap.
fn rotate_assertion_keys_by_age(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    let platform = parts.platform;
    Swept::of(assertions::RotateByAgeUseCase::new(
        assertions::RotateByAgePorts {
            keys: assertion_keys(parts),
            key_sets: Arc::new(PgCrossTenantAssertionKeys::new(Arc::clone(
                &platform.databases,
            ))),
            key_generator: Arc::new(Pkcs8KeyGenerator),
            unit_of_work: Arc::clone(&platform.unit_of_work),
        },
        KeyRotationSchedule::FOR_ASSERTION_KEYS,
    ))
}

/// The assertion keys rotated out longer than the schedule's overlap ago,
/// retired.
fn retire_assertion_keys_after_overlap(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    let platform = parts.platform;
    Swept::of(assertions::RetireAfterOverlapUseCase::new(
        assertions::RetireAfterOverlapPorts {
            keys: assertion_keys(parts),
            key_sets: Arc::new(PgCrossTenantAssertionKeys::new(Arc::clone(
                &platform.databases,
            ))),
            unit_of_work: Arc::clone(&platform.unit_of_work),
        },
        KeyRotationSchedule::FOR_ASSERTION_KEYS.overlap(),
    ))
}

/// `JWKS_ROTATION_GRACE_SECONDS` as a lifetime.
fn jwks_grace(parts: &Parts<'_>) -> Result<Lifetime, ServerError> {
    lifetime(
        parts.config.sign_in.tokens.jwks_grace,
        "the JWKS rotation grace",
    )
}

/// `span` as a lifetime, refused with `part` named when it is not one.
fn lifetime(span: Duration, part: &'static str) -> Result<Lifetime, ServerError> {
    let span = time::Duration::try_from(span).map_err(PlatformError::of(part))?;
    Lifetime::new(span).map_err(|error| PlatformError::of(part)(error).into())
}

/// The verified domains still waiting on a certificate, each handed to the
/// one issuance a certificate job runs too.
fn provision_pending_tls(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    let platform = parts.platform;
    let databases = &platform.databases;
    let issuance = ProvisionTlsUseCase::new(ProvisionTlsPorts {
        domain_store: Arc::new(PgRegisteredDomainStore::new(Arc::clone(databases))),
        certificate_store: certificates(parts),
        tls_provisioners: parts.tls.clone(),
        unit_of_work: Arc::clone(&platform.unit_of_work),
    });
    let stale_after = whole(parts.config.domains.tls_pending_stale_after, 60);
    Swept::of(ProvisionPendingTlsUseCase::new(
        ProvisionPendingTlsPorts {
            cross_tenant_domains: Arc::new(PgCrossTenantDomainStore::new(Arc::clone(databases))),
            provision_tls: Arc::new(issuance),
        },
        stale_after,
    ))
}

/// The certificates nearing their expiry, renewed the way each domain's
/// connection proves it.
fn renew_certificates(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    let platform = parts.platform;
    let databases = &platform.databases;
    let encryptor: Arc<dyn SecretEncryptor> = platform.secrets.encryptor.clone();
    let threshold_days = whole(parts.config.domains.tls_renewal_threshold, 86_400);
    Swept::of(RenewUseCase::new(
        RenewPorts {
            certificate_store: certificates(parts),
            expiring_certificates: Arc::new(PgCrossTenantCertificateStore::new(
                Arc::clone(databases),
                encryptor,
            )),
            domain_store: Arc::new(PgRegisteredDomainStore::new(Arc::clone(databases))),
            tls_provisioners: parts.tls.clone(),
            unit_of_work: Arc::clone(&platform.unit_of_work),
        },
        threshold_days,
    ))
}

/// `span` in whole units of `unit_seconds`.
fn whole(span: Duration, unit_seconds: u64) -> u32 {
    u32::try_from(span.as_secs() / unit_seconds).unwrap_or(u32::MAX)
}

/// The certificates, their private keys sealed at rest.
fn certificates(parts: &Parts<'_>) -> Arc<PgCertificateStore> {
    let platform = parts.platform;
    let encryptor: Arc<dyn SecretEncryptor> = platform.secrets.encryptor.clone();
    Arc::new(PgCertificateStore::new(
        Arc::clone(&platform.databases),
        encryptor,
    ))
}

/// The rules a domain is proved under: the deployment's nameservers and
/// the domains its operator vouches for.
fn proof_rules(parts: &Parts<'_>) -> ProofRules {
    ProofRules::new(
        parts.config.domains.nameservers.clone(),
        parts.config.deployment.trusted_domains.clone(),
    )
}

/// The verified domains checked again, those that lost their proof put
/// back to unverified.
fn health_check(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    let platform = parts.platform;
    let databases = &platform.databases;
    Swept::of(DomainHealthCheckUseCase::new(
        DomainHealthCheckPorts {
            domain_store: Arc::new(PgRegisteredDomainStore::new(Arc::clone(databases))),
            cross_tenant_domains: Arc::new(PgCrossTenantDomainStore::new(Arc::clone(databases))),
            dns_resolver: Arc::clone(&parts.resolver),
            tenants: Arc::clone(&parts.tenants),
            unit_of_work: Arc::clone(&platform.unit_of_work),
        },
        proof_rules(parts),
    ))
}

/// The domains still waiting on their proof checked again, each that
/// passes queued for its certificate.
fn retry_verification(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    let platform = parts.platform;
    let databases = &platform.databases;
    Swept::of(RetryUseCase::new(
        RetryPorts {
            domain_store: Arc::new(PgRegisteredDomainStore::new(Arc::clone(databases))),
            cross_tenant_domains: Arc::new(PgCrossTenantDomainStore::new(Arc::clone(databases))),
            dns_resolver: Arc::clone(&parts.resolver),
            certificates: CertificateQueue {
                queue: Arc::clone(&parts.jobs),
                attempts: parts.attempts,
            },
            unit_of_work: Arc::clone(&platform.unit_of_work),
        },
        proof_rules(parts),
    ))
}

/// The SAML connections that follow their provider's metadata address,
/// refreshed from it through the platform's metadata reader.
fn refresh_saml_metadata(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    let platform = parts.platform;
    let databases = &platform.databases;
    Swept::of(RefreshMetadataUseCase::new(RefreshMetadataPorts {
        followers: Arc::new(PgMetadataFollowers::new(Arc::clone(databases))),
        connection_store: Arc::new(PgConnectionStore::new(Arc::clone(databases))),
        metadata_reader: Arc::clone(&platform.saml_metadata),
        unit_of_work: Arc::clone(&platform.unit_of_work),
    }))
}
