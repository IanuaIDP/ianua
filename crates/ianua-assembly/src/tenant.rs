//! The tenant use cases the API serves: a tenant's life (provisioning,
//! suspension, archival, restoration, deletion), its overview, its
//! settings (general, sign-in, mTLS, hostnames, compliance, break-glass,
//! environment), copies of its setup into another tenant, and the streams
//! of its audit records to a SIEM.

use std::num::NonZeroU32;
use std::sync::Arc;

use ianua_app::use_cases::tenant::lifecycle::{
    ActivateTenantPorts, ActivateTenantUseCase, ArchiveTenantPorts, ArchiveTenantUseCase,
    DeleteTenantEarlyPorts, DeleteTenantEarlyUseCase, DeleteTenantPorts, DeleteTenantUseCase,
    GetTenantLabelPorts, GetTenantLabelUseCase, GetTenantMetricsPorts, GetTenantMetricsUseCase,
    GetTenantPorts, GetTenantUseCase, ListTenantsPorts, ListTenantsUseCase, ProvisionTenantPorts,
    ProvisionTenantUseCase, ReactivateTenantPorts, ReactivateTenantUseCase, RestoreTenantPorts,
    RestoreTenantUseCase, SuspendTenantPorts, SuspendTenantUseCase,
};
use ianua_app::use_cases::tenant::settings::{
    ChangeBreakGlassPolicyPorts, ChangeBreakGlassPolicyUseCase, ChangeCompliancePorts,
    ChangeComplianceUseCase, ChangeEnvironmentPorts, ChangeEnvironmentUseCase, GetAuthConfigPorts,
    GetAuthConfigUseCase, GetCompliancePorts, GetComplianceUseCase, GetHostnameConfigPorts,
    GetHostnameConfigUseCase, GetMtlsConfigPorts, GetMtlsConfigUseCase, UpdateAuthConfigPorts,
    UpdateAuthConfigUseCase, UpdateMtlsConfigPorts, UpdateMtlsConfigUseCase, UpdatePorts,
    UpdateUseCase,
};
use ianua_app::use_cases::tenant::{audit_streams, clones};
use ianua_domain::domains::tenant::hosts::PlatformAddressing;
use ianua_domain::domains::tenant::provisioning::infrastructure::DeploymentRegion;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::types::{DomainName, HttpsUrl};

use crate::deps::{Adapters, Settings};

/// The tenant use cases, and the deployment facts their answers name.
#[derive(Clone)]
pub struct TenantState {
    /// A tenant's life.
    pub lifecycle: LifecycleUseCases,
    pub settings: SettingsUseCases,
    pub clones: CloneUseCases,
    pub audit_streams: AuditStreamUseCases,
    /// Where the platform's pages live, for each tenant's sign-in link.
    pub app_base_url: HttpsUrl,
    /// The domain each tenant's platform subdomains sit under.
    pub base_domain: DomainName,
    /// The certificate-backed platform address shape.
    pub platform_addressing: PlatformAddressing,
    /// Lengths and counts a tenant's names are checked against.
    pub domain_limits: DomainLimits,
    /// The region a tenant lands in when its provisioning names none.
    pub default_region: DeploymentRegion,
}

/// A tenant's life, and its overview.
#[derive(Clone)]
pub struct LifecycleUseCases {
    /// Makes a new tenant for an organization.
    pub provision: Arc<ProvisionTenantUseCase>,
    pub list: Arc<ListTenantsUseCase>,
    pub get: Arc<GetTenantUseCase>,
    pub activate: Arc<ActivateTenantUseCase>,
    pub suspend: Arc<SuspendTenantUseCase>,
    pub reactivate: Arc<ReactivateTenantUseCase>,
    pub archive: Arc<ArchiveTenantUseCase>,
    pub restore: Arc<RestoreTenantUseCase>,
    pub delete: Arc<DeleteTenantUseCase>,
    pub delete_early: Arc<DeleteTenantEarlyUseCase>,
    pub label: Arc<GetTenantLabelUseCase>,
    pub metrics: Arc<GetTenantMetricsUseCase>,
}

/// A tenant's settings.
#[derive(Clone)]
pub struct SettingsUseCases {
    pub update: Arc<UpdateUseCase>,
    pub get_auth_config: Arc<GetAuthConfigUseCase>,
    pub update_auth_config: Arc<UpdateAuthConfigUseCase>,
    pub get_mtls: Arc<GetMtlsConfigUseCase>,
    pub update_mtls: Arc<UpdateMtlsConfigUseCase>,
    pub get_hostnames: Arc<GetHostnameConfigUseCase>,
    pub get_compliance: Arc<GetComplianceUseCase>,
    pub change_compliance: Arc<ChangeComplianceUseCase>,
    pub change_break_glass: Arc<ChangeBreakGlassPolicyUseCase>,
    pub change_environment: Arc<ChangeEnvironmentUseCase>,
}

/// Copies of one tenant's setup into another of its organization.
#[derive(Clone)]
pub struct CloneUseCases {
    pub start: Arc<clones::StartUseCase>,
    pub get: Arc<clones::GetUseCase>,
}

/// The streams of a tenant's audit records to its SIEM.
#[derive(Clone)]
pub struct AuditStreamUseCases {
    pub create: Arc<audit_streams::CreateUseCase>,
    pub list: Arc<audit_streams::ListUseCase>,
    pub reconfigure: Arc<audit_streams::ReconfigureUseCase>,
    pub pause: Arc<audit_streams::PauseUseCase>,
    pub resume: Arc<audit_streams::ResumeUseCase>,
    pub remove: Arc<audit_streams::RemoveUseCase>,
}

/// Builds the tenant use cases over `a`, under the deployment's `s`.
pub fn build(a: &Adapters, s: &Settings) -> TenantState {
    TenantState {
        lifecycle: lifecycle(a, s),
        settings: settings(a, s),
        clones: clone_use_cases(a),
        audit_streams: audit_stream_use_cases(a),
        app_base_url: s.app_base_url.clone(),
        base_domain: s.base_domain.clone(),
        platform_addressing: s.platform_addressing,
        domain_limits: s.domain_limits.clone(),
        default_region: s.compliance_limits.default_region(),
    }
}

/// The use cases that provision, move through its life and remove a
/// tenant, and read its overview.
fn lifecycle(a: &Adapters, s: &Settings) -> LifecycleUseCases {
    LifecycleUseCases {
        provision: Arc::new(provision(a, s)),
        list: Arc::new(list(a)),
        get: Arc::new(get(a)),
        activate: Arc::new(ActivateTenantUseCase::new(ActivateTenantPorts {
            tenant_store: a.tenant_store.clone(),
            operator_authorities: a.operator_authorities.clone(),
        })),
        suspend: Arc::new(suspend(a)),
        reactivate: Arc::new(reactivate(a)),
        archive: Arc::new(archive(a)),
        restore: Arc::new(restore(a)),
        delete: Arc::new(delete(a)),
        delete_early: Arc::new(delete_early(a)),
        label: Arc::new(GetTenantLabelUseCase::new(GetTenantLabelPorts {
            tenant_store: a.tenant_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        metrics: Arc::new(GetTenantMetricsUseCase::new(GetTenantMetricsPorts {
            reader: a.tenant_metrics_reader.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
    }
}

/// Provisions tenants with organization limits and the configured deployment policy.
fn provision(a: &Adapters, s: &Settings) -> ProvisionTenantUseCase {
    ProvisionTenantUseCase::new(
        s.compliance_limits.clone(),
        ProvisionTenantPorts {
            random: a.secure_random.clone(),
            tenant_store: a.tenant_store.clone(),
            org_store: a.organization_store.clone(),
            limit_enforcer: a.limit_enforcer.clone(),
            org_actors: a.org_actors.clone(),
            operator_authorities: a.operator_authorities.clone(),
        },
    )
}

/// Lists tenants together with setup progress under organization or operator authority.
fn list(a: &Adapters) -> ListTenantsUseCase {
    ListTenantsUseCase::new(ListTenantsPorts {
        tenant_store: a.tenant_store.clone(),
        setup_store: a.tenant_setup_store.clone(),
        org_actors: a.org_actors.clone(),
        operator_authorities: a.operator_authorities.clone(),
    })
}

/// Reads a tenant and its setup through tenant, organization or operator authority.
fn get(a: &Adapters) -> GetTenantUseCase {
    GetTenantUseCase::new(GetTenantPorts {
        tenant_store: a.tenant_store.clone(),
        setup_store: a.tenant_setup_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        org_actors: a.org_actors.clone(),
        operator_authorities: a.operator_authorities.clone(),
    })
}

/// Suspends a tenant with access to its sessions and the governing authorities.
fn suspend(a: &Adapters) -> SuspendTenantUseCase {
    SuspendTenantUseCase::new(SuspendTenantPorts {
        tenant_store: a.tenant_store.clone(),
        session_store: a.session_store.clone(),
        org_actors: a.org_actors.clone(),
        operator_authorities: a.operator_authorities.clone(),
    })
}

/// Reactivates a suspended tenant under organization or operator authority.
fn reactivate(a: &Adapters) -> ReactivateTenantUseCase {
    ReactivateTenantUseCase::new(ReactivateTenantPorts {
        tenant_store: a.tenant_store.clone(),
        org_actors: a.org_actors.clone(),
        operator_authorities: a.operator_authorities.clone(),
    })
}

/// Archives a tenant with access to the sessions affected by its lifecycle change.
fn archive(a: &Adapters) -> ArchiveTenantUseCase {
    ArchiveTenantUseCase::new(ArchiveTenantPorts {
        tenant_store: a.tenant_store.clone(),
        session_store: a.session_store.clone(),
        org_actors: a.org_actors.clone(),
        operator_authorities: a.operator_authorities.clone(),
    })
}

/// Restores an archived tenant under organization or operator authority.
fn restore(a: &Adapters) -> RestoreTenantUseCase {
    RestoreTenantUseCase::new(RestoreTenantPorts {
        tenant_store: a.tenant_store.clone(),
        org_actors: a.org_actors.clone(),
        operator_authorities: a.operator_authorities.clone(),
    })
}

/// Deletes tenants with their organization records and governing authorities.
fn delete(a: &Adapters) -> DeleteTenantUseCase {
    DeleteTenantUseCase::new(DeleteTenantPorts {
        tenant_store: a.tenant_store.clone(),
        org_store: a.organization_store.clone(),
        org_actors: a.org_actors.clone(),
        operator_authorities: a.operator_authorities.clone(),
    })
}

/// Restricts early deletion to the platform's operator authority.
fn delete_early(a: &Adapters) -> DeleteTenantEarlyUseCase {
    DeleteTenantEarlyUseCase::new(DeleteTenantEarlyPorts {
        tenant_store: a.tenant_store.clone(),
        org_store: a.organization_store.clone(),
        operator_authorities: a.operator_authorities.clone(),
    })
}

/// The use cases that read and change a tenant's settings: sign-in, mTLS,
/// hostnames, compliance and break-glass.
fn settings(a: &Adapters, s: &Settings) -> SettingsUseCases {
    SettingsUseCases {
        update: Arc::new(update(a, s)),
        get_auth_config: Arc::new(GetAuthConfigUseCase::new(GetAuthConfigPorts {
            tenant_store: a.tenant_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        update_auth_config: Arc::new(update_auth_config(a)),
        get_mtls: Arc::new(GetMtlsConfigUseCase::new(GetMtlsConfigPorts {
            tenant_store: a.tenant_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        update_mtls: Arc::new(update_mtls(a)),
        get_hostnames: Arc::new(get_hostnames(a)),
        get_compliance: Arc::new(GetComplianceUseCase::new(GetCompliancePorts {
            tenant_store: a.tenant_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        change_compliance: Arc::new(change_compliance(a, s)),
        change_break_glass: Arc::new(change_break_glass(a)),
        change_environment: Arc::new(ChangeEnvironmentUseCase::new(ChangeEnvironmentPorts {
            tenant_store: a.tenant_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
    }
}

/// Changes tenant settings against registered domains and platform addressing.
fn update(a: &Adapters, s: &Settings) -> UpdateUseCase {
    UpdateUseCase::new(
        UpdatePorts {
            tenant_store: a.tenant_store.clone(),
            domains: a.registered_domain_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        },
        s.platform_addressing,
    )
}

/// Changes sign-in policy with fresh proofs and messaging readiness checks.
fn update_auth_config(a: &Adapters) -> UpdateAuthConfigUseCase {
    UpdateAuthConfigUseCase::new(UpdateAuthConfigPorts {
        tenant_store: a.tenant_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        fresh_proofs: a.fresh_proofs.clone(),
        org_users: a.org_user_store.clone(),
        organizations: a.organization_store.clone(),
        text_messaging: a.text_messaging.clone(),
        mail: a.mail_setup.clone(),
    })
}

/// Changes mTLS settings with certificate validation and fresh authorization proofs.
fn update_mtls(a: &Adapters) -> UpdateMtlsConfigUseCase {
    UpdateMtlsConfigUseCase::new(UpdateMtlsConfigPorts {
        tenant_store: a.tenant_store.clone(),
        cert_validator: a.cert_pem_validator.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        fresh_proofs: a.fresh_proofs.clone(),
        org_users: a.org_user_store.clone(),
        organizations: a.organization_store.clone(),
    })
}

/// Reads hostname settings together with the owning organization's configuration.
fn get_hostnames(a: &Adapters) -> GetHostnameConfigUseCase {
    GetHostnameConfigUseCase::new(GetHostnameConfigPorts {
        tenant_store: a.tenant_store.clone(),
        organization_store: a.organization_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Applies deployment compliance limits to changes authorized by fresh proofs.
fn change_compliance(a: &Adapters, s: &Settings) -> ChangeComplianceUseCase {
    ChangeComplianceUseCase::new(
        s.compliance_limits.clone(),
        ChangeCompliancePorts {
            tenant_store: a.tenant_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
            fresh_proofs: a.fresh_proofs.clone(),
            org_users: a.org_user_store.clone(),
            organizations: a.organization_store.clone(),
        },
    )
}

/// Changes emergency-access policy through the tenant's authority checks.
fn change_break_glass(a: &Adapters) -> ChangeBreakGlassPolicyUseCase {
    ChangeBreakGlassPolicyUseCase::new(ChangeBreakGlassPolicyPorts {
        break_glass_store: a.break_glass_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Tries a clone's copy job gets. Each starts at the first part not yet
/// copied, and the reconciliation sweep queues it again after that.
const CLONE_TRIES: NonZeroU32 = match NonZeroU32::new(5) {
    Some(tries) => tries,
    None => NonZeroU32::MIN,
};

/// The use cases that start a copy of one tenant's setup into another and
/// follow it.
fn clone_use_cases(a: &Adapters) -> CloneUseCases {
    CloneUseCases {
        start: Arc::new(clones::StartUseCase::new(clones::StartPorts {
            tenant_store: a.tenant_store.clone(),
            clone_store: a.tenant_clone_store.clone(),
            org_actors: a.org_actors.clone(),
            operator_authorities: a.operator_authorities.clone(),
            runs: clones::CloneRuns {
                queue: a.job_queue.clone(),
                attempts: CLONE_TRIES,
            },
        })),
        get: Arc::new(clones::GetUseCase::new(clones::GetPorts {
            tenant_store: a.tenant_store.clone(),
            clone_store: a.tenant_clone_store.clone(),
            org_actors: a.org_actors.clone(),
            operator_authorities: a.operator_authorities.clone(),
        })),
    }
}

/// The use cases that add, list, change, pause, resume and remove a
/// tenant's audit streams.
fn audit_stream_use_cases(a: &Adapters) -> AuditStreamUseCases {
    AuditStreamUseCases {
        create: Arc::new(create_audit_stream(a)),
        list: Arc::new(audit_streams::ListUseCase::new(audit_streams::ListPorts {
            stream_store: a.audit_stream_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        reconfigure: Arc::new(reconfigure_audit_stream(a)),
        pause: Arc::new(audit_streams::PauseUseCase::new(
            audit_streams::PausePorts {
                tenant_store: a.tenant_store.clone(),
                stream_store: a.audit_stream_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        resume: Arc::new(audit_streams::ResumeUseCase::new(
            audit_streams::ResumePorts {
                tenant_store: a.tenant_store.clone(),
                stream_store: a.audit_stream_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        remove: Arc::new(audit_streams::RemoveUseCase::new(
            audit_streams::RemovePorts {
                tenant_store: a.tenant_store.clone(),
                stream_store: a.audit_stream_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
    }
}

/// Creates encrypted audit streams with plan limits and fresh authority proofs.
fn create_audit_stream(a: &Adapters) -> audit_streams::CreateUseCase {
    audit_streams::CreateUseCase::new(audit_streams::CreatePorts {
        tenant_store: a.tenant_store.clone(),
        stream_store: a.audit_stream_store.clone(),
        encryptor: a.secret_encryptor.clone(),
        limit_enforcer: a.limit_enforcer.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        fresh_proofs: a.fresh_proofs.clone(),
        org_users: a.org_user_store.clone(),
        organizations: a.organization_store.clone(),
    })
}

/// Reconfigures encrypted audit streams under fresh tenant authority proofs.
fn reconfigure_audit_stream(a: &Adapters) -> audit_streams::ReconfigureUseCase {
    audit_streams::ReconfigureUseCase::new(audit_streams::ReconfigurePorts {
        tenant_store: a.tenant_store.clone(),
        stream_store: a.audit_stream_store.clone(),
        encryptor: a.secret_encryptor.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        fresh_proofs: a.fresh_proofs.clone(),
        org_users: a.org_user_store.clone(),
        organizations: a.organization_store.clone(),
    })
}
