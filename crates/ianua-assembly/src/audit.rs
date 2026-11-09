//! The audit use cases the API serves: the audit log of an organization, of
//! a tenant and of the whole platform, its exports, and the last verdict on
//! a tenant's audit chain.

use std::sync::Arc;

use ianua_app::use_cases::audit::exports::{
    ExportLimits, GetForOrgPorts, GetForOrgUseCase, GetForPlatformPorts, GetForPlatformUseCase,
    GetForTenantPorts, GetForTenantUseCase, RequestForOrgPorts, RequestForOrgUseCase,
    RequestForPlatformPorts, RequestForPlatformUseCase, RequestForTenantPorts,
    RequestForTenantUseCase,
};
use ianua_app::use_cases::audit::{
    ListForOrgPorts, ListForOrgUseCase, ListForPlatformPorts, ListForPlatformUseCase,
    ListForTenantPorts, ListForTenantUseCase, VerifyChainPorts, VerifyChainUseCase,
};

use crate::deps::Adapters;

/// The audit use cases.
#[derive(Clone)]
pub struct AuditState {
    pub list: Arc<ListForOrgUseCase>,
    pub list_for_tenant: Arc<ListForTenantUseCase>,
    pub list_for_platform: Arc<ListForPlatformUseCase>,
    pub exports: ExportsState,
    pub verify_chain: Arc<VerifyChainUseCase>,
}

/// The use cases of audit log exports, one pair per log.
#[derive(Clone)]
pub struct ExportsState {
    pub request_for_org: Arc<RequestForOrgUseCase>,
    pub get_for_org: Arc<GetForOrgUseCase>,
    pub request_for_tenant: Arc<RequestForTenantUseCase>,
    pub get_for_tenant: Arc<GetForTenantUseCase>,
    pub request_for_platform: Arc<RequestForPlatformUseCase>,
    pub get_for_platform: Arc<GetForPlatformUseCase>,
}

/// Builds the audit use cases over `a`, exports bounded by `limits`.
pub fn build(a: &Adapters, limits: ExportLimits) -> AuditState {
    AuditState {
        list: Arc::new(ListForOrgUseCase::new(ListForOrgPorts {
            audit_log: a.org_audit_log_store.clone(),
            org_actors: a.org_actors.clone(),
            tenant_grants: a.org_tenant_grant_store.clone(),
        })),
        list_for_tenant: Arc::new(ListForTenantUseCase::new(ListForTenantPorts {
            audit_log: a.tenant_audit_log_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        list_for_platform: Arc::new(ListForPlatformUseCase::new(ListForPlatformPorts {
            audit_log: a.platform_audit_log_store.clone(),
            operator_authorities: a.operator_authorities.clone(),
        })),
        exports: exports(a, limits),
        verify_chain: Arc::new(VerifyChainUseCase::new(VerifyChainPorts {
            verdicts: a.audit_chain_verdict_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
    }
}

/// Builds the export use cases over `a`, bounded by `limits`.
fn exports(a: &Adapters, limits: ExportLimits) -> ExportsState {
    ExportsState {
        request_for_org: Arc::new(request_for_org(a, limits)),
        get_for_org: Arc::new(GetForOrgUseCase::new(GetForOrgPorts {
            exports: a.audit_export_store.clone(),
            files: a.audit_export_files.clone(),
            org_actors: a.org_actors.clone(),
            tenant_grants: a.org_tenant_grant_store.clone(),
        })),
        request_for_tenant: Arc::new(RequestForTenantUseCase::new(
            RequestForTenantPorts {
                exports: a.audit_export_store.clone(),
                jobs: a.job_queue.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
                guard: crate::workflows::change_guard(a),
            },
            limits,
        )),
        get_for_tenant: Arc::new(GetForTenantUseCase::new(GetForTenantPorts {
            exports: a.audit_export_store.clone(),
            files: a.audit_export_files.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        request_for_platform: Arc::new(request_for_platform(a, limits)),
        get_for_platform: Arc::new(GetForPlatformUseCase::new(GetForPlatformPorts {
            exports: a.audit_export_store.clone(),
            files: a.audit_export_files.clone(),
            operator_authorities: a.operator_authorities.clone(),
        })),
    }
}

/// Queues an organization export after resolving its member's authority.
fn request_for_org(a: &Adapters, limits: ExportLimits) -> RequestForOrgUseCase {
    RequestForOrgUseCase::new(
        RequestForOrgPorts {
            exports: a.audit_export_store.clone(),
            jobs: a.job_queue.clone(),
            org_actors: a.org_actors.clone(),
            tenant_grants: a.org_tenant_grant_store.clone(),
        },
        limits,
    )
}

/// Queues a platform export under the operator's authority and export limits.
fn request_for_platform(a: &Adapters, limits: ExportLimits) -> RequestForPlatformUseCase {
    RequestForPlatformUseCase::new(
        RequestForPlatformPorts {
            exports: a.audit_export_store.clone(),
            jobs: a.job_queue.clone(),
            operator_authorities: a.operator_authorities.clone(),
        },
        limits,
    )
}
