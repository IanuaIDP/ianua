//! The sweeps that end what was only ever given for a while: access
//! reviews, access requests, holdings, invitations, organization offers,
//! device codes and API keys.

use std::sync::Arc;

use ianua_app::ports::shared::AuditLabelResolver;
use ianua_app::use_cases::authorization::{access_requests, access_reviews, holdings};
use ianua_app::use_cases::identity::invitations;
use ianua_app::use_cases::oauth::api_keys;
use ianua_app::use_cases::oauth::flows::{
    ExpireDeviceAuthorizationsPorts, ExpireDeviceAuthorizationsUseCase,
};
use ianua_app::use_cases::organization::invitations::{LapseOrgPorts, LapseOrgUseCase};
use ianua_domain::shared::config::DomainLimits;
use ianua_infra::postgres::authorization::{
    PgAccessRequestStore, PgAccessReviewStore, PgGroupMembershipStore, PgGroupStore,
    PgRoleAssignmentStore, PgRoleStore,
};
use ianua_infra::postgres::identity::{PgInvitationStore, PgUserStore};
use ianua_infra::postgres::oauth::{PgCrossTenantApiKeyStore, PgDeviceAuthStore};
use ianua_infra::postgres::organization::{PgOrgInvitationStore, PgOrgUserStore};
use ianua_infra::postgres::shared::PgAuditLabelResolver;

use crate::worker::parts::Parts;
use crate::worker::sweeps::{SweepRun, Swept};

/// The expiry sweeps' runners.
pub(super) fn runners(parts: &Parts<'_>) -> Vec<Arc<dyn SweepRun>> {
    vec![
        overdue_reviews(parts),
        requests(parts),
        held(parts),
        tenant_invitations(parts),
        org_invitations(parts),
        device_authorizations(parts),
        expired_keys(parts),
    ]
}

/// The labels the records of the tenants' access are written with.
fn labels(parts: &Parts<'_>) -> Arc<dyn AuditLabelResolver> {
    Arc::new(PgAuditLabelResolver::new(Arc::clone(
        &parts.platform.databases,
    )))
}

/// The access reviews past their deadline, completed as they stand.
fn overdue_reviews(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    let platform = parts.platform;
    let databases = &platform.databases;
    Swept::of(access_reviews::CompleteOverdueUseCase::new(
        access_reviews::CompleteOverduePorts {
            tenant_store: Arc::clone(&parts.tenants),
            review_store: Arc::new(PgAccessReviewStore::new(Arc::clone(databases))),
            access_records: Arc::clone(&platform.access_records),
            assignment_store: Arc::new(PgRoleAssignmentStore::new(Arc::clone(databases))),
            membership_store: Arc::new(PgGroupMembershipStore::new(Arc::clone(databases))),
            role_store: Arc::new(PgRoleStore::new(Arc::clone(databases))),
            group_store: Arc::new(PgGroupStore::new(Arc::clone(databases))),
            audit_label_resolver: labels(parts),
            unit_of_work: Arc::clone(&platform.unit_of_work),
        },
    ))
}

/// The access requests nobody answered in time, expired.
fn requests(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    let platform = parts.platform;
    Swept::of(access_requests::ExpireUseCase::new(
        access_requests::ExpirePorts {
            tenant_store: Arc::clone(&parts.tenants),
            request_store: Arc::new(PgAccessRequestStore::new(Arc::clone(&platform.databases))),
            unit_of_work: Arc::clone(&platform.unit_of_work),
        },
    ))
}

/// The roles and group memberships given for a while, taken back once
/// their time is up.
fn held(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    let platform = parts.platform;
    let databases = &platform.databases;
    Swept::of(holdings::ExpireUseCase::new(holdings::ExpirePorts {
        tenant_store: Arc::clone(&parts.tenants),
        assignment_store: Arc::new(PgRoleAssignmentStore::new(Arc::clone(databases))),
        membership_store: Arc::new(PgGroupMembershipStore::new(Arc::clone(databases))),
        role_store: Arc::new(PgRoleStore::new(Arc::clone(databases))),
        group_store: Arc::new(PgGroupStore::new(Arc::clone(databases))),
        audit_label_resolver: labels(parts),
        unit_of_work: Arc::clone(&platform.unit_of_work),
    }))
}

/// The tenants' invitations whose link ran out, expired.
fn tenant_invitations(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    let platform = parts.platform;
    let databases = &platform.databases;
    Swept::of(invitations::ExpireUseCase::new(invitations::ExpirePorts {
        tenant_store: Arc::clone(&parts.tenants),
        invitation_store: Arc::new(PgInvitationStore::new(Arc::clone(databases))),
        user_store: Arc::new(PgUserStore::new(
            Arc::clone(databases),
            DomainLimits::default(),
        )),
        unit_of_work: Arc::clone(&platform.unit_of_work),
    }))
}

/// The organizations' invitations whose link ran out, lapsed.
fn org_invitations(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    let databases = &parts.platform.databases;
    Swept::of(LapseOrgUseCase::new(LapseOrgPorts {
        org_invitation_store: Arc::new(PgOrgInvitationStore::new(Arc::clone(databases))),
        org_user_store: Arc::new(PgOrgUserStore::new(
            Arc::clone(databases),
            DomainLimits::default(),
        )),
        unit_of_work: Arc::clone(&parts.platform.unit_of_work),
    }))
}

/// The device sign-ins nobody approved in time, expired.
fn device_authorizations(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    let platform = parts.platform;
    let databases = &platform.databases;
    let codes = &platform.digests.codes;
    let encryptor = &platform.secrets.encryptor;
    Swept::of(ExpireDeviceAuthorizationsUseCase::new(
        ExpireDeviceAuthorizationsPorts {
            device_auth_store: Arc::new(PgDeviceAuthStore::new(
                Arc::clone(databases),
                Arc::clone(codes) as _,
                Arc::clone(encryptor) as _,
            )),
            tenant_store: Arc::clone(&parts.tenants),
        },
    ))
}

/// The API keys past their expiry, removed.
fn expired_keys(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    let platform = parts.platform;
    Swept::of(api_keys::ExpireUseCase::new(api_keys::ExpirePorts {
        key_store: Arc::new(PgCrossTenantApiKeyStore::new(Arc::clone(
            &platform.databases,
        ))),
        unit_of_work: Arc::clone(&platform.unit_of_work),
    }))
}
