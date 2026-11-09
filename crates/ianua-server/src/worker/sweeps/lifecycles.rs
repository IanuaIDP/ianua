//! The sweeps that move an account, organization or tenant on when its
//! time comes: erasures, data exports, trials, overdue bills, archived
//! tenants and evaluations past their deadline.

use std::num::NonZeroU32;
use std::sync::Arc;

use ianua_app::ports::identity::{DataExportFiles, DataExportStore, UserStore};
use ianua_app::ports::organization::OrgSessionStore;
use ianua_app::services::authorization::grant_revocation::{GrantRevocation, OrgGrantRevocation};
use ianua_app::use_cases::identity::privacy::{
    BuildExportsPorts, BuildExportsUseCase, ExpireExportsPorts, ExpireExportsUseCase,
    ProcessErasuresPorts, ProcessErasuresUseCase,
};
use ianua_app::use_cases::identity::users::StandingRemoval;
use ianua_app::use_cases::organization::billing::{
    EndLapsedTrialsPorts, EndLapsedTrialsUseCase, SuspendOverdueOrganizationsPorts,
    SuspendOverdueOrganizationsUseCase,
};
use ianua_app::use_cases::organization::privacy::{
    ProcessOrgErasuresPorts, ProcessOrgErasuresUseCase,
};
use ianua_app::use_cases::tenant::lifecycle::{DeleteArchivedPorts, DeleteArchivedUseCase};
use ianua_app::use_cases::workflows::evaluations::{EndOverduePorts, EndOverdueUseCase};
use ianua_app::use_cases::workflows::memories;
use ianua_domain::shared::config::DomainLimits;
use ianua_infra::cache::CacheSignInAttemptCounts;
use ianua_infra::files::{FileDataExportBuilder, FileDataExportFiles, PersonalDataSources};
use ianua_infra::mail::MailedDataExportNotifier;
use ianua_infra::postgres::agents::PgDelegationStore;
use ianua_infra::postgres::audit::PgTenantAuditLogStore;
use ianua_infra::postgres::authentication::{
    PgBreakGlassStore, PgMfaEnrollmentStore, PgPasskeyStore, PgResetRequestStore,
    PgSignInHistoryStore, PgTrustedDeviceStore,
};
use ianua_infra::postgres::authorization::{PgGroupMembershipStore, PgGroupStore, PgRoleStore};
use ianua_infra::postgres::federation::PgFederatedLinkStore;
use ianua_infra::postgres::identity::{
    PgConsentStore, PgDataExportStore, PgErasureRequestStore, PgInvitationStore, PgMetadataStore,
    PgSupportImpersonationStore, PgUserStore,
};
use ianua_infra::postgres::notifications::{
    PgNotificationPreferenceStore, PgTenantNotificationStore,
};
use ianua_infra::postgres::oauth::PgOAuthConsentStore;
use ianua_infra::postgres::organization::{
    PgOrgErasureRequestStore, PgOrgSessionStore, PgOrgSubscriptionStore, PgOrgUserStore,
};
use ianua_infra::postgres::shared::PgSessionStore;
use ianua_infra::postgres::workflows::PgEvaluationStore;

use crate::worker::parts::Parts;
use crate::worker::sweeps::{SweepRun, Swept};

/// How long a payment may stay owed before the organization is suspended.
/// No setting names it; two weeks covers a card renewal and a reminder.
const OVERDUE_GRACE: time::Duration = time::Duration::days(14);

/// The most archived tenants past their grace one round deletes.
const ARCHIVED_BATCH: NonZeroU32 = NonZeroU32::MIN.saturating_add(99);

/// The lifecycle sweeps' runners.
pub(super) fn runners(parts: &Parts<'_>) -> Vec<Arc<dyn SweepRun>> {
    let export_files = data_export_files(parts);
    vec![
        process_erasures(parts, &export_files),
        process_org_erasures(parts),
        build_exports(parts),
        expire_exports(parts, export_files),
        end_lapsed_trials(parts),
        suspend_overdue(parts),
        delete_archived(parts),
        purge_memories(parts),
        end_overdue_evaluations(parts),
    ]
}

/// The evaluations still running past their deadline, ended with every
/// open case not run.
fn end_overdue_evaluations(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    Swept::of(EndOverdueUseCase::new(EndOverduePorts {
        evaluations: Arc::new(PgEvaluationStore::new(Arc::clone(
            &parts.platform.databases,
        ))),
        tenants: Arc::clone(&parts.tenants),
        unit_of_work: Arc::clone(&parts.platform.unit_of_work),
    }))
}

/// The memories past their waiting period, deleted for good with every
/// text they kept.
fn purge_memories(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    let memory = &parts.platform.memory;
    Swept::of(memories::PurgeUseCase::new(memories::PurgePorts {
        memories: Arc::clone(&memory.store),
        due: Arc::clone(&memory.due),
        entries: Arc::clone(&memory.entries),
        unit_of_work: Arc::clone(&parts.platform.unit_of_work),
    }))
}

/// The files of people's data exports, in the platform's file store.
fn data_export_files(parts: &Parts<'_>) -> Arc<dyn DataExportFiles> {
    Arc::new(FileDataExportFiles::new(
        Arc::clone(&parts.platform.files),
        parts.platform.file_links.clone(),
    ))
}

/// The people's data export requests.
fn data_exports(parts: &Parts<'_>) -> Arc<dyn DataExportStore> {
    Arc::new(PgDataExportStore::new(Arc::clone(
        &parts.platform.databases,
    )))
}

/// The tenants' user accounts.
fn users(parts: &Parts<'_>) -> Arc<dyn UserStore> {
    Arc::new(PgUserStore::new(
        Arc::clone(&parts.platform.databases),
        DomainLimits::default(),
    ))
}

/// The members' sessions.
fn org_sessions(parts: &Parts<'_>) -> Arc<dyn OrgSessionStore> {
    Arc::new(PgOrgSessionStore::new(Arc::clone(
        &parts.platform.databases,
    )))
}

/// The revocation of every delegation a person granted.
fn grant_revocation(parts: &Parts<'_>) -> GrantRevocation {
    GrantRevocation::new(Arc::new(PgDelegationStore::new(Arc::clone(
        &parts.platform.databases,
    ))))
}

/// The erasures past their grace, carried out: the account's sessions,
/// delegations and data export files go first, then the account.
fn process_erasures(
    parts: &Parts<'_>,
    export_files: &Arc<dyn DataExportFiles>,
) -> Arc<dyn SweepRun> {
    let platform = parts.platform;
    let databases = &platform.databases;
    Swept::of(ProcessErasuresUseCase::new(ProcessErasuresPorts {
        tenant_store: Arc::clone(&parts.tenants),
        erasure_store: Arc::new(PgErasureRequestStore::new(Arc::clone(databases))),
        user_store: users(parts),
        removal: StandingRemoval {
            session_store: Arc::new(PgSessionStore::new(Arc::clone(databases))),
            grant_revocation: grant_revocation(parts),
            exports: data_exports(parts),
            export_files: Arc::clone(export_files),
        },
        unit_of_work: Arc::clone(&platform.unit_of_work),
    }))
}

/// The members' erasures past their grace, carried out: what they granted
/// in every tenant and their sessions go first, then the account.
fn process_org_erasures(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    let platform = parts.platform;
    let databases = &platform.databases;
    Swept::of(ProcessOrgErasuresUseCase::new(ProcessOrgErasuresPorts {
        erasures: Arc::new(PgOrgErasureRequestStore::new(Arc::clone(databases))),
        org_users: Arc::new(PgOrgUserStore::new(
            Arc::clone(databases),
            DomainLimits::default(),
        )),
        org_sessions: org_sessions(parts),
        grant_revocation: OrgGrantRevocation::new(
            Arc::clone(&parts.tenants),
            grant_revocation(parts),
        ),
        unit_of_work: Arc::clone(&platform.unit_of_work),
    }))
}

/// The data exports asked for, each file written whole and the person
/// mailed that it is ready.
fn build_exports(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    let builder =
        FileDataExportBuilder::new(Arc::clone(&parts.platform.files), personal_data(parts));
    Swept::of(BuildExportsUseCase::new(BuildExportsPorts {
        tenant_store: Arc::clone(&parts.tenants),
        export_store: data_exports(parts),
        builder: Arc::new(builder),
        user_store: users(parts),
        notifier: Arc::new(MailedDataExportNotifier::new(Arc::clone(
            &parts.mail.mailer,
        ))),
    }))
}

/// Every kind of record a person's data export reads.
fn personal_data(parts: &Parts<'_>) -> PersonalDataSources {
    let databases = &parts.platform.databases;
    let db = || Arc::clone(databases);
    PersonalDataSources {
        users: users(parts),
        metadata: Arc::new(PgMetadataStore::new(db())),
        consents: Arc::new(PgConsentStore::new(db())),
        app_grants: Arc::new(PgOAuthConsentStore::new(db())),
        linked_identities: Arc::new(PgFederatedLinkStore::new(db())),
        roles: Arc::new(PgRoleStore::new(db())),
        groups: Arc::new(PgGroupStore::new(db())),
        memberships: Arc::new(PgGroupMembershipStore::new(db())),
        sessions: Arc::new(PgSessionStore::new(db())),
        factors: Arc::new(PgMfaEnrollmentStore::new(db())),
        passkeys: Arc::new(PgPasskeyStore::new(db())),
        devices: Arc::new(PgTrustedDeviceStore::new(db())),
        sign_in_places: Arc::new(PgSignInHistoryStore::new(db())),
        notifications: Arc::new(PgTenantNotificationStore::new(db())),
        notification_choices: Arc::new(PgNotificationPreferenceStore::new(db())),
        impersonations: Arc::new(PgSupportImpersonationStore::new(db())),
        sign_in_counts: Arc::new(CacheSignInAttemptCounts::new(Arc::clone(
            &parts.platform.shared_state,
        ))),
        resets: Arc::new(PgResetRequestStore::new(db())),
        invitations: Arc::new(PgInvitationStore::new(db())),
        break_glass: Arc::new(PgBreakGlassStore::new(db())),
        activity: Arc::new(PgTenantAuditLogStore::new(db(), DomainLimits::default())),
    }
}

/// The data exports past their keeping, their files deleted.
fn expire_exports(parts: &Parts<'_>, export_files: Arc<dyn DataExportFiles>) -> Arc<dyn SweepRun> {
    Swept::of(ExpireExportsUseCase::new(ExpireExportsPorts {
        tenant_store: Arc::clone(&parts.tenants),
        export_store: data_exports(parts),
        files: export_files,
    }))
}

/// The trials that ran out, ended.
fn end_lapsed_trials(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    Swept::of(EndLapsedTrialsUseCase::new(EndLapsedTrialsPorts {
        subscriptions: Arc::new(PgOrgSubscriptionStore::new(Arc::clone(
            &parts.platform.databases,
        ))),
        unit_of_work: Arc::clone(&parts.platform.unit_of_work),
    }))
}

/// The organizations owing a payment past the grace, suspended and their
/// members signed out.
fn suspend_overdue(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    Swept::of(SuspendOverdueOrganizationsUseCase::new(
        SuspendOverdueOrganizationsPorts {
            subscriptions: Arc::new(PgOrgSubscriptionStore::new(Arc::clone(
                &parts.platform.databases,
            ))),
            organizations: Arc::clone(&parts.organizations),
            org_sessions: org_sessions(parts),
            unit_of_work: Arc::clone(&parts.platform.unit_of_work),
        },
        OVERDUE_GRACE,
    ))
}

/// The archived tenants past their grace, deleted, their teardown left to
/// the event the deletion records.
fn delete_archived(parts: &Parts<'_>) -> Arc<dyn SweepRun> {
    Swept::of(DeleteArchivedUseCase::new(
        DeleteArchivedPorts {
            tenant_store: Arc::clone(&parts.tenants),
            org_store: Arc::clone(&parts.organizations),
            unit_of_work: Arc::clone(&parts.platform.unit_of_work),
        },
        ARCHIVED_BATCH,
    ))
}
