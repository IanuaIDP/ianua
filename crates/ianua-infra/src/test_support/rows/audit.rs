//! Rows the audit store tests build from: organizations and their tenants
//! saved through their stores, audit records kept through the trail as a
//! use case's events are, and the exports, streams and verdicts of the
//! audit ports.

use std::sync::Arc;

use ianua_app::auditor::RequestAuditor;
use ianua_app::ports::organization::OrganizationStore;
use ianua_app::ports::tenant::TenantStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::audit::access::AuditLogOf;
use ianua_domain::domains::audit::builder::AuditContext;
use ianua_domain::domains::audit::export::filter::{AuditExportFilter, AuditExportFormat};
use ianua_domain::domains::audit::export::seal::{ExportSeal, FileDigest};
use ianua_domain::domains::audit::export::state::AuditExportState;
use ianua_domain::domains::audit::export::{AuditLogExport, AuditLogExportRow, DOWNLOAD_WINDOW};
use ianua_domain::domains::audit::streaming::{
    SplunkIndex, SplunkTarget, StreamDestination, StreamFilter,
};
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::tenant::audit_streams::{AuditStreamRow, StreamState};
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::test_support::events::sample_login_failed;
use ianua_domain::types::event_type::AuthenticationEvent;
use ianua_domain::types::{
    ActingFor, ActorRef, AgentId, AuditExportId, AuditStreamId, EventType, Label, OperatorId,
    OrganizationId, PublicHttpsUrl, SealedSecret, TenantId, UserId,
};

use crate::crypto::{AuditChainSeals, RootSecret};
use crate::postgres::Databases;
use crate::postgres::audit::PgEventDispatcher;
use crate::postgres::organization::PgOrganizationStore;
use crate::postgres::tenant::PgTenantStore;
use crate::test_support::rows::at;
use crate::test_support::rows::organization::organization_row;
use crate::test_support::rows::tenant::tenant_row;

/// A word no other test's slug holds, for a slug of its own.
fn fresh_key() -> String {
    TenantId::new().as_uuid().simple().to_string()
}

/// An organization saved through its store in `databases`.
///
/// # Panics
///
/// When it cannot be saved, which is a broken test database.
pub async fn saved_organization(databases: &Arc<Databases>) -> OrganizationId {
    let organization =
        Organization::reconstitute(organization_row(&format!("o{}", fresh_key()), "Acme"))
            .expect("a valid organization");
    PgOrganizationStore::new(Arc::clone(databases), DomainLimits::default())
        .save(&organization)
        .await
        .expect("the organization is saved");
    *organization.id()
}

/// A tenant of `organization` saved through its store in `databases`.
///
/// # Panics
///
/// When it cannot be saved, which is a broken test database.
pub async fn saved_tenant_of(
    databases: &Arc<Databases>,
    organization: OrganizationId,
) -> ScopedTenant {
    let tenant = Tenant::reconstitute(tenant_row(organization, &format!("t{}", fresh_key())))
        .expect("a valid tenant");
    PgTenantStore::new(Arc::clone(databases), DomainLimits::default())
        .save(&tenant)
        .await
        .expect("the tenant is saved");
    ScopedTenant::for_background(*tenant.id())
}

/// Keeps `events` as audit records through the trail, as the platform's
/// own work records them.
///
/// # Panics
///
/// When they cannot be kept, which is a broken test database.
pub async fn recorded(databases: &Arc<Databases>, events: Vec<DomainEvent>) {
    recorded_as(databases, events, &AuditContext::system()).await;
}

/// Keeps `events` as audit records through the trail, in `context`.
///
/// # Panics
///
/// When they cannot be kept, which is a broken test database.
pub async fn recorded_as(
    databases: &Arc<Databases>,
    events: Vec<DomainEvent>,
    context: &AuditContext,
) {
    let trail = Arc::new(PgEventDispatcher::new(Arc::clone(databases), chain_heads()));
    RequestAuditor::new(trail, context.clone())
        .dispatch(&events)
        .await
        .expect("the records are kept");
}

/// The seal every test trail and walk puts on chain heads, under a fixed
/// test root.
///
/// # Panics
///
/// Never: the fixed root is 32 bytes of hex.
#[must_use]
pub fn chain_heads() -> AuditChainSeals {
    AuditChainSeals::new(&RootSecret::parse(&"ab".repeat(32)).expect("a 32-byte test root"))
}

/// A failed sign-in in `tenant`, `seconds` after the fixed moment.
#[must_use]
pub fn failed_sign_in(tenant: TenantId, seconds: i64) -> DomainEvent {
    sample_login_failed(tenant, at(seconds))
}

/// A failed sign-in in `tenant`, `seconds` after the fixed moment, made by
/// `agent` acting on its own authority.
#[must_use]
pub fn agent_event(tenant: TenantId, agent: AgentId, seconds: i64) -> DomainEvent {
    failed_sign_in(tenant, seconds).with_actor(ActorRef::Agent {
        id: agent,
        on_behalf_of: ActingFor::Itself,
    })
}

/// An active stream named `name`, made at `seconds` after the fixed moment,
/// sending sign-ins to a Splunk collector with its token sealed.
///
/// # Panics
///
/// When `name` is not a valid label, which is a mistake in the test.
#[must_use]
pub fn stream_row(name: &str, seconds: i64) -> AuditStreamRow {
    let sign_ins = EventType::Authentication(AuthenticationEvent::LoginSucceeded);
    AuditStreamRow {
        id: AuditStreamId::new(),
        name: Label::new("name", name).expect("a valid name"),
        destination: StreamDestination::Splunk(SplunkTarget::new(
            PublicHttpsUrl::new("https://splunk.acme.com:8088/services/collector")
                .expect("a public address"),
            SealedSecret::new("v1.c3BsdW5r").expect("a sealed token"),
            SplunkIndex::TokenDefault,
        )),
        filter: StreamFilter::only(vec![sign_ins]).expect("one event type"),
        state: StreamState::Active,
        created_at: at(seconds),
        updated_at: at(seconds),
    }
}

/// Who asks for an export of `log`: an operator for the platform's, a
/// person for any other.
fn asker_of(log: AuditLogOf) -> ActorRef {
    match log {
        AuditLogOf::Platform => ActorRef::Operator(OperatorId::new()),
        AuditLogOf::Organization(_) | AuditLogOf::Tenant(_) => ActorRef::User(UserId::new()),
    }
}

/// The digest every written test export's file comes to.
///
/// # Panics
///
/// Never: 32 bytes are a SHA-256.
#[must_use]
pub fn file_digest() -> FileDigest {
    FileDigest::from_bytes(&[5; 32]).expect("32 bytes are a SHA-256")
}

/// The seal every written test tenant export carries.
///
/// # Panics
///
/// Never: the text is a compact JWS in shape.
#[must_use]
pub fn export_seal() -> ExportSeal {
    ExportSeal::new("eyJh.eyJi.c2ln").expect("a compact JWS")
}

/// An export of `log` in `state`, written as CSV, asked for `seconds`
/// after the fixed moment, sealed when it is a ready tenant export.
#[must_use]
pub fn export_row(log: AuditLogOf, state: AuditExportState, seconds: i64) -> AuditLogExportRow {
    let sealed =
        matches!(log, AuditLogOf::Tenant(_)) && matches!(state, AuditExportState::Ready { .. });
    AuditLogExportRow {
        id: AuditExportId::new(),
        log,
        requested_by: asker_of(log),
        filter: AuditExportFilter::default(),
        format: AuditExportFormat::Csv,
        state,
        seal: sealed.then(export_seal),
        requested_at: at(seconds),
    }
}

/// An export of `log` the worker is still writing, asked for `seconds`
/// after the fixed moment.
///
/// # Panics
///
/// Never: a pending export always rebuilds.
#[must_use]
pub fn pending_export(log: AuditLogOf, seconds: i64) -> AuditLogExport {
    AuditLogExport::reconstitute(export_row(log, AuditExportState::Pending, seconds))
        .expect("a pending export rebuilds")
}

/// An export of `log` asked for at the fixed moment and written `seconds`
/// later, holding three records, downloadable for its whole window.
///
/// # Panics
///
/// Never: the window is the one every export has.
#[must_use]
pub fn written_export(log: AuditLogOf, seconds: i64) -> AuditLogExport {
    let state = AuditExportState::Ready {
        at: at(seconds),
        available_until: at(seconds).saturating_add(DOWNLOAD_WINDOW),
        rows: 3,
        digest: file_digest(),
    };
    AuditLogExport::reconstitute(export_row(log, state, 0)).expect("a written export rebuilds")
}
