//! Live stream handlers: each admits the caller through one of the app's
//! use cases, then upgrades to a WebSocket that forwards what is published
//! for them.

use axum::extract::{Path, State};
use axum::response::Response;
use ianua_app::ports::realtime::{PLATFORM_DASHBOARD_SUBJECT, org_setup_subject, setup_subject};
use ianua_app::use_case::Query as _;
use ianua_app::use_cases::notifications::NotificationReader;
use ianua_app::use_cases::tenant::lifecycle::{TenantLister, TenantViewer};
use ianua_assembly::realtime::RealtimeState;

use crate::dto::realtime::followed_tenants;
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::{Operator, OrgMember, TenantCaller};
use crate::extractors::paths::realtime::ProvisioningPath;
use crate::extractors::realtime::Handshake;
use crate::state::StreamGates;
use crate::state::streams::RealtimeStreamState;
use crate::ws::{
    Admission, FeedWatch, InboxWatch, SubjectSubscription, TenantWatch, TenantsWatch, stream_inbox,
    stream_subject,
};

#[utoipa::path(
    get,
    path = "/api/v1/ws/notifications",
    tag = "Real-time",
    responses(
        (status = 101, description = "WebSocket upgrade: live operator notification stream"),
        (status = 400, description = "Not a WebSocket handshake"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 429, description = "Too many open streams", body = ErrorBody)
    )
)]
/// Operator notification stream (WebSocket)
///
/// Upgrades to a WebSocket and streams the calling operator's notifications
/// as they are sent: one JSON frame per notification, the same items as the
/// platform inbox. The connection stays open until the client closes it.
/// Requires an operator's own key that still counts.
pub(crate) async fn platform_ws(
    State(realtime): State<RealtimeState>,
    State(gates): State<StreamGates>,
    operator: Operator,
    handshake: Handshake,
) -> Result<Response, ApiError> {
    let operator_id = *operator.caller.operator();
    let reader = NotificationReader::Operator(operator.caller);
    let stream = realtime.open_inbox.execute(&reader, ()).await?;
    let permit = gates.streams.claim(*operator_id.as_uuid())?;
    let admission = Admission::everything(FeedWatch::new(&stream, reader));
    let timing = gates.timing;
    Ok(handshake.accept(move |socket| async move {
        let _permit = permit;
        stream_inbox(socket, stream, admission, timing).await;
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/ws/dashboard",
    tag = "Real-time",
    responses(
        (status = 101, description = "WebSocket upgrade: live platform security dashboard"),
        (status = 400, description = "Not a WebSocket handshake"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 429, description = "Too many open streams", body = ErrorBody)
    )
)]
/// Platform security dashboard (WebSocket)
///
/// Upgrades to a WebSocket for the live platform security dashboard, which
/// streams what happens across the deployment. On connect the server sends
/// a `{ "type": "connected", "subject" }` frame, then one JSON frame per
/// update. Every operator sees it. Requires an operator's own key that
/// still counts.
pub(crate) async fn platform_dashboard(
    State(realtime): State<RealtimeState>,
    State(gates): State<StreamGates>,
    operator: Operator,
    handshake: Handshake,
) -> Result<Response, ApiError> {
    let operator_id = *operator.caller.operator();
    let reader = NotificationReader::Operator(operator.caller);
    realtime.inbox.execute(&reader, ()).await?;
    let permit = gates.streams.claim(*operator_id.as_uuid())?;
    let admission = Admission::everything(InboxWatch::new(realtime.inbox, reader));
    let (live, timing) = (realtime.live, gates.timing);
    Ok(handshake.accept(move |socket| async move {
        let _permit = permit;
        let subject = PLATFORM_DASHBOARD_SUBJECT.to_owned();
        let subscription = SubjectSubscription::new(live, subject);
        stream_subject(socket, subscription, admission, timing).await;
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/ws/notifications",
    tag = "Real-time",
    responses(
        (status = 101, description = "WebSocket upgrade: live organization notification stream"),
        (status = 400, description = "Not a WebSocket handshake"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such organization", body = ErrorBody),
        (status = 429, description = "Too many open streams", body = ErrorBody)
    )
)]
/// Organization member notification stream (WebSocket)
///
/// Upgrades to a WebSocket and streams the calling member's notifications
/// in their organization as they are sent: one JSON frame per notification.
/// Requires a member's own session or organization API key that still
/// counts.
pub(crate) async fn org_ws(
    State(realtime): State<RealtimeState>,
    State(gates): State<StreamGates>,
    member: OrgMember,
    handshake: Handshake,
) -> Result<Response, ApiError> {
    let member_id = *member.caller.member();
    let reader = NotificationReader::Member(member.caller);
    let stream = realtime.open_inbox.execute(&reader, ()).await?;
    let permit = gates.streams.claim(*member_id.as_uuid())?;
    let admission = Admission::everything(FeedWatch::new(&stream, reader));
    let timing = gates.timing;
    Ok(handshake.accept(move |socket| async move {
        let _permit = permit;
        stream_inbox(socket, stream, admission, timing).await;
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/ws/notifications",
    tag = "Real-time",
    responses(
        (status = 101, description = "WebSocket upgrade: live tenant user notification stream"),
        (status = 400, description = "Not a WebSocket handshake"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 429, description = "Too many open streams", body = ErrorBody)
    )
)]
/// Tenant user notification stream (WebSocket)
///
/// Upgrades to a WebSocket and streams the calling user's notifications in
/// the tenant as they are sent: one JSON frame per notification, the same
/// items as the tenant inbox. Only notifications whose category the user
/// may see when the stream opens are sent, and any other update is held
/// back; after a new role the dashboard connects again to see more. The
/// stream asks again from time to time what the user may still see: a
/// category whose right they lost stops, and the stream closes (`1008`)
/// once no category is left or on the first refusal. An organization
/// member reads their notifications in the organization, so is `403` here.
/// Requires a tenant user's own session or key.
pub(crate) async fn tenant_ws(
    State(realtime): State<RealtimeState>,
    State(gates): State<StreamGates>,
    tenant: TenantCaller,
    handshake: Handshake,
) -> Result<Response, ApiError> {
    let who = *tenant.caller.identity();
    let reader = NotificationReader::Tenant(tenant.caller);
    let stream = realtime.open_inbox.execute(&reader, ()).await?;
    let permit = gates.streams.claim_for(&who)?;
    let admission = Admission::everything(FeedWatch::new(&stream, reader));
    let timing = gates.timing;
    Ok(handshake.accept(move |socket| async move {
        let _permit = permit;
        stream_inbox(socket, stream, admission, timing).await;
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/ws/workflows",
    tag = "Real-time",
    responses(
        (status = 101, description = "WebSocket upgrade: live progress of every provisioning run the caller can see"),
        (status = 400, description = "Not a WebSocket handshake"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such organization", body = ErrorBody),
        (status = 429, description = "Too many open streams", body = ErrorBody)
    )
)]
/// Organization-wide provisioning progress stream (WebSocket)
///
/// Upgrades to a WebSocket and streams the progress of every tenant
/// provisioning run the member can see, so one connection drives a whole
/// list of tenants; each frame names its `reference_id`. On connect the
/// server sends a `{ "type": "connected", "subject" }` frame. The tenants
/// followed are the ones the member sees when they connect (every tenant
/// of the organization, or those granted to them), up to 100; a tenant
/// added later appears on reconnect. Requires a member's own session or
/// organization API key.
pub(crate) async fn org_workflows_ws(
    State(realtime): State<RealtimeState>,
    State(gates): State<StreamGates>,
    member: OrgMember,
    handshake: Handshake,
) -> Result<Response, ApiError> {
    let organization_id = member.caller.organization_id();
    let member_id = *member.caller.member();
    let lister = TenantLister::Member(member.caller);
    let seen = realtime
        .tenants
        .execute(&lister, followed_tenants())
        .await?;
    let admission = Admission::setups_of(&seen, TenantsWatch::new(realtime.tenants, lister));
    let permit = gates.streams.claim(*member_id.as_uuid())?;
    let (live, timing) = (realtime.live, gates.timing);
    Ok(handshake.accept(move |socket| async move {
        let _permit = permit;
        let subject = org_setup_subject(&organization_id);
        let subscription = SubjectSubscription::new(live, subject);
        stream_subject(socket, subscription, admission, timing).await;
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/ws/workflow/{reference_id}",
    tag = "Real-time",
    responses(
        (status = 101, description = "WebSocket upgrade: live progress of one tenant's provisioning"),
        (status = 400, description = "Not a WebSocket handshake"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant in the organization", body = ErrorBody),
        (status = 429, description = "Too many open streams", body = ErrorBody)
    )
)]
/// Provisioning progress stream (WebSocket)
///
/// Upgrades to a WebSocket and streams live progress of the provisioning
/// run for the tenant named by `{reference_id}`: stage changes, completion
/// and errors. On connect the server sends a `{ "type": "connected",
/// "subject" }` frame, then one JSON frame per update. Requires a member
/// who may view the organization's tenants; `404` for a tenant of another
/// organization.
pub(crate) async fn workflow_progress_ws(
    State(RealtimeStreamState { realtime, gates }): State<RealtimeStreamState>,
    member: OrgMember,
    Path(path): Path<ProvisioningPath>,
    handshake: Handshake,
) -> Result<Response, ApiError> {
    let organization_id = member.caller.organization_id();
    let member_id = *member.caller.member();
    let tenant_id = path.tenant();
    let viewer = TenantViewer::Organization {
        caller: member.caller,
        tenant_id,
    };
    realtime.tenant.execute(&viewer, ()).await?;
    let permit = gates.streams.claim(*member_id.as_uuid())?;
    let admission = Admission::everything(TenantWatch::new(realtime.tenant, viewer));
    let (live, timing) = (realtime.live, gates.timing);
    Ok(handshake.accept(move |socket| async move {
        let _permit = permit;
        let subject = setup_subject(&organization_id, &tenant_id);
        let subscription = SubjectSubscription::new(live, subject);
        stream_subject(socket, subscription, admission, timing).await;
    }))
}
