//! Who sent a request, and where they act.
//!
//! The auth middleware turns a bearer token into the app's
//! [`ResolvedCaller`]. These extractors take it from there: they find the
//! organization and tenant the path names, check that the credential belongs
//! to them, and hand the handler the app's caller and an auditor for the
//! request. They check no permission, role or plan limit: what the caller
//! may do is the app's question, asked from the stored records.
//!
//! A credential only ever acts in its own plane:
//! - a tenant user's session or key, and an operator acting as a user
//!   through an impersonation grant, act in the one tenant they belong to;
//! - an organization member's session or key acts in their organization,
//!   and in a tenant of it (whether they were granted that tenant is the
//!   app's question);
//! - an operator's own key acts on the platform.
//!
//! A request naming any other organization or tenant is refused before a use
//! case runs.
//!
//! A tenant admin's request naming a support impersonation in the
//! `ianua-support-impersonation` header acts as its person, through the
//! caller the app hands back for it, and is refused when the app refuses.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{FromRequestParts, RawPathParams};
use axum::http::request::Parts;
use ianua_app::auditor::RequestAuditor;
use ianua_app::context::{
    CallerContext, CallerIdentity, Credential, OperatorCaller, OrgCaller, OrgCredential,
};
use ianua_app::error::AppError;
use ianua_app::ports::shared::ResolvedCaller;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::authentication::sessions::{SessionStanding, WatchUseRequest};
use ianua_app::use_cases::oauth::api_keys::UseStamp;
use ianua_app::use_cases::organization::sign_in::OrgCredentialBearer;
use ianua_domain::domains::audit::builder::AuditContext;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::tenant::hosts::PlatformLabel;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::message;
use ianua_domain::shared::config::SlugLimits;
use ianua_domain::types::{Fact, ImpersonationGrantId, IpAddress, TenantSlug, UserAgent};

use crate::error::ApiError;
use crate::extractors::identity::impersonation::named_impersonation;
use crate::extractors::operator::named_grant;
use crate::state::ApiState;

/// The client's address and user agent, as the request arrived.
///
/// The address is the socket peer, unless the peer is a trusted proxy, in
/// which case the forwarded chain is read. Reading the header from anyone
/// else would let a client choose the address the audit trail records and
/// the risk engine scores.
#[derive(Debug, Clone, Default)]
pub(crate) struct RequestMeta {
    /// The client's address, when it could be read.
    pub ip_address: Option<IpAddress>,
    /// The client's user agent, when it sent one.
    pub user_agent: Option<UserAgent>,
}

impl FromRequestParts<ApiState> for RequestMeta {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|info| info.0);
        let ip_address =
            crate::middleware::client_ip::resolve(&parts.headers, peer, &state.trusted_proxies)
                .and_then(|ip| IpAddress::new(ip.to_string()).ok());
        let user_agent = parts
            .headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| UserAgent::new(value).ok());
        Ok(Self {
            ip_address,
            user_agent,
        })
    }
}

/// Someone nobody has identified yet, such as a person signing in or
/// following an emailed link.
///
/// The auditor records the client's address and user agent; the use case
/// names whom the request concerns once it knows.
pub(crate) struct Visitor {
    /// The client's address and user agent.
    pub meta: RequestMeta,
    /// Records what the request changes.
    pub auditor: RequestAuditor,
}

impl FromRequestParts<ApiState> for Visitor {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let Ok(meta) = RequestMeta::from_request_parts(parts, state).await;
        let context = AuditContext::system().with_request(
            Fact::from_option(meta.ip_address.clone()),
            Fact::from_option(meta.user_agent.clone()),
        );
        Ok(Self {
            auditor: RequestAuditor::new(state.event_dispatcher.clone(), context),
            meta,
        })
    }
}

/// A caller acting in the tenant the path names: one of its users, a member
/// of its organization, or an operator acting as a user.
pub(crate) struct TenantCaller {
    /// Who is calling, where, and with what credential.
    pub caller: CallerContext,
    /// The permanent DNS label of the tenant already resolved from the path.
    pub platform_label: PlatformLabel,
    /// Records what the request changes.
    pub auditor: RequestAuditor,
}

impl FromRequestParts<ApiState> for TenantCaller {
    type Rejection = ApiError;

    /// Shares caller resolution across handlers without carrying its full
    /// future layout through every generated Axum handler.
    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let resolution: Pin<Box<dyn Future<Output = Result<Self, ApiError>> + Send + '_>> =
            Box::pin(Self::resolve(parts, state));
        resolution.await
    }
}

impl TenantCaller {
    /// Resolves the request's tenant and credential before granting a handler
    /// its caller; dropping the future cancels resolution with the request.
    async fn resolve(parts: &mut Parts, state: &ApiState) -> Result<Self, ApiError> {
        let resolved = resolved_caller(parts)?;
        let slugs = PathSlugs::of(parts, state).await?;
        let organization = organization_named(state, slugs.organization()?).await?;
        let tenant = tenant_named(state, slugs.tenant()?, &organization).await?;
        let Ok(meta) = RequestMeta::from_request_parts(parts, state).await;
        let (identity, credential) = match named_grant(&parts.headers)? {
            Some(grant) => {
                let operator = operator_from(resolved, &meta)?;
                through_grant(state, &operator, grant, &tenant).await?
            }
            None => {
                ensure_acts_in_tenant(&resolved, &organization, &tenant)?;
                (resolved.identity, resolved.credential)
            }
        };
        let caller = CallerContext::new(
            identity,
            credential,
            *organization.id(),
            *tenant.id(),
            organization.limits(),
        )?
        .with_request_metadata(meta.ip_address, meta.user_agent);
        mark_used_in_tenant(state, &caller).await?;
        watch_session_use(state, &caller).await?;
        let caller = acting_through(parts, state, caller).await?;
        Ok(Self::in_tenant(state, &tenant, caller))
    }

    /// `caller` acting in `tenant`, with an auditor that records under its
    /// audit context.
    fn in_tenant(state: &ApiState, tenant: &Tenant, caller: CallerContext) -> Self {
        Self {
            platform_label: tenant.platform_label().clone(),
            auditor: RequestAuditor::new(state.event_dispatcher.clone(), caller.audit_context()),
            caller,
        }
    }
}

/// The identity and credential an operator's request acts with through
/// `grant` in `tenant`: their own key, the grant and its user, once the app
/// finds the grant theirs and in force. Only an operator's own key names a
/// grant, and only in the grant's own tenant.
async fn through_grant(
    state: &ApiState,
    caller: &OperatorCaller,
    grant: ImpersonationGrantId,
    tenant: &Tenant,
) -> Result<(CallerIdentity, Credential), ApiError> {
    let in_use = state
        .operator
        .act_through_grant
        .execute(caller, grant)
        .await?;
    if in_use.tenant_id != *tenant.id() {
        return Err(wrong_plane());
    }
    Ok((
        CallerIdentity::Operator(*caller.operator()),
        in_use.credential,
    ))
}

/// Takes an operator's own key from the resolved credential and attaches
/// the request metadata before an impersonation grant is checked.
fn operator_from(resolved: ResolvedCaller, meta: &RequestMeta) -> Result<OperatorCaller, ApiError> {
    let (CallerIdentity::Operator(operator), Credential::OperatorKey(key)) =
        (resolved.identity, resolved.credential)
    else {
        return Err(wrong_plane());
    };
    Ok(OperatorCaller::new(operator, key)
        .with_request_metadata(meta.ip_address.clone(), meta.user_agent.clone()))
}

/// Holds the session `caller` came with against where it was last used,
/// and refuses the request as unauthenticated if that stops it. A caller
/// who came with anything else has no session to look like its holder.
async fn watch_session_use(state: &ApiState, caller: &CallerContext) -> Result<(), ApiError> {
    let Credential::TenantSession(session_id) = caller.credential() else {
        return Ok(());
    };
    let context = caller.audit_context();
    let auditor = RequestAuditor::new(state.event_dispatcher.clone(), context.clone());
    let request = WatchUseRequest {
        session_id: *session_id,
        ip_address: context.ip_address().clone(),
    };
    let watching = &state.authentication.sessions.watch_use;
    match watching
        .execute(&caller.tenant(), &auditor, request)
        .await?
    {
        SessionStanding::Stands => Ok(()),
        SessionStanding::Stopped => Err(ApiError(AppError::Unauthenticated)),
    }
}

/// `caller`, or, when the request names a support impersonation, the
/// caller the admin acts through as its person. The app grants that on
/// every request; a refusal refuses the request rather than running it as
/// the admin.
async fn acting_through(
    parts: &Parts,
    state: &ApiState,
    caller: CallerContext,
) -> Result<CallerContext, ApiError> {
    let Some(impersonation) = named_impersonation(&parts.headers)? else {
        return Ok(caller);
    };
    let acting = state
        .identity
        .impersonation
        .act_as
        .execute(&caller, impersonation)
        .await?;
    Ok(acting.caller)
}

/// Marks the credential `caller` came with as used. A tenant API key has
/// the country of every request noted, and its last use written once an
/// interval or when the country is new to it; a member's organization
/// session or key is marked as it is on the organization, once an
/// interval. A credential of any other kind has nothing to mark.
async fn mark_used_in_tenant(state: &ApiState, caller: &CallerContext) -> Result<(), ApiError> {
    let (id, holder) = match caller.credential() {
        Credential::TenantApiKey(key) => (*key.as_uuid(), Holder::Tenant),
        Credential::OrgSession(session) => (*session.as_uuid(), Holder::Organization),
        Credential::OrgApiKey(key) => (*key.as_uuid(), Holder::Organization),
        _ => return Ok(()),
    };
    let stamp = match state.http.credential_use.is_due(id, Instant::now()) {
        true => UseStamp::Due,
        false => UseStamp::Recent,
    };
    let auditor = RequestAuditor::new(state.event_dispatcher.clone(), caller.audit_context());
    let marked = match (holder, stamp) {
        (Holder::Tenant, stamp) => {
            let record_use = &state.oauth.api_keys.record_use;
            record_use.execute(caller, &auditor, stamp).await
        }
        (Holder::Organization, UseStamp::Recent) => return Ok(()),
        (Holder::Organization, UseStamp::Due) => {
            let bearer = OrgCredentialBearer::Tenant(caller.clone());
            let mark = &state.organization.sign_in.mark_credential_used;
            mark.execute(&bearer, &auditor, ()).await
        }
    };
    finish_credential_mark(marked)
}

/// Who keeps the credential a request came with into a tenant.
enum Holder {
    /// The tenant: one of its API keys.
    Tenant,
    /// Its organization: a member's session or key.
    Organization,
}

/// Marks the session or key a member came with to their organization as
/// used, once an interval.
async fn mark_used_on_organization(state: &ApiState, caller: &OrgCaller) -> Result<(), ApiError> {
    let id = match caller.credential() {
        OrgCredential::Session(session) => *session.as_uuid(),
        OrgCredential::ApiKey(key) => *key.as_uuid(),
    };
    if !state.http.credential_use.is_due(id, Instant::now()) {
        return Ok(());
    }
    let auditor = RequestAuditor::new(state.event_dispatcher.clone(), caller.audit_context());
    let bearer = OrgCredentialBearer::Organization(caller.clone());
    let mark = &state.organization.sign_in.mark_credential_used;
    finish_credential_mark(mark.execute(&bearer, &auditor, ()).await)
}

/// The request goes on once its credential is marked used. A credential
/// that is gone refuses the request as unauthenticated, and a caller the
/// app refuses is refused as the app says; a mark that could not be
/// written is logged and the request goes on, since the mark is bookkeeping
/// and the use case the request runs checks its caller again.
fn finish_credential_mark(marked: Result<(), AppError>) -> Result<(), ApiError> {
    match marked {
        Ok(()) => Ok(()),
        Err(AppError::Internal(error)) => {
            tracing::warn!(error = %error, "a credential could not be marked used");
            Ok(())
        }
        Err(AppError::NotFound(_)) => Err(ApiError(AppError::Unauthenticated)),
        Err(refused) => Err(ApiError(refused)),
    }
}

/// A member of the organization the path names, acting on it.
pub(crate) struct OrgMember {
    /// Who is calling, and with what credential.
    pub caller: OrgCaller,
    /// Records what the request changes.
    pub auditor: RequestAuditor,
}

impl FromRequestParts<ApiState> for OrgMember {
    type Rejection = ApiError;

    /// Shares organization caller resolution without embedding its future
    /// layout in every generated Axum handler.
    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let resolution: Pin<Box<dyn Future<Output = Result<Self, ApiError>> + Send + '_>> =
            Box::pin(Self::resolve(parts, state));
        resolution.await
    }
}

impl OrgMember {
    /// Resolves and marks the member's credential within the request's lifetime.
    async fn resolve(parts: &mut Parts, state: &ApiState) -> Result<Self, ApiError> {
        let caller = member_of_path_organization(parts, state).await?;
        mark_used_on_organization(state, &caller).await?;
        Ok(Self {
            auditor: RequestAuditor::new(state.event_dispatcher.clone(), caller.audit_context()),
            caller,
        })
    }
}

/// The member of the organization the path names, with the session or key
/// they came with, as the bearer resolved.
///
/// Only that the credential is the member's and belongs to this
/// organization is checked here. Whether it still counts, and for what, is
/// the app's question: [`OrgMember`] asks it at once by marking the
/// credential used, which a session still waiting for its second factor
/// does not pass; the sign-in steps leave it to the use case they run.
///
/// # Errors
///
/// `401` without a caller, `403` for another plane's credential or another
/// organization's member, `404` when the path names no organization.
pub(crate) async fn member_of_path_organization(
    parts: &mut Parts,
    state: &ApiState,
) -> Result<OrgCaller, ApiError> {
    let resolved = resolved_caller(parts)?;
    let slugs = PathSlugs::of(parts, state).await?;
    let organization = organization_named(state, slugs.organization()?).await?;
    let (member, credential) = org_credential(&resolved)?;
    ensure_member_of(&resolved, &organization)?;
    let Ok(meta) = RequestMeta::from_request_parts(parts, state).await;
    Ok(OrgCaller::new(member, credential, *organization.id())
        .with_request_metadata(meta.ip_address, meta.user_agent))
}

/// A platform operator, with their own key.
pub(crate) struct Operator {
    /// Who is calling, and with which key.
    pub caller: OperatorCaller,
    /// Records what the request changes.
    pub auditor: RequestAuditor,
}

impl FromRequestParts<ApiState> for Operator {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let resolved = resolved_caller(parts)?;
        let (CallerIdentity::Operator(operator), Credential::OperatorKey(key)) =
            (resolved.identity, resolved.credential)
        else {
            return Err(wrong_plane());
        };
        let Ok(meta) = RequestMeta::from_request_parts(parts, state).await;
        let caller = OperatorCaller::new(operator, key)
            .with_request_metadata(meta.ip_address, meta.user_agent);
        Ok(Self {
            auditor: RequestAuditor::new(state.event_dispatcher.clone(), caller.audit_context()),
            caller,
        })
    }
}

/// The organization and tenant slugs a path names, read once.
pub(crate) struct PathSlugs {
    organization: Option<TenantSlug>,
    tenant: Option<TenantSlug>,
}

impl PathSlugs {
    /// The slugs of `parts`' path. A slug that is not a valid one names
    /// nothing, so it is not found.
    pub(crate) async fn of(parts: &mut Parts, state: &ApiState) -> Result<Self, ApiError> {
        let params = RawPathParams::from_request_parts(parts, state)
            .await
            .map_err(|_| not_found())?;
        let limits = SlugLimits::default();
        let slug = |name: &str| {
            params
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| TenantSlug::new(value, &limits).map_err(|_| not_found()))
                .transpose()
        };
        Ok(Self {
            organization: slug("org_slug")?,
            tenant: slug("tenant_slug")?,
        })
    }

    /// The organization slug the path names, or not found when it names
    /// none.
    pub(crate) fn organization(&self) -> Result<&TenantSlug, ApiError> {
        self.organization.as_ref().ok_or_else(not_found)
    }

    /// The tenant slug the path names, or not found when it names none.
    pub(crate) fn tenant(&self) -> Result<&TenantSlug, ApiError> {
        self.tenant.as_ref().ok_or_else(not_found)
    }
}

/// The caller the auth middleware found, or `401` when there is none.
pub(crate) fn resolved_caller(parts: &Parts) -> Result<ResolvedCaller, ApiError> {
    parts
        .extensions
        .get::<ResolvedCaller>()
        .cloned()
        .ok_or(ApiError(AppError::Unauthenticated))
}

/// The organization `slug` names, or not found when there is none.
pub(crate) async fn organization_named(
    state: &ApiState,
    slug: &TenantSlug,
) -> Result<Arc<Organization>, ApiError> {
    state
        .org_store
        .find_by_slug(slug)
        .await
        .map_err(AppError::internal)?
        .ok_or_else(not_found)
}

/// The open tenant `slug` names inside `organization`: not found when there
/// is none, and refused as unavailable when it is suspended, archived or
/// deleted, since nothing is done in a closed tenant's name. Acting on a
/// tenant from outside (reactivating, restoring, deleting it) goes through
/// the tenant extractors, not this.
pub(crate) async fn tenant_named(
    state: &ApiState,
    slug: &TenantSlug,
    organization: &Organization,
) -> Result<Arc<Tenant>, ApiError> {
    let tenant = state
        .tenant_store
        .find_by_slug_in_org(slug, organization.id())
        .await
        .map_err(AppError::internal)?
        .ok_or_else(not_found)?;
    if !tenant.status().is_open() {
        return Err(ApiError(AppError::TenantUnavailable(message!(
            "api-this-workspace-is-not-available",
            "this workspace is not available"
        ))));
    }
    Ok(tenant)
}

/// Refuses unless `resolved` acts in `tenant` of `organization`: a user or
/// impersonated user of that very tenant, or a member of its organization.
fn ensure_acts_in_tenant(
    resolved: &ResolvedCaller,
    organization: &Organization,
    tenant: &Tenant,
) -> Result<(), ApiError> {
    let belongs = match resolved.identity {
        CallerIdentity::TenantUser(_) => resolved.tenant_id == Some(*tenant.id()),
        CallerIdentity::OrgUser(_) => resolved.organization_id == Some(*organization.id()),
        CallerIdentity::Operator(_) => false,
    };
    if !belongs {
        return Err(wrong_plane());
    }
    Ok(())
}

/// Refuses unless `resolved` is a member of `organization`.
fn ensure_member_of(
    resolved: &ResolvedCaller,
    organization: &Organization,
) -> Result<(), ApiError> {
    if resolved.organization_id != Some(*organization.id()) {
        return Err(wrong_plane());
    }
    Ok(())
}

/// The member and their organization credential, or a refusal for any
/// other plane's credential.
pub(crate) fn org_credential(
    resolved: &ResolvedCaller,
) -> Result<(ianua_domain::types::OrgUserId, OrgCredential), ApiError> {
    let CallerIdentity::OrgUser(member) = resolved.identity else {
        return Err(wrong_plane());
    };
    let credential = match &resolved.credential {
        Credential::OrgSession(session) => OrgCredential::Session(*session),
        Credential::OrgApiKey(key) => OrgCredential::ApiKey(*key),
        _ => return Err(wrong_plane()),
    };
    Ok((member, credential))
}

/// The plain `404` for a path that names nothing the caller can reach.
fn not_found() -> ApiError {
    ApiError(AppError::NotFound(message!("api-not-found", "not found")))
}

/// A credential used outside the plane it belongs to.
fn wrong_plane() -> ApiError {
    ApiError(AppError::Forbidden(message!(
        "api-this-credential-does-not-act-here",
        "this credential does not act here"
    )))
}
