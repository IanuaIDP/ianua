//! A caller on the tenant plane: who they are, the credential they came
//! with, and the request's address and client.

use ianua_domain::domains::audit::builder::{AuditContext, SupportActing};
use ianua_domain::domains::authentication::risk_engine::origin::AttemptOrigin;
use ianua_domain::domains::organization::billing::plan::PlanLimits;
use ianua_domain::message;
use ianua_domain::types::{
    ActorRef, ApiKeyId, Fact, ImpersonationGrantId, IpAddress, KeyPrefix, OperatorId, OrgApiKeyId,
    OrgUserId, OrganizationId, PrincipalRef, SessionId, SupportImpersonationId, TenantId,
    UserAgent, UserId, WorkflowExecutionId,
};

use crate::context::DirectoryBound;
use crate::error::AppError;
use crate::tenancy::ScopedTenant;

/// Which identity plane the caller belongs to.
///
/// Carried mainly for audit. A few use cases branch on it where each plane
/// keeps its records in a different store (for example the approver's second
/// factor).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerIdentity {
    /// A platform operator.
    Operator(OperatorId),
    /// A member of an organization.
    OrgUser(OrgUserId),
    /// An account whose identity is scoped to one tenant.
    TenantUser(UserId),
}

/// The credential a request came with, as the API layer found it.
///
/// It names the stored record only. What the record lets its holder do is
/// worked out from that record, never from this value. A directory bind
/// also carries the domain's proof that the password was checked, since no
/// record keeps that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    /// A tenant user's session.
    TenantSession(SessionId),
    /// The stored credential used for requests scoped to a tenant.
    TenantApiKey(ApiKeyId),
    /// A tenant user's directory bind, made over LDAP with their password
    /// and a client certificate.
    DirectoryBind(DirectoryBound),
    /// An organization member's session.
    OrgSession(SessionId),
    /// An organization API key.
    OrgApiKey(OrgApiKeyId),
    /// An operator's own key, found by its prefix.
    OperatorKey(KeyPrefix),
    /// An operator acting as a tenant user through an impersonation grant,
    /// signed in with their own key.
    Impersonation {
        /// The operator's own key.
        key: KeyPrefix,
        /// The grant that lets them act as the user.
        grant: ImpersonationGrantId,
        /// The user they act as.
        user: UserId,
    },
    /// A workflow run's company step, acting as the person the run is for.
    ///
    /// No request carries it: only the platform's own company steps make
    /// it, and what it holds is worked out from the run and the person on
    /// every use, only while the run runs.
    WorkflowRun(WorkflowExecutionId),
    /// A tenant admin acting as one of the tenant's people for support,
    /// signed in with their own session.
    SupportImpersonation {
        /// The admin's own session.
        session: SessionId,
        /// The support impersonation that lets them act as the person.
        impersonation: SupportImpersonationId,
        /// The person they act as.
        user: UserId,
    },
}

/// The caller of a use case: who they are, where they act, and the
/// credential they came with.
///
/// The client's IP address and user agent are attached afterwards through
/// [`with_request_metadata`](Self::with_request_metadata) and flow into the
/// [`AuditContext`] built by [`audit_context`](Self::audit_context).
#[derive(Debug, Clone)]
pub struct CallerContext {
    identity: CallerIdentity,
    credential: Credential,
    organization_id: OrganizationId,
    tenant_id: TenantId,
    plan_limits: Box<PlanLimits>,
    ip_address: Option<IpAddress>,
    user_agent: Option<UserAgent>,
}

impl CallerContext {
    /// The caller `identity`, acting in `tenant_id` of `organization_id`
    /// through `credential`.
    ///
    /// Request metadata (IP, user-agent) is attached separately via
    /// [`with_request_metadata`](Self::with_request_metadata).
    ///
    /// # Errors
    ///
    /// - [`AppError::Forbidden`] when the credential belongs to another plane
    ///   than the identity, such as an organization session for a tenant
    ///   user.
    pub fn new(
        identity: CallerIdentity,
        credential: Credential,
        organization_id: OrganizationId,
        tenant_id: TenantId,
        plan_limits: PlanLimits,
    ) -> Result<Self, AppError> {
        ensure_credential_fits(identity, &credential)?;
        Ok(Self {
            identity,
            credential,
            organization_id,
            tenant_id,
            plan_limits: Box::new(plan_limits),
            ip_address: None,
            user_agent: None,
        })
    }

    /// Attaches the client's IP address and User-Agent, captured at the
    /// request boundary. These flow into the audit log.
    #[must_use]
    pub fn with_request_metadata(
        mut self,
        ip_address: Option<IpAddress>,
        user_agent: Option<UserAgent>,
    ) -> Self {
        self.ip_address = ip_address;
        self.user_agent = user_agent;
        self
    }

    /// Where the request came from, as failed passwords are counted.
    #[must_use]
    pub fn origin(&self) -> AttemptOrigin {
        AttemptOrigin::of(Fact::from_option(self.ip_address.as_ref()))
    }

    /// The caller as a typed audit actor (org user / tenant user / operator).
    #[must_use]
    pub fn actor(&self) -> ActorRef {
        match &self.identity {
            CallerIdentity::Operator(id) => ActorRef::Operator(*id),
            CallerIdentity::OrgUser(id) => ActorRef::OrgUser(*id),
            CallerIdentity::TenantUser(id) => ActorRef::User(*id),
        }
    }

    /// The caller as a principal that can hold, hand out, or decide on
    /// authority in the tenant, under its own kind: a tenant user as a tenant
    /// user, an org user as an org user.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Forbidden` for a platform operator. An operator has
    /// no standing in a tenant's authority graph; recording one under another
    /// kind would be a principal that never existed.
    pub fn principal(&self) -> Result<PrincipalRef, AppError> {
        match &self.identity {
            CallerIdentity::TenantUser(id) => Ok(PrincipalRef::User(*id)),
            CallerIdentity::OrgUser(id) => Ok(PrincipalRef::OrgUser(*id)),
            CallerIdentity::Operator(_) => Err(AppError::Forbidden(message!(
                "app-a-platform-operator-holds-no-authority",
                "a platform operator holds no authority in a tenant"
            ))),
        }
    }

    /// The caller's identity plane and ID.
    #[must_use]
    pub fn identity(&self) -> &CallerIdentity {
        &self.identity
    }

    /// The credential the request came with.
    #[must_use]
    pub fn credential(&self) -> &Credential {
        &self.credential
    }

    /// The organization that owns the resolved tenant.
    #[must_use]
    pub fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    /// The resolved tenant's ID.
    #[must_use]
    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// The resolved tenant, as tenant-scoped stores take it.
    #[must_use]
    pub fn tenant(&self) -> ScopedTenant {
        ScopedTenant::from_resolved_caller(self.tenant_id)
    }

    /// The organization's plan limits, pre-resolved.
    #[must_use]
    pub fn plan_limits(&self) -> &PlanLimits {
        &self.plan_limits
    }

    /// Builds an `AuditContext` carrying the caller (typed actor), the
    /// request IP and user-agent, and the org/tenant scope. An operator
    /// acting as a user is recorded as such.
    #[must_use]
    pub fn audit_context(&self) -> AuditContext {
        let context = AuditContext::for_caller(self.organization_id, self.actor())
            .with_tenant(self.tenant_id)
            .with_request(
                Fact::from_option(self.ip_address.clone()),
                Fact::from_option(self.user_agent.clone()),
            );
        match (&self.identity, &self.credential) {
            (CallerIdentity::Operator(operator), Credential::Impersonation { user, .. }) => {
                context.impersonating(*operator, *user)
            }
            (
                CallerIdentity::TenantUser(admin),
                Credential::SupportImpersonation {
                    impersonation,
                    user,
                    ..
                },
            ) => context.supporting(SupportActing {
                admin: *admin,
                as_user: *user,
                impersonation: *impersonation,
            }),
            (
                CallerIdentity::TenantUser(_) | CallerIdentity::OrgUser(_),
                Credential::WorkflowRun(execution),
            ) => context.through_run(*execution),
            _ => context,
        }
    }

    /// This caller, signed in with their own session, acting as `user`
    /// through the support impersonation `impersonation` from now on.
    ///
    /// It names the records only: what it lets the caller do is worked out
    /// again from the impersonation and the session on every use.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Unauthenticated` when the caller is not a tenant
    /// user signed in with a session.
    pub fn through_support_impersonation(
        &self,
        impersonation: SupportImpersonationId,
        user: UserId,
    ) -> Result<Self, AppError> {
        let (CallerIdentity::TenantUser(_), Credential::TenantSession(session)) =
            (&self.identity, &self.credential)
        else {
            return Err(AppError::Unauthenticated);
        };
        Ok(Self {
            credential: Credential::SupportImpersonation {
                session: *session,
                impersonation,
                user,
            },
            ..self.clone()
        })
    }
}

/// Refuses a credential of another plane than `identity`.
fn ensure_credential_fits(
    identity: CallerIdentity,
    credential: &Credential,
) -> Result<(), AppError> {
    if !fits(identity, credential) {
        return Err(AppError::Forbidden(message!(
            "app-the-credential-belongs-to-another-kind",
            "the credential belongs to another kind of caller"
        )));
    }
    Ok(())
}

/// Whether `credential` is one `identity`'s kind of caller comes with.
fn fits(identity: CallerIdentity, credential: &Credential) -> bool {
    match (identity, credential) {
        (
            CallerIdentity::TenantUser(_),
            Credential::TenantSession(_)
            | Credential::TenantApiKey(_)
            | Credential::DirectoryBind(_)
            | Credential::SupportImpersonation { .. }
            | Credential::WorkflowRun(_),
        )
        | (
            CallerIdentity::OrgUser(_),
            Credential::OrgSession(_)
            | Credential::OrgApiKey(_)
            | Credential::TenantApiKey(_)
            | Credential::WorkflowRun(_),
        )
        | (
            CallerIdentity::Operator(_),
            Credential::OperatorKey(_) | Credential::Impersonation { .. },
        ) => true,
        (CallerIdentity::TenantUser(_), _)
        | (CallerIdentity::OrgUser(_), _)
        | (CallerIdentity::Operator(_), _) => false,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::builder::ActedThrough;
    use ianua_domain::domains::organization::billing::plan::OrganizationPlan;

    use super::*;

    fn caller(identity: CallerIdentity, credential: Credential) -> Result<CallerContext, AppError> {
        CallerContext::new(
            identity,
            credential,
            OrganizationId::new(),
            TenantId::new(),
            OrganizationPlan::Free.default_limits(),
        )
    }

    fn signed_in(user: UserId) -> CallerContext {
        caller(
            CallerIdentity::TenantUser(user),
            Credential::TenantSession(SessionId::new()),
        )
        .unwrap()
    }

    /// The audit record of a tenant user's request names the tenant it was
    /// made in and the user as the actor.
    #[test]
    fn a_tenant_users_audit_names_the_tenant_and_the_user() {
        let ann = UserId::new();
        let ctx = signed_in(ann);

        let audit = ctx.audit_context();

        assert_eq!(audit.tenant_id(), Fact::Known(ctx.tenant_id()));
        assert!(matches!(ctx.actor(), ActorRef::User(id) if id == ann));
    }

    /// An org member is recorded under their own kind, so separation of duty
    /// never compares them with a tenant user who does not exist.
    #[test]
    fn an_org_user_is_recorded_as_an_org_user() {
        let id = OrgUserId::new();
        let ctx = caller(
            CallerIdentity::OrgUser(id),
            Credential::OrgSession(SessionId::new()),
        )
        .unwrap();

        assert_eq!(ctx.principal().unwrap(), PrincipalRef::OrgUser(id));
    }

    /// An organization member may carry a tenant API key while retaining
    /// their organization-member principal.
    #[test]
    fn a_tenant_key_a_member_made_fits_a_member_caller() {
        let id = OrgUserId::new();

        let ctx = caller(
            CallerIdentity::OrgUser(id),
            Credential::TenantApiKey(ApiKeyId::new()),
        );

        assert_eq!(ctx.unwrap().principal().unwrap(), PrincipalRef::OrgUser(id));
    }

    /// A platform operator holds no principal in a tenant.
    #[test]
    fn an_operator_holds_no_principal_in_a_tenant() {
        let ctx = caller(
            CallerIdentity::Operator(OperatorId::new()),
            Credential::OperatorKey(KeyPrefix::new("opk_abcd1234").unwrap()),
        )
        .unwrap();

        assert!(matches!(ctx.principal(), Err(AppError::Forbidden(_))));
    }

    /// An organization session cannot form a caller context for a tenant-user identity.
    #[test]
    fn a_credential_of_another_plane_is_refused() {
        let refused = caller(
            CallerIdentity::TenantUser(UserId::new()),
            Credential::OrgSession(SessionId::new()),
        );

        assert!(matches!(refused, Err(AppError::Forbidden(_))));
    }

    /// Bob, an operator, acts as Ann through an impersonation grant. The
    /// audit records Bob acting as Ann, not Ann acting herself.
    #[test]
    fn an_impersonation_is_recorded_as_the_operator_acting_as_the_user() {
        let (bob, ann) = (OperatorId::new(), UserId::new());
        let ctx = caller(
            CallerIdentity::Operator(bob),
            Credential::Impersonation {
                key: KeyPrefix::new("opk_abcd1234").unwrap(),
                grant: ImpersonationGrantId::new(),
                user: ann,
            },
        )
        .unwrap();

        assert_eq!(
            ctx.audit_context().acted_through(),
            ActedThrough::Impersonation {
                operator_id: bob,
                as_user: ann,
            }
        );
    }
}
