//! Turns a domain event and its request context into an audit record ready
//! to store.

use crate::domains::audit::record::{AuditRecord, AuditScope, AuditTarget};
use crate::shared::events::chain::EventOrigin;
use crate::shared::events::event::{CopyScope, DomainEvent, Recorded};
use crate::types::{
    ActorRef, Fact, IpAddress, OperatorId, OrganizationId, SupportImpersonationId, TenantId,
    UserAgent, UserId, WorkflowExecutionId,
};

/// Who a request's audit records name as having acted.
#[derive(Clone, Debug)]
pub enum AuditActor {
    /// The signed-in caller, taken where the request comes in.
    ///
    /// It wins over the actor the event names, because use cases do not all
    /// set that one the same way.
    Caller(ActorRef),
    /// Nobody proved who they are, as in a sign-in attempt.
    ///
    /// The record takes the actor the event names, or
    /// [`ActorRef::Anonymous`] when it names none.
    Anonymous,
    /// No request at all: a seed or a background job.
    System,
}

/// How an action was carried out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActedThrough {
    /// By the actor in their own name.
    Directly,
    /// By an operator acting as a user.
    Impersonation {
        /// The staff identity responsible for acting as the user.
        operator_id: OperatorId,
        /// The user they acted as.
        as_user: UserId,
    },
    /// By a tenant admin acting as one of the tenant's people for support,
    /// through a support impersonation.
    SupportImpersonation {
        /// The admin, who is the actor.
        admin: UserId,
        /// The person they acted as.
        as_user: UserId,
        /// The impersonation that let them.
        impersonation: SupportImpersonationId,
    },
    /// By a workflow run, as the person it acts for, who is the actor.
    WorkflowRun {
        /// The run that acted.
        execution: WorkflowExecutionId,
    },
}

impl ActedThrough {
    /// The name of its kind: `directly`, `impersonation`,
    /// `support_impersonation` or `workflow_run`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Directly => "directly",
            Self::Impersonation { .. } => "impersonation",
            Self::SupportImpersonation { .. } => "support_impersonation",
            Self::WorkflowRun { .. } => "workflow_run",
        }
    }
}

/// The request details an audit record needs beside the event.
///
/// The app layer fills it from the HTTP request. With a [`DomainEvent`] it
/// makes an [`AuditRecord`].
///
/// Make one with [`for_caller`](Self::for_caller) or
/// [`anonymous`](Self::anonymous) and the `with_*` methods. Use
/// [`system`](Self::system) only for work with no request, such as a seed or
/// a background job. The fields are private, so a request cannot be recorded
/// as the system by leaving its caller out.
#[derive(Clone, Debug)]
pub struct AuditContext {
    actor: AuditActor,
    organization_id: Fact<OrganizationId>,
    tenant_id: Fact<TenantId>,
    ip_address: Fact<IpAddress>,
    user_agent: Fact<UserAgent>,
    target_id: AuditTarget,
    acted_through: ActedThrough,
    origin: EventOrigin,
}

impl AuditContext {
    /// Where the request's events come from: outside any workflow, or the
    /// work of an execution at its depth in a chain.
    #[must_use]
    pub fn origin(&self) -> EventOrigin {
        self.origin
    }

    /// This context, for the work of an execution at `origin`: every event
    /// dispatched with it counts as raised by that work, so a workflow it
    /// sets off continues the chain and a chain of workflows always ends.
    #[must_use]
    pub fn from_execution(mut self, origin: EventOrigin) -> Self {
        self.origin = origin;
        self
    }

    /// Who acted.
    #[must_use]
    pub fn actor(&self) -> &AuditActor {
        &self.actor
    }

    /// The organization this request belongs to.
    ///
    /// It is unknown for platform work, and for flows that learn it only
    /// inside the use case.
    #[must_use]
    pub fn organization_id(&self) -> Fact<OrganizationId> {
        self.organization_id
    }

    /// The tenant this request belongs to. It is unknown for organization or
    /// platform work.
    #[must_use]
    pub fn tenant_id(&self) -> Fact<TenantId> {
        self.tenant_id
    }

    /// The client's IP address, when the edge reported one.
    #[must_use]
    pub fn ip_address(&self) -> &Fact<IpAddress> {
        &self.ip_address
    }

    /// The client's User-Agent, when it sent one.
    #[must_use]
    pub fn user_agent(&self) -> &Fact<UserAgent> {
        &self.user_agent
    }

    /// The entity affected, such as a user, a session or a role, or that
    /// there is none.
    #[must_use]
    pub fn target_id(&self) -> &AuditTarget {
        &self.target_id
    }

    /// Whether the actor acted in their own name or as someone else.
    #[must_use]
    pub fn acted_through(&self) -> ActedThrough {
        self.acted_through
    }

    /// A context for a request from an authenticated `caller` in an
    /// organization.
    #[must_use]
    pub fn for_caller(organization_id: OrganizationId, caller: ActorRef) -> Self {
        Self {
            actor: AuditActor::Caller(caller),
            organization_id: Fact::Known(organization_id),
            ..Self::system()
        }
    }

    /// A context for a request from an authenticated `caller` on the
    /// platform itself, in no organization, such as an operator managing
    /// the platform's operators.
    #[must_use]
    pub fn for_platform_caller(caller: ActorRef) -> Self {
        Self {
            actor: AuditActor::Caller(caller),
            ..Self::system()
        }
    }

    /// A context for a request nobody has proved who sent, such as a
    /// sign-in attempt, in an organization.
    #[must_use]
    pub fn anonymous(organization_id: OrganizationId) -> Self {
        Self {
            actor: AuditActor::Anonymous,
            organization_id: Fact::Known(organization_id),
            ..Self::system()
        }
    }

    /// A context for the platform's own work: no request, caller, IP or
    /// tenant.
    ///
    /// Use it only when there is no request, such as `MODE=seed` or a
    /// background job.
    #[must_use]
    pub fn system() -> Self {
        Self {
            actor: AuditActor::System,
            organization_id: Fact::Unknown,
            tenant_id: Fact::Unknown,
            ip_address: Fact::Unknown,
            user_agent: Fact::Unknown,
            target_id: AuditTarget::Untargeted,
            acted_through: ActedThrough::Directly,
            origin: EventOrigin::Outside,
        }
    }

    /// Attaches the client's IP address and User-Agent from the request.
    #[must_use]
    pub fn with_request(
        mut self,
        ip_address: Fact<IpAddress>,
        user_agent: Fact<UserAgent>,
    ) -> Self {
        self.ip_address = ip_address;
        self.user_agent = user_agent;
        self
    }

    /// Sets the entity the action affected, such as a user or a session.
    #[must_use]
    pub fn with_target_id(mut self, target_id: AuditTarget) -> Self {
        self.target_id = target_id;
        self
    }

    /// Sets the organization.
    ///
    /// For flows with no signed-in caller, such as login, that find the
    /// organization inside the use case.
    #[must_use]
    pub fn with_organization(mut self, organization_id: OrganizationId) -> Self {
        self.organization_id = Fact::Known(organization_id);
        self
    }

    /// Sets the tenant.
    ///
    /// For flows with no signed-in caller that find the tenant inside the
    /// use case.
    #[must_use]
    pub fn with_tenant(mut self, tenant_id: TenantId) -> Self {
        self.tenant_id = Fact::Known(tenant_id);
        self
    }

    /// Marks the action as an operator acting as a user.
    #[must_use]
    pub fn impersonating(mut self, operator_id: OperatorId, as_user: UserId) -> Self {
        self.acted_through = ActedThrough::Impersonation {
            operator_id,
            as_user,
        };
        self
    }

    /// Marks the action as a workflow run's step, acting as the person the
    /// run is for, so the record reads "Pat, through run 4182", never as
    /// Pat acting by hand.
    #[must_use]
    pub fn through_run(mut self, execution: WorkflowExecutionId) -> Self {
        self.acted_through = ActedThrough::WorkflowRun { execution };
        self
    }

    /// Marks the action as a tenant admin acting as one of the tenant's
    /// people through a support impersonation.
    #[must_use]
    pub fn supporting(mut self, acting: SupportActing) -> Self {
        self.acted_through = ActedThrough::SupportImpersonation {
            admin: acting.admin,
            as_user: acting.as_user,
            impersonation: acting.impersonation,
        };
        self
    }
}

/// A tenant admin acting as one of the tenant's people, and the support
/// impersonation that lets them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupportActing {
    /// The staff account exercising the support impersonation.
    pub admin: UserId,
    /// The person acted as.
    pub as_user: UserId,
    /// The impersonation that lets them.
    pub impersonation: SupportImpersonationId,
}

/// Builds an [`AuditRecord`] from a [`DomainEvent`] and its request context.
///
/// The actor is the signed-in caller when there is one. Otherwise it is the
/// actor the event names. Failing that, it is [`ActorRef::Anonymous`] for a
/// request nobody signed, or [`ActorRef::System`] for the platform's own
/// work. An anonymous attempt is never written down as the system.
///
/// The record is filed where the event belongs, not where the request came
/// from. A tenant event goes under its tenant, an organization event under
/// that organization alone, and a platform event on the platform.
#[must_use]
pub fn build_audit_record(event: &DomainEvent, ctx: &AuditContext) -> AuditRecord {
    let actor = match (&ctx.actor, event.performed_by()) {
        (AuditActor::Caller(caller), _) => caller.clone(),
        (AuditActor::Anonymous | AuditActor::System, Fact::Known(named)) => named.clone(),
        (AuditActor::Anonymous, Fact::Unknown) => ActorRef::Anonymous,
        (AuditActor::System, Fact::Unknown) => ActorRef::System,
    };

    AuditRecord {
        id: crate::types::AuditRecordId::new(),
        scope: scope_of(event, ctx),
        actor,
        event_type: event.event_type(),
        target: ctx.target_id.clone(),
        ip_address: ctx.ip_address.clone(),
        user_agent: ctx.user_agent.clone(),
        payload: event.payload(),
        acted_through: ctx.acted_through,
        occurred_at: event.occurred_at(),
    }
}

/// Where a record of `event` is filed.
///
/// A tenant event goes under its tenant, naming the request's organization
/// as owner. An organization event goes under that organization alone. A
/// platform event goes on the platform. The request's own tenant is never
/// used, so an organization's record never shows up in a tenant's log.
fn scope_of(event: &DomainEvent, ctx: &AuditContext) -> AuditScope {
    if let Some(tenant) = event.tenant_id() {
        return AuditScope::Tenant {
            organization: ctx.organization_id,
            tenant: *tenant,
        };
    }
    event
        .organization_id()
        .map_or(AuditScope::Platform, |organization| {
            AuditScope::Organization(*organization)
        })
}

/// An event read back from its record, with the context it was recorded
/// in.
pub struct ReadBack {
    /// A copy of the event, as [`DomainEvent::recorded`] makes one.
    pub event: DomainEvent,
    /// The context it was recorded in.
    pub context: AuditContext,
}

/// The event `record` keeps and its context, read back, for a consumer
/// handed the record after the change that raised it, such as one hearing
/// it on the message bus. Building a record of the two again gives the
/// same record, under a new id.
///
/// A record does not say whether a workflow execution's work raised its
/// event, so `origin` says it. The copy is never dispatched: that would
/// record the event a second time.
#[must_use]
pub fn read_back(record: &AuditRecord, origin: EventOrigin) -> ReadBack {
    let core = Recorded {
        event_type: record.event_type,
        occurred_at: record.occurred_at,
        payload: record.payload.clone(),
    };
    let scope = match record.scope {
        AuditScope::Tenant { tenant, .. } => CopyScope::Tenant(tenant),
        AuditScope::Organization(organization) => CopyScope::Organization(organization),
        AuditScope::Platform => CopyScope::Platform,
    };
    ReadBack {
        event: DomainEvent::copied(scope, core, Fact::Known(record.actor.clone()), origin),
        context: AuditContext {
            actor: AuditActor::Caller(record.actor.clone()),
            organization_id: Fact::from_option(record.scope.organization_id().copied()),
            tenant_id: Fact::from_option(record.scope.tenant_id().copied()),
            ip_address: record.ip_address.clone(),
            user_agent: record.user_agent.clone(),
            target_id: record.target.clone(),
            acted_through: record.acted_through,
            origin,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::events::login::{LoginFailed, LoginFailureReason};

    fn login_failed(tenant_id: TenantId) -> DomainEvent {
        crate::shared::events::raised::scoped(
            tenant_id,
            LoginFailed {
                email: crate::types::UntrustedText::record("alice@acme.com"),
                reason: LoginFailureReason::BadPassword,
                ip_address: Fact::Unknown,
                occurred_at: crate::shared::clock::now(),
            },
        )
    }

    /// A failed sign-in is recorded by a system job with a known IP. The
    /// record files it under the event's tenant, names the system and keeps
    /// the IP and event type.
    #[test]
    fn builds_record_from_event_and_context() {
        let tenant_id = TenantId::new();
        let event = login_failed(tenant_id).system();
        let ctx = AuditContext {
            tenant_id: Fact::Known(tenant_id),
            ip_address: Fact::Known(IpAddress::new("10.0.0.1").unwrap()),
            ..AuditContext::system()
        };

        let record = build_audit_record(&event, &ctx);

        assert_eq!(record.scope.tenant_id(), Some(&tenant_id));
        assert_eq!(record.event_type.as_str(), "authentication.login_failed");
        assert!(matches!(record.actor, ActorRef::System));
        assert!(record.ip_address.known().is_some());
        assert_eq!(record.acted_through, ActedThrough::Directly);
    }

    /// A sign-in attempt has no proven caller. The record names the account
    /// the event says was tried.
    #[test]
    fn an_anonymous_request_takes_the_actor_the_event_names() {
        let tenant_id = TenantId::new();
        let user_id = UserId::new();
        let event = login_failed(tenant_id).with_actor(ActorRef::User(user_id));
        let ctx = AuditContext::anonymous(crate::types::OrganizationId::new())
            .with_target_id(AuditTarget::Entity("user-123".to_owned()));

        let record = build_audit_record(&event, &ctx);

        assert!(matches!(record.actor, ActorRef::User(id) if id == user_id));
        assert_eq!(record.target.id(), Some("user-123"));
    }

    /// A failed sign-in naming nobody is recorded as anonymous in a request
    /// context, while a system context still records the platform as actor.
    #[test]
    fn an_anonymous_request_naming_nobody_is_recorded_as_anonymous() {
        let event = login_failed(TenantId::new());
        let anonymous = AuditContext::anonymous(crate::types::OrganizationId::new());

        let record = build_audit_record(&event, &anonymous);
        let system = build_audit_record(&event, &AuditContext::system());

        assert!(matches!(record.actor, ActorRef::Anonymous));
        assert!(matches!(system.actor, ActorRef::System));
    }

    /// A background job records a tenant event with no tenant in its
    /// context. The record takes the event's tenant, so it shows up in that
    /// tenant's log.
    #[test]
    fn prefers_event_tenant_when_context_has_none() {
        let tenant_id = TenantId::new();
        let event = login_failed(tenant_id).system();

        let record = build_audit_record(&event, &AuditContext::system());

        assert_eq!(record.scope.tenant_id(), Some(&tenant_id));
    }

    /// The request runs in tenant A but the event belongs to tenant B. The
    /// record goes under B, the tenant the action affected.
    #[test]
    fn event_tenant_takes_precedence_over_context() {
        let event_tenant = TenantId::new();
        let event = login_failed(event_tenant).system();
        let ctx = AuditContext::system().with_tenant(TenantId::new());

        let record = build_audit_record(&event, &ctx);

        assert_eq!(record.scope.tenant_id(), Some(&event_tenant));
    }

    /// An organization sign-in stays in the organization's audit scope even
    /// when the request context carries a tenant.
    #[test]
    fn an_organization_event_is_never_filed_under_the_requests_tenant() {
        let organization = OrganizationId::new();
        let event = DomainEvent::organization(Box::new(
            crate::domains::organization::events::access::OrgLoginSucceeded {
                organization_id: organization,
                org_user_id: crate::types::OrgUserId::new(),
                method: crate::domains::organization::events::access::OrgSignInMethod::Password,
                occurred_at: crate::shared::clock::now(),
            },
        ));
        let ctx = AuditContext::system().with_tenant(TenantId::new());

        let record = build_audit_record(&event, &ctx);

        assert_eq!(record.scope, AuditScope::Organization(organization));
    }

    /// Alice makes a request from 203.0.113.7. The record names Alice as the
    /// actor and keeps her IP.
    #[test]
    fn request_context_ip_and_actor_are_carried() {
        let user_id = UserId::new();
        let event = login_failed(TenantId::new()).system();
        let ctx = AuditContext::for_caller(OrganizationId::new(), ActorRef::User(user_id))
            .with_request(
                Fact::Known(IpAddress::new("203.0.113.7").unwrap()),
                Fact::Unknown,
            );

        let record = build_audit_record(&event, &ctx);

        assert!(matches!(record.actor, ActorRef::User(id) if id == user_id));
        assert_eq!(
            record.ip_address.known().map(IpAddress::as_str),
            Some("203.0.113.7")
        );
    }

    /// An operator acts as Bob. The record keeps both the operator and Bob,
    /// so the log shows who really did it.
    #[test]
    fn an_impersonated_action_records_the_operator_and_the_user() {
        let operator_id = OperatorId::new();
        let as_user = UserId::new();
        let ctx = AuditContext::system().impersonating(operator_id, as_user);

        let record = build_audit_record(&login_failed(TenantId::new()).system(), &ctx);

        assert_eq!(
            record.acted_through,
            ActedThrough::Impersonation {
                operator_id,
                as_user
            }
        );
    }

    /// Sam, a tenant admin, acts as Bob for support. The record names Sam
    /// as the actor and keeps Bob and the impersonation, so the log shows
    /// it was done as Bob and by whom.
    #[test]
    fn a_support_impersonated_action_records_the_admin_and_the_person() {
        let acting = SupportActing {
            admin: UserId::new(),
            as_user: UserId::new(),
            impersonation: SupportImpersonationId::new(),
        };
        let ctx = AuditContext::for_caller(OrganizationId::new(), ActorRef::User(acting.admin))
            .supporting(acting);

        let record = build_audit_record(&login_failed(TenantId::new()).system(), &ctx);

        assert!(matches!(record.actor, ActorRef::User(id) if id == acting.admin));
        assert_eq!(
            record.acted_through,
            ActedThrough::SupportImpersonation {
                admin: acting.admin,
                as_user: acting.as_user,
                impersonation: acting.impersonation,
            }
        );
    }

    /// Bob, an operator, does something on the platform in no organization.
    /// The record names Bob, never the system.
    #[test]
    fn a_platform_callers_record_names_the_caller() {
        let bob = crate::types::OperatorId::new();
        let event = login_failed(TenantId::new()).system();

        let record = build_audit_record(
            &event,
            &AuditContext::for_platform_caller(ActorRef::Operator(bob)),
        );

        assert!(matches!(record.actor, ActorRef::Operator(id) if id == bob));
    }

    /// Bob, an operator, acts as Ann from a known address, and the failed
    /// sign-in is recorded. Read back from its record and recorded again,
    /// it gives the same record in every part but its id.
    #[test]
    fn a_record_read_back_records_the_same_again() {
        let tenant_id = TenantId::new();
        let ctx = AuditContext::for_caller(OrganizationId::new(), ActorRef::User(UserId::new()))
            .with_tenant(tenant_id)
            .with_request(
                Fact::Known(IpAddress::new("10.0.0.1").unwrap()),
                Fact::Unknown,
            )
            .with_target_id(AuditTarget::Entity("session-1".to_owned()))
            .impersonating(OperatorId::new(), UserId::new());
        let first = build_audit_record(&login_failed(tenant_id), &ctx);

        let read = read_back(&first, EventOrigin::Outside);
        let again = build_audit_record(&read.event, &read.context);

        assert_eq!(again.actor.audit_label(), first.actor.audit_label());
        assert_eq!(again.scope, first.scope);
        assert_eq!(again.event_type, first.event_type);
        assert_eq!(again.target, first.target);
        assert_eq!(again.ip_address, first.ip_address);
        assert_eq!(again.user_agent, first.user_agent);
        assert_eq!(again.payload, first.payload);
        assert_eq!(again.acted_through, first.acted_through);
        assert_eq!(again.occurred_at, first.occurred_at);
    }

    /// An organization's record reads back as the organization's event,
    /// never as a tenant's or the platform's.
    #[test]
    fn an_organizations_record_reads_back_as_the_organizations() {
        let organization = OrganizationId::new();
        let event = crate::test_support::events::sample_organization_event(
            organization,
            crate::shared::clock::now(),
        );
        let record = build_audit_record(&event, &AuditContext::system());

        let read = read_back(&record, EventOrigin::Outside);

        assert_eq!(read.event.organization_id(), Some(&organization));
        assert!(read.event.tenant_id().is_none());
    }

    /// A tenant's event raised by an execution's work keeps the depth the
    /// reader says, so a workflow it sets off continues the chain.
    #[test]
    fn a_tenant_record_read_back_keeps_the_origin_given() {
        let tenant_id = TenantId::new();
        let record = build_audit_record(&login_failed(tenant_id).system(), &AuditContext::system());
        let origin = EventOrigin::Execution(crate::shared::events::chain::ChainDepth::FIRST);

        let read = read_back(&record, origin);

        assert_eq!(read.event.origin(), origin);
        assert_eq!(read.event.tenant_id(), Some(&tenant_id));
    }
}
