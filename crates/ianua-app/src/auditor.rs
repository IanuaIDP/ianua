//! Request-scoped audit dispatcher.
//!
//! [`RequestAuditor`] binds the shared [`EventDispatcher`] sink to a single
//! request's [`AuditContext`] once, at the request boundary. Use cases then
//! call [`RequestAuditor::dispatch`] with only the events, the actor, IP, and
//! tenant are already bound and cannot be forgotten at the dispatch site.
//!
//! Because use cases no longer hold an `Arc<dyn EventDispatcher>` directly,
//! there is no path to dispatch that bypasses the bound context. That is the
//! type-level guarantee: every audit record carries the resolved caller and
//! request metadata (or, for genuine non-request origins, an explicit
//! [`RequestAuditor::system`] context).

use std::sync::Arc;

use ianua_domain::domains::audit::builder::AuditContext;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::chain::EventOrigin;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::{Raises, SavedFor};
use ianua_domain::types::{ActorRef, Fact, IpAddress, OrganizationId, TenantId, UserAgent, UserId};

use crate::ports::shared::EventDispatcher;

/// The only way a use case reaches the audit sink.
///
/// Constructed once at the request boundary (API handler, seed, worker) from a
/// resolved [`AuditContext`] and the shared [`EventDispatcher`], then passed by
/// reference into every `execute`. Use cases call
/// [`dispatch`](Self::dispatch) and never see the underlying context.
#[derive(Clone)]
pub struct RequestAuditor {
    sink: Arc<dyn EventDispatcher>,
    ctx: AuditContext,
}

impl RequestAuditor {
    /// Binds a sink to a fully-resolved request context.
    ///
    /// Use at the edge after the scope/extractor has resolved identity,
    /// org/tenant, IP, and user-agent.
    #[must_use]
    pub fn new(sink: Arc<dyn EventDispatcher>, ctx: AuditContext) -> Self {
        Self { sink, ctx }
    }

    /// This auditor, marking every event it dispatches as raised by the
    /// work of an execution at `origin`, so a workflow that event sets off
    /// continues that execution's chain and a chain of workflows always
    /// ends.
    #[must_use]
    pub fn from_execution(mut self, origin: EventOrigin) -> Self {
        self.ctx = self.ctx.from_execution(origin);
        self
    }

    /// Background or boot origin, no caller, IP, or tenant.
    ///
    /// For genuine non-request origins only: `MODE=seed`, scheduled jobs that
    /// don't carry a caller. Resulting records fall back to `ActorRef::System`.
    /// Prefer [`new`](Self::new) whenever a caller exists.
    #[must_use]
    pub fn system(sink: Arc<dyn EventDispatcher>) -> Self {
        Self {
            sink,
            ctx: AuditContext::system(),
        }
    }

    /// Dispatches `events` to the bound sink with the bound context.
    ///
    /// # Errors
    ///
    /// Propagates `DomainError::Infrastructure` if audit persistence fails.
    /// Event-bus failures remain best-effort (logged by the sink).
    //
    // This is the single legitimate call to the raw sink; the bound context
    // is what makes it safe. See clippy.toml's `disallowed-methods`.
    #[allow(clippy::disallowed_methods)]
    pub async fn dispatch(&self, events: &[DomainEvent]) -> Result<(), DomainError> {
        self.sink.dispatch(events, &self.ctx).await
    }

    /// Dispatches `events` as done by `actor`, in the order given: what an
    /// aggregate raised and handed over once its change was saved.
    ///
    /// # Errors
    ///
    /// As [`dispatch`](Self::dispatch).
    pub async fn dispatch_by(
        &self,
        actor: &ActorRef,
        events: Vec<DomainEvent>,
    ) -> Result<(), DomainError> {
        let recorded: Vec<DomainEvent> = events
            .into_iter()
            .map(|event| event.with_actor(actor.clone()))
            .collect();
        self.dispatch(&recorded).await
    }

    /// Read-only access to the bound context (for fan-out, tracing).
    #[must_use]
    pub fn context(&self) -> &AuditContext {
        &self.ctx
    }

    /// Returns a new auditor recording to the same trail as `ctx` says, for
    /// work a background job does as a person, such as a workflow run's
    /// company step acting as the person the run is for.
    #[must_use]
    pub fn recording_as(&self, ctx: AuditContext) -> Self {
        Self {
            sink: self.sink.clone(),
            ctx,
        }
    }

    /// Returns a new auditor scoped to `organization_id`, for unauthenticated
    /// flows (login) where the org is resolved inside the use case rather than
    /// at the request boundary.
    #[must_use]
    pub fn with_organization(&self, organization_id: OrganizationId) -> Self {
        Self {
            sink: self.sink.clone(),
            ctx: self.ctx.clone().with_organization(organization_id),
        }
    }

    /// Returns a new auditor scoped to `tenant_id`, for unauthenticated flows
    /// where the tenant is resolved inside the use case.
    #[must_use]
    pub fn with_tenant(&self, tenant_id: TenantId) -> Self {
        Self {
            sink: self.sink.clone(),
            ctx: self.ctx.clone().with_tenant(tenant_id),
        }
    }

    /// Returns a new auditor carrying the client's address and user agent,
    /// for requests relayed through another service, whose client is only
    /// known once the relayed request is opened.
    #[must_use]
    pub fn with_request(
        &self,
        ip_address: Option<IpAddress>,
        user_agent: Option<UserAgent>,
    ) -> Self {
        Self {
            sink: self.sink.clone(),
            ctx: self
                .ctx
                .clone()
                .with_request(Fact::from_option(ip_address), Fact::from_option(user_agent)),
        }
    }
}

/// What `raiser` raised once saved for `tenant`, each event made by the
/// account holder `holder`, to be dispatched later with others.
pub(crate) fn raised_by_holder(
    raiser: &mut impl Raises,
    tenant: &impl SavedFor,
    holder: UserId,
) -> Vec<DomainEvent> {
    let actor = ActorRef::User(holder);
    raiser
        .take_events(tenant)
        .into_iter()
        .map(|event| event.with_actor(actor.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use ianua_domain::domains::audit::builder::AuditActor;
    use ianua_domain::types::{ActorRef, Fact, IpAddress, OrganizationId, TenantId, UserId};

    use super::*;

    /// A sink that captures every `AuditContext` it was dispatched with.
    struct CapturingDispatcher {
        seen: Mutex<Vec<AuditContext>>,
    }

    #[async_trait]
    impl EventDispatcher for CapturingDispatcher {
        async fn dispatch(
            &self,
            _events: &[DomainEvent],
            ctx: &AuditContext,
        ) -> Result<(), DomainError> {
            self.seen.lock().unwrap().push(ctx.clone());
            Ok(())
        }
    }

    /// Ann's request is audited. The record that reaches the audit sink names
    /// Ann as the actor and keeps the address her request came from.
    #[test]
    fn dispatch_passes_bound_context_to_sink() {
        let sink = Arc::new(CapturingDispatcher {
            seen: Mutex::new(Vec::new()),
        });
        let user = UserId::new();
        let ctx = AuditContext::for_caller(OrganizationId::new(), ActorRef::User(user))
            .with_request(
                Fact::Known(IpAddress::new("203.0.113.7").unwrap()),
                Fact::Unknown,
            );
        let auditor = RequestAuditor::new(sink.clone(), ctx);

        crate::test_support::block_on(auditor.dispatch(&[])).unwrap();

        let seen = sink.seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "the sink must receive the bound context");
        assert!(matches!(seen[0].actor(), AuditActor::Caller(ActorRef::User(id)) if *id == user));
        assert_eq!(
            seen[0].ip_address().known().map(IpAddress::as_str),
            Some("203.0.113.7")
        );
    }

    /// A sink that keeps who each dispatched event names as its actor.
    struct ActorCapturingDispatcher {
        actors: Mutex<Vec<Option<ActorRef>>>,
    }

    #[async_trait]
    impl EventDispatcher for ActorCapturingDispatcher {
        async fn dispatch(
            &self,
            events: &[DomainEvent],
            _ctx: &AuditContext,
        ) -> Result<(), DomainError> {
            let mut actors = self.actors.lock().unwrap();
            actors.extend(
                events
                    .iter()
                    .map(|event| event.performed_by().cloned().known().cloned()),
            );
            Ok(())
        }
    }

    /// Ann pauses a topic and resumes it in one change. Both events the
    /// topic raised reach the sink naming Ann as the one who acted.
    #[test]
    fn dispatch_by_names_the_actor_on_every_event() {
        let sink = Arc::new(ActorCapturingDispatcher {
            actors: Mutex::new(Vec::new()),
        });
        let auditor = RequestAuditor::system(sink.clone());
        let ann = UserId::new();
        let events = vec![
            ianua_domain::test_support::events::sample_tenant_event(TenantId::new()),
            ianua_domain::test_support::events::sample_tenant_event(TenantId::new()),
        ];

        crate::test_support::block_on(auditor.dispatch_by(&ActorRef::User(ann), events)).unwrap();

        let actors = sink.actors.lock().unwrap();
        assert_eq!(actors.len(), 2);
        assert!(
            actors
                .iter()
                .all(|actor| matches!(actor, Some(ActorRef::User(id)) if *id == ann))
        );
    }

    /// Once the organization and tenant are known, the auditor records both,
    /// so its events land in the right place.
    #[test]
    fn with_organization_and_tenant_set_scope() {
        let sink: Arc<dyn EventDispatcher> = Arc::new(CapturingDispatcher {
            seen: Mutex::new(Vec::new()),
        });
        let auditor = RequestAuditor::system(sink)
            .with_organization(OrganizationId::new())
            .with_tenant(TenantId::new());

        assert!(auditor.context().organization_id().known().is_some());
        assert!(auditor.context().tenant_id().known().is_some());
    }

    /// Adding the organization and tenant later does not lose the address
    /// the request came from.
    #[test]
    fn enrichment_preserves_request_metadata() {
        let sink: Arc<dyn EventDispatcher> = Arc::new(CapturingDispatcher {
            seen: Mutex::new(Vec::new()),
        });
        let auditor = RequestAuditor::new(
            sink,
            AuditContext::system().with_request(
                Fact::Known(IpAddress::new("198.51.100.4").unwrap()),
                Fact::Unknown,
            ),
        )
        .with_organization(OrganizationId::new())
        .with_tenant(TenantId::new());

        assert_eq!(
            auditor
                .context()
                .ip_address()
                .known()
                .map(IpAddress::as_str),
            Some("198.51.100.4")
        );
        assert!(auditor.context().organization_id().known().is_some());
        assert!(auditor.context().tenant_id().known().is_some());
    }
}
