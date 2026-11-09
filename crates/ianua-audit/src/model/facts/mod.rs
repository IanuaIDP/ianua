//! Facts about each use case and each domain change, read from the code,
//! for `explain` and `impact`.
//!
//! A use case's facts are what its `execute` and the helpers it calls say,
//! at most [`FOLLOW_DEPTH`] calls away: the methods it calls on each port,
//! the domain changes it calls, the rights and plan limits it checks, the
//! events it dispatches and the `AppError` variants it documents and
//! writes. A helper is followed when it is a method of the use case, a
//! function of the same file, or an app function the file imports by a
//! `crate::`, `super::` or `self::` path, such as a shared service in
//! `services/`. Each fact found in a helper says which, as `via`.
//!
//! The domain side comes from the domain model: each change's rights and
//! the events it raises, read by [`crate::model::raising`]. A change is
//! joined to a use case only when the reader knows the type of the value it
//! is called on: a creator by its path, `WebhookSubscription::create`, and
//! a change on a value whose type the reader followed from an annotation, a
//! port method, a helper or a domain function that returns it. A call it
//! cannot place is kept as not read, never guessed.

mod body;
mod change;
pub(crate) mod flow;
mod known;
mod order;
mod scope;
mod shape;
mod use_case;

use serde::Serialize;

pub(crate) use self::flow::Flow;
use self::known::Known;
use crate::model::Model;
use crate::model::paths::AppItem;
use crate::model::raising::RightFound;
use crate::source::{Place, Workspace};

/// How many helper calls away from `execute` facts are still read. Each
/// helper is read once, and one that calls itself again is not unrolled,
/// so the depth only bounds how long a `via` chain grows.
pub(crate) const FOLLOW_DEPTH: usize = 10;

/// Everything read about the use cases, the domain changes and the app's
/// shared services.
#[derive(Debug, Default, Serialize)]
pub(crate) struct Facts {
    /// One entry per use case.
    pub(crate) use_cases: Vec<UseCaseFacts>,
    /// One entry per public creator or change of a domain aggregate.
    pub(crate) changes: Vec<ChangeFacts>,
    /// One entry per function in the app's `services/`.
    pub(crate) services: Vec<ServiceFacts>,
}

impl Facts {
    /// Reads the facts of every use case, change and service in
    /// `workspace`, joined through `model`.
    pub(crate) fn build(workspace: &Workspace, model: &Model) -> Self {
        let known = Known::new(workspace, model);
        let use_cases: Vec<UseCaseFacts> = model
            .app
            .use_cases
            .iter()
            .map(|found| use_case::read(&known, found))
            .collect();
        Self {
            changes: change::read_all(&known, &use_cases),
            services: use_case::read_services(&known),
            use_cases,
        }
    }
}

/// What one use case does, as far as its code says.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct UseCaseFacts {
    /// Its type's name.
    pub(crate) name: String,
    /// `command` or `query`.
    pub(crate) kind: &'static str,
    /// The context folder it is in.
    pub(crate) context: String,
    /// Where it is implemented.
    pub(crate) place: Place,
    /// `type Caller` as written.
    pub(crate) caller: Option<String>,
    /// `type Input` as written.
    pub(crate) input: Option<String>,
    /// `type Output` as written.
    pub(crate) output: Option<String>,
    /// The `*Ports` struct it holds.
    pub(crate) ports_struct: Option<String>,
    /// Each port it holds or calls, with the methods called on it.
    pub(crate) ports: Vec<PortUse>,
    /// The domain changes it calls, each with what the domain says of it.
    pub(crate) changes: Vec<ChangeCall>,
    /// The rights it checks itself, outside the domain changes.
    pub(crate) rights: Vec<RightFound>,
    /// The plan limits it checks.
    pub(crate) limits: Vec<LimitCheck>,
    /// Each dispatch of events, with the events it sends.
    pub(crate) dispatches: Vec<Dispatch>,
    /// The `AppError` variants its `# Errors` section names.
    pub(crate) documented_errors: Vec<DocumentedError>,
    /// The `AppError` variants written in its body and helpers.
    pub(crate) written_errors: Vec<String>,
    /// What the reader met and could not read.
    pub(crate) not_read: Vec<NotRead>,
    /// What its flow says of the order of its steps, such as a limit
    /// checked before a create on every path.
    pub(crate) order: Vec<OrderFact>,
    /// Its flow: its steps in order, with the helpers it follows.
    #[serde(skip)]
    pub(crate) flow: Flow,
    /// Where a path that runs off the end of `execute` is said to leave.
    #[serde(skip)]
    pub(crate) end: Place,
}

/// One thing the flow says of the order of a use case's steps.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct OrderFact {
    /// What, in words.
    pub(crate) what: String,
    /// Where it is shown, when it is shown somewhere.
    pub(crate) place: Option<Place>,
}

/// A port a use case holds or calls.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct PortUse {
    /// The field of the `*Ports` struct, when known.
    pub(crate) field: Option<String>,
    /// The port trait's name, when known.
    pub(crate) trait_name: Option<String>,
    /// The port trait, when the reader knows which of the ports of that
    /// name it is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) port: Option<AppItem>,
    /// The field's type as written, when the field is known.
    pub(crate) written: Option<String>,
    /// The methods called on it.
    pub(crate) calls: Vec<Call>,
}

/// A method or function called, where, and through which helpers.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct Call {
    /// The method's name.
    pub(crate) name: String,
    /// Where the call is written.
    pub(crate) place: Place,
    /// The helpers it goes through, as `a > b`.
    pub(crate) via: Option<String>,
}

/// A domain change a use case calls.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct ChangeCall {
    /// The aggregate.
    pub(crate) owner: String,
    /// The creator or change.
    pub(crate) name: String,
    /// `create` or `change`.
    pub(crate) kind: &'static str,
    /// Where the call is written.
    pub(crate) place: Place,
    /// The helpers it goes through.
    pub(crate) via: Option<String>,
    /// The caller proofs its signature takes, such as `OperatorAuthority`:
    /// a right held by type rather than checked by a call.
    pub(crate) takes: Vec<String>,
    /// The rights the change checks.
    pub(crate) rights: Vec<RightFound>,
    /// The events the change raises.
    pub(crate) events: Vec<EventFact>,
}

impl ChangeCall {
    /// `Owner::name`.
    pub(crate) fn subject(&self) -> String {
        format!("{}::{}", self.owner, self.name)
    }
}

/// An event, with the dotted type it is recorded under when the domain
/// names one.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct EventFact {
    /// The event struct.
    pub(crate) name: String,
    /// Such as `webhooks.subscription_created`.
    pub(crate) event_type: Option<String>,
}

/// A plan limit checked.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct LimitCheck {
    /// The `ResourceKind` variant.
    pub(crate) kind: String,
    /// The function handed it, such as `ensure_room_in_tenant`.
    pub(crate) call: String,
    /// Where.
    pub(crate) place: Place,
    /// The helpers it goes through.
    pub(crate) via: Option<String>,
}

/// One call that dispatches events.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Dispatch {
    /// `dispatch` or `dispatch_by`.
    pub(crate) method: String,
    /// Where.
    pub(crate) place: Place,
    /// The helpers it goes through.
    pub(crate) via: Option<String>,
    /// The events it sends, as far as read.
    pub(crate) events: Vec<EventFact>,
    /// What it sends that the reader could not read.
    pub(crate) not_read: Vec<String>,
}

/// One `AppError` variant a `# Errors` section names.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct DocumentedError {
    /// The variant, such as `Forbidden`.
    pub(crate) variant: String,
    /// The doc entry it is named in, as written.
    pub(crate) text: String,
}

/// Something the reader met and could not read.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct NotRead {
    /// What, in words.
    pub(crate) what: String,
    /// Where.
    pub(crate) place: Place,
}

/// What a domain creator or change does, and who calls it.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct ChangeFacts {
    /// The aggregate.
    pub(crate) owner: String,
    /// The creator or change.
    pub(crate) name: String,
    /// `create` or `change`.
    pub(crate) kind: &'static str,
    /// The context it is in.
    pub(crate) context: String,
    /// Where it is declared.
    pub(crate) place: Place,
    /// The caller proofs its signature takes, such as `WebhookControl`.
    pub(crate) takes: Vec<String>,
    /// The rights it checks.
    pub(crate) rights: Vec<RightFound>,
    /// The events it raises.
    pub(crate) events: Vec<EventFact>,
    /// The use cases that call it.
    pub(crate) callers: Vec<CallerRef>,
}

impl ChangeFacts {
    /// `Owner::name`.
    pub(crate) fn subject(&self) -> String {
        format!("{}::{}", self.owner, self.name)
    }
}

/// A use case calling a change.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct CallerRef {
    /// The use case.
    pub(crate) use_case: String,
    /// Its context.
    pub(crate) context: String,
    /// Where it calls the change.
    pub(crate) place: Place,
    /// The helpers the call goes through.
    pub(crate) via: Option<String>,
}

/// What one function of the app's `services/` calls.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct ServiceFacts {
    /// `Owner::name`, or the bare name of a free function.
    pub(crate) function: String,
    /// Where it is declared.
    pub(crate) place: Place,
    /// The port methods it calls, as `(trait, method, place)`.
    pub(crate) port_calls: Vec<(AppItem, String, Place)>,
    /// The domain changes it calls, as `(owner, name, place)`.
    pub(crate) changes: Vec<(String, String, Place)>,
}

#[cfg(test)]
pub(crate) mod planted {
    //! A small webhooks context, read whole, for the facts and the
    //! commands built on them.

    use crate::model::Model;
    use crate::model::domain::DomainLists;
    use crate::source::Workspace;
    use crate::source::planted::{app, domain, workspace};

    /// A subscription with a creator and a change, each checking a right
    /// and raising an event.
    pub(crate) const SUBSCRIPTION: &str = r#"
        pub struct WebhookSubscription<T> { raised: Raised<T> }
        impl<T: TenantScope> WebhookSubscription<T> {
            pub fn create(params: CreateWebhookParams, control: &WebhookControl<'_>) -> Result<Self, DomainError> {
                control.ensure_may(WebhooksAction::Update)?;
                let mut subscription = Self { raised: Raised::default() };
                subscription.raised.raise(WebhookSubscriptionCreated { at: now() });
                Ok(subscription)
            }
            pub fn reconstitute(row: WebhookSubscriptionRow) -> Result<Self, DomainError> { make() }
            pub fn pause(&mut self, control: &WebhookControl<'_>) -> Result<(), DomainError> {
                control.ensure_may(WebhooksAction::Update)?;
                self.raised.raise(WebhookSubscriptionPaused { at: now() });
                Ok(())
            }
            pub fn id(&self) -> &WebhookSubscriptionId { &self.id }
        }
        pub struct WebhookControl<'a> { authority: &'a TenantAuthority }
        tenant_event! { WebhookSubscriptionCreated => WebhooksEvent::SubscriptionCreated }
        tenant_event! { WebhookSubscriptionPaused => WebhooksEvent::SubscriptionPaused }
        event_types! {
            pub enum WebhooksEvent {
                SubscriptionCreated => "webhooks.subscription_created",
                SubscriptionPaused => "webhooks.subscription_paused",
            }
        }
    "#;

    /// The webhook ports.
    pub(crate) const PORTS: &str = r"
        pub trait WebhookStore: Send + Sync {
            async fn find_by_id(&self, tenant: &ScopedTenant, id: &WebhookSubscriptionId)
                -> Result<Option<WebhookSubscription<ResolvedTenant>>, DomainError>;
            async fn save(&self, tenant: &ScopedTenant, subscription: &WebhookSubscription<ResolvedTenant>)
                -> Result<(), DomainError>;
        }
        pub trait WebhookSecretGenerator: Send + Sync {
            async fn generate(&self) -> Result<Secret, DomainError>;
        }
    ";

    /// The limit ports and the shared room check.
    pub(crate) const LIMITS: &str = r"
        pub trait LimitEnforcer: Send + Sync {
            async fn check_tenant_limit(&self, kind: ResourceKind) -> Result<(), DomainError>;
        }
    ";

    /// The shared limit check in `services/`.
    pub(crate) const ROOM: &str = r"
        pub(crate) async fn ensure_room_in_tenant(
            enforcer: &dyn LimitEnforcer,
            caller: &CallerContext,
            kind: ResourceKind,
        ) -> Result<(), AppError> {
            enforcer.check_tenant_limit(kind).await.map_err(AppError::from_domain)
        }
    ";

    /// Loading a subscription, beside the use cases.
    pub(crate) const LOOKUP: &str = r#"
        pub(super) async fn existing_subscription(
            store: &dyn WebhookStore,
            id: &WebhookSubscriptionId,
        ) -> Result<WebhookSubscription<ResolvedTenant>, AppError> {
            store.find_by_id(&tenant, id).await.or_internal()?.or_not_found("gone")
        }
    "#;

    /// Creating a subscription through a helper of the same file.
    pub(crate) const CREATE: &str = r#"
        use crate::services::limits::room::ensure_room_in_tenant;
        use crate::use_cases::webhooks::missing::gone_helper;

        pub struct CreatePorts {
            pub webhook_store: Arc<dyn WebhookStore>,
            pub secret_generator: Arc<dyn WebhookSecretGenerator>,
            pub limit_enforcer: Arc<dyn LimitEnforcer>,
        }
        pub struct CreateUseCase { ports: CreatePorts }
        impl CreateUseCase {
            async fn new_secret(&self) -> Result<Secret, AppError> {
                self.ports.secret_generator.generate().await.or_internal()
            }
        }
        impl Command for CreateUseCase {
            type Caller = CallerContext;
            type Input = CreateRequest;
            type Output = Result<CreatedSubscription, AppError>;

            /// Creates it.
            ///
            /// # Errors
            ///
            /// - `AppError::Forbidden` when the caller may not, or the
            ///   plan's limit is reached.
            /// - `AppError::Internal` on storage failure.
            async fn execute(&self, caller: &CallerContext, auditor: &RequestAuditor, request: CreateRequest)
                -> Result<CreatedSubscription, AppError> {
                ensure_room_in_tenant(self.ports.limit_enforcer.as_ref(), caller, ResourceKind::Webhooks).await?;
                let secret = self.new_secret().await?;
                let mut subscription = new_subscription(request, &authority)?;
                self.ports.webhook_store.save(&tenant, &subscription).await.or_internal()?;
                auditor.dispatch_by(&caller.actor(), subscription.take_events(&tenant)).await.or_internal()?;
                gone_helper();
                Err(AppError::Conflict("taken".into()))
            }
        }
        fn new_subscription(request: CreateRequest, authority: &TenantAuthority)
            -> Result<WebhookSubscription<ResolvedTenant>, AppError> {
            WebhookSubscription::create(request.params, &WebhookControl::new(authority)).map_err(AppError::from_domain)
        }
    "#;

    /// Pausing a subscription loaded through a helper of another file, with
    /// a right checked in the use case too.
    pub(crate) const PAUSE: &str = r"
        use crate::use_cases::webhooks::lookup::existing_subscription;

        pub struct PausePorts { pub webhook_store: Arc<dyn WebhookStore> }
        pub struct PauseUseCase { ports: PausePorts }
        impl Command for PauseUseCase {
            type Caller = CallerContext;
            type Input = WebhookSubscriptionId;
            type Output = Result<(), AppError>;
            async fn execute(&self, caller: &CallerContext, auditor: &RequestAuditor, id: WebhookSubscriptionId)
                -> Result<(), AppError> {
                control.ensure_may(WebhooksAction::Update).map_err(AppError::from_domain)?;
                let mut subscription = existing_subscription(self.ports.webhook_store.as_ref(), &id).await?;
                subscription.pause(&control).map_err(AppError::from_domain)?;
                for other in others { other.pause(&control); }
                self.ports.webhook_store.save(&tenant, &subscription).await.or_internal()?;
                auditor.dispatch_by(&caller.actor(), subscription.take_events(&tenant)).await.or_internal()
            }
        }
    ";

    /// A query that holds no `*Ports` struct.
    pub(crate) const LIST: &str = r"
        pub struct ListUseCase { store: Store }
        impl Query for ListUseCase {
            type Caller = CallerContext;
            type Input = ();
            type Output = Vec<Thing>;
            async fn execute(&self, caller: &CallerContext, input: ()) -> Vec<Thing> { self.store.all() }
        }
    ";

    /// Revoking every operator key: a creator that takes an operator proof
    /// and checks no right by a call.
    pub(crate) const REVOCATION: &str = r#"
        pub struct EveryKeyRevocation { raised: RaisedEvents }
        impl EveryKeyRevocation {
            pub fn revoke(keys: Vec<OperatorApiKey>, by: &OperatorAuthority) -> Result<Self, DomainError> {
                let mut revocation = Self { raised: RaisedEvents::default() };
                revocation.raised.raise_platform(OperatorApiKeysRevoked { at: now() });
                Ok(revocation)
            }
        }
        impl RaisesComplete for EveryKeyRevocation {
            fn take_events(&mut self) -> Vec<DomainEvent> { take() }
        }
        pub struct OperatorAuthority { operator: OperatorId }
        platform_event! { OperatorApiKeysRevoked => OperatorEvent::KeysRevoked }
        event_types! {
            pub enum OperatorEvent { KeysRevoked => "operator.keys_revoked" }
        }
    "#;

    /// The operator key ports, whose `*Ports` struct settles a revocation
    /// in a method of its own: it clears the token cache and dispatches.
    pub(crate) const REVOKE_PORTS: &str = r"
        pub trait OperatorKeyStore { async fn list_by_operator(&self) -> Result<Vec<OperatorApiKey>, DomainError>; }
        pub trait TokenLookup { async fn invalidate_all(&self) -> Result<(), DomainError>; }
    ";

    /// The ports struct with its method, beside the one-key use case.
    pub(crate) const REVOKE: &str = r"
        pub struct RevokeOperatorPorts {
            pub key_store: Arc<dyn OperatorKeyStore>,
            pub token_lookup: Arc<dyn TokenLookup>,
        }
        impl RevokeOperatorPorts {
            pub(super) async fn settle_revocation(
                &self,
                auditor: &RequestAuditor,
                by: &OperatorAuthority,
                events: Vec<DomainEvent>,
            ) -> Result<(), AppError> {
                self.token_lookup.invalidate_all().await.or_internal()?;
                auditor.dispatch_by(&by.actor(), events).await.or_internal()
            }
        }
    ";

    /// Revoking every key, settled through the ports struct's method.
    pub(crate) const REVOKE_ALL: &str = r"
        use crate::use_cases::operator::keys::revoke::RevokeOperatorPorts;

        pub struct RevokeAllOperatorUseCase { ports: RevokeOperatorPorts }
        impl RevokeAllOperatorUseCase {
            async fn revoke_each(&self, by: &OperatorAuthority) -> Result<EveryKeyRevocation, AppError> {
                let held = self.ports.key_store.list_by_operator().await.or_internal()?;
                EveryKeyRevocation::revoke(held, by).map_err(AppError::from_domain)
            }
        }
        impl Command for RevokeAllOperatorUseCase {
            type Caller = OperatorCaller;
            type Input = ();
            type Output = Result<u64, AppError>;
            async fn execute(&self, caller: &OperatorCaller, auditor: &RequestAuditor, (): ()) -> Result<u64, AppError> {
                let mut revocation = self.revoke_each(&authority).await?;
                self.ports.settle_revocation(auditor, &authority, revocation.take_events()).await?;
                Ok(count)
            }
        }
    ";

    /// A use case whose ports and auditor go into calls the reader cannot
    /// follow.
    pub(crate) const OPAQUE: &str = r"
        use crate::use_cases::operator::keys::revoke::RevokeOperatorPorts;

        pub struct RotateUseCase { ports: RevokeOperatorPorts }
        impl Command for RotateUseCase {
            type Caller = OperatorCaller;
            type Input = ();
            type Output = Result<(), AppError>;
            async fn execute(&self, caller: &OperatorCaller, auditor: &RequestAuditor, (): ()) -> Result<(), AppError> {
                self.ports.settle_elsewhere(auditor).await?;
                external::record(auditor, ()).await
            }
        }
    ";

    /// The operator files, read whole.
    pub(crate) fn operator() -> Workspace {
        workspace(vec![
            domain("domains/operator/api_key.rs", REVOCATION),
            app("ports/operator.rs", REVOKE_PORTS),
            app("use_cases/operator/keys/revoke.rs", REVOKE),
            app("use_cases/operator/keys/revoke_all.rs", REVOKE_ALL),
            app("use_cases/operator/keys/rotate.rs", OPAQUE),
        ])
    }

    /// The planted files.
    pub(crate) fn planted() -> Workspace {
        workspace(vec![
            domain("domains/webhooks/subscription.rs", SUBSCRIPTION),
            app("ports/webhooks.rs", PORTS),
            app("ports/limits.rs", LIMITS),
            app("services/limits/room.rs", ROOM),
            app("use_cases/webhooks/lookup.rs", LOOKUP),
            app("use_cases/webhooks/subscriptions/create.rs", CREATE),
            app("use_cases/webhooks/subscriptions/pause.rs", PAUSE),
            app("use_cases/webhooks/subscriptions/list.rs", LIST),
        ])
    }

    /// The model of `ws`, with `WebhookControl` as a caller proof.
    pub(crate) fn model(ws: &Workspace) -> Model {
        let lists = DomainLists {
            proofs: vec!["WebhookControl".to_owned(), "OperatorAuthority".to_owned()],
            ..DomainLists::default()
        };
        Model::build(ws, &lists)
    }
}

#[cfg(test)]
mod tests {
    use super::planted::{model, planted};
    use super::*;
    use crate::source::SourceFile;

    fn facts() -> Facts {
        let ws = planted();
        Facts::build(&ws, &model(&ws))
    }

    fn use_case<'f>(facts: &'f Facts, name: &str) -> &'f UseCaseFacts {
        facts
            .use_cases
            .iter()
            .find(|found| found.name == name)
            .unwrap()
    }

    fn calls(facts: &UseCaseFacts) -> Vec<(String, String, Option<String>)> {
        facts
            .ports
            .iter()
            .flat_map(|port| {
                port.calls.iter().map(|call| {
                    (
                        format!("{}.{}", port.field.clone().unwrap_or_default(), call.name),
                        port.trait_name.clone().unwrap_or_default(),
                        call.via.clone(),
                    )
                })
            })
            .collect()
    }

    #[test]
    fn the_caller_input_and_output_are_read_as_written() {
        let found = facts();

        let create = use_case(&found, "CreateUseCase");

        assert_eq!(create.caller.as_deref(), Some("CallerContext"));
        assert_eq!(create.input.as_deref(), Some("CreateRequest"));
        assert_eq!(
            create.output.as_deref(),
            Some("Result<CreatedSubscription, AppError>")
        );
    }

    #[test]
    fn port_calls_are_read_directly_and_through_own_methods_and_services() {
        let found = facts();

        let create = use_case(&found, "CreateUseCase");

        assert_eq!(
            calls(create),
            [
                (
                    "webhook_store.save".to_owned(),
                    "WebhookStore".to_owned(),
                    None
                ),
                (
                    "secret_generator.generate".to_owned(),
                    "WebhookSecretGenerator".to_owned(),
                    Some("new_secret".to_owned())
                ),
                (
                    "limit_enforcer.check_tenant_limit".to_owned(),
                    "LimitEnforcer".to_owned(),
                    Some("ensure_room_in_tenant".to_owned())
                ),
            ]
        );
    }

    #[test]
    fn a_creator_in_a_helper_is_joined_with_its_rights_and_events() {
        let found = facts();

        let change = &use_case(&found, "CreateUseCase").changes[0];

        assert_eq!(change.subject(), "WebhookSubscription::create");
        assert_eq!(change.via.as_deref(), Some("new_subscription"));
        assert_eq!(
            change.rights[0].check.right.as_deref(),
            Some("WebhooksAction::Update")
        );
        assert_eq!(
            change.events,
            [EventFact {
                name: "WebhookSubscriptionCreated".to_owned(),
                event_type: Some("webhooks.subscription_created".to_owned()),
            }]
        );
    }

    #[test]
    fn a_change_on_a_value_a_helper_of_another_file_hands_back_is_joined() {
        let found = facts();

        let pause = use_case(&found, "PauseUseCase");

        let subjects: Vec<String> = pause.changes.iter().map(ChangeCall::subject).collect();
        assert_eq!(subjects, ["WebhookSubscription::pause"]);
        assert_eq!(
            calls(pause)[0],
            (
                "webhook_store.find_by_id".to_owned(),
                "WebhookStore".to_owned(),
                Some("existing_subscription".to_owned())
            )
        );
    }

    #[test]
    fn a_limit_kind_is_read_from_the_call_it_is_handed_to() {
        let found = facts();

        let limit = &use_case(&found, "CreateUseCase").limits[0];

        assert_eq!(limit.kind, "Webhooks");
        assert_eq!(limit.call, "ensure_room_in_tenant");
    }

    #[test]
    fn a_dispatch_sends_the_events_of_the_changes_on_the_value_it_takes_from() {
        let found = facts();

        let dispatch = &use_case(&found, "PauseUseCase").dispatches[0];

        assert_eq!(dispatch.method, "dispatch_by");
        assert_eq!(dispatch.events[0].name, "WebhookSubscriptionPaused");
        assert!(dispatch.not_read.is_empty());
    }

    #[test]
    fn a_right_checked_in_the_use_case_itself_is_its_own() {
        let found = facts();

        let rights = &use_case(&found, "PauseUseCase").rights;

        assert_eq!(
            rights[0].check.right.as_deref(),
            Some("WebhooksAction::Update")
        );
        assert!(rights[0].via.is_none());
    }

    #[test]
    fn documented_and_written_errors_are_kept_apart() {
        let found = facts();

        let create = use_case(&found, "CreateUseCase");

        let documented: Vec<&str> = create
            .documented_errors
            .iter()
            .map(|error| error.variant.as_str())
            .collect();
        assert_eq!(documented, ["Forbidden", "Internal"]);
        assert_eq!(create.written_errors, ["Conflict"]);
    }

    #[test]
    fn a_change_named_call_on_a_value_of_unread_type_is_not_read() {
        let found = facts();

        let pause = use_case(&found, "PauseUseCase");

        assert!(pause.not_read.iter().any(|unread| unread.what
            == "`other.pause(..)`: the type of `other` was not read; domain changes named `pause`: WebhookSubscription::pause"));
    }

    #[test]
    fn an_imported_helper_that_is_not_there_is_not_read() {
        let found = facts();

        let create = use_case(&found, "CreateUseCase");

        assert!(create.not_read.iter().any(|unread| unread.what
            == "`gone_helper`, imported from `crate::use_cases::webhooks::missing`: not found there"));
    }

    #[test]
    fn a_use_case_without_a_ports_struct_says_its_ports_were_not_read() {
        let found = facts();

        let list = use_case(&found, "ListUseCase");

        assert!(list.ports.is_empty());
        assert!(
            list.not_read
                .iter()
                .any(|unread| unread.what.starts_with("its ports"))
        );
    }

    #[test]
    fn a_change_knows_its_proofs_rights_events_and_callers() {
        let found = facts();

        let pause = found
            .changes
            .iter()
            .find(|change| change.subject() == "WebhookSubscription::pause")
            .unwrap();

        assert_eq!(pause.takes, ["WebhookControl"]);
        assert_eq!(
            pause.rights[0].check.right.as_deref(),
            Some("WebhooksAction::Update")
        );
        assert_eq!(pause.events[0].name, "WebhookSubscriptionPaused");
        assert_eq!(pause.callers[0].use_case, "PauseUseCase");
    }

    #[test]
    fn a_port_held_in_a_nested_ports_struct_keeps_its_path() {
        let ws = crate::source::planted::workspace(vec![
            crate::source::planted::app("ports/webhooks.rs", planted::PORTS),
            crate::source::planted::app(
                "use_cases/webhooks/delivery/sending.rs",
                "pub struct SendingPorts { pub webhook_store: Arc<dyn WebhookStore> }",
            ),
            crate::source::planted::app(
                "use_cases/webhooks/delivery/deliver.rs",
                "use crate::use_cases::webhooks::delivery::sending::SendingPorts;
                 pub struct DeliverPorts { pub sending: SendingPorts }
                 pub struct DeliverUseCase { ports: DeliverPorts }
                 impl Command for DeliverUseCase {
                     async fn execute(&self, caller: &CallerContext, auditor: &RequestAuditor, input: ()) {
                         let store = self.ports.sending.webhook_store.as_ref();
                         store.save(&tenant, &thing).await;
                     }
                 }",
            ),
        ]);
        let found = Facts::build(&ws, &model(&ws));

        let deliver = use_case(&found, "DeliverUseCase");

        assert_eq!(
            calls(deliver),
            [(
                "sending.webhook_store.save".to_owned(),
                "WebhookStore".to_owned(),
                None
            )]
        );
    }

    fn operator_facts() -> Facts {
        let ws = planted::operator();
        Facts::build(&ws, &model(&ws))
    }

    /// `execute` hands the events to a method of its `*Ports` struct, which
    /// clears the token cache and dispatches them. Both count, through it.
    #[test]
    fn a_method_of_the_ports_struct_is_followed_like_an_own_helper() {
        let found = operator_facts();

        let revoke_all = use_case(&found, "RevokeAllOperatorUseCase");

        let dispatch = &revoke_all.dispatches[0];
        assert_eq!(dispatch.via.as_deref(), Some("settle_revocation"));
        assert_eq!(dispatch.events[0].name, "OperatorApiKeysRevoked");
        assert!(calls(revoke_all).contains(&(
            "token_lookup.invalidate_all".to_owned(),
            "TokenLookup".to_owned(),
            Some("settle_revocation".to_owned())
        )));
        assert!(revoke_all.not_read.is_empty());
    }

    #[test]
    fn a_creator_taking_a_caller_proof_says_so() {
        let found = operator_facts();

        let change = &use_case(&found, "RevokeAllOperatorUseCase").changes[0];

        assert_eq!(change.takes, ["OperatorAuthority"]);
        assert!(change.rights.is_empty());
    }

    /// The ports struct has no `settle_elsewhere`, and `external::record`
    /// is handed the auditor. Neither is read, and both say so.
    #[test]
    fn calls_that_can_reach_ports_or_the_auditor_and_are_not_read_say_so() {
        let found = operator_facts();

        let rotate = use_case(&found, "RotateUseCase");

        let unread: Vec<&str> = rotate
            .not_read
            .iter()
            .map(|unread| unread.what.as_str())
            .collect();
        assert_eq!(
            unread,
            [
                "`self.ports.settle_elsewhere(..)`: no method of that name on its `*Ports` struct was found",
                "`external::record(..)`: it is handed `auditor`, and the reader does not follow it",
            ]
        );
    }

    /// A helper reaching the export store through the struct it is handed.
    const EXPORT_DESK: &str =
        "pub(super) struct Answering<'a> { pub(super) exports: &'a dyn ExportStore }
                 pub(super) async fn answered(answering: Answering<'_>) {
                     let Answering { exports } = answering;
                     exports.find().await;
                 }";

    /// A query handing its export store to that helper inside a struct.
    const EXPORT_GET: &str = "use crate::use_cases::audit::desk::{Answering, answered};
                 pub struct GetPorts { pub exports: Arc<dyn ExportStore> }
                 pub struct GetUseCase { ports: GetPorts }
                 impl Query for GetUseCase {
                     async fn execute(&self, caller: &CallerContext, input: ()) {
                         answered(Answering { exports: self.ports.exports.as_ref() }).await
                     }
                 }";

    /// A `*Ports` struct whose method hands back a sender holding the
    /// store and the auditor.
    const SENDING_PORTS: &str = "pub struct SendingPorts { pub webhook_store: Arc<dyn WebhookStore> }
                 impl SendingPorts {
                     pub(super) fn sender<'a>(&'a self, auditor: &'a RequestAuditor) -> Sender<'a> {
                         Sender { store: self.webhook_store.as_ref(), auditor }
                     }
                 }
                 pub(super) struct Sender<'a> { store: &'a dyn WebhookStore, auditor: &'a RequestAuditor }
                 impl Sender<'_> {
                     pub(super) async fn send(&self) {
                         self.store.save(&tenant, &thing).await;
                         self.auditor.dispatch(&events).await;
                     }
                 }";

    /// A command sending through that sender.
    const TEST_SEND: &str = "use crate::use_cases::webhooks::sending::SendingPorts;
                 pub struct TestPorts { pub sending: SendingPorts }
                 pub struct TestUseCase { ports: TestPorts }
                 impl Command for TestUseCase {
                     async fn execute(&self, caller: &CallerContext, auditor: &RequestAuditor, input: ()) {
                         self.ports.sending.sender(auditor).send().await
                     }
                 }";

    /// A command whose ports hold an app struct holding the job queue, and
    /// a call on a part of that queue the reader cannot place.
    const REQUEST_TLS: &str = "pub struct CertificateQueue { pub queue: Arc<dyn JobQueue>, pub attempts: u32 }
                 pub struct RequestPorts { pub certificates: CertificateQueue }
                 pub struct RequestUseCase { ports: RequestPorts }
                 impl Command for RequestUseCase {
                     async fn execute(&self, caller: &CallerContext, auditor: &RequestAuditor, input: ()) {
                         queue_certificate(&self.ports.certificates).await;
                         self.ports.certificates.queue.inner.go();
                     }
                 }
                 async fn queue_certificate(certificates: &CertificateQueue) {
                     certificates.queue.enqueue().await;
                 }";

    /// The use case puts its port into a struct and hands that to a helper
    /// of another file, which calls the port through the struct's field.
    #[test]
    fn a_port_put_into_a_struct_is_followed_into_the_helper_it_is_handed_to() {
        let ws = crate::source::planted::workspace(vec![
            crate::source::planted::app(
                "ports/audit.rs",
                "pub trait ExportStore { async fn find(&self) -> Result<Export, DomainError>; }",
            ),
            crate::source::planted::app("use_cases/audit/desk.rs", EXPORT_DESK),
            crate::source::planted::app("use_cases/audit/get.rs", EXPORT_GET),
        ]);
        let found = Facts::build(&ws, &model(&ws));

        let get = use_case(&found, "GetUseCase");

        assert_eq!(
            calls(get),
            [(
                "exports.find".to_owned(),
                "ExportStore".to_owned(),
                Some("answered".to_owned())
            )]
        );
        assert!(get.not_read.is_empty());
    }

    /// A method of the `*Ports` struct hands back a `Sender` holding the
    /// store and the auditor; the use case calls `send` on it, which saves
    /// and dispatches. Both are read, through `Sender::send`.
    #[test]
    fn a_method_of_an_app_type_holding_ports_is_followed() {
        let ws = crate::source::planted::workspace(vec![
            crate::source::planted::app("ports/webhooks.rs", planted::PORTS),
            crate::source::planted::app("use_cases/webhooks/sending.rs", SENDING_PORTS),
            crate::source::planted::app("use_cases/webhooks/test_send.rs", TEST_SEND),
        ]);
        let found = Facts::build(&ws, &model(&ws));

        let test = use_case(&found, "TestUseCase");

        assert_eq!(
            calls(test),
            [(
                "sending.webhook_store.save".to_owned(),
                "WebhookStore".to_owned(),
                Some("Sender::send".to_owned())
            )]
        );
        assert_eq!(test.dispatches[0].via.as_deref(), Some("Sender::send"));
    }

    /// A field of the `*Ports` struct holds an app struct that holds the
    /// port; the helper reaches the port through it. A call on a part of a
    /// port the reader cannot place is not read, and says so.
    #[test]
    fn a_port_inside_an_app_struct_held_by_the_ports_is_named_by_its_path() {
        let ws = crate::source::planted::workspace(vec![
            crate::source::planted::app(
                "ports/jobs.rs",
                "pub trait JobQueue { async fn enqueue(&self) -> Result<(), DomainError>; }",
            ),
            crate::source::planted::app("use_cases/domain/request_tls.rs", REQUEST_TLS),
        ]);
        let found = Facts::build(&ws, &model(&ws));

        let request = use_case(&found, "RequestUseCase");

        assert_eq!(
            calls(request),
            [(
                "certificates.queue.enqueue".to_owned(),
                "JobQueue".to_owned(),
                Some("queue_certificate".to_owned())
            )]
        );
        assert_eq!(
            request.not_read[0].what,
            "`self.ports.certificates.queue.inner.go(..)`: the type of that field of `self` was not read"
        );
    }

    /// The webhook ports with a listing.
    const LISTING: &str = r"
        pub trait WebhookStore: Send + Sync {
            async fn list(&self, tenant: &ScopedTenant) -> Result<Vec<WebhookSubscription<ResolvedTenant>>, DomainError>;
            async fn save(&self, tenant: &ScopedTenant, subscription: &WebhookSubscription<ResolvedTenant>)
                -> Result<(), DomainError>;
        }
    ";

    /// A command over the webhook files, with `extra` app files, `ports` in
    /// its `*Ports` struct, `items` beside it and `body` as its `execute`.
    fn command(extra: Vec<SourceFile>, ports: &str, items: &str, body: &str) -> UseCaseFacts {
        let text = format!(
            "use crate::services::batches::{{self, Batches}};
             pub struct SweepPorts {{ pub webhook_store: Arc<dyn WebhookStore>, {ports} }}
             pub struct SweepUseCase {{ ports: SweepPorts }}
             impl Command for SweepUseCase {{
                 async fn execute(&self, caller: &(), auditor: &RequestAuditor, (): ()) -> Result<(), AppError> {{
                     {body}
                 }}
             }}
             {items}"
        );
        let mut files = vec![
            crate::source::planted::domain(
                "domains/webhooks/subscription.rs",
                planted::SUBSCRIPTION,
            ),
            crate::source::planted::app("ports/webhooks.rs", LISTING),
            crate::source::planted::app("use_cases/webhooks/sweep.rs", &text),
        ];
        files.extend(extra);
        let ws = crate::source::planted::workspace(files);
        let found = Facts::build(&ws, &model(&ws));
        use_case(&found, "SweepUseCase").clone()
    }

    fn unread(facts: &UseCaseFacts) -> Vec<&str> {
        facts
            .not_read
            .iter()
            .map(|unread| unread.what.as_str())
            .collect()
    }

    fn changes(facts: &UseCaseFacts) -> Vec<String> {
        facts.changes.iter().map(ChangeCall::subject).collect()
    }

    /// The batches come from an app type's function called by its path, and
    /// a function of its module called through the module; the items of
    /// the batch it hands back are subscriptions.
    #[test]
    fn app_functions_by_type_or_module_path_are_followed_and_loop_items_typed() {
        let batches = crate::source::planted::app(
            "services/batches.rs",
            "pub(crate) struct Batches<'a> { store: &'a dyn WebhookStore }
             impl<'a> Batches<'a> {
                 pub(crate) fn over(store: &'a dyn WebhookStore) -> Self { Self { store } }
                 pub(crate) async fn next(&self) -> Result<Vec<WebhookSubscription<ResolvedTenant>>, AppError> {
                     self.store.list(&tenant).await.or_internal()
                 }
             }
             pub(crate) async fn settle(store: &dyn WebhookStore, subscription: &WebhookSubscription<ResolvedTenant>) -> Result<(), AppError> {
                 store.save(&tenant, subscription).await.or_internal()
             }",
        );

        let sweep = command(
            vec![batches],
            "",
            "",
            "let batches = Batches::over(self.ports.webhook_store.as_ref());
             for mut subscription in batches.next().await? {
                 subscription.pause(&control).map_err(AppError::from_domain)?;
                 batches::settle(self.ports.webhook_store.as_ref(), &subscription).await?;
             }
             Ok(())",
        );

        assert!(unread(&sweep).is_empty(), "{:?}", unread(&sweep));
        assert_eq!(changes(&sweep), ["WebhookSubscription::pause"]);
        assert!(calls(&sweep).iter().any(|(call, _, via)| {
            call == "webhook_store.save" && via.as_deref() == Some("settle")
        }));
    }

    /// Events gathered into a list are dispatched with it, and looking at
    /// the list sends nothing.
    #[test]
    fn events_gathered_into_a_list_are_the_lists() {
        let sweep = command(
            Vec::new(),
            "",
            "",
            "let mut events = Vec::new();
             for mut subscription in self.ports.webhook_store.list(&tenant).await.or_internal()? {
                 subscription.pause(&control).map_err(AppError::from_domain)?;
                 events.extend(subscription.take_events(&tenant));
             }
             if events.is_empty() { return Ok(()); }
             auditor.dispatch(&events).await.or_internal()",
        );

        assert!(unread(&sweep).is_empty(), "{:?}", unread(&sweep));
        assert_eq!(
            sweep.dispatches[0].events[0].name,
            "WebhookSubscriptionPaused"
        );
    }

    /// A closure run for each item is handed a subscription.
    #[test]
    fn a_closure_run_for_each_item_is_handed_one() {
        let sweep = command(
            Vec::new(),
            "",
            "",
            "let listed = self.ports.webhook_store.list(&tenant).await.or_internal()?;
             listed.into_iter().try_for_each(|mut subscription| subscription.pause(&control)).map_err(AppError::from_domain)",
        );

        assert!(unread(&sweep).is_empty(), "{:?}", unread(&sweep));
        assert_eq!(changes(&sweep), ["WebhookSubscription::pause"]);
    }

    /// A field holding a domain trait, such as a hasher an adapter
    /// implements, reaches none of the app's ports: calls on it are read as
    /// done.
    #[test]
    fn a_field_holding_a_domain_trait_is_no_unread_port() {
        let hasher = crate::source::planted::domain(
            "domains/authentication/hashing.rs",
            "pub trait PasswordHasher: Send + Sync { fn hash(&self, raw: &str) -> Result<PasswordHash, DomainError>; }",
        );

        let sweep = command(
            vec![hasher],
            "pub hasher: Arc<dyn PasswordHasher>",
            "",
            "let hash = self.ports.hasher.hash(&raw).or_internal()?;
             Ok(())",
        );

        assert!(unread(&sweep).is_empty(), "{:?}", unread(&sweep));
    }

    /// A ports field whose type is an alias of an app struct holding a port
    /// is followed into the struct's methods.
    #[test]
    fn a_ports_field_typed_by_an_alias_is_followed() {
        let steps = crate::source::planted::app(
            "services/batches.rs",
            "pub struct Jobs<S> { store: Arc<dyn WebhookStore>, steps: PhantomData<S> }
             pub type SweepJobs = Jobs<Step>;
             impl<S> Jobs<S> {
                 pub async fn queue_each(&self, subscription: &WebhookSubscription<ResolvedTenant>) -> Result<(), AppError> {
                     self.store.save(&tenant, subscription).await.or_internal()
                 }
             }",
        );

        let sweep = command(
            vec![steps],
            "pub jobs: SweepJobs",
            "",
            "self.ports.jobs.queue_each(&subscription).await",
        );

        assert!(unread(&sweep).is_empty(), "{:?}", unread(&sweep));
        assert!(
            calls(&sweep)
                .iter()
                .any(|(call, _, via)| call.ends_with("save")
                    && via.as_deref() == Some("Jobs::queue_each"))
        );
    }

    /// The use case takes an app struct apart, and reads a field of a field
    /// and a tuple struct's field of its own.
    #[test]
    fn fields_of_app_structs_are_typed_through_patterns_and_paths() {
        let sweep = command(
            Vec::new(),
            "",
            "struct Progress { held: Held }
             struct Held(WebhookSubscription<ResolvedTenant>);
             struct Wrapped { progress: Progress }
             impl Held { fn paused(&mut self) -> Result<(), DomainError> { self.0.pause(&control) } }",
            "let progress: Progress = make();
             let Progress { mut held } = progress;
             held.paused().map_err(AppError::from_domain)?;
             let wrapped: Wrapped = make();
             wrapped.progress.held.0.pause(&control).map_err(AppError::from_domain)",
        );

        assert!(unread(&sweep).is_empty(), "{:?}", unread(&sweep));
        assert_eq!(changes(&sweep).len(), 2);
    }

    #[test]
    fn a_service_function_lists_the_port_methods_it_calls() {
        let found = facts();

        let room = &found.services[0];

        assert_eq!(room.function, "ensure_room_in_tenant");
        assert_eq!(room.port_calls[0].0.name, "LimitEnforcer");
        assert_eq!(room.port_calls[0].1, "check_tenant_limit");
    }
}
