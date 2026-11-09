//! An API that an agent's run may call.
//!
//! A tool ties a description and an input schema, both shown to the model, to
//! one HTTP endpoint behind one route. Its [`ActionClass`] and its data class
//! come from that route, the same way the gateway reads them. So a run and
//! the gateway never disagree on what a call does or how sensitive it is. A
//! tool outside the agent's declared intent is never offered to the model. If
//! the model calls it anyway, the proxy refuses.
//!
//! The data class says how sensitive the tool's output is, and the most
//! sensitive data the tool may be sent. Reading from the tool raises a run's
//! exposure to that class. Calling it needs a run whose exposure is no
//! higher.
//!
//! A tool has no owner. Every run in the tenant may be given it, so only
//! someone allowed to manage agents registers it, edits it, or turns it on
//! and off.

mod path;
mod status;

use std::marker::PhantomData;

pub use path::*;
pub use status::*;
use time::OffsetDateTime;

use crate::domains::agents::events::execution::{
    AgentToolDeleted, AgentToolRegistered, AgentToolStatusChanged,
};
use crate::domains::agents::events::setup::AgentToolEdited;
use crate::domains::agents::identity::control::AgentControl;
use crate::domains::authorization::permission::AgentAction;
use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::routing::route::Route;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::clock;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::{Charset, TextValue, Validator, text_value};
use crate::types::{ActionClass, AgentToolId, CanonicalPath, DeclaredAction, HttpMethod, RouteId};

/// The HTTP method a tool call uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ToolMethod {
    /// Read.
    Get,
    /// Create or update.
    Post,
    /// Replace.
    Put,
    /// Partial update.
    Patch,
    /// Removes the resource addressed by the tool's URL.
    Delete,
}

impl ToolMethod {
    /// The uppercase HTTP verb.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        HttpMethod::from(self).as_str()
    }

    /// Parses a verb, in any case.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when HTTP has no such verb.
    /// - [`DomainError::Validation`] when the verb is `HEAD`, `OPTIONS` or the
    ///   route wildcard, which a tool cannot use.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let verb = value.to_ascii_uppercase();
        HttpMethod::parse(&verb)
            .and_then(Self::for_tools)
            .ok_or_else(|| {
                DomainError::invalid(message!(
                    "agents-unsupported-tool-method",
                    format!("unsupported tool method: {verb}")
                ))
            })
    }

    /// The tool method an HTTP method is, if a tool may use it.
    fn for_tools(method: HttpMethod) -> Option<Self> {
        match method {
            HttpMethod::Get => Some(Self::Get),
            HttpMethod::Post => Some(Self::Post),
            HttpMethod::Put => Some(Self::Put),
            HttpMethod::Patch => Some(Self::Patch),
            HttpMethod::Delete => Some(Self::Delete),
            HttpMethod::Head | HttpMethod::Options | HttpMethod::Any => None,
        }
    }
}

impl From<ToolMethod> for HttpMethod {
    fn from(method: ToolMethod) -> Self {
        match method {
            ToolMethod::Get => Self::Get,
            ToolMethod::Post => Self::Post,
            ToolMethod::Put => Self::Put,
            ToolMethod::Patch => Self::Patch,
            ToolMethod::Delete => Self::Delete,
        }
    }
}

text_value! {
    /// The name the model calls a tool by, such as `get_order`.
    pub struct ToolName;
}

impl TextValue for ToolName {
    const FIELD: &'static str = "tool_name";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.identifier(
            1..=64,
            Charset::LOWERCASE
                | Charset::UPPERCASE
                | Charset::DIGIT
                | Charset::UNDERSCORE
                | Charset::HYPHEN
                | Charset::DOT,
        )
    }
}

text_value! {
    /// What the tool does, as the model is told it.
    pub struct ToolDescription;
}

impl TextValue for ToolDescription {
    const FIELD: &'static str = "tool_description";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.free_text(1024)
    }
}

text_value! {
    /// The JSON schema text for the tool's input.
    ///
    /// It is kept as text so the domain needs no JSON library. The API checks
    /// that it parses. The model adapter passes it to the model.
    pub struct ToolSchema;
}

impl TextValue for ToolSchema {
    const FIELD: &'static str = "tool_schema";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.not_blank().char_length(1..=8192)
    }
}

/// Parameters for registering a tool, or for replacing its definition.
///
/// The action class and data class are not among them. Both come from the
/// route the tool calls.
pub struct RegisterToolParams {
    /// The name the model calls.
    pub name: ToolName,
    /// The description shown to the model.
    pub description: ToolDescription,
    /// The input JSON schema.
    pub schema: ToolSchema,
    /// The HTTP method the call uses.
    pub method: ToolMethod,
    /// The URL path template.
    pub path: ToolPath,
}

/// Persisted state for reconstitution.
pub struct AgentToolRow {
    /// Unique identifier.
    pub id: AgentToolId,
    /// Tool name.
    pub name: ToolName,
    /// Explains the operation to the model when choosing a tool.
    pub description: ToolDescription,
    /// Input schema.
    pub schema: ToolSchema,
    /// HTTP method.
    pub method: ToolMethod,
    /// URL path template.
    pub path: ToolPath,
    /// The route the tool calls.
    pub route_id: RouteId,
    /// The action class the route declared when the tool was registered.
    pub declared_action: DeclaredAction,
    /// The class of action this tool takes.
    pub action_class: ActionClass,
    /// The tool's data class.
    pub classification: DataClassLevel,
    /// Whether it is offered to agents.
    pub status: ToolStatus,
    /// When created.
    pub created_at: OffsetDateTime,
    /// When last modified.
    pub updated_at: OffsetDateTime,
}

/// A registered API an agent may call.
#[derive(Debug, Clone)]
pub struct AgentTool<T: TenantScope> {
    id: AgentToolId,
    name: ToolName,
    description: ToolDescription,
    schema: ToolSchema,
    method: ToolMethod,
    path: ToolPath,
    route_id: RouteId,
    declared_action: DeclaredAction,
    action_class: ActionClass,
    classification: DataClassLevel,
    status: ToolStatus,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> AgentTool<T> {
    /// Registers an active tool that calls `route`.
    ///
    /// Its action class is the one the gateway gives a request on `route`
    /// with the tool's method and path. Its data class is the route's.
    /// `POST /transfers` declared financial on its route is financial here
    /// too, so a run pauses on it for approval.
    ///
    /// Raises `agents.tool_registered`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person registering it may not
    ///   manage agents.
    /// - [`DomainError::Validation`] when `route` does not serve the tool's
    ///   method and path.
    pub fn register(
        params: RegisterToolParams,
        route: &Route<T>,
        control: &AgentControl<'_>,
    ) -> Result<Self, DomainError> {
        ensure_manages_tools(control)?;
        ensure_route_serves(route, params.method, &params.path)?;
        let declared_action = route.action_class();
        let action_class =
            ActionClass::for_route(params.method.into(), params.path.as_str(), declared_action);
        let now = clock::now();
        let mut tool = Self {
            id: AgentToolId::new(),
            name: params.name,
            description: params.description,
            schema: params.schema,
            method: params.method,
            path: params.path,
            route_id: *route.id(),
            declared_action,
            action_class,
            classification: route.data_class(),
            status: ToolStatus::Active,
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        tool.raise_registered();
        Ok(tool)
    }

    /// Raises the registration of this tool, as it stands when created.
    fn raise_registered(&mut self) {
        let registered = AgentToolRegistered {
            tool_id: self.id,
            name: self.name.clone(),
            action_class: self.action_class,
            classification: self.classification,
            occurred_at: self.created_at,
        };
        self.raised.raise(registered);
    }

    /// Rebuilds a tool from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the tool changed
    ///   before it was registered.
    /// - [`DomainError::Infrastructure`] when the row holds a class its
    ///   method, path and declared action do not give.
    pub fn reconstitute(row: AgentToolRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            name: row.name,
            description: row.description,
            schema: row.schema,
            method: row.method,
            path: row.path,
            route_id: row.route_id,
            declared_action: row.declared_action,
            action_class: row.action_class,
            classification: row.classification,
            status: row.status,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &AgentToolRow) -> Result<(), DomainError> {
        let class =
            ActionClass::for_route(row.method.into(), row.path.as_str(), row.declared_action);
        RowCheck::of("agent tool")
            .holds(
                row.action_class == class,
                "an action class its method, path and route do not make",
            )
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was registered",
            )
            .finish()
    }

    /// Unique identifier.
    #[must_use]
    pub fn id(&self) -> &AgentToolId {
        &self.id
    }

    /// Tool name.
    #[must_use]
    pub fn name(&self) -> &ToolName {
        &self.name
    }

    /// Explains the operation to the model when choosing a tool.
    #[must_use]
    pub fn description(&self) -> &ToolDescription {
        &self.description
    }

    /// Input schema.
    #[must_use]
    pub fn schema(&self) -> &ToolSchema {
        &self.schema
    }

    /// HTTP method.
    #[must_use]
    pub fn method(&self) -> ToolMethod {
        self.method
    }

    /// URL path template.
    #[must_use]
    pub fn path(&self) -> &ToolPath {
        &self.path
    }

    /// The route the tool calls.
    #[must_use]
    pub fn route_id(&self) -> &RouteId {
        &self.route_id
    }

    /// The action class the route declared when the tool was registered.
    #[must_use]
    pub fn declared_action(&self) -> DeclaredAction {
        self.declared_action
    }

    /// The class of action this tool takes, read from its path template.
    /// The tools offered to a run are picked by it.
    #[must_use]
    pub fn action_class(&self) -> ActionClass {
        self.action_class
    }

    /// The class of action a call to `target` takes: the class the gateway
    /// gives this tool's method on that path, under the route's declared
    /// action.
    #[must_use]
    pub fn action_class_at(&self, target: &CanonicalPath) -> ActionClass {
        ActionClass::for_route(self.method.into(), target.as_str(), self.declared_action)
    }

    /// The tool's data class.
    ///
    /// Reading from the tool exposes a run to this class. It is also the most
    /// sensitive data the tool may be sent.
    #[must_use]
    pub fn classification(&self) -> DataClassLevel {
        self.classification
    }

    /// Whether it is offered to agents.
    #[must_use]
    pub fn status(&self) -> ToolStatus {
        self.status
    }

    /// Whether the tool is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self.status, ToolStatus::Active)
    }

    /// Disables the tool. Raises `agents.tool_status_changed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not manage agents.
    /// - [`DomainError::InvalidTransition`] when it is already disabled.
    pub fn disable(&mut self, control: &AgentControl<'_>) -> Result<(), DomainError> {
        ensure_manages_tools(control)?;
        self.move_to(ToolStatus::Disabled)
    }

    /// Re-enables a disabled tool. Raises `agents.tool_status_changed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not manage agents.
    /// - [`DomainError::InvalidTransition`] when it is already active.
    pub fn enable(&mut self, control: &AgentControl<'_>) -> Result<(), DomainError> {
        ensure_manages_tools(control)?;
        self.move_to(ToolStatus::Active)
    }

    /// Replaces the tool's definition with `params`, calling `route`.
    ///
    /// The classes are read again from `route`, the same way registering
    /// reads them, never kept from before. A tool for `GET /orders` edited
    /// to `POST /transfers` takes the class that route gives a transfer, so
    /// a run pauses on it for approval. The tool keeps its status.
    ///
    /// Raises `agents.tool_edited`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not manage agents.
    /// - [`DomainError::Validation`] when `route` does not serve the new
    ///   method and path.
    pub fn edit(
        &mut self,
        params: RegisterToolParams,
        route: &Route<T>,
        control: &AgentControl<'_>,
    ) -> Result<(), DomainError> {
        ensure_manages_tools(control)?;
        ensure_route_serves(route, params.method, &params.path)?;
        self.declared_action = route.action_class();
        self.action_class = ActionClass::for_route(
            params.method.into(),
            params.path.as_str(),
            self.declared_action,
        );
        self.classification = route.data_class();
        self.route_id = *route.id();
        self.name = params.name;
        self.description = params.description;
        self.schema = params.schema;
        self.method = params.method;
        self.path = params.path;
        self.touch();
        self.raised.raise(AgentToolEdited {
            tool_id: self.id,
            name: self.name.clone(),
            action_class: self.action_class,
            classification: self.classification,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Deletes this tool, which only someone who may manage agents does, and
    /// only once the tool is disabled. Raises `agents.tool_deleted`, taken
    /// once the tool is removed from storage.
    ///
    /// A tool is disabled first, so no run is part way through a call to it
    /// when it goes. Sam may only view agents. Without this check, he
    /// deletes the tool a team's runs depend on.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not manage agents.
    /// - [`DomainError::InvalidTransition`] while the tool is active.
    pub fn delete(&mut self, control: &AgentControl<'_>) -> Result<(), DomainError> {
        ensure_manages_tools(control)?;
        if self.is_active() {
            return Err(DomainError::invalid_transition(message!(
                "agents-a-tool-is-disabled-before-it",
                "a tool is disabled before it is deleted"
            )));
        }
        self.raised.raise(AgentToolDeleted {
            tool_id: self.id,
            name: self.name.clone(),
            occurred_at: clock::now(),
        });
        Ok(())
    }

    fn move_to(&mut self, to: ToolStatus) -> Result<(), DomainError> {
        self.status = self.status.try_transition(to)?;
        self.touch();
        self.raised.raise(AgentToolStatusChanged {
            tool_id: self.id,
            name: self.name.clone(),
            status: self.status,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    fn touch(&mut self) {
        self.updated_at = clock::now();
    }
}

/// Refuses a person who may not manage agents.
///
/// A tool decides what runs may call and what data they may send. Sam may
/// only view agents. Without this check, he registers a tool to his own
/// endpoint as restricted, and a run that read HR records sends them there.
fn ensure_manages_tools(control: &AgentControl<'_>) -> Result<(), DomainError> {
    if control.holds_agent(AgentAction::Manage) {
        return Ok(());
    }
    Err(DomainError::forbidden(message!(
        "agents-only-someone-allowed-to-manage-agents",
        "only someone allowed to manage agents may register or change a tool"
    )))
}

/// Refuses a route that would not take the tool's calls.
///
/// The tool takes its classes from the route. A tool for `POST /transfers`
/// named with the route for `GET /weather` would pass as a public read.
fn ensure_route_serves<T: TenantScope>(
    route: &Route<T>,
    method: ToolMethod,
    path: &ToolPath,
) -> Result<(), DomainError> {
    let serves_path = path
        .as_canonical()
        .is_ok_and(|template| route.matches_path(&template));
    if route.matches_method(method.into()) && serves_path {
        return Ok(());
    }
    Err(DomainError::invalid(message!(
        "agents-the-route-does-not-serve-the",
        "the route does not serve the tool's method and path"
    )))
}

impl<T: TenantScope> Raises for AgentTool<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for AgentTool<T> {
    type Id = AgentToolId;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

#[cfg(test)]
pub(crate) mod tests {
    pub(crate) mod fixtures;

    use self::fixtures::{MANAGE, holding, person, registered, route};
    use super::*;
    use crate::domains::authorization::permission::SystemPermission;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::{raised, raised_names};

    const VIEW: [SystemPermission; 1] = [SystemPermission::Agents(AgentAction::View)];

    fn tool(method: ToolMethod, path: &str) -> AgentTool<ResolvedTenant> {
        registered(
            "get_order",
            method,
            path,
            DeclaredAction::Undeclared,
            DataClassLevel::Internal,
        )
    }

    fn params(method: ToolMethod, path: &str) -> RegisterToolParams {
        RegisterToolParams {
            name: ToolName::new("transfer").unwrap(),
            description: ToolDescription::new("Move money").unwrap(),
            schema: ToolSchema::new(r#"{"type":"object"}"#).unwrap(),
            method,
            path: ToolPath::new(path).unwrap(),
        }
    }

    /// On routes that declare nothing, a `GET` on an order is a read, a
    /// `DELETE` on it is a delete, and a `POST` under `/admin` is an admin
    /// action. The class comes from the method and path together.
    #[test]
    fn register_classifies_the_action_from_method_and_path() {
        assert_eq!(
            tool(ToolMethod::Get, "/orders/{id}").action_class(),
            ActionClass::Read
        );
        assert_eq!(
            tool(ToolMethod::Delete, "/orders/{id}").action_class(),
            ActionClass::Delete
        );
        assert_eq!(
            tool(ToolMethod::Post, "/admin/roles").action_class(),
            ActionClass::Admin
        );
    }

    /// A transfer tool inherits its route's explicit financial action class,
    /// even though the path alone would classify it as a write.
    #[test]
    fn a_tool_takes_the_action_class_its_route_declares() {
        let tool = registered(
            "transfer",
            ToolMethod::Post,
            "/transfers",
            DeclaredAction::Declared(ActionClass::Financial),
            DataClassLevel::Confidential,
        );

        assert_eq!(tool.action_class(), ActionClass::Financial);
    }

    /// A tool registered on a public route receives public data classification.
    #[test]
    fn a_tool_takes_the_data_class_of_its_route() {
        let tool = registered(
            "post_issue",
            ToolMethod::Post,
            "/issues",
            DeclaredAction::Undeclared,
            DataClassLevel::Public,
        );

        assert_eq!(tool.classification(), DataClassLevel::Public);
    }

    /// Registering a transfer tool against a weather route is refused because
    /// the route does not serve the tool's path.
    #[test]
    fn a_tool_for_a_path_its_route_does_not_serve_is_refused() {
        let bob = person("bob@corp.test");
        let weather = route(
            "/weather",
            DeclaredAction::Declared(ActionClass::Read),
            DataClassLevel::Public,
        );

        let result = AgentTool::register(
            params(ToolMethod::Post, "/transfers"),
            &weather,
            &holding(&bob, &MANAGE),
        );

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A viewer cannot register a tool even when its route serves the request.
    #[test]
    fn registering_a_tool_needs_an_agent_manager() {
        let sam = person("sam@corp.test");
        let transfers = route(
            "/transfers",
            DeclaredAction::Undeclared,
            DataClassLevel::Restricted,
        );

        let result: Result<AgentTool<ResolvedTenant>, DomainError> = AgentTool::register(
            params(ToolMethod::Post, "/transfers"),
            &transfers,
            &holding(&sam, &VIEW),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A viewer cannot enable or disable a tool. Each refusal preserves its
    /// status, while a manager can enable it between those attempts.
    #[test]
    fn turning_a_tool_on_or_off_needs_an_agent_manager() {
        let sam = person("sam@corp.test");
        let bob = person("bob@corp.test");
        let mut t = tool(ToolMethod::Get, "/orders/{id}");
        t.disable(&holding(&bob, &MANAGE)).unwrap();

        let enabled = t.enable(&holding(&sam, &VIEW));
        assert!(matches!(enabled, Err(DomainError::Forbidden(_))));
        assert!(!t.is_active());

        t.enable(&holding(&bob, &MANAGE)).unwrap();
        let disabled = t.disable(&holding(&sam, &VIEW));
        assert!(matches!(disabled, Err(DomainError::Forbidden(_))));
        assert!(t.is_active());
    }

    /// A tool on `/items/{kind}`, on a route that declares nothing, called
    /// with `kind` set to `admin`, goes to `/items/admin`. That is an admin
    /// action, though the template reads as a plain read.
    #[test]
    fn the_class_at_a_target_reads_the_path_the_call_goes_to() {
        let t = tool(ToolMethod::Get, "/items/{kind}");
        let target = CanonicalPath::new("/items/admin").unwrap();

        assert_eq!(t.action_class(), ActionClass::Read);
        assert_eq!(t.action_class_at(&target), ActionClass::Admin);
    }

    /// `get_order` is a valid name. `get order` and `get/order` are refused.
    #[test]
    fn tool_name_rejects_spaces_and_symbols() {
        assert!(ToolName::new("get_order").is_ok());
        assert!(ToolName::new("get order").is_err());
        assert!(ToolName::new("get/order").is_err());
    }

    /// `/orders/{id}` is a valid path. `orders` with no leading slash and
    /// `/or ders` with a space are refused.
    #[test]
    fn path_must_start_with_slash_and_have_no_whitespace() {
        assert!(ToolPath::new("/orders/{id}").is_ok());
        assert!(ToolPath::new("orders").is_err());
        assert!(ToolPath::new("/or ders").is_err());
    }

    /// Each of the five methods parses back from its own verb. `TRACE` is
    /// refused.
    #[test]
    fn every_tool_method_reads_back_from_its_verb() {
        for m in [
            ToolMethod::Get,
            ToolMethod::Post,
            ToolMethod::Put,
            ToolMethod::Patch,
            ToolMethod::Delete,
        ] {
            assert_eq!(ToolMethod::parse(m.as_str()).unwrap(), m);
        }
        assert!(ToolMethod::parse("TRACE").is_err());
    }

    /// `HEAD`, `OPTIONS` and the route wildcard `*` are refused as validation
    /// errors. A tool call has no use for the first two, and `*` is not a
    /// method.
    #[test]
    fn a_tool_cannot_use_head_options_or_the_wildcard() {
        for verb in ["HEAD", "OPTIONS", "*"] {
            assert!(
                matches!(ToolMethod::parse(verb), Err(DomainError::Validation(_))),
                "{verb}"
            );
        }
    }

    /// A lowercase `patch` parses as [`ToolMethod::Patch`].
    #[test]
    fn a_tool_method_reads_regardless_of_case() {
        assert_eq!(ToolMethod::parse("patch").unwrap(), ToolMethod::Patch);
    }

    /// A new tool is active. Bob, an agent manager, disables and enables it
    /// again, but enabling an active tool is refused.
    #[test]
    fn register_starts_active_and_disable_toggles() {
        let bob = person("bob@corp.test");
        let control = holding(&bob, &MANAGE);
        let mut t = tool(ToolMethod::Get, "/orders/{id}");
        assert!(t.is_active());
        t.disable(&control).unwrap();
        assert!(!t.is_active());
        t.enable(&control).unwrap();
        assert!(t.is_active());
        assert!(t.enable(&control).is_err());
    }

    /// A tool reads back the name, description and schema it was registered
    /// with. All three go into the system prompt as given, and grants match
    /// the name.
    #[test]
    fn a_tool_reports_the_name_description_and_schema_it_was_registered_with() {
        let t = tool(ToolMethod::Get, "/orders/{id}");

        assert_eq!(t.name().as_str(), "get_order");
        assert_eq!(t.description().as_str(), "A tool");
        assert_eq!(t.schema().as_str(), r#"{"type":"object"}"#);
        assert_eq!(Aggregate::id(&t), t.id());
    }

    /// A tool is disabled five seconds after it was registered. Its update
    /// time moves forward.
    #[test]
    fn disabling_a_tool_moves_its_updated_stamp() {
        let bob = person("bob@corp.test");
        let mut t = tool(ToolMethod::Get, "/orders/{id}");
        let before = t.updated_at();
        let frozen = crate::shared::clock::freeze(before + time::Duration::seconds(5));

        t.disable(&holding(&bob, &MANAGE)).unwrap();

        assert!(t.updated_at() > before);
        drop(frozen);
    }

    /// Deleting a tool requires management authority and a disabled tool.
    /// An active tool and a viewer's request are refused; a manager succeeds.
    #[test]
    fn only_an_agent_manager_deletes_a_disabled_tool() {
        let (bob, sam) = (person("bob@corp.test"), person("sam@corp.test"));
        let views = [SystemPermission::Agents(AgentAction::View)];
        let mut t = tool(ToolMethod::Get, "/orders/{id}");

        let while_active = t.delete(&holding(&bob, &MANAGE));
        t.disable(&holding(&bob, &MANAGE)).unwrap();

        assert!(matches!(
            while_active,
            Err(DomainError::InvalidTransition(_))
        ));
        assert!(matches!(
            t.delete(&holding(&sam, &views)),
            Err(DomainError::Forbidden(_))
        ));
        assert!(t.delete(&holding(&bob, &MANAGE)).is_ok());
    }

    /// Bob registers `get_order`. The registration is raised with the
    /// classes it took from its route.
    #[test]
    fn registering_raises_agents_tool_registered() {
        let mut t = tool(ToolMethod::Get, "/orders/{id}");

        let events = raised(&mut t);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type().to_string(), "agents.tool_registered");
        assert_eq!(
            events[0].payload().value("action_class"),
            Some(&FieldValue::Text("read".to_owned()))
        );
    }

    /// Bob turns `get_order` off and on again. Each change is raised, in
    /// order.
    #[test]
    fn turning_a_tool_off_and_on_raises_agents_tool_status_changed() {
        let bob = person("bob@corp.test");
        let control = holding(&bob, &MANAGE);
        let mut t = tool(ToolMethod::Get, "/orders/{id}");
        raised_names(&mut t);

        t.disable(&control).unwrap();
        t.enable(&control).unwrap();

        assert_eq!(
            raised_names(&mut t),
            ["agents.tool_status_changed", "agents.tool_status_changed"]
        );
    }

    /// Bob deletes the disabled `get_order`. The deletion is raised.
    #[test]
    fn deleting_raises_agents_tool_deleted() {
        let bob = person("bob@corp.test");
        let mut t = tool(ToolMethod::Get, "/orders/{id}");
        t.disable(&holding(&bob, &MANAGE)).unwrap();
        raised_names(&mut t);

        t.delete(&holding(&bob, &MANAGE)).unwrap();

        assert_eq!(raised_names(&mut t), ["agents.tool_deleted"]);
    }

    /// A viewer's attempt to disable a tool is refused without raising an event.
    #[test]
    fn a_refused_change_to_a_tool_raises_nothing() {
        let sam = person("sam@corp.test");
        let mut t = tool(ToolMethod::Get, "/orders/{id}");
        raised_names(&mut t);

        let refused = t.disable(&holding(&sam, &VIEW));

        assert!(refused.is_err());
        assert!(raised_names(&mut t).is_empty());
    }

    /// `get_order` is read back from storage. Loading it is no change, so it
    /// has raised nothing.
    #[test]
    fn a_tool_read_back_from_storage_has_raised_nothing() {
        let t = tool(ToolMethod::Get, "/orders/{id}");

        let mut read_back = AgentTool::<ResolvedTenant>::reconstitute(stored(&t)).unwrap();

        assert!(raised_names(&mut read_back).is_empty());
    }

    /// Storage and transport are not trusted. A value that never passed the
    /// constructor must not become valid by being read back.
    #[cfg(feature = "serde")]
    mod serde_goes_through_the_constructor {
        use super::*;

        /// JSON holding the name `get order` fails to read.
        #[cfg(feature = "serde")]
        #[test]
        fn a_stored_tool_name_with_spaces_is_refused() {
            assert!(serde_json::from_str::<ToolName>(r#""get order""#).is_err());
        }

        /// A valid name written to JSON reads back equal.
        #[cfg(feature = "serde")]
        #[test]
        fn a_tool_name_reads_back_what_it_writes() {
            let name = ToolName::new("get_order").unwrap();

            let json = serde_json::to_string(&name).unwrap();

            assert_eq!(serde_json::from_str::<ToolName>(&json).unwrap(), name);
        }

        /// JSON holding a description with a terminal escape code, or an empty
        /// one, fails to read.
        #[cfg(feature = "serde")]
        #[test]
        fn a_stored_tool_description_with_a_control_character_is_refused() {
            assert!(serde_json::from_str::<ToolDescription>(r#""fetch\u001b[31m""#).is_err());
            assert!(serde_json::from_str::<ToolDescription>(r#""""#).is_err());
        }

        /// A valid description written to JSON reads back equal.
        #[cfg(feature = "serde")]
        #[test]
        fn a_tool_description_reads_back_what_it_writes() {
            let description = ToolDescription::new("Fetch an order by id").unwrap();

            let json = serde_json::to_string(&description).unwrap();

            assert_eq!(
                serde_json::from_str::<ToolDescription>(&json).unwrap(),
                description
            );
        }

        /// JSON holding `orders/{id}`, with no leading slash, fails to read.
        #[cfg(feature = "serde")]
        #[test]
        fn a_stored_relative_tool_path_is_refused() {
            assert!(serde_json::from_str::<ToolPath>(r#""orders/{id}""#).is_err());
        }

        /// A valid path written to JSON reads back equal.
        #[cfg(feature = "serde")]
        #[test]
        fn a_tool_path_reads_back_what_it_writes() {
            let path = ToolPath::new("/orders/{id}").unwrap();

            let json = serde_json::to_string(&path).unwrap();

            assert_eq!(serde_json::from_str::<ToolPath>(&json).unwrap(), path);
        }

        /// JSON holding an empty schema fails to read.
        #[cfg(feature = "serde")]
        #[test]
        fn a_stored_tool_schema_that_is_empty_is_refused() {
            assert!(serde_json::from_str::<ToolSchema>(r#""""#).is_err());
        }

        /// A valid schema written to JSON reads back equal.
        #[cfg(feature = "serde")]
        #[test]
        fn a_tool_schema_reads_back_what_it_writes() {
            let schema = ToolSchema::new(r#"{"type":"object"}"#).unwrap();

            let json = serde_json::to_string(&schema).unwrap();

            assert_eq!(serde_json::from_str::<ToolSchema>(&json).unwrap(), schema);
        }
    }

    fn stored(tool: &AgentTool<ResolvedTenant>) -> AgentToolRow {
        AgentToolRow {
            id: tool.id,
            name: tool.name.clone(),
            description: tool.description.clone(),
            schema: tool.schema.clone(),
            method: tool.method,
            path: tool.path.clone(),
            route_id: tool.route_id,
            declared_action: tool.declared_action,
            action_class: tool.action_class,
            classification: tool.classification,
            status: tool.status,
            created_at: tool.created_at,
            updated_at: tool.updated_at,
        }
    }

    /// A stored tool was updated one second before it was registered. The
    /// row is refused as corrupt.
    #[test]
    fn a_stored_tool_changed_before_it_was_registered_is_refused() {
        let tool = tool(ToolMethod::Get, "/reports");
        let row = AgentToolRow {
            updated_at: tool.created_at - time::Duration::SECOND,
            ..stored(&tool)
        };

        assert!(refused_as_corrupt(
            &AgentTool::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A delete tool stored as a read is refused as corrupt, while its
    /// consistent stored form reconstructs successfully.
    #[test]
    fn a_stored_tool_with_a_class_its_method_does_not_make_is_refused() {
        let tool = tool(ToolMethod::Delete, "/orders/{id}");
        let row = AgentToolRow {
            action_class: ActionClass::Read,
            ..stored(&tool)
        };

        assert!(AgentTool::<ResolvedTenant>::reconstitute(stored(&tool)).is_ok());
        assert!(refused_as_corrupt(
            &AgentTool::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A financial tool whose stored declaration is changed to undeclared
    /// is refused as corrupt because the resulting action classes disagree.
    #[test]
    fn a_stored_tool_whose_declared_action_was_changed_is_refused() {
        let tool = registered(
            "transfer",
            ToolMethod::Post,
            "/transfers",
            DeclaredAction::Declared(ActionClass::Financial),
            DataClassLevel::Confidential,
        );
        let row = AgentToolRow {
            declared_action: DeclaredAction::Undeclared,
            ..stored(&tool)
        };

        assert!(refused_as_corrupt(
            &AgentTool::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// Bob edits the `get_order` read into a transfer on a route declared
    /// financial and restricted. It takes the route's classes, not its old
    /// ones, so a run pauses on it, and the edit is raised.
    #[test]
    fn an_edited_tool_takes_its_classes_from_its_new_route() {
        let bob = person("bob@corp.test");
        let mut edited = tool(ToolMethod::Get, "/orders");
        raised_names(&mut edited);
        let transfers = route(
            "/transfers",
            DeclaredAction::Declared(ActionClass::Financial),
            DataClassLevel::Restricted,
        );

        edited
            .edit(
                params(ToolMethod::Post, "/transfers"),
                &transfers,
                &holding(&bob, &MANAGE),
            )
            .unwrap();

        assert_eq!(edited.name().as_str(), "transfer");
        assert_eq!(edited.action_class(), ActionClass::Financial);
        assert_eq!(edited.classification(), DataClassLevel::Restricted);
        assert_eq!(edited.route_id(), transfers.id());
        assert_eq!(raised_names(&mut edited), ["agents.tool_edited"]);
    }

    /// A viewer cannot edit a tool's route; the forbidden attempt preserves
    /// its original route id.
    #[test]
    fn only_an_agent_manager_edits_a_tool() {
        let sam = person("sam@corp.test");
        let mut edited = tool(ToolMethod::Get, "/orders");
        let before = *edited.route_id();

        let result = edited.edit(
            params(ToolMethod::Get, "/orders"),
            &route(
                "/orders",
                DeclaredAction::Undeclared,
                DataClassLevel::Public,
            ),
            &holding(&sam, &VIEW),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(edited.route_id(), &before);
    }

    /// Editing a tool to call transfers through a weather route is refused,
    /// leaving its original GET method intact.
    #[test]
    fn an_edit_naming_a_route_that_does_not_serve_it_is_refused() {
        let bob = person("bob@corp.test");
        let mut edited = tool(ToolMethod::Get, "/orders");

        let result = edited.edit(
            params(ToolMethod::Post, "/transfers"),
            &route(
                "/weather",
                DeclaredAction::Undeclared,
                DataClassLevel::Public,
            ),
            &holding(&bob, &MANAGE),
        );

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert_eq!(edited.method(), ToolMethod::Get);
    }
}
