//! Which Model Context Protocol calls a caller may make.
//!
//! MCP is JSON-RPC over one endpoint: every tool call an agent makes is the
//! same `POST` to the same path, so a route policy cannot tell
//! `github_list_issues` from `github_delete_repo`. An adapter reads the
//! envelope, only as far as the method and the tool, resource or prompt it
//! names, never the arguments; the rules for what those names may reach
//! are here.
//!
//! Deny by default:
//!
//! - A batch passes only if every call in it does, and an empty one does
//!   not.
//! - A method not listed here is refused; new protocol surface is granted,
//!   never inherited.
//! - A caller with no grant reaches nothing: only an agent's task token
//!   carries one, so a person or a consumer may connect and list, and call
//!   nothing.
//! - Reading a resource and fetching a prompt are their own rights, never
//!   carried by a tool grant, and both are reads the purpose must allow:
//!   they return content the agent acts on, which is what a prompt
//!   injection rides in on.

use crate::domains::agents::authority::capability::McpResourceUri;
use crate::domains::agents::execution::tool::ToolName;
use crate::domains::proxy::request::context::{AgentLimits, Authentication, Caller, Verified};
use crate::domains::proxy::stages::decision::StageDecision;
use crate::shared::model::restriction::Restriction;
use crate::types::{ActionClass, DenialStatus, Fact};

/// JSON-RPC methods that carry no authority: the handshake, discovery and
/// liveness. Knowing a tool exists is not leave to call it.
pub(crate) const AUTHORITY_FREE_METHODS: &[&str] = &[
    "initialize",
    "notifications/initialized",
    "notifications/cancelled",
    "notifications/progress",
    "ping",
    "tools/list",
    "prompts/list",
    "resources/list",
    "resources/templates/list",
    "completion/complete",
    "logging/setLevel",
];

/// What an MCP method asks the server to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpMethod {
    /// `tools/call`: invoke the tool its `name` parameter names.
    CallTool,
    /// `resources/read`: read the content at its `uri` parameter.
    ReadResource,
    /// `prompts/get`: fetch the prompt its `name` parameter names.
    GetPrompt,
    /// Protocol traffic that reaches nothing.
    AuthorityFree,
}

impl McpMethod {
    /// The method `name` is, or `None` for one the gateway does not know,
    /// which is refused.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        match name {
            "tools/call" => Some(Self::CallTool),
            "resources/read" => Some(Self::ReadResource),
            "prompts/get" => Some(Self::GetPrompt),
            other => AUTHORITY_FREE_METHODS
                .contains(&other)
                .then_some(Self::AuthorityFree),
        }
    }

    /// The parameter naming what the method reaches, when it reaches
    /// something: `name` for a tool or a prompt, `uri` for a resource.
    #[must_use]
    pub fn target_parameter(self) -> Option<&'static str> {
        match self {
            Self::CallTool | Self::GetPrompt => Some("name"),
            Self::ReadResource => Some("uri"),
            Self::AuthorityFree => None,
        }
    }

    /// The class of action the method is, when the method alone says it:
    /// reading a resource and fetching a prompt are reads. A tool's class
    /// is the one its grant gives it; protocol traffic has none.
    #[must_use]
    pub fn purpose_class(self) -> Option<ActionClass> {
        match self {
            Self::ReadResource | Self::GetPrompt => Some(ActionClass::Read),
            Self::CallTool | Self::AuthorityFree => None,
        }
    }
}

/// One call an envelope makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpCall<'a> {
    /// Invoke this tool.
    Tool(&'a str),
    /// Read the content at this URI.
    Resource(&'a str),
    /// Fetch this prompt.
    Prompt(&'a str),
    /// Protocol traffic that reaches nothing.
    AuthorityFree,
}

impl<'a> McpCall<'a> {
    /// The call `method` makes on `target`, the value of its
    /// [`target_parameter`](McpMethod::target_parameter). `None` when a
    /// method that reaches something names nothing: a call the gateway
    /// cannot read is refused.
    #[must_use]
    pub fn new(method: McpMethod, target: Fact<&'a str>) -> Option<Self> {
        match (method, target) {
            (McpMethod::AuthorityFree, _) => Some(Self::AuthorityFree),
            (_, Fact::Unknown) => None,
            (McpMethod::CallTool, Fact::Known(name)) => Some(Self::Tool(name)),
            (McpMethod::ReadResource, Fact::Known(uri)) => Some(Self::Resource(uri)),
            (McpMethod::GetPrompt, Fact::Known(name)) => Some(Self::Prompt(name)),
        }
    }
}

/// Why MCP calls are refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpRefusal {
    /// The body was not read whole, so no name in it may be trusted.
    NotReadWhole,
    /// The body is not a JSON-RPC envelope, or names a method or a target
    /// the gateway does not read, or is an empty batch.
    NotACall,
    /// The caller holds no grant on the server.
    NoGrant,
    /// The tool's name is not one a grant can name.
    ToolUnnamed,
    /// The caller's tool patterns do not cover the requested operation.
    ToolNotGranted,
    /// The tool is outside the purpose the token declared.
    ToolOutsidePurpose,
    /// The resource's address could resolve elsewhere.
    ResourceUnsafe,
    /// The caller's resource patterns do not cover the requested address.
    ResourceNotGranted,
    /// The caller's prompt patterns do not cover the requested template.
    PromptNotGranted,
    /// Reading is outside the purpose the token declared.
    ReadOutsidePurpose,
}

impl McpRefusal {
    /// The reason the request record keeps.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotReadWhole => "mcp: the call was not read whole",
            Self::NotACall => "mcp: the body is not a call the gateway reads",
            Self::NoGrant => "mcp: the caller holds no grant on this server",
            Self::ToolUnnamed => "mcp: the tool's name is not one a grant can name",
            Self::ToolNotGranted => "mcp: the tool is not granted",
            Self::ToolOutsidePurpose => "mcp: the tool is outside the token's declared purpose",
            Self::ResourceUnsafe => "mcp: the resource's address could resolve elsewhere",
            Self::ResourceNotGranted => "mcp: the resource is not granted",
            Self::PromptNotGranted => "mcp: the prompt is not granted",
            Self::ReadOutsidePurpose => "mcp: reading is outside the token's purpose",
        }
    }

    /// The 403 the refusal is answered with.
    #[must_use]
    pub fn decision(self) -> StageDecision {
        StageDecision::Deny {
            status: DenialStatus::FORBIDDEN,
            reason: self.as_str().to_owned(),
        }
    }
}

/// Refuses `calls` unless the caller `authentication` proved may make
/// every one of them.
///
/// # Errors
///
/// - [`McpRefusal::NotACall`] for no call at all, such as an empty batch.
/// - [`McpRefusal::NoGrant`] for a call that reaches something, made by a
///   caller that is not an agent.
/// - The refusal of the first call the agent's grant or purpose does not
///   allow.
pub fn ensure_calls_granted(
    authentication: &Authentication,
    calls: &[McpCall<'_>],
) -> Result<(), McpRefusal> {
    if calls.is_empty() {
        return Err(McpRefusal::NotACall);
    }
    let holding = McpHolding::of(authentication);
    calls
        .iter()
        .try_for_each(|call| ensure_call_granted(holding, *call))
}

/// What a caller holds on an MCP server.
#[derive(Clone, Copy)]
enum McpHolding<'a> {
    /// An agent, held to these limits.
    Agent(&'a AgentLimits),
    /// Anyone else, signed in or not: they hold nothing.
    Nothing,
}

impl<'a> McpHolding<'a> {
    /// What the caller `authentication` proved holds.
    fn of(authentication: &'a Authentication) -> Self {
        let Authentication::Authenticated(Verified {
            caller: Caller::Agent { limits, .. },
            ..
        }) = authentication
        else {
            return Self::Nothing;
        };
        Self::Agent(limits.as_ref())
    }
}

fn ensure_call_granted(holding: McpHolding<'_>, call: McpCall<'_>) -> Result<(), McpRefusal> {
    if call == McpCall::AuthorityFree {
        return Ok(());
    }
    let McpHolding::Agent(limits) = holding else {
        return Err(McpRefusal::NoGrant);
    };
    match call {
        McpCall::Tool(name) => ensure_tool(limits, name),
        McpCall::Resource(uri) => ensure_resource(limits, uri),
        McpCall::Prompt(name) => ensure_prompt(limits, name),
        McpCall::AuthorityFree => Ok(()),
    }
}

fn ensure_tool(limits: &AgentLimits, name: &str) -> Result<(), McpRefusal> {
    let Ok(tool) = ToolName::new(name) else {
        return Err(McpRefusal::ToolUnnamed);
    };
    if !limits.mcp.permits_tool(&tool) {
        return Err(McpRefusal::ToolNotGranted);
    }
    let Restriction::To(purpose) = &limits.intent_envelope else {
        return Ok(());
    };
    if purpose.permits_mcp_tool(&limits.mcp, &tool) {
        return Ok(());
    }
    Err(McpRefusal::ToolOutsidePurpose)
}

fn ensure_resource(limits: &AgentLimits, uri: &str) -> Result<(), McpRefusal> {
    let Ok(resource) = McpResourceUri::new(uri) else {
        return Err(McpRefusal::ResourceUnsafe);
    };
    if !limits.mcp.permits_resource(&resource) {
        return Err(McpRefusal::ResourceNotGranted);
    }
    ensure_purpose_allows(limits, McpMethod::ReadResource)
}

fn ensure_prompt(limits: &AgentLimits, name: &str) -> Result<(), McpRefusal> {
    if !limits.mcp.permits_prompt(name) {
        return Err(McpRefusal::PromptNotGranted);
    }
    ensure_purpose_allows(limits, McpMethod::GetPrompt)
}

/// Refuses a method whose class the token's purpose does not allow.
fn ensure_purpose_allows(limits: &AgentLimits, method: McpMethod) -> Result<(), McpRefusal> {
    let Restriction::To(purpose) = &limits.intent_envelope else {
        return Ok(());
    };
    let Some(class) = method.purpose_class() else {
        return Ok(());
    };
    if purpose.permits(class) {
        return Ok(());
    }
    Err(McpRefusal::ReadOutsidePurpose)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::authority::capability::{
        ActionApproval, McpGrant, McpResourcePattern, McpTool, McpToolPattern,
    };
    use crate::domains::agents::authority::intent::IntentEnvelope;
    use crate::domains::proxy::request::context::{KeyBinding, Metering, UserSignIn};
    use crate::types::{AgentId, DelegationId, Expiry, PrincipalRef, UserId};

    fn tools(names: &[(&str, ActionClass)]) -> Vec<McpTool> {
        names
            .iter()
            .map(|(name, class)| McpTool::new(McpToolPattern::new(*name).unwrap(), *class))
            .collect()
    }

    fn agent(grant: McpGrant, purpose: Restriction<IntentEnvelope>) -> Caller {
        Caller::Agent {
            agent_id: AgentId::new(),
            delegation_id: DelegationId::new(),
            acting_for: PrincipalRef::User(UserId::new()),
            limits: Box::new(AgentLimits {
                intent_envelope: purpose,
                mcp: grant,
                resource_scope: Restriction::Unrestricted,
                max_data_class: Restriction::Unrestricted,
                key_binding: KeyBinding::Bearer,
                approval: ActionApproval::NotRequired,
                metering: Metering::Unmetered,
            }),
        }
    }

    fn granting(names: &[(&str, ActionClass)]) -> Caller {
        agent(
            McpGrant::new(tools(names), Vec::new(), Vec::new()),
            Restriction::Unrestricted,
        )
    }

    fn signed_in(caller: &Caller) -> Authentication {
        Authentication::Authenticated(Verified {
            caller: caller.clone(),
            expiry: Expiry::Never,
        })
    }

    fn check(caller: &Caller, calls: &[McpCall<'_>]) -> Result<(), McpRefusal> {
        ensure_calls_granted(&signed_in(caller), calls)
    }

    #[test]
    fn methods_are_read_by_name_and_unknown_ones_are_not() {
        assert_eq!(McpMethod::named("tools/call"), Some(McpMethod::CallTool));
        assert_eq!(McpMethod::named("ping"), Some(McpMethod::AuthorityFree));
        assert_eq!(McpMethod::named("sampling/createMessage"), None);
    }

    /// A method that reaches something but names nothing is not a call
    /// the gateway can read.
    #[test]
    fn a_call_naming_no_target_is_not_read() {
        assert_eq!(McpCall::new(McpMethod::CallTool, Fact::Unknown), None);
        assert_eq!(
            McpCall::new(McpMethod::AuthorityFree, Fact::Unknown),
            Some(McpCall::AuthorityFree)
        );
    }

    /// Reading a resource and fetching a prompt are reads; a tool's class
    /// is its grant's.
    #[test]
    fn resources_and_prompts_are_reads() {
        assert_eq!(
            McpMethod::ReadResource.purpose_class(),
            Some(ActionClass::Read)
        );
        assert_eq!(
            McpMethod::GetPrompt.purpose_class(),
            Some(ActionClass::Read)
        );
        assert_eq!(McpMethod::CallTool.purpose_class(), None);
    }

    #[test]
    fn a_granted_tool_is_allowed() {
        let caller = granting(&[("read_file", ActionClass::Read)]);

        assert_eq!(check(&caller, &[McpCall::Tool("read_file")]), Ok(()));
    }

    #[test]
    fn a_tool_outside_the_grant_is_refused() {
        let caller = granting(&[("read_file", ActionClass::Read)]);

        assert_eq!(
            check(&caller, &[McpCall::Tool("delete_file")]),
            Err(McpRefusal::ToolNotGranted)
        );
    }

    /// A person holds nothing on the server, not everything: they may
    /// connect and list, and call nothing.
    #[test]
    fn a_caller_without_a_grant_calls_nothing() {
        let ann = Caller::User {
            user_id: UserId::new(),
            sign_in: UserSignIn::Token,
        };

        assert_eq!(
            check(&ann, &[McpCall::Tool("read_file")]),
            Err(McpRefusal::NoGrant)
        );
        assert_eq!(
            ensure_calls_granted(&Authentication::Anonymous, &[McpCall::AuthorityFree]),
            Ok(())
        );
    }

    /// An anonymous caller's request for `read_file` returns `NoGrant`.
    #[test]
    fn a_caller_with_no_credential_calls_nothing() {
        assert_eq!(
            ensure_calls_granted(&Authentication::Anonymous, &[McpCall::Tool("read_file")]),
            Err(McpRefusal::NoGrant)
        );
    }

    #[test]
    fn an_empty_batch_is_refused() {
        let caller = granting(&[("*", ActionClass::Read)]);

        assert_eq!(check(&caller, &[]), Err(McpRefusal::NotACall));
    }

    /// A batch containing the granted `read_file` and ungranted `delete_all`
    /// tools returns `ToolNotGranted` for the batch.
    #[test]
    fn a_batch_with_one_call_not_granted_is_refused() {
        let caller = granting(&[("read_file", ActionClass::Read)]);

        assert_eq!(
            check(
                &caller,
                &[McpCall::Tool("read_file"), McpCall::Tool("delete_all")]
            ),
            Err(McpRefusal::ToolNotGranted)
        );
    }

    /// A granted delete tool returns `ToolOutsidePurpose` when the agent's
    /// intent permits only reading.
    #[test]
    fn a_granted_tool_outside_the_purpose_is_refused() {
        let caller = agent(
            McpGrant::new(
                tools(&[("delete_repo", ActionClass::Delete)]),
                Vec::new(),
                Vec::new(),
            ),
            Restriction::To(IntentEnvelope::new([ActionClass::Read])),
        );

        assert_eq!(
            check(&caller, &[McpCall::Tool("delete_repo")]),
            Err(McpRefusal::ToolOutsidePurpose)
        );
    }

    /// A project resource grant permits its README, refuses other folders,
    /// and rejects a path that climbs out of the project.
    #[test]
    fn resources_need_their_own_grant() {
        let reads_project = agent(
            McpGrant::new(
                Vec::new(),
                vec![McpResourcePattern::new("file:///project/*").unwrap()],
                Vec::new(),
            ),
            Restriction::Unrestricted,
        );

        assert_eq!(
            check(
                &reads_project,
                &[McpCall::Resource("file:///project/README")]
            ),
            Ok(())
        );
        assert_eq!(
            check(&reads_project, &[McpCall::Resource("file:///etc/passwd")]),
            Err(McpRefusal::ResourceNotGranted)
        );
        assert_eq!(
            check(
                &reads_project,
                &[McpCall::Resource("file:///project/../etc/shadow")]
            ),
            Err(McpRefusal::ResourceUnsafe)
        );
    }

    /// A wildcard read-tool grant does not permit reading a server resource.
    #[test]
    fn a_tool_grant_does_not_grant_resources() {
        assert_eq!(
            check(
                &granting(&[("*", ActionClass::Read)]),
                &[McpCall::Resource("file:///project/README")]
            ),
            Err(McpRefusal::ResourceNotGranted)
        );
    }

    /// Fetching a granted prompt returns `ReadOutsidePurpose` when the
    /// agent's intent permits only writing.
    #[test]
    fn a_prompt_is_a_read_the_purpose_must_allow() {
        let writer = agent(
            McpGrant::new(
                Vec::new(),
                Vec::new(),
                vec![McpToolPattern::new("triage_*").unwrap()],
            ),
            Restriction::To(IntentEnvelope::new([ActionClass::Write])),
        );

        assert_eq!(
            check(&writer, &[McpCall::Prompt("triage_issue")]),
            Err(McpRefusal::ReadOutsidePurpose)
        );
    }

    #[test]
    fn prompts_need_their_own_grant() {
        let triage = agent(
            McpGrant::new(
                Vec::new(),
                Vec::new(),
                vec![McpToolPattern::new("triage_*").unwrap()],
            ),
            Restriction::Unrestricted,
        );

        assert_eq!(check(&triage, &[McpCall::Prompt("triage_issue")]), Ok(()));
        assert_eq!(
            check(&triage, &[McpCall::Prompt("exfiltrate")]),
            Err(McpRefusal::PromptNotGranted)
        );
    }
}
