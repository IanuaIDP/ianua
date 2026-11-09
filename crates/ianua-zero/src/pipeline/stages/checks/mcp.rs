//! Authorizing Model Context Protocol calls.
//!
//! MCP is JSON-RPC over one endpoint: every tool call an agent makes is the
//! same `POST` to the same path, so a route policy cannot tell
//! `github_list_issues` from `github_delete_repo`. This stage reads the
//! envelope, and only as far as it must: the method, and the tool, resource
//! or prompt it names. Arguments are never read. Each name is held to the
//! caller's grant and the purpose its token declared by the domain's
//! `ensure_calls_granted`; the gateway decides nothing of its own.
//!
//! Deny by default:
//!
//! - A body cut short by the read, or not read, is refused: a name the
//!   gateway could not read is not one it may allow.
//! - A batch passes only if every call in it does, and an empty one does
//!   not.
//! - A method the stage does not know is refused; new protocol surface is
//!   granted, never inherited.
//! - A caller with no grant reaches nothing: only an agent's task token
//!   carries one, so a person or a consumer may connect and list, and call
//!   nothing.
//! - Reading a resource and fetching a prompt are their own rights, never
//!   carried by a tool grant, and both are reads the purpose must allow:
//!   they return content the agent acts on, which is what a prompt
//!   injection rides in on.

use ianua_domain::domains::proxy::request::body::CapturedBody;
use ianua_domain::domains::proxy::request::context::Authentication;
use ianua_domain::domains::proxy::stages::checks::mcp::{
    McpCall, McpMethod, McpRefusal, ensure_calls_granted,
};
use ianua_domain::domains::proxy::stages::decision::StageDecision;
use ianua_domain::types::Fact;
use serde_json::Value;

use super::pass;

/// The decision on the calls in `body`, made by the caller
/// `authentication` proved. What each call may reach is the domain's rule;
/// this stage only reads the names out of the envelope.
pub(super) fn verdict(
    authentication: &Authentication,
    body: Option<CapturedBody<'_>>,
) -> StageDecision {
    let Some(body) = body.filter(CapturedBody::is_whole) else {
        return McpRefusal::NotReadWhole.decision();
    };
    let Ok(envelope) = serde_json::from_slice::<Value>(body.bytes) else {
        return McpRefusal::NotACall.decision();
    };
    let Some(calls) = calls_in(&envelope) else {
        return McpRefusal::NotACall.decision();
    };
    match ensure_calls_granted(authentication, &calls) {
        Ok(()) => pass("mcp: every call is granted"),
        Err(refusal) => refusal.decision(),
    }
}

/// Every call in `envelope`, single or batched. `None` when any part is
/// not a call the stage reads; an empty batch is refused by the domain.
fn calls_in(envelope: &Value) -> Option<Vec<McpCall<'_>>> {
    let Some(batch) = envelope.as_array() else {
        return call_in(envelope).map(|call| vec![call]);
    };
    batch.iter().map(call_in).collect()
}

/// The call one envelope names: its method, and the tool, resource or
/// prompt the method's parameter names.
fn call_in(envelope: &Value) -> Option<McpCall<'_>> {
    let method = McpMethod::named(envelope.get("method")?.as_str()?)?;
    let target = method
        .target_parameter()
        .and_then(|key| envelope.get("params")?.get(key)?.as_str());
    McpCall::new(method, Fact::from_option(target))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::{
        ActionApproval, McpGrant, McpResourcePattern, McpTool, McpToolPattern,
    };
    use ianua_domain::domains::agents::authority::intent::IntentEnvelope;
    use ianua_domain::domains::proxy::request::body::BodyExtent;
    use ianua_domain::domains::proxy::request::context::{
        AgentLimits, Caller, KeyBinding, Metering, Verified,
    };
    use ianua_domain::shared::model::restriction::Restriction;
    use ianua_domain::types::{ActionClass, AgentId, DelegationId, Expiry, PrincipalRef, UserId};

    use super::*;

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

    fn envelope(method: &str, params: &Value) -> Vec<u8> {
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
            .to_string()
            .into_bytes()
    }

    fn tool_call(name: &str) -> Vec<u8> {
        envelope(
            "tools/call",
            &serde_json::json!({ "name": name, "arguments": {} }),
        )
    }

    fn signed_in(caller: &Caller) -> Authentication {
        Authentication::Authenticated(Verified {
            caller: caller.clone(),
            expiry: Expiry::Never,
        })
    }

    fn decide(caller: &Caller, sent: &[u8]) -> StageDecision {
        verdict(
            &signed_in(caller),
            Some(CapturedBody::new(sent, BodyExtent::Whole)),
        )
    }

    #[test]
    fn a_granted_tool_is_allowed() {
        let caller = granting(&[("read_file", ActionClass::Read)]);

        assert!(!decide(&caller, &tool_call("read_file")).is_terminal());
    }

    #[test]
    fn a_tool_outside_the_grant_is_refused() {
        let caller = granting(&[("read_file", ActionClass::Read)]);

        assert!(decide(&caller, &tool_call("delete_file")).is_terminal());
    }

    /// A caller that is not an agent holds nothing on the server, not
    /// everything.
    #[test]
    fn a_caller_without_a_grant_calls_nothing() {
        let sent = tool_call("read_file");

        let decision = verdict(
            &Authentication::Anonymous,
            Some(CapturedBody::new(&sent, BodyExtent::Whole)),
        );

        assert!(decision.is_terminal());
    }

    /// Partial and unread MCP bodies are refused even with a wildcard tool grant.
    #[test]
    fn a_call_not_read_whole_is_refused() {
        let caller = granting(&[("*", ActionClass::Read)]);
        let sent = tool_call("read_file");

        let cut = verdict(
            &signed_in(&caller),
            Some(CapturedBody::new(&sent, BodyExtent::Prefix)),
        );
        let unread = verdict(&signed_in(&caller), None);

        assert!(cut.is_terminal());
        assert!(unread.is_terminal());
    }

    #[test]
    fn a_body_that_is_not_a_call_is_refused() {
        let caller = granting(&[("*", ActionClass::Read)]);

        assert!(decide(&caller, b"not json").is_terminal());
        assert!(decide(&caller, br#"{"jsonrpc":"2.0","id":1}"#).is_terminal());
        assert!(decide(&caller, b"[]").is_terminal());
    }

    #[test]
    fn a_method_the_stage_does_not_know_is_refused() {
        let caller = granting(&[("*", ActionClass::Read)]);

        let decision = decide(&caller, &envelope("sampling/createMessage", &Value::Null));

        assert!(decision.is_terminal());
    }

    #[test]
    fn the_handshake_and_discovery_pass_without_a_grant() {
        let caller = granting(&[]);
        for method in ["initialize", "ping", "tools/list"] {
            assert!(
                !decide(&caller, &envelope(method, &Value::Null)).is_terminal(),
                "{method}"
            );
        }
    }

    /// A batch containing one granted read and one ungranted delete is refused as a whole.
    #[test]
    fn a_batch_with_one_call_not_granted_is_refused() {
        let caller = granting(&[("read_file", ActionClass::Read)]);
        let batch = serde_json::json!([
            { "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "read_file" } },
            { "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": { "name": "delete_all" } }
        ])
        .to_string();

        assert!(decide(&caller, batch.as_bytes()).is_terminal());
    }

    /// A granted delete tool is still refused when the agent's intent permits only reads.
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

        assert!(decide(&caller, &tool_call("delete_repo")).is_terminal());
    }

    /// A tool grant is not leave to read what the server holds.
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
        let read = |uri: &str| envelope("resources/read", &serde_json::json!({ "uri": uri }));

        assert!(!decide(&reads_project, &read("file:///project/README")).is_terminal());
        assert!(decide(&reads_project, &read("file:///etc/passwd")).is_terminal());
        assert!(decide(&reads_project, &read("file:///project/../etc/shadow")).is_terminal());
        assert!(
            decide(
                &granting(&[("*", ActionClass::Read)]),
                &read("file:///project/README")
            )
            .is_terminal()
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
        let fetch = |name: &str| envelope("prompts/get", &serde_json::json!({ "name": name }));

        assert!(!decide(&triage, &fetch("triage_issue")).is_terminal());
        assert!(decide(&triage, &fetch("exfiltrate")).is_terminal());
    }
}
