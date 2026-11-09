//! What a run says to its model, and how it reads the reply.
//!
//! The prompt offers the run's tools and its goal, and replays every step
//! the run has already taken. A reply is a tool call when it is a JSON
//! object naming a tool, and a final answer otherwise.

use ianua_domain::domains::agents::execution::chat::{
    ChatMessage, UNTRUSTED_NOTICE, fence_untrusted,
};
use ianua_domain::domains::agents::execution::run::{AgentRun, RunStep, StepOutcome};
use ianua_domain::domains::agents::execution::tool::AgentTool;
use ianua_domain::isolation::scope::ResolvedTenant;

/// The messages for the next model call: the system prompt offering
/// `offered`, the run's goal, and every step the run has already taken.
pub(in crate::use_cases::agents::runs) fn conversation_so_far(
    offered: &[AgentTool<ResolvedTenant>],
    run: &AgentRun<ResolvedTenant>,
) -> Vec<ChatMessage> {
    let mut messages = vec![
        ChatMessage::system(system_prompt(offered)),
        ChatMessage::user(run.goal().as_str().to_owned()),
    ];
    replay_history(&mut messages, run.steps());
    messages
}

/// Replays a run's recorded steps into the message history, so a reclaimed run
/// resumes with the context it had before the driver that started it stopped.
/// A fresh run has no steps and is unaffected.
fn replay_history(messages: &mut Vec<ChatMessage>, steps: &[RunStep]) {
    for step in steps {
        match step.tool() {
            Some(tool) => replay_tool_step(messages, tool, step),
            None => replay_model_step(messages, step),
        }
    }
}

/// Replays a step taken without a tool: an answer a check turned back, as
/// the model gave it, and what the check said of it.
fn replay_model_step(messages: &mut Vec<ChatMessage>, step: &RunStep) {
    match step.outcome() {
        StepOutcome::Answered(answer) => messages.push(ChatMessage::assistant(answer.as_str())),
        StepOutcome::CheckFailed(said) => {
            messages.push(ChatMessage::user(check_failed_message(said)));
        }
        StepOutcome::Allowed(_) | StepOutcome::Denied(_) | StepOutcome::Replied(_) => {}
    }
}

/// Replays a tool call `step` made to `tool`, and what came of it.
fn replay_tool_step(messages: &mut Vec<ChatMessage>, tool: &str, step: &RunStep) {
    let answered = match step.outcome() {
        StepOutcome::Allowed(result) => tool_result_message(tool, result),
        StepOutcome::Denied(reason) => format!("DENIED ({tool}): {reason}"),
        StepOutcome::Replied(reply) => replied_message(tool, reply),
        StepOutcome::Answered(_) | StepOutcome::CheckFailed(_) => return,
    };
    messages.push(ChatMessage::assistant(tool_call_json(
        tool,
        step.arguments(),
    )));
    messages.push(ChatMessage::user(answered));
}

/// What the check a run is held to found in its last answer, as the model
/// sees it: the answer was not accepted, and the check's words, fenced as
/// data, say what to fix.
pub(in crate::use_cases::agents::runs) fn check_failed_message(said: &str) -> String {
    format!(
        "CHECK FAILED: your answer broke a rule it must keep, and was not accepted. \
         Fix your work and give a new final answer. {}",
        fence_untrusted("what the check found", said)
    )
}

/// Reconstructs the tool-call turn for a recorded step from its persisted tool
/// and arguments, so a reclaimed run replays exactly the call it already made.
fn tool_call_json(tool: &str, arguments: Option<&str>) -> String {
    let arguments = arguments.unwrap_or("{}");
    format!("{{\"tool\": \"{tool}\", \"arguments\": {arguments}}}")
}

/// Builds the system prompt: the tool list, the reply protocol, and how to
/// read untrusted data.
fn system_prompt(tools: &[AgentTool<ResolvedTenant>]) -> String {
    let mut s = String::from(
        "You are an agent that reaches a goal by calling tools. On each turn reply with \
         EITHER a final answer as plain text, OR a single tool call as JSON exactly like \
         {\"tool\": \"<name>\", \"arguments\": {...}}. Only these tools are available:\n",
    );
    if tools.is_empty() {
        s.push_str("(none: answer directly)\n");
    }
    for t in tools {
        s.push_str(&format!(
            "- {}: {}\n",
            t.name().as_str(),
            t.description().as_str()
        ));
    }
    s.push('\n');
    s.push_str(UNTRUSTED_NOTICE);
    s
}

/// What a person wrote back instead of letting the call to `tool` run, as
/// the model sees it: the call did not run, and here is what they said.
fn replied_message(tool: &str, reply: &str) -> String {
    format!("NOT RUN ({tool}): a person answered this call instead of approving it: {reply}")
}

/// A tool's result as the model sees it: fenced, so nothing the tool returns
/// reads as an instruction from the loop.
pub(in crate::use_cases::agents::runs) fn tool_result_message(tool: &str, result: &str) -> String {
    fence_untrusted(&format!("result of {tool}"), result)
}

/// Parses a model reply into a tool call, if it is one.
///
/// Accepts a bare JSON object or one wrapped in a ```` ``` ```` / ```` ```json ```` fence.
/// Anything else is treated as a final answer.
pub(in crate::use_cases::agents::runs) fn parse_tool_call(text: &str) -> Option<(String, String)> {
    let cleaned = strip_fences(text);
    let value: serde_json::Value = serde_json::from_str(cleaned).ok()?;
    let object = value.as_object()?;
    let name = object.get("tool")?.as_str()?.to_owned();
    let arguments = object
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
    Some((name, arguments.to_string()))
}

fn strip_fences(text: &str) -> &str {
    let trimmed = text.trim();
    let Some(rest) = trimmed.strip_prefix("```") else {
        return trimmed;
    };
    let rest = rest.strip_prefix("json").unwrap_or(rest);
    rest.trim_matches(|c: char| c == '`' || c.is_whitespace())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The model answers with a call as bare JSON, or fenced as ```json or
    /// plain ```. Each reads as the call it names.
    #[test]
    fn parse_tool_call_reads_bare_and_fenced_json() {
        let (name, args) =
            parse_tool_call(r#"{"tool": "get_order", "arguments": {"id": 1}}"#).expect("bare json");
        assert_eq!(name, "get_order");
        assert!(args.contains("\"id\":1") || args.contains("\"id\": 1"));

        let fenced = "```json\n{\"tool\": \"x\", \"arguments\": {}}\n```";
        assert_eq!(parse_tool_call(fenced).unwrap().0, "x");

        let fenced_plain = "```\n{\"tool\": \"y\", \"arguments\": {}}\n```";
        assert_eq!(parse_tool_call(fenced_plain).unwrap().0, "y");
    }

    /// A call naming a tool and no arguments reads as one with empty
    /// arguments.
    #[test]
    fn parse_tool_call_defaults_empty_arguments() {
        let (name, args) = parse_tool_call(r#"{"tool": "ping"}"#).unwrap();
        assert_eq!(name, "ping");
        assert_eq!(args, "{}");
    }

    /// Prose, broken JSON, JSON that names no tool, and a call buried in
    /// prose all read as a final answer, never as a call.
    #[test]
    fn parse_tool_call_treats_non_tool_json_and_prose_as_a_final_answer() {
        assert!(parse_tool_call("The answer is 42.").is_none());
        assert!(parse_tool_call("{ not valid json").is_none());
        assert!(parse_tool_call(r#"{"message": "hello"}"#).is_none());
        assert!(parse_tool_call(r#"[1, 2, 3]"#).is_none());
        assert!(parse_tool_call(r#""just a string""#).is_none());
        assert!(parse_tool_call(r#"{"tool": 5}"#).is_none());
        assert!(parse_tool_call("Here is the call: {\"tool\":\"x\"}").is_none());
    }
}
