//! Anthropic's Messages API wire format.
//!
//! As Anthropic documents it
//! (<https://platform.claude.com/docs/en/api/messages>,
//! <https://platform.claude.com/docs/en/api/versioning>,
//! <https://platform.claude.com/docs/en/api/errors>,
//! <https://platform.claude.com/docs/en/build-with-claude/handling-stop-reasons>):
//!
//! - `POST /v1/messages` on `https://api.anthropic.com`, with the key in
//!   `x-api-key` and the API version in `anthropic-version`, which every
//!   request must send;
//! - `model`, `max_tokens` and `messages` are required; each message is a
//!   `user` or `assistant` turn, and the system prompt is the top-level
//!   `system` field, not a message;
//! - "consecutive `user` or `assistant` turns in your request will be
//!   combined into a single turn", so turns are sent as the run wrote them;
//! - the answer's `content` is a list of blocks; its text is the `text`
//!   blocks in order, and the others (`thinking`, `redacted_thinking`,
//!   `tool_use` and the rest) are not the model's reply;
//! - `stop_reason` is `end_turn` or `stop_sequence` for a finish,
//!   `max_tokens` or `model_context_window_exceeded` for an answer to
//!   "treat as truncated", `pause_turn` for a turn left to continue, and
//!   `refusal` when the model declined, which arrives "as a normal HTTP 200
//!   response" with its usage; `end_turn` can also come with no content;
//! - `usage` holds `input_tokens` and `output_tokens`, and "total input
//!   tokens in a request is the summation of `input_tokens`,
//!   `cache_creation_input_tokens`, and `cache_read_input_tokens`", the last
//!   two of which may be null;
//! - an error is `{"type":"error","error":{"type":…,"message":…}}`.
//!
//! The version sent is `2023-06-01`, the one the reference's own requests
//! send. Nothing this adapter sends is changed by a later version.
//!
//! **Thinking.** The thinking guide
//! (<https://platform.claude.com/docs/en/build-with-claude/thinking>) says
//! thinking tokens "count toward `max_tokens` alongside the response text".
//! With no `thinking` field, Claude Opus 5.5, Sonnet 5.5, Haiku 5.5, Fable,
//! Mythos, Opus 5 and Sonnet 5 think adaptively, and older models do not.
//! Turning it off cannot be asked of every model: `"disabled"` is a 400
//! error on Opus 5.5, Sonnet 5.5, Fable and Mythos, and works on others
//! only at `high` effort or below; nor can `output_config.effort`, which
//! some older models do not take. So each model keeps its own default,
//! and `max_tokens` is the answer's cap with [`THINKING_ROOM`] on top. Every
//! current model accepts far more output than that, and the run's spend
//! limit counts the tokens really used.

use ianua_app::ports::agents::ModelFailure;
use ianua_domain::domains::agents::execution::chat::{
    AnswerEnd, ChatMessage, ChatRole, Completion, CompletionRequest,
};
use ianua_domain::domains::agents::execution::model_provider::ModelName;
use ianua_domain::domains::agents::execution::usage::{ModelTokens, ModelUsage};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use serde::{Deserialize, Serialize};

use crate::crypto::sigv4::sensitive;
use crate::http::models::{Ending, completion_of, read};

/// Where a message is asked for, under the API's host.
pub(super) const PATH: &str = "/v1/messages";

/// The header the key travels in.
const KEY_HEADER: &str = "x-api-key";

/// The header naming the API version.
const VERSION_HEADER: &str = "anthropic-version";

/// The API version every request is made under.
const VERSION: &str = "2023-06-01";

/// The answer's cap when the run sets none: the value the reference's own
/// examples use.
const DEFAULT_ANSWER_TOKENS: u32 = 1024;

/// The room a thinking model is given on top of the answer's cap: the
/// `max_tokens` the thinking guide's own examples send.
const THINKING_ROOM: u32 = 16_000;

/// Between the system messages, when a run has more than one.
const SYSTEM_SEPARATOR: &str = "\n\n";

/// `call` carrying `request` for `model`, with `key` in `x-api-key` and the
/// API version named.
///
/// # Errors
///
/// `DomainError::Infrastructure` when there is no key, or it cannot be
/// sent in a header.
pub(super) fn request(
    call: reqwest::RequestBuilder,
    model: &ModelName,
    request: &CompletionRequest,
    key: Option<&Secret>,
) -> Result<reqwest::RequestBuilder, DomainError> {
    let Some(key) = key else {
        return Err(DomainError::infra_msg(
            "the model provider takes a key and none is set",
        ));
    };
    Ok(call
        .header(KEY_HEADER, sensitive(key.expose())?)
        .header(VERSION_HEADER, VERSION)
        .json(&body(model, request)))
}

/// The body asking `model` to continue `request`'s conversation.
fn body<'a>(model: &'a ModelName, request: &'a CompletionRequest) -> MessagesRequest<'a> {
    MessagesRequest {
        model: model.as_str(),
        max_tokens: request
            .max_tokens
            .unwrap_or(DEFAULT_ANSWER_TOKENS)
            .saturating_add(THINKING_ROOM),
        system: system_of(request),
        messages: request
            .messages
            .iter()
            .filter_map(|message| {
                turn_role(message.role()).map(|role| Turn {
                    role,
                    content: message.content(),
                })
            })
            .collect(),
    }
}

/// The run's system messages as the one `system` field, or none.
fn system_of(request: &CompletionRequest) -> Option<String> {
    let parts: Vec<&str> = request
        .messages
        .iter()
        .filter(|message| message.role() == ChatRole::System)
        .map(ChatMessage::content)
        .collect();
    (!parts.is_empty()).then(|| parts.join(SYSTEM_SEPARATOR))
}

/// The role a message is sent under, or none for a system message, which
/// travels in `system`.
fn turn_role(role: ChatRole) -> Option<&'static str> {
    match role {
        ChatRole::System => None,
        ChatRole::User => Some("user"),
        ChatRole::Assistant => Some("assistant"),
    }
}

/// The completion a Messages answer holds: its text blocks in order, how
/// it ended, and the usage it reported.
///
/// # Errors
///
/// A [`ModelFailure`], billed, when the answer is not in the documented
/// shape, the model declined, or it finished with no text.
pub(super) fn completion(body: &[u8]) -> Result<Completion, ModelFailure> {
    let answer: MessagesAnswer = read(body)?;
    let usage = usage_of(answer.usage.as_ref());
    let ending = ending_of(answer.stop_reason.as_deref());
    let content: String = answer
        .content
        .into_iter()
        .filter_map(|block| match block {
            Block::Text { text } => Some(text),
            Block::Other => None,
        })
        .collect();
    completion_of(content, usage, ending)
}

/// How an answer that stopped for `reason` ended: a finish on `end_turn`
/// or `stop_sequence`, declined on `refusal`, cut off on anything else.
fn ending_of(reason: Option<&str>) -> Ending {
    match reason {
        Some("end_turn" | "stop_sequence") => Ending::Answered(AnswerEnd::Finished),
        Some("refusal") => Ending::Declined,
        _ => Ending::Answered(AnswerEnd::CutOff),
    }
}

/// The tokens `usage` reports, input counted with what was written to and
/// read from the cache, or unreported when it is missing or lacks either
/// main count.
fn usage_of(usage: Option<&MessagesUsage>) -> ModelUsage {
    let Some(MessagesUsage {
        input_tokens: Some(input),
        output_tokens: Some(output),
        cache_creation_input_tokens,
        cache_read_input_tokens,
    }) = usage
    else {
        return ModelUsage::Unreported;
    };
    let input = input
        .saturating_add(cache_creation_input_tokens.unwrap_or(0))
        .saturating_add(cache_read_input_tokens.unwrap_or(0));
    ModelUsage::Reported(ModelTokens::new(input, *output))
}

/// A Messages API request.
#[derive(Serialize)]
struct MessagesRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    messages: Vec<Turn<'a>>,
}

/// One turn of the conversation sent.
#[derive(Serialize)]
struct Turn<'a> {
    role: &'static str,
    content: &'a str,
}

/// A Messages answer, read only as far as a completion needs.
#[derive(Deserialize)]
struct MessagesAnswer {
    content: Vec<Block>,
    stop_reason: Option<String>,
    usage: Option<MessagesUsage>,
}

/// One block of an answer's content.
#[derive(Deserialize)]
#[serde(tag = "type")]
enum Block {
    /// Text the model wrote.
    #[serde(rename = "text")]
    Text { text: String },
    /// Anything else: thinking, a tool use, a server tool's result.
    #[serde(other)]
    Other,
}

/// The tokens an answer reports.
#[derive(Deserialize)]
struct MessagesUsage {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    cache_creation_input_tokens: Option<u64>,
    cache_read_input_tokens: Option<u64>,
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::agents::{ModelCharge, ModelClient as _};
    use ianua_domain::domains::agents::execution::model_provider::ModelProviderKind;
    use serde_json::json;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::http::models::tests::{KEY, answering, client, printed, probe, target};
    use crate::http::models::{NO_TEXT, REFUSED_TO_ANSWER};

    /// The example answer of Anthropic's Messages reference.
    fn documented_answer() -> serde_json::Value {
        json!({
            "id": "msg_1234567890abcdef",
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "text", "text": "Hello! How can I help you today?"}
            ],
            "model": "claude-opus-5-5",
            "stop_reason": "end_turn",
            "stop_sequence": null,
            "usage": {
                "input_tokens": 10,
                "output_tokens": 15,
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 0
            }
        })
    }

    /// The documented answer, stopped for `reason` with `content`.
    fn stopped(reason: &str, content: serde_json::Value) -> serde_json::Value {
        let mut answer = documented_answer();
        answer["stop_reason"] = json!(reason);
        answer["content"] = content;
        answer
    }

    /// The system prompt goes in `system`, the turns go in `messages`
    /// under their roles, `max_tokens` is the answer's cap with room for
    /// thinking on top and no thinking setting is sent, and the text,
    /// ending and usage come back.
    #[tokio::test]
    async fn a_conversation_is_sent_in_the_messages_shape() {
        let server = MockServer::start().await;
        mount_conversation(&server).await;
        let request = CompletionRequest {
            messages: vec![
                ChatMessage::system("only these tools"),
                ChatMessage::user("reconcile the ledger"),
                ChatMessage::assistant(r#"{"tool":"get_order"}"#),
                ChatMessage::user("result"),
            ],
            max_tokens: Some(512),
        };

        let completion = client()
            .complete(
                &target(&server, ModelProviderKind::Anthropic, Some(KEY)),
                &request,
            )
            .await
            .unwrap();

        assert_eq!(completion.content, "Hello! How can I help you today?");
        assert_eq!(completion.ended, AnswerEnd::Finished);
        assert_eq!(
            completion.usage,
            ModelUsage::Reported(ModelTokens::new(10, 15))
        );
    }

    /// Answers only the conversation's documented message shape and API version.
    async fn mount_conversation(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(header("anthropic-version", "2023-06-01"))
            .and(body_json(json!({
                "model": "test-model",
                "max_tokens": 512 + THINKING_ROOM,
                "system": "only these tools",
                "messages": [
                    {"role": "user", "content": "reconcile the ledger"},
                    {"role": "assistant", "content": r#"{"tool":"get_order"}"#},
                    {"role": "user", "content": "result"}
                ]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(documented_answer()))
            .mount(server)
            .await;
    }

    /// A request with a 512-token answer cap adds room for thinking and
    /// omits `thinking`, `output_config` and the unused `system` field.
    /// An uncapped request adds the same room to the default answer cap.
    #[test]
    fn the_cap_leaves_room_for_thinking_and_sends_no_thinking_setting() {
        let model = ModelName::new("test-model").unwrap();
        let capped = CompletionRequest::single(ChatMessage::user("ping"), Some(512));
        let uncapped = CompletionRequest::single(ChatMessage::user("ping"), None);

        let sent = serde_json::to_value(body(&model, &capped)).unwrap();
        let default = serde_json::to_value(body(&model, &uncapped)).unwrap();

        assert_eq!(sent["max_tokens"], json!(512 + THINKING_ROOM));
        assert!(sent.get("thinking").is_none());
        assert!(sent.get("output_config").is_none());
        assert!(sent.get("system").is_none());
        assert_eq!(
            default["max_tokens"],
            json!(DEFAULT_ANSWER_TOKENS + THINKING_ROOM)
        );
    }

    /// The model's tool call comes back as the text the run reads it from,
    /// and a thinking block before it is not part of the reply.
    #[tokio::test]
    async fn a_tool_call_comes_back_as_its_text_without_the_thinking() {
        let answer = stopped(
            "end_turn",
            json!([
                {"type": "thinking", "thinking": "", "signature": "sig"},
                {"type": "text", "text": r#"{"tool":"get_order","#},
                {"type": "text", "text": r#""arguments":{"id":42}}"#}
            ]),
        );
        let server = answering(ResponseTemplate::new(200).set_body_json(answer)).await;

        let completion = client()
            .complete(
                &target(&server, ModelProviderKind::Anthropic, Some(KEY)),
                &probe(),
            )
            .await
            .unwrap();

        assert_eq!(
            completion.content,
            r#"{"tool":"get_order","arguments":{"id":42}}"#
        );
    }

    /// Answers stopped at the token limit or context window, and paused
    /// answers, are cut off with their reported usage retained. This also
    /// holds when the answer contains only thinking or no content.
    #[tokio::test]
    async fn an_answer_stopped_short_is_cut_off() {
        for (reason, content) in [
            (
                "max_tokens",
                json!([{"type": "text", "text": r#"{"tool": "get_or"#}]),
            ),
            (
                "max_tokens",
                json!([{"type": "thinking", "thinking": "", "signature": "s"}]),
            ),
            (
                "model_context_window_exceeded",
                json!([{"type": "text", "text": "Half"}]),
            ),
            ("pause_turn", json!([])),
        ] {
            let server =
                answering(ResponseTemplate::new(200).set_body_json(stopped(reason, content))).await;

            let completion = client()
                .complete(
                    &target(&server, ModelProviderKind::Anthropic, Some(KEY)),
                    &probe(),
                )
                .await
                .unwrap();

            assert_eq!(completion.ended, AnswerEnd::CutOff, "{reason}");
            assert_eq!(
                completion.usage,
                ModelUsage::Reported(ModelTokens::new(10, 15))
            );
        }
    }

    /// Input read from or written to the cache is input too, as the
    /// reference counts it, so a run's spend is not under-counted.
    #[test]
    fn cached_input_is_counted_as_input() {
        let usage = MessagesUsage {
            input_tokens: Some(10),
            output_tokens: Some(15),
            cache_creation_input_tokens: Some(100),
            cache_read_input_tokens: Some(1000),
        };

        assert_eq!(
            usage_of(Some(&usage)),
            ModelUsage::Reported(ModelTokens::new(1110, 15))
        );
    }

    /// An answer without usage and usage missing its input count are both
    /// represented as `ModelUsage::Unreported`.
    #[tokio::test]
    async fn an_answer_without_usage_is_unreported() {
        let mut answer = documented_answer();
        answer.as_object_mut().unwrap().remove("usage");
        let server = answering(ResponseTemplate::new(200).set_body_json(answer)).await;
        let half = MessagesUsage {
            input_tokens: None,
            output_tokens: Some(15),
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        };

        let completion = client()
            .complete(
                &target(&server, ModelProviderKind::Anthropic, Some(KEY)),
                &probe(),
            )
            .await
            .unwrap();

        assert_eq!(completion.usage, ModelUsage::Unreported);
        assert_eq!(usage_of(Some(&half)), ModelUsage::Unreported);
    }

    /// The key travels in `x-api-key` and nowhere else: not as a bearer
    /// token, in the address or in the body.
    #[tokio::test]
    async fn the_key_is_sent_only_in_x_api_key() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("x-api-key", KEY))
            .respond_with(ResponseTemplate::new(200).set_body_json(documented_answer()))
            .mount(&server)
            .await;

        client()
            .complete(
                &target(&server, ModelProviderKind::Anthropic, Some(KEY)),
                &probe(),
            )
            .await
            .unwrap();

        let sent = &server.received_requests().await.unwrap()[0];
        assert!(!sent.headers.contains_key("authorization"));
        assert!(!sent.url.as_str().contains(KEY));
        assert!(!String::from_utf8_lossy(&sent.body).contains(KEY));
    }

    /// An empty answer with a refusal stop reason returns a refusal error
    /// billed for its reported input and output tokens.
    #[tokio::test]
    async fn a_refusal_is_a_failed_call_that_keeps_its_usage() {
        let server =
            answering(ResponseTemplate::new(200).set_body_json(stopped("refusal", json!([]))))
                .await;

        let failure = client()
            .complete(
                &target(&server, ModelProviderKind::Anthropic, Some(KEY)),
                &probe(),
            )
            .await
            .unwrap_err();

        assert!(printed(&failure).contains(REFUSED_TO_ANSWER));
        assert_eq!(
            failure.charge,
            ModelCharge::Billed(ModelUsage::Reported(ModelTokens::new(10, 15)))
        );
    }

    /// The documented empty answer, `end_turn` with no content, is a failed
    /// call, billed.
    #[tokio::test]
    async fn an_empty_finished_answer_is_a_failed_call() {
        let server =
            answering(ResponseTemplate::new(200).set_body_json(stopped("end_turn", json!([]))))
                .await;

        let failure = client()
            .complete(
                &target(&server, ModelProviderKind::Anthropic, Some(KEY)),
                &probe(),
            )
            .await
            .unwrap_err();

        assert!(printed(&failure).contains(NO_TEXT));
        assert!(matches!(failure.charge, ModelCharge::Billed(_)));
    }

    /// An overloaded API, which answers 529 with the documented error
    /// body, is a failed call naming its status and error type, billed for
    /// nothing.
    #[tokio::test]
    async fn an_overloaded_api_is_a_failed_call() {
        let server = answering(ResponseTemplate::new(529).set_body_json(json!({
            "type": "error",
            "error": {"type": "overloaded_error", "message": "Overloaded"},
            "request_id": "req_011CSHoEeqs5C35K2UUqR7Fy"
        })))
        .await;

        let failure = client()
            .complete(
                &target(&server, ModelProviderKind::Anthropic, Some(KEY)),
                &probe(),
            )
            .await
            .unwrap_err();

        assert!(printed(&failure).contains("status 529 (overloaded_error)"));
        assert_eq!(failure.charge, ModelCharge::Unbilled);
    }
}
