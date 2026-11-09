//! The Chat Completions wire format, spoken by OpenAI and by self-hosted
//! servers such as vLLM and Ollama.
//!
//! As OpenAI documents it
//! (<https://developers.openai.com/api/docs/api-reference/chat>):
//!
//! - `POST /chat/completions` under the API base, with
//!   `Authorization: Bearer <key>`;
//! - the body names `model` and `messages`, each message a `role`
//!   (`system`, `user`, `assistant`) and its `content`;
//! - `max_tokens` "is now deprecated in favor of `max_completion_tokens`,
//!   and is not compatible with o-series models", so OpenAI is sent
//!   `max_completion_tokens`, "an upper bound for the number of tokens that
//!   can be generated for a completion, including visible output tokens and
//!   reasoning tokens";
//! - the answer's text is `choices[0].message.content`, which may be null,
//!   with `message.refusal` set when the model declined;
//! - `finish_reason` is `stop`, `length`, `tool_calls`, `content_filter` or
//!   `function_call`;
//! - `usage` holds `prompt_tokens` and `completion_tokens`, and may be
//!   left out.
//!
//! A reasoning model reasons inside `max_completion_tokens`, and OpenAI's
//! reasoning guide (<https://developers.openai.com/api/docs/guides/reasoning>)
//! recommends "reserving at least 25,000 tokens for reasoning and outputs".
//! Whether a model reasons is not in the request, and a reasoning setting
//! sent to a model without one is refused, so OpenAI is given that room on
//! top of the answer's cap, and the run's spend limit counts what was
//! really used.
//!
//! Self-hosted servers take `max_tokens`: Ollama lists it among the fields
//! it supports and does not list `max_completion_tokens`
//! (<https://docs.ollama.com/api/openai-compatibility>); vLLM takes both
//! and reads its key from `Authorization: Bearer`
//! (<https://docs.vllm.ai/en/latest/serving/online_serving/openai_compatible_server/>).
//! A keyless server is sent no `Authorization` header at all. A finish is
//! `stop`, or TGI's `eos_token` and `stop_sequence`
//! (<https://pypi.org/project/text-generation/>); `length` is a cut-off.
//!
//! Any other `finish_reason`, or none, is not called a finish, so the
//! answer counts as cut off and the run does not use it.

use ianua_app::ports::agents::ModelFailure;
use ianua_domain::domains::agents::execution::chat::{
    AnswerEnd, ChatMessage, Completion, CompletionRequest,
};
use ianua_domain::domains::agents::execution::model_provider::ModelName;
use ianua_domain::domains::agents::execution::usage::{ModelTokens, ModelUsage};
use ianua_domain::shared::errors::DomainError;
use reqwest::header::AUTHORIZATION;
use serde::{Deserialize, Serialize};

use crate::crypto::sigv4::sensitive;
use crate::http::models::{CompletionCall, Ending, NO_TEXT, completion_of, read};

/// Where a completion is asked for, under the API base.
pub(super) const PATH: &str = "/chat/completions";

/// The room OpenAI's reasoning guide recommends keeping for reasoning,
/// given on top of the answer's cap.
const REASONING_ROOM: u32 = 25_000;

/// The field a server reads the cap on generated tokens from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TokenCap {
    /// `max_completion_tokens`, which OpenAI reads, with room for
    /// reasoning on top.
    MaxCompletionTokens,
    /// `max_tokens`, which self-hosted servers read, as it is.
    MaxTokens,
}

/// `call` carrying `request` for `model`, the cap in the field `cap` names
/// and `key`, when there is one, as a bearer token.
///
/// # Errors
///
/// `DomainError::Infrastructure` when the key cannot be sent in a header.
pub(super) fn request(
    call: reqwest::RequestBuilder,
    completion: CompletionCall<'_>,
    cap: TokenCap,
) -> Result<reqwest::RequestBuilder, DomainError> {
    let call = call.json(&body(&completion.target.model, completion.request, cap));
    let Some(key) = completion.key else {
        return Ok(call);
    };
    Ok(call.header(
        AUTHORIZATION,
        sensitive(&format!("Bearer {}", key.expose()))?,
    ))
}

/// The body asking `model` to continue `request`'s conversation.
fn body<'a>(
    model: &'a ModelName,
    request: &'a CompletionRequest,
    cap: TokenCap,
) -> ChatRequest<'a> {
    let (max_tokens, max_completion_tokens) = match cap {
        TokenCap::MaxTokens => (request.max_tokens, None),
        TokenCap::MaxCompletionTokens => (
            None,
            request
                .max_tokens
                .map(|answer| answer.saturating_add(REASONING_ROOM)),
        ),
    };
    ChatRequest {
        model: model.as_str(),
        messages: request.messages.iter().map(ChatTurn::of).collect(),
        max_tokens,
        max_completion_tokens,
    }
}

/// The completion a Chat Completions answer holds: the first choice's
/// text, how it ended, and the usage the server reported.
///
/// # Errors
///
/// A [`ModelFailure`], billed, when the answer is not in the documented
/// shape, holds no choice, the model declined, or it finished with no
/// text.
pub(super) fn completion(body: &[u8]) -> Result<Completion, ModelFailure> {
    let answer: ChatAnswer = read(body)?;
    let usage = usage_of(answer.usage.as_ref());
    let Some(choice) = answer.choices.into_iter().next() else {
        return Err(ModelFailure::billed(usage, DomainError::infra_msg(NO_TEXT)));
    };
    let ending = ending_of(&choice);
    completion_of(choice.message.content.unwrap_or_default(), usage, ending)
}

/// How `choice` ended: declined when it carries a refusal or was filtered,
/// finished on a reason that names a finish, cut off otherwise.
fn ending_of(choice: &Choice) -> Ending {
    if choice.message.refusal.is_some() {
        return Ending::Declined;
    }
    match choice.finish_reason.as_deref() {
        Some("stop" | "eos_token" | "stop_sequence") => Ending::Answered(AnswerEnd::Finished),
        Some("content_filter") => Ending::Declined,
        _ => Ending::Answered(AnswerEnd::CutOff),
    }
}

/// The tokens `usage` reports, or unreported when it is missing or lacks
/// either count.
fn usage_of(usage: Option<&ChatUsage>) -> ModelUsage {
    let Some(ChatUsage {
        prompt_tokens: Some(input),
        completion_tokens: Some(output),
    }) = usage
    else {
        return ModelUsage::Unreported;
    };
    ModelUsage::Reported(ModelTokens::new(*input, *output))
}

/// A Chat Completions request.
#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<ChatTurn<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_completion_tokens: Option<u32>,
}

/// One message of the conversation sent.
#[derive(Serialize)]
struct ChatTurn<'a> {
    role: &'static str,
    content: &'a str,
}

impl<'a> ChatTurn<'a> {
    /// `message` under its Chat Completions role.
    fn of(message: &'a ChatMessage) -> Self {
        Self {
            role: message.role().as_str(),
            content: message.content(),
        }
    }
}

/// A Chat Completions answer, read only as far as a completion needs.
#[derive(Deserialize)]
struct ChatAnswer {
    choices: Vec<Choice>,
    usage: Option<ChatUsage>,
}

/// One choice of an answer.
#[derive(Deserialize)]
struct Choice {
    message: AnswerMessage,
    finish_reason: Option<String>,
}

/// The message a choice holds.
#[derive(Deserialize)]
struct AnswerMessage {
    content: Option<String>,
    refusal: Option<String>,
}

/// The tokens an answer reports.
#[derive(Deserialize)]
struct ChatUsage {
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::agents::{ModelCharge, ModelClient as _};
    use ianua_domain::domains::agents::execution::model_provider::ModelProviderKind;
    use serde_json::json;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::http::models::REFUSED_TO_ANSWER;
    use crate::http::models::tests::{
        KEY, answering, client, named, printed, probe, target, target_at,
    };

    /// The example answer of OpenAI's chat completion reference.
    fn documented_answer() -> serde_json::Value {
        json!({
            "id": "chatcmpl-123",
            "object": "chat.completion",
            "created": 1741569952,
            "model": "gpt-6-astra",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Hello! How can I assist you today?",
                    "refusal": null
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 19,
                "completion_tokens": 10,
                "total_tokens": 29
            }
        })
    }

    /// A conversation of a system prompt, a goal, a tool call and its
    /// result.
    fn conversation() -> CompletionRequest {
        CompletionRequest {
            messages: vec![
                ChatMessage::system("only these tools"),
                ChatMessage::user("reconcile the ledger"),
                ChatMessage::assistant(r#"{"tool":"get_order"}"#),
                ChatMessage::user("result"),
            ],
            max_tokens: Some(512),
        }
    }

    /// OpenAI is asked at `/chat/completions` with every message under its
    /// role and the cap as `max_completion_tokens`, the answer's cap with
    /// room for reasoning on top, and its text, ending and usage are read
    /// back.
    #[tokio::test]
    async fn openai_answers_with_its_text_and_usage() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(body_json(json!({
                "model": "test-model",
                "messages": [
                    {"role": "system", "content": "only these tools"},
                    {"role": "user", "content": "reconcile the ledger"},
                    {"role": "assistant", "content": r#"{"tool":"get_order"}"#},
                    {"role": "user", "content": "result"}
                ],
                "max_completion_tokens": 512 + REASONING_ROOM
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(documented_answer()))
            .mount(&server)
            .await;
        let openai = target_at(
            &format!("{}/v1", named(&server)),
            ModelProviderKind::OpenAi,
            Some(KEY),
        );

        let completion = client().complete(&openai, &conversation()).await.unwrap();

        assert_eq!(completion.content, "Hello! How can I assist you today?");
        assert_eq!(completion.ended, AnswerEnd::Finished);
        assert_eq!(
            completion.usage,
            ModelUsage::Reported(ModelTokens::new(19, 10))
        );
    }

    /// A self-hosted server is sent the cap as `max_tokens`, as it is,
    /// which Ollama and vLLM both read.
    #[tokio::test]
    async fn a_self_hosted_server_is_sent_max_tokens() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(body_json(json!({
                "model": "test-model",
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 16
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(documented_answer()))
            .mount(&server)
            .await;

        let completion = client()
            .complete(
                &target(&server, ModelProviderKind::SelfHosted, None),
                &probe(),
            )
            .await
            .unwrap();

        assert_eq!(completion.content, "Hello! How can I assist you today?");
    }

    /// The model's tool call comes back as the text the run reads it from.
    #[tokio::test]
    async fn a_tool_call_comes_back_as_its_text() {
        let mut answer = documented_answer();
        answer["choices"][0]["message"]["content"] =
            json!(r#"{"tool":"get_order","arguments":{"id":42}}"#);
        let server = answering(ResponseTemplate::new(200).set_body_json(answer)).await;

        let completion = client()
            .complete(
                &target(&server, ModelProviderKind::SelfHosted, None),
                &probe(),
            )
            .await
            .unwrap();

        assert_eq!(
            completion.content,
            r#"{"tool":"get_order","arguments":{"id":42}}"#
        );
    }

    /// Answers ending with `length`, `tool_calls` or no finish reason are
    /// marked cut off while retaining both reported token counts.
    #[tokio::test]
    async fn an_answer_stopped_at_its_cap_is_cut_off() {
        for reason in [json!("length"), json!("tool_calls"), json!(null)] {
            let mut answer = documented_answer();
            answer["choices"][0]["finish_reason"] = reason.clone();
            let server = answering(ResponseTemplate::new(200).set_body_json(answer)).await;

            let completion = client()
                .complete(
                    &target(&server, ModelProviderKind::SelfHosted, None),
                    &probe(),
                )
                .await
                .unwrap();

            assert_eq!(completion.ended, AnswerEnd::CutOff, "{reason}");
            assert_eq!(
                completion.usage,
                ModelUsage::Reported(ModelTokens::new(19, 10))
            );
        }
    }

    /// A reasoning model that spent its whole cap reasoning answers with no
    /// text and `length`. It is a cut-off answer, not an unreadable one.
    #[tokio::test]
    async fn a_cap_spent_on_reasoning_is_a_cut_off_answer() {
        let mut answer = documented_answer();
        answer["choices"][0]["message"]["content"] = json!("");
        answer["choices"][0]["finish_reason"] = json!("length");
        let server = answering(ResponseTemplate::new(200).set_body_json(answer)).await;

        let completion = client()
            .complete(
                &target(&server, ModelProviderKind::OpenAi, Some(KEY)),
                &probe(),
            )
            .await
            .unwrap();

        assert_eq!(completion.ended, AnswerEnd::CutOff);
    }

    /// TGI's own words for a finish read as finished.
    #[test]
    fn tgi_finishes_read_as_finished() {
        for reason in ["eos_token", "stop_sequence"] {
            let choice = Choice {
                message: AnswerMessage {
                    content: Some("done".to_owned()),
                    refusal: None,
                },
                finish_reason: Some(reason.to_owned()),
            };

            assert_eq!(
                ending_of(&choice),
                Ending::Answered(AnswerEnd::Finished),
                "{reason}"
            );
        }
    }

    /// An answer without a usage object produces unreported usage.
    #[tokio::test]
    async fn an_answer_without_usage_is_unreported() {
        let mut answer = documented_answer();
        answer.as_object_mut().unwrap().remove("usage");
        let server = answering(ResponseTemplate::new(200).set_body_json(answer)).await;

        let completion = client()
            .complete(
                &target(&server, ModelProviderKind::SelfHosted, None),
                &probe(),
            )
            .await
            .unwrap();

        assert_eq!(completion.usage, ModelUsage::Unreported);
    }

    /// Usage with an input count but no output count is unreported.
    #[test]
    fn half_a_usage_is_unreported() {
        let half = ChatUsage {
            prompt_tokens: Some(19),
            completion_tokens: None,
        };

        assert_eq!(usage_of(Some(&half)), ModelUsage::Unreported);
    }

    /// The key travels as a bearer token and nowhere else: not in
    /// `x-api-key`, the address or the body.
    #[tokio::test]
    async fn the_key_is_sent_only_as_a_bearer_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("authorization", format!("Bearer {KEY}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(documented_answer()))
            .mount(&server)
            .await;

        client()
            .complete(
                &target(&server, ModelProviderKind::OpenAi, Some(KEY)),
                &probe(),
            )
            .await
            .unwrap();

        let sent = &server.received_requests().await.unwrap()[0];
        assert!(!sent.headers.contains_key("x-api-key"));
        assert!(!sent.url.as_str().contains(KEY));
        assert!(!String::from_utf8_lossy(&sent.body).contains(KEY));
    }

    /// A keyless self-hosted server is sent no `Authorization` header.
    #[tokio::test]
    async fn a_keyless_server_is_sent_no_authorization() {
        let server = answering(ResponseTemplate::new(200).set_body_json(documented_answer())).await;

        client()
            .complete(
                &target(&server, ModelProviderKind::SelfHosted, None),
                &probe(),
            )
            .await
            .unwrap();

        let sent = &server.received_requests().await.unwrap()[0];
        assert!(!sent.headers.contains_key("authorization"));
    }

    /// A refusal with null content returns a billed failure retaining the
    /// reported token counts and excluding the provider's refusal text.
    #[tokio::test]
    async fn a_refusal_is_a_failed_call_that_keeps_its_usage() {
        let mut answer = documented_answer();
        answer["choices"][0]["message"] =
            json!({"role": "assistant", "content": null, "refusal": "I can't help with that."});
        let server = answering(ResponseTemplate::new(200).set_body_json(answer)).await;

        let failure = client()
            .complete(
                &target(&server, ModelProviderKind::OpenAi, Some(KEY)),
                &probe(),
            )
            .await
            .unwrap_err();

        let text = printed(&failure);
        assert!(text.contains(REFUSED_TO_ANSWER), "{text}");
        assert!(!text.contains("can't help"), "{text}");
        assert_eq!(
            failure.charge,
            ModelCharge::Billed(ModelUsage::Reported(ModelTokens::new(19, 10)))
        );
    }

    /// An answer the provider's filter stopped is declined, with its usage
    /// kept.
    #[tokio::test]
    async fn a_filtered_answer_is_declined() {
        let mut answer = documented_answer();
        answer["choices"][0]["finish_reason"] = json!("content_filter");
        let server = answering(ResponseTemplate::new(200).set_body_json(answer)).await;

        let failure = client()
            .complete(
                &target(&server, ModelProviderKind::OpenAi, Some(KEY)),
                &probe(),
            )
            .await
            .unwrap_err();

        assert!(printed(&failure).contains(REFUSED_TO_ANSWER));
        assert_eq!(
            failure.charge,
            ModelCharge::Billed(ModelUsage::Reported(ModelTokens::new(19, 10)))
        );
    }

    /// A malformed choices field returns a billed failure with unreported
    /// usage; the error describes the shape problem without quoting the value.
    #[tokio::test]
    async fn an_answer_in_another_shape_is_refused_without_its_text() {
        let server = answering(
            ResponseTemplate::new(200).set_body_json(json!({"choices": "the secret plan"})),
        )
        .await;

        let failure = client()
            .complete(
                &target(&server, ModelProviderKind::SelfHosted, None),
                &probe(),
            )
            .await
            .unwrap_err();

        let text = printed(&failure);
        assert!(text.contains("documented shape"), "{text}");
        assert!(!text.contains("secret plan"), "{text}");
        assert_eq!(failure.charge, ModelCharge::Billed(ModelUsage::Unreported));
    }
}
