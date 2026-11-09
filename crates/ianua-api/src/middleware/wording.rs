//! Error answers in the reader's language: a refusal with a message key is
//! reworded in the first language of `Accept-Language` the platform words
//! it in. Its key, values, code and status stay as they were; with no
//! such language, or no wording, the English answer goes out unchanged.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::HeaderValue;
use axum::http::header::{ACCEPT_LANGUAGE, CONTENT_LENGTH, VARY};
use axum::middleware::Next;
use axum::response::Response;
use ianua_app::ports::shared::RefusalWording;

use crate::error::{WordableRefusal, sentence};
use crate::extractors::language::preferred_languages;

/// Rewords an error answer that carries a keyed refusal.
pub async fn wording(
    State(wording): State<Arc<dyn RefusalWording>>,
    request: Request,
    next: Next,
) -> Response {
    let languages = preferred_languages(request.headers().get(ACCEPT_LANGUAGE));
    let mut response = next.run(request).await;
    let Some(wordable) = response.extensions_mut().remove::<WordableRefusal>() else {
        return response;
    };
    response
        .headers_mut()
        .append(VARY, HeaderValue::from_static("accept-language"));
    let Some(worded) = wording.worded(&wordable.refusal, &languages) else {
        return response;
    };
    reworded(response, wordable, &worded)
}

/// `response` with its body's message replaced by `worded`, capitalized as
/// the English message was.
fn reworded(response: Response, wordable: WordableRefusal, worded: &str) -> Response {
    let mut body = wordable.body;
    body.message = capitalized_like(&body.message, worded);
    let Ok(json) = serde_json::to_vec(&body) else {
        return response;
    };
    let (mut parts, _) = response.into_parts();
    parts.headers.remove(CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(json))
}

/// `worded` starting with a capital when `english` does.
fn capitalized_like(english: &str, worded: &str) -> String {
    if english.starts_with(char::is_uppercase) {
        return sentence(worded);
    }
    worded.to_owned()
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::http::StatusCode;
    use axum::routing::get;
    use ianua_app::error::AppError;
    use ianua_app::ports::shared::PreferredLanguages;
    use ianua_domain::shared::errors::Refusal;
    use tower::ServiceExt as _;

    use super::*;
    use crate::error::ApiError;

    /// Words every keyed refusal as `Auf Deutsch` when German is asked for.
    struct German;

    impl RefusalWording for German {
        fn worded(&self, refusal: &Refusal, languages: &PreferredLanguages) -> Option<String> {
            let german = languages
                .tags()
                .first()
                .is_some_and(|tag| tag.starts_with("de"));
            (german && refusal.key().is_some()).then(|| "auf Deutsch".to_owned())
        }
    }

    /// A router answering a keyed and an unkeyed refusal, behind the wording.
    fn app() -> Router {
        Router::new()
            .route(
                "/keyed",
                get(|| async {
                    ApiError(AppError::Conflict(ianua_domain::message!(
                        "people-is-taken",
                        format!("{} is taken", "Ann")
                    )))
                }),
            )
            .route(
                "/plain",
                get(|| async { ApiError(AppError::Conflict("taken".into())) }),
            )
            .layer(axum::middleware::from_fn_with_state(
                Arc::new(German) as Arc<dyn RefusalWording>,
                wording,
            ))
    }

    /// The status and body `path` answers, asked in `language` when given.
    async fn answer(path: &str, language: Option<&str>) -> (StatusCode, serde_json::Value) {
        let mut request = Request::get(path);
        if let Some(language) = language {
            request = request.header(ACCEPT_LANGUAGE, language);
        }
        let response = app()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    /// Ann reads German. The refusal is worded in German and keeps its
    /// key, values, code and status.
    #[tokio::test]
    async fn a_keyed_refusal_is_worded_in_the_readers_language() {
        let (status, body) = answer("/keyed", Some("de-AT, en;q=0.5")).await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["message"], "Auf Deutsch");
        assert_eq!(body["key"], "people-is-taken");
        assert_eq!(body["params"]["arg0"], "Ann");
        assert_eq!(body["error"], "conflict");
    }

    /// With no language asked for, the English answer goes out unchanged.
    #[tokio::test]
    async fn no_language_keeps_the_english() {
        let (_, body) = answer("/keyed", None).await;

        assert_eq!(body["message"], "Ann is taken");
    }

    /// An unkeyed refusal retains its message without translation keys or parameters.
    #[tokio::test]
    async fn a_refusal_without_a_key_is_sent_as_written() {
        let (_, body) = answer("/plain", Some("de")).await;

        assert_eq!(body["message"], "Taken");
        assert!(body.get("key").is_none());
        assert!(body.get("params").is_none());
    }
}
