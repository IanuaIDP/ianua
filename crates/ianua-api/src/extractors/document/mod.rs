//! JSON or YAML, whichever the caller is speaking.
//!
//! Only the gateway configuration endpoints use this. A configuration document
//! is written by hand and reviewed in a pull request, and people write those in
//! YAML: comments, no trailing-comma arguments, and a diff that reads. The
//! rest of the API stays JSON-only, because nothing else about it is meant to
//! be edited by a person in a text editor.

use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::header::{ACCEPT, CONTENT_TYPE};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use ianua_domain::message;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::ApiError;

mod budget;

/// The media type registered for YAML (RFC 9512).
const YAML: &str = "application/yaml";

/// The two spellings that predate the registration and are still what most
/// tools send.
const YAML_ALIASES: [&str; 2] = ["text/yaml", "application/x-yaml"];

/// Which serialization a request or response is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Format {
    /// JSON. The default everywhere, and what any caller that says nothing
    /// gets.
    #[default]
    Json,
    /// Human-edited configuration documents requested through media-type headers.
    Yaml,
}

impl Format {
    /// The format a media-type header names, defaulting to JSON.
    fn of(headers: &HeaderMap, name: &HeaderName) -> Self {
        let Some(value) = headers.get(name).and_then(|value| value.to_str().ok()) else {
            return Self::Json;
        };
        let mentions_yaml = value
            .split(',')
            .map(|entry| entry.split(';').next().unwrap_or_default().trim())
            .any(|media| media == YAML || YAML_ALIASES.contains(&media));
        if mentions_yaml {
            return Self::Yaml;
        }
        Self::Json
    }

    /// The media type to answer with.
    fn media_type(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Yaml => YAML,
        }
    }
}

/// The format the caller asked to be answered in, read from `Accept`.
///
/// A caller that asks for nothing, or for something this does not speak, gets
/// JSON: an unknown `Accept` is a preference, not an error, and refusing it
/// would break every client that sends `*/*`.
impl<S: Send + Sync> FromRequestParts<S> for Format {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self::of(&parts.headers, &ACCEPT))
    }
}

/// A request body in whichever format its `Content-Type` names.
pub(crate) struct Document<T>(pub T);

impl<T, S> FromRequest<S> for Document<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let format = Format::of(request.headers(), &CONTENT_TYPE);
        let bytes = axum::body::Bytes::from_request(request, state)
            .await
            .map_err(|e| {
                ApiError::validation(message!(
                    "api-could-not-read-the-request-body",
                    format!("could not read the request body: {e}")
                ))
            })?;
        let value = match format {
            Format::Json => serde_json::from_slice(&bytes).map_err(|e| {
                ApiError::validation(message!("api-invalid-json", format!("invalid JSON: {e}")))
            }),
            Format::Yaml => budget::yaml_within_budget(&bytes)
                .map_err(|e| {
                    ApiError::validation(message!("api-invalid-yaml", format!("invalid YAML: {e}")))
                })
                .and_then(|value| {
                    serde_json::from_value(value).map_err(|e| {
                        ApiError::validation(message!(
                            "api-invalid-yaml",
                            format!("invalid YAML: {e}")
                        ))
                    })
                }),
        }?;
        Ok(Self(value))
    }
}

/// A response body in whichever format the caller asked for.
pub(crate) struct Rendered<T: Serialize>(pub Format, pub T);

impl<T: Serialize> IntoResponse for Rendered<T> {
    fn into_response(self) -> Response {
        let Self(format, value) = self;
        let body = match format {
            Format::Json => serde_json::to_vec(&value).map_err(|e| e.to_string()),
            Format::Yaml => serde_norway::to_string(&value)
                .map(String::into_bytes)
                .map_err(|e| e.to_string()),
        };
        let Ok(body) = body else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        ([(CONTENT_TYPE, format.media_type())], body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    /// Request headers holding one header with the given value.
    fn headers(name: HeaderName, value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(name, HeaderValue::from_str(value).unwrap());
        headers
    }

    /// A caller that sends no `Accept` header gets JSON.
    #[test]
    fn a_caller_saying_nothing_gets_json() {
        assert_eq!(Format::of(&HeaderMap::new(), &ACCEPT), Format::Json);
    }

    /// A caller asking for `application/yaml` gets YAML.
    #[test]
    fn the_registered_yaml_media_type_is_recognized() {
        assert_eq!(Format::of(&headers(ACCEPT, YAML), &ACCEPT), Format::Yaml);
    }

    /// Both predate the registration and both are still in the wild.
    #[test]
    fn the_older_yaml_spellings_are_recognized() {
        for alias in YAML_ALIASES {
            assert_eq!(Format::of(&headers(ACCEPT, alias), &ACCEPT), Format::Yaml);
        }
    }

    /// A browser-style `Accept` with several types and weights still finds
    /// YAML among them.
    #[test]
    fn parameters_and_multiple_entries_are_read_past() {
        let value = "text/html, application/yaml;q=0.9, */*;q=0.1";

        assert_eq!(Format::of(&headers(ACCEPT, value), &ACCEPT), Format::Yaml);
    }

    /// Refusing an unknown `Accept` would break every client sending `*/*`.
    #[test]
    fn an_unknown_accept_falls_back_to_json() {
        assert_eq!(
            Format::of(&headers(ACCEPT, "application/xml"), &ACCEPT),
            Format::Json
        );
    }

    /// A body sent as `application/json` is read as JSON.
    #[test]
    fn a_json_content_type_is_read_as_json() {
        assert_eq!(
            Format::of(&headers(CONTENT_TYPE, "application/json"), &CONTENT_TYPE),
            Format::Json
        );
    }

    /// The media type goes on the response, and a client parses the body
    /// according to it. Answering YAML under a JSON content type, or under
    /// none, hands them something they cannot read.
    #[test]
    fn each_format_names_the_media_type_it_answers_with() {
        assert_eq!(Format::Json.media_type(), "application/json");
        assert_eq!(Format::Yaml.media_type(), YAML);
        assert_ne!(Format::Json.media_type(), Format::Yaml.media_type());
    }

    /// A rendered response carries the format that was asked for, in both
    /// the body and the header that describes it.
    #[test]
    fn a_rendered_body_is_written_in_the_format_it_was_asked_for() {
        #[derive(serde::Serialize)]
        struct Body {
            slug: &'static str,
        }

        let json = Rendered(Format::Json, Body { slug: "acme" }).into_response();
        assert_eq!(
            json.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let yaml = Rendered(Format::Yaml, Body { slug: "acme" }).into_response();
        assert_eq!(yaml.headers().get(CONTENT_TYPE).unwrap(), YAML);
        assert_eq!(yaml.status(), StatusCode::OK);
    }
}
