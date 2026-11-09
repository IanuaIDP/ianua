//! What a post-response stage changes about the response before it reaches
//! the client.

#[cfg(feature = "serde")]
use crate::domains::proxy::request::transform::header_pair;
use crate::domains::proxy::request::transform::{
    BodyTransform, CONNECTION_HEADERS, resolve_values,
};
use crate::domains::proxy::stages::decision::HeaderEntry;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::web::proxy_headers::{header_spelling, is_proxy_owned};
use crate::types::{HeaderName, HeaderValue};

/// What a post-response stage changes about the response before it reaches
/// the client.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ResponseMutation {
    set_headers: Vec<HeaderEntry>,
    remove_headers: Vec<HeaderName>,
    body: Option<BodyTransform>,
}

/// Reads a response mutation through [`ResponseMutation::configured`].
///
/// The reason is the same as for
/// [`RequestMutation`](crate::domains::proxy::request::transform::RequestMutation):
/// stored or sent configuration keeps the same rules as configuration built
/// in code.
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ResponseMutation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct Wire {
            #[serde(default)]
            set_headers: Vec<HeaderEntry>,
            #[serde(default)]
            remove_headers: Vec<HeaderName>,
            #[serde(default)]
            body: Option<BodyTransform>,
        }

        let wire = Wire::deserialize(deserializer)?;

        Self::configured(ResponseMutationRules {
            set_headers: wire.set_headers.iter().map(header_pair).collect(),
            remove_headers: wire.remove_headers,
            body: wire.body,
        })
        .map_err(<D::Error as serde::de::Error>::custom)
    }
}

/// The rules a tenant configures on a response-transform stage.
#[derive(Debug, Clone, Default)]
pub struct ResponseMutationRules {
    /// Headers to add to the response, overwriting any the upstream set.
    pub set_headers: Vec<(HeaderName, HeaderValue)>,
    /// Headers to drop from the response.
    pub remove_headers: Vec<HeaderName>,
    /// What to change inside a JSON body.
    ///
    /// Left out, the body streams through untouched.
    pub body: Option<BodyTransform>,
}

impl ResponseMutation {
    /// Headers a platform stage adds to the response.
    ///
    /// It cannot fail and has no limits, like
    /// [`RequestMutation::asserting`](crate::domains::proxy::request::transform::RequestMutation::asserting).
    /// The `ResponseSign` stage needs it to write the signature header.
    #[must_use]
    pub fn asserting(headers: Vec<HeaderEntry>) -> Self {
        Self {
            set_headers: headers,
            remove_headers: Vec::new(),
            body: None,
        }
    }

    /// A mutation built from tenant configuration.
    ///
    /// Unlike the request side, no proxy-owned header needs guarding here. The
    /// response headers the proxy asserts are added after the post-response
    /// stages run, so a transform cannot forge or erase one.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] if a header to set or drop describes the
    ///   connection, not the message.
    ///
    /// Header values are checked when they are built, by [`HeaderValue`].
    /// Body rules are checked when they are built, by
    /// [`FieldRename::new`](crate::domains::proxy::request::transform::FieldRename::new)
    /// and [`FieldPath`](crate::types::FieldPath).
    pub fn configured(rules: ResponseMutationRules) -> Result<Self, DomainError> {
        for (name, _) in &rules.set_headers {
            validate_message_header(name)?;
        }
        for name in &rules.remove_headers {
            validate_message_header(name)?;
        }

        Ok(Self {
            set_headers: rules
                .set_headers
                .into_iter()
                .map(|(name, value)| HeaderEntry::new(name, value))
                .collect(),
            remove_headers: rules.remove_headers,
            body: rules.body.filter(|body| !body.is_empty()),
        })
    }

    /// Whether this mutation changes nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.set_headers.is_empty() && self.remove_headers.is_empty() && self.body.is_none()
    }

    /// What to change inside the body, if the stage asked for anything.
    #[must_use]
    pub fn body(&self) -> Option<&BodyTransform> {
        self.body.as_ref()
    }

    /// Folds a later stage's mutation into this one.
    pub fn merge(&mut self, other: Self) {
        self.set_headers.extend(other.set_headers);
        self.remove_headers.extend(other.remove_headers);
        if other.body.is_some() {
            self.body = other.body;
        }
    }

    /// A copy with each header value replaced by what `resolved` holds for
    /// the value as configured.
    ///
    /// For configuration that names a credential instead of carrying one.
    /// The caller fetches the values, and the replacement happens here, where
    /// the rules about what a mutation may set already hold. A value with no
    /// entry in `resolved` is kept as written, so a literal stays as it is.
    ///
    /// # Errors
    ///
    /// - [`DomainError`] if a resolved value is not one a header may carry,
    ///   such as a secret store answering with a newline in it.
    pub fn with_resolved_values(
        &self,
        resolved: &std::collections::HashMap<String, String>,
    ) -> Result<Self, DomainError> {
        let mut replaced = self.clone();
        replaced.set_headers = resolve_values(&self.set_headers, resolved)?;
        Ok(replaced)
    }

    /// Headers to add or overwrite on the response.
    #[must_use]
    pub fn headers_to_set(&self) -> &[HeaderEntry] {
        &self.set_headers
    }

    /// Headers to drop from the response.
    #[must_use]
    pub fn remove_headers(&self) -> &[HeaderName] {
        &self.remove_headers
    }
}

/// Refuses a header name a tenant may not write on the request.
pub(in crate::domains::proxy) fn validate_configurable(
    name: &HeaderName,
) -> Result<(), DomainError> {
    if is_proxy_owned(name.as_str()) {
        return Err(DomainError::invalid(message!(
            "proxy-is-asserted-by-the-proxy-and",
            format!("'{name}' is asserted by the proxy and cannot be set from a transform")
        )));
    }
    validate_message_header(name)
}

/// Refuses a header that frames the connection, not the message.
pub(in crate::domains::proxy) fn validate_message_header(
    name: &HeaderName,
) -> Result<(), DomainError> {
    if CONNECTION_HEADERS.contains(&header_spelling(name.as_str()).as_str()) {
        return Err(DomainError::invalid(message!(
            "proxy-describes-the-connection-and-cannot-be",
            format!("'{name}' describes the connection and cannot be set from a transform")
        )));
    }
    Ok(())
}
