//! The body the API refuses with.

use std::fmt;

use serde::Deserialize;

/// Why the API refused a request: a code a client branches on, and a
/// sentence a person reads.
///
/// The API's own refusals carry `error` and `message`, with `challenge`
/// when sign-in asks for one. OAuth's refusals carry `error` and
/// `error_description`, which is read as the message.
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct Problem {
    error: String,
    #[serde(default, alias = "error_description")]
    message: String,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    challenge: Option<String>,
}

impl Problem {
    /// The machine-readable code, such as `unauthenticated`.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.error
    }

    /// The sentence a person reads.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The internal detail a development deployment adds to a server
    /// error.
    #[must_use]
    pub fn details(&self) -> Option<&str> {
        self.details.as_deref()
    }

    /// The challenge sign-in asks for under pressure, such as
    /// `proof_of_work`.
    #[must_use]
    pub fn challenge(&self) -> Option<&str> {
        self.challenge.as_deref()
    }
}

/// A refusal in SCIM's own error format (RFC 7644 section 3.12), which the
/// provisioning endpoints answer a directory with. Read as a [`Problem`]
/// whose code is the SCIM error type, such as `uniqueness`, or empty for a
/// status that has none, and whose message is the detail.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScimError {
    /// The schemas the body follows, which only a SCIM error carries.
    #[serde(rename = "schemas")]
    _schemas: Vec<String>,
    /// The SCIM error type, for the statuses that have one.
    #[serde(default)]
    scim_type: Option<String>,
    /// What went wrong.
    #[serde(default)]
    detail: String,
}

impl From<ScimError> for Problem {
    fn from(error: ScimError) -> Self {
        Self {
            error: error.scim_type.unwrap_or_default(),
            message: error.detail,
            details: None,
            challenge: None,
        }
    }
}

impl fmt::Debug for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error, self.message)?;
        if let Some(challenge) = &self.challenge {
            write!(f, " (challenge {challenge})")?;
        }
        if let Some(details) = &self.details {
            write!(f, " [{details}]")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The API's own refusal is read with its code and message.
    #[test]
    fn the_apis_refusal_is_read() {
        let problem: Problem = serde_json::from_str(
            r#"{"error":"challenge_required","message":"Sign-in is busy","challenge":"proof_of_work"}"#,
        )
        .unwrap();

        assert_eq!(problem.code(), "challenge_required");
        assert_eq!(problem.challenge(), Some("proof_of_work"));
    }

    /// An OAuth refusal is read with its description as the message.
    #[test]
    fn an_oauth_refusal_is_read() {
        let problem: Problem =
            serde_json::from_str(r#"{"error":"invalid_grant","error_description":"expired"}"#)
                .unwrap();

        assert_eq!(problem.code(), "invalid_grant");
        assert_eq!(problem.message(), "expired");
    }

    /// A SCIM refusal is read with its error type as the code and its
    /// detail as the message.
    #[test]
    fn a_scim_refusal_is_read_with_its_type_as_the_code() {
        let error: ScimError = serde_json::from_str(
            r#"{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"409","scimType":"uniqueness","detail":"taken"}"#,
        )
        .unwrap();

        let problem = Problem::from(error);

        assert_eq!(problem.code(), "uniqueness");
        assert_eq!(problem.message(), "taken");
    }

    /// A SCIM refusal whose status has no error type is read with an empty
    /// code.
    #[test]
    fn a_scim_refusal_without_a_type_has_an_empty_code() {
        let error: ScimError = serde_json::from_str(
            r#"{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"401","detail":"no"}"#,
        )
        .unwrap();

        assert_eq!(Problem::from(error).code(), "");
    }
}
