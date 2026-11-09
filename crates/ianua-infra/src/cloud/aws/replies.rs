//! Reading what AWS's query APIs answer, which is XML: the parts of a
//! success the adapters need, and whose fault a failure was.
//!
//! A failure carries an error code. Only an access denial of the
//! customer's grant is theirs to fix; every other code, our own
//! credentials refused among them, is ours, so a customer is never sent to
//! rebuild a role because our egress or our keys failed.

use ianua_domain::shared::errors::DomainError;
use roxmltree::{Document, Node};

use crate::cloud::answers::Reply;
use crate::reading::xml::{ensure_shallow, plain_word};

/// The deepest an element of an answer may sit. AWS's answers nest a
/// handful of levels; far deeper is an answer built to exhaust the stack.
const MOST_DEPTH: usize = 32;

/// Whose credentials signed a call, which decides whose fault a refusal is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignedBy {
    /// The platform's own keys, assuming the customer's role.
    Platform,
    /// The session the customer's role granted.
    Session,
}

/// The codes that mean the customer's grant was refused, by whose keys
/// signed the call.
fn refused_codes(signed_by: SignedBy) -> &'static [&'static str] {
    match signed_by {
        SignedBy::Platform => &["AccessDenied"],
        SignedBy::Session => &[
            "AccessDenied",
            "AccessDeniedException",
            "UnauthorizedOperation",
            "AuthFailure",
        ],
    }
}

/// The text of a success, or the failure it stands for.
///
/// # Errors
///
/// - `DomainError::Forbidden` with `refusal` when AWS refused the
///   customer's grant.
/// - `DomainError::Infrastructure` for any other failure, or an answer that
///   is not text.
pub(crate) fn answered(
    reply: Reply,
    signed_by: SignedBy,
    refusal: &str,
) -> Result<String, DomainError> {
    let succeeded = reply.succeeded();
    let status = reply.status;
    let text = String::from_utf8(reply.body).map_err(DomainError::infra)?;
    if succeeded {
        return Ok(text);
    }
    let code = error_code(&text).unwrap_or_default();
    if refused_codes(signed_by)
        .iter()
        .any(|refused| *refused == code)
    {
        return Err(DomainError::forbidden(refusal));
    }
    Err(DomainError::infra_msg(format!(
        "AWS answered with status {status} and code {}",
        plain_word(&code)
    )))
}

/// The error code of a failure's XML, if it names one.
fn error_code(xml: &str) -> Option<String> {
    let document = parsed(xml).ok()?;
    first_text(document.root(), "Code").map(str::to_owned)
}

/// The text of the first element named `name` beneath `node`.
pub(crate) fn first_text<'a>(node: Node<'a, '_>, name: &str) -> Option<&'a str> {
    node.descendants()
        .find(|found| found.has_tag_name(name))
        .and_then(|found| found.text())
        .map(str::trim)
}

/// The text of the child element named `name` of `node`.
pub(crate) fn child_text<'a>(node: Node<'a, '_>, name: &str) -> Option<&'a str> {
    node.children()
        .find(|found| found.has_tag_name(name))
        .and_then(|found| found.text())
        .map(str::trim)
}

/// `xml` parsed, once its raw text is known to nest no deeper than
/// [`MOST_DEPTH`] and to carry no document type.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when it is not XML, nests too
/// deep or carries a document type.
pub(crate) fn parsed(xml: &str) -> Result<Document<'_>, DomainError> {
    ensure_shallow(xml, MOST_DEPTH)
        .map_err(|_| DomainError::infra_msg("AWS answered with XML nested past what is read"))?;
    Document::parse(xml).map_err(DomainError::infra)
}

/// The text of the first element named `name` in `xml`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when it is not XML or holds no
/// such element.
pub(crate) fn required(xml: &str, name: &str) -> Result<String, DomainError> {
    let document = parsed(xml)?;
    first_text(document.root(), name)
        .map(str::to_owned)
        .ok_or_else(|| DomainError::infra_msg("AWS answered without a value it always sends"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DENIED: &str = "<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code>\
                          <Message>not authorized</Message></Error></ErrorResponse>";

    fn reply(status: u16, body: &str) -> Reply {
        Reply {
            status,
            body: body.as_bytes().to_vec(),
        }
    }

    /// AWS refusing to let us assume the role is the customer's trust
    /// policy, and reads as forbidden.
    #[test]
    fn a_denied_assumption_is_forbidden() {
        let result = answered(
            reply(403, DENIED),
            SignedBy::Platform,
            "fix the trust policy",
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Rejection of the platform's AWS signing credentials is classified as an infrastructure error.
    #[test]
    fn our_own_keys_refused_are_our_failure() {
        let body =
            "<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>";

        let result = answered(reply(403, body), SignedBy::Platform, "fix the trust policy");

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// EC2's own error shape is read too: a session refused an operation
    /// is forbidden.
    #[test]
    fn an_operation_the_role_may_not_do_is_forbidden() {
        let body = "<Response><Errors><Error><Code>UnauthorizedOperation</Code></Error></Errors>\
                    </Response>";

        let result = answered(reply(403, body), SignedBy::Session, "grant the permission");

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// An error code containing unexpected text is omitted from the returned error.
    #[test]
    fn an_odd_code_is_not_echoed() {
        let body = "<E><Code>secret value here</Code></E>";

        let error = answered(reply(500, body), SignedBy::Session, "x").unwrap_err();

        assert!(!format!("{error:?}").contains("secret value"));
    }

    /// A value is read from the first element of its name, wherever it
    /// sits.
    #[test]
    fn a_value_is_read_by_its_name() {
        let xml = "<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\
                   <GetCallerIdentityResult><Account>123456789012</Account>\
                   </GetCallerIdentityResult></GetCallerIdentityResponse>";

        assert_eq!(required(xml, "Account").unwrap(), "123456789012");
        assert!(required(xml, "Arn").is_err());
    }

    /// XML nested a hundred thousand levels produces an infrastructure error
    /// through both success-response and error-response parsing.
    #[test]
    fn an_answer_nested_past_the_limit_is_refused() {
        let deep = format!("{}{}", "<a>".repeat(100_000), "</a>".repeat(100_000));

        assert!(matches!(
            required(&deep, "Account"),
            Err(DomainError::Infrastructure(_))
        ));
        assert!(matches!(
            answered(reply(400, &deep), SignedBy::Session, "x"),
            Err(DomainError::Infrastructure(_))
        ));
    }
}
