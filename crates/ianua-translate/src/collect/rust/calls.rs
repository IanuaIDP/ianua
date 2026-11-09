//! The current error constructors that distinguish public refusals from internal diagnostics.

use syn::Expr;

use crate::collect::tokens::strings;

/// Which argument of a recognized constructor holds outward text.
pub(crate) fn message_index(names: &[String]) -> Option<usize> {
    let [.., owner, method] = names else {
        return None;
    };
    let first = match owner.as_str() {
        "DomainError" => matches!(
            method.as_str(),
            "invalid" | "conflict" | "unauthorized" | "forbidden" | "invalid_transition"
        ),
        "AppError" => matches!(
            method.as_str(),
            "NotFound"
                | "Forbidden"
                | "Conflict"
                | "TenantUnavailable"
                | "LinkExpired"
                | "TooManyRequests"
        ),
        "Refusal" => method == "new",
        "ApiError" => method == "validation",
        "ScimApiError" => matches!(method.as_str(), "invalid_value" | "invalid_filter"),
        "OAuthError" => matches!(method.as_str(), "invalid_request" | "invalid_client"),
        "RegistrationError" => matches!(method.as_str(), "InvalidRedirectUri" | "InvalidMetadata"),
        _ => false,
    };
    if first {
        return Some(0);
    }
    (owner == "OAuthError" && method == "refused").then_some(1)
}

/// Calls whose diagnostic details are deliberately masked before an outward response.
pub(crate) fn internal_call(names: &[String]) -> bool {
    let [.., owner, method] = names else {
        return false;
    };
    match owner.as_str() {
        "DomainError" => matches!(
            method.as_str(),
            "infra" | "infra_msg" | "corrupt_row" | "corrupt_value"
        ),
        "AppError" => matches!(method.as_str(), "internal" | "internal_msg" | "upstream"),
        _ => false,
    }
}

/// Whether the primary message expression contains literal source that was actually collected.
pub(crate) fn has_message_literal(expression: &Expr) -> bool {
    match expression {
        Expr::Lit(literal) => matches!(literal.lit, syn::Lit::Str(_)),
        Expr::Macro(invocation) => !strings(invocation.mac.tokens.clone()).is_empty(),
        Expr::MethodCall(call) => has_message_literal(&call.receiver),
        Expr::Reference(reference) => has_message_literal(&reference.expr),
        Expr::Paren(parentheses) => has_message_literal(&parentheses.expr),
        _ => false,
    }
}
