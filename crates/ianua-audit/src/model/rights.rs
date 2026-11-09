//! The rights a function checks, read from the calls that check them.
//!
//! A call refuses unless a right is held when its name starts with
//! `ensure_may`, `ensure_holds` or `ensure_controls`, or when it is any
//! other `ensure_*` call handed a right. `holds`, `holds_agent` and
//! `has_system_permission` handed a right only ask, for a condition whose
//! branches the audit does not follow. A right counts as read when an
//! argument names it: `WebhooksAction::Update`,
//! `SystemPermission::ManageWebhooks` or
//! `SystemPermission::Webhooks(WebhooksAction::Update)`, through a path
//! whose enum is `SystemPermission` or ends in `Action`, `Right`, `Area` or
//! `Permission`. A refusing call handed only a variable, or nothing, is
//! kept with its right not read.

use serde::Serialize;
use syn::Expr;

/// Whether a check refuses or only asks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RightKind {
    /// The call refuses unless the right is held.
    Requires,
    /// The call asks whether it is held, for a condition.
    Asks,
}

impl RightKind {
    /// The word cards use.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Requires => "requires",
            Self::Asks => "asks for",
        }
    }
}

/// One call that checks a right.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct RightCheck {
    /// The function or method called, such as `ensure_may`.
    pub(crate) call: String,
    /// The right as written, such as `WebhooksAction::Update`; `None` when
    /// the call is handed a variable or nothing.
    pub(crate) right: Option<String>,
    /// Whether it refuses or asks.
    pub(crate) kind: RightKind,
}

/// Call names that refuse unless a right is held, by prefix.
const REFUSING: &[&str] = &["ensure_may", "ensure_holds", "ensure_controls"];

/// Call names that ask whether a right is held.
const ASKING: &[&str] = &["holds", "holds_agent", "has_system_permission"];

/// How the names of enums holding rights end.
const RIGHT_ENUM_ENDS: &[&str] = &["Action", "Right", "Area", "Permission"];

/// The rights the call `call` handed `args` checks; none when it checks no
/// right.
pub(crate) fn checks_in<'a>(
    call: &str,
    args: impl IntoIterator<Item = &'a Expr>,
) -> Vec<RightCheck> {
    let rights: Vec<String> = args.into_iter().filter_map(right_in).collect();
    let Some(kind) = kind_of(call, !rights.is_empty()) else {
        return Vec::new();
    };
    if rights.is_empty() {
        return vec![RightCheck {
            call: call.to_owned(),
            right: None,
            kind,
        }];
    }
    rights
        .into_iter()
        .map(|right| RightCheck {
            call: call.to_owned(),
            right: Some(right),
            kind,
        })
        .collect()
}

fn kind_of(call: &str, names_a_right: bool) -> Option<RightKind> {
    let refuses = REFUSING.iter().any(|prefix| call.starts_with(prefix));
    match (refuses, names_a_right) {
        (true, _) => Some(RightKind::Requires),
        (false, true) if call.starts_with("ensure_") => Some(RightKind::Requires),
        (false, true) if ASKING.contains(&call) => Some(RightKind::Asks),
        _ => None,
    }
}

/// The right an argument names, as written.
fn right_in(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Reference(reference) => right_in(&reference.expr),
        Expr::Paren(inner) => right_in(&inner.expr),
        Expr::Path(path) => right_path(&path.path),
        Expr::Call(call) => wrapped_right(call),
        _ => None,
    }
}

/// `SystemPermission::Webhooks(WebhooksAction::Update)`: a right variant
/// wrapping one right.
fn wrapped_right(call: &syn::ExprCall) -> Option<String> {
    let Expr::Path(function) = call.func.as_ref() else {
        return None;
    };
    let head = right_path(&function.path)?;
    let args: Vec<&Expr> = call.args.iter().collect();
    let [inner] = args.as_slice() else {
        return None;
    };
    Some(format!("{head}({})", right_in(inner)?))
}

fn right_path(path: &syn::Path) -> Option<String> {
    let names: Vec<String> = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    let [.., owner, name] = names.as_slice() else {
        return None;
    };
    let holds_rights =
        owner == "SystemPermission" || RIGHT_ENUM_ENDS.iter().any(|end| owner.ends_with(end));
    holds_rights.then(|| format!("{owner}::{name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checks(call: &str) -> Vec<RightCheck> {
        let parsed: syn::ExprCall = syn::parse_str(call).unwrap();
        let Expr::Path(function) = parsed.func.as_ref() else {
            panic!("a call by path");
        };
        let name = function.path.segments.last().unwrap().ident.to_string();
        checks_in(&name, &parsed.args)
    }

    #[test]
    fn an_action_handed_to_ensure_may_is_a_required_right() {
        let found = checks("ensure_may(WebhooksAction::Update)");

        assert_eq!(found[0].right.as_deref(), Some("WebhooksAction::Update"));
        assert_eq!(found[0].kind, RightKind::Requires);
    }

    #[test]
    fn a_wrapped_right_is_read_whole() {
        let found = checks("ensure_holds(SystemPermission::Webhooks(WebhooksAction::View))");

        assert_eq!(
            found[0].right.as_deref(),
            Some("SystemPermission::Webhooks(WebhooksAction::View)")
        );
    }

    #[test]
    fn a_right_handed_in_a_variable_is_not_read() {
        let found = checks("ensure_holds(SystemPermission::Webhooks(action))");

        assert_eq!(found.len(), 1);
        assert!(found[0].right.is_none());
    }

    #[test]
    fn a_question_about_a_right_asks_and_a_plain_rule_checks_none() {
        let asked = checks("has_system_permission(SystemPermission::ManageUsers)");
        let rule = checks("ensure_open(topic)");

        assert_eq!(asked[0].kind, RightKind::Asks);
        assert!(rule.is_empty());
    }
}
