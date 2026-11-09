//! What kind of thing an action is. Routes, tools, approvals and intents all
//! work with these classes.

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::words::{is_form_of, words_of};
use crate::types::HttpMethod;

/// A broad class of action, such as read, delete or financial.
///
/// An agent's intent envelope is checked in these classes. A route or tool
/// declares which class it is. The check compares classes, not the words
/// of the intent. Classifying uses no model and no I/O, so it is
/// cheap enough for every request. Working out which classes an intent
/// allows happens once, when an adapter compiles the intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ActionClass {
    /// Reads state without changing it, as `GET`, `HEAD` and `OPTIONS` do.
    Read,
    /// Creates or updates state, as `POST`, `PUT` and `PATCH` do.
    Write,
    /// Destroys state, as `DELETE` does.
    Delete,
    /// Changes configuration, policy, or settings.
    Configure,
    /// Sends a message to a person or system, such as an email,
    /// notification or chat.
    Communicate,
    /// Moves money or changes billing, such as payments, invoices or
    /// refunds.
    Financial,
    /// Administers identities, roles, or access.
    Admin,
}

impl ActionClass {
    /// The name stored for the class.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Delete => "delete",
            Self::Configure => "configure",
            Self::Communicate => "communicate",
            Self::Financial => "financial",
            Self::Admin => "admin",
        }
    }

    /// Reads a value a caller sent.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] naming the value when it is not one of
    ///   the known names.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        Self::named(value).ok_or_else(|| {
            DomainError::invalid(message!(
                "values-unknown-action-class",
                format!("unknown action class: {value}")
            ))
        })
    }

    /// Reads a stored value.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the stored name is not one of
    ///   the known names. The row is corrupt, not the caller's input.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        Self::named(value)
            .ok_or_else(|| DomainError::corrupt_row("action class", "an unknown name"))
    }

    /// The value a name stands for.
    fn named(value: &str) -> Option<Self> {
        match value {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "delete" => Some(Self::Delete),
            "configure" => Some(Self::Configure),
            "communicate" => Some(Self::Communicate),
            "financial" => Some(Self::Financial),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }

    /// Guesses the class of an HTTP request from its method and path.
    ///
    /// Words in the path that point to admin, money, messaging or settings
    /// win over the method. So `POST /admin/roles` is
    /// [`Admin`](Self::Admin), not [`Write`](Self::Write). This only names the
    /// action. The intent envelope decides whether it is allowed.
    ///
    /// A word counts only as a whole word of the path, split at every
    /// character that is not a letter or a digit, or as one of its regular
    /// forms: `/admins` and `/user-settings` count, `/badminton` and
    /// `/payload` do not.
    ///
    /// [`HttpMethod::Any`], which a caller passes for a method it does not
    /// know, counts as a write, never a read.
    #[must_use]
    pub fn classify(method: HttpMethod, path: &str) -> Self {
        let words = path_words(path);
        PATH_WORDS
            .iter()
            .find(|(_, keywords)| names_any(&words, keywords))
            .map_or_else(|| Self::of_method(method), |(class, _)| *class)
    }

    /// The class a method alone gives: a read, a delete, or else a write.
    fn of_method(method: HttpMethod) -> Self {
        if method.is_safe() {
            return Self::Read;
        }
        if method == HttpMethod::Delete {
            return Self::Delete;
        }
        Self::Write
    }

    /// The class of a call to `target`, a path that may carry a query.
    ///
    /// The query is dropped first, so it never changes the class.
    /// `POST /payments?note=read` stays financial.
    #[must_use]
    pub fn for_call(method: HttpMethod, target: &str, declared: DeclaredAction) -> Self {
        let path = target.split('?').next().unwrap_or_default();
        Self::for_route(method, path, declared)
    }

    /// The class of a request to `path` on a route.
    ///
    /// It is the class the operator declared for the route, or the guess
    /// from [`classify`](Self::classify) when they declared none. A `DELETE`
    /// is never declared down below a delete. A route declared as a read
    /// still counts a `DELETE` on it as a delete.
    #[must_use]
    pub fn for_route(method: HttpMethod, path: &str, declared: DeclaredAction) -> Self {
        let DeclaredAction::Declared(declared) = declared else {
            return Self::classify(method, path);
        };
        if method == HttpMethod::Delete && !declared.is_high_risk() {
            return Self::Delete;
        }
        declared
    }

    /// Whether an off-purpose action of this class gets the severe response.
    ///
    /// Deletes, money, settings and admin are high risk. Under `Enforce`, an
    /// agent that strays into one is suspended. Reads, writes and messages
    /// are lower risk. Straying into one revokes the delegation it used and
    /// every delegation made from it. The agent's other work goes on.
    #[must_use]
    pub fn is_high_risk(self) -> bool {
        matches!(
            self,
            Self::Delete | Self::Configure | Self::Financial | Self::Admin
        )
    }
}

/// The path words that put a request in a class, tried in this order, so a
/// path naming both admin and billing reads as admin. Each counts whole or
/// in a regular form, as [`is_form_of`] reads it.
const PATH_WORDS: &[(ActionClass, &[&str])] = &[
    (
        ActionClass::Admin,
        &[
            "admin",
            "administrator",
            "administration",
            "administer",
            "iam",
            "role",
            "permission",
            "policies",
        ],
    ),
    (
        ActionClass::Financial,
        &[
            "bill", "payment", "pay", "invoice", "charge", "refund", "payout",
        ],
    ),
    (
        ActionClass::Communicate,
        &["message", "email", "notify", "send", "sms", "webhook"],
    ),
    (
        ActionClass::Configure,
        &["config", "configuration", "configure", "setting", "policy"],
    ),
];

/// The words of `path`, split at every character that is not a letter or
/// a digit and where a lower-case letter or digit meets a capital, so
/// `/sendEmail` reads as "send" and "email".
fn path_words(path: &str) -> Vec<String> {
    let mut spaced = String::with_capacity(path.len());
    let mut after_lower = false;
    for c in path.chars() {
        if c.is_uppercase() && after_lower {
            spaced.push(' ');
        }
        after_lower = c.is_lowercase() || c.is_ascii_digit();
        spaced.push(c);
    }
    words_of(&spaced)
}

/// Whether one of `words` is one of `keywords`, whole or in a regular form.
fn names_any(words: &[String], keywords: &[&str]) -> bool {
    keywords
        .iter()
        .any(|keyword| words.iter().any(|word| is_form_of(word, keyword)))
}

/// The kind of action something says it takes, or that it says none.
///
/// It is one value, not an optional class. So each check has to say what an
/// undeclared action counts as, and a missing class cannot pass as harmless.
/// An approval treats it as high risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DeclaredAction {
    /// Nothing was declared.
    #[default]
    Undeclared,
    /// This class was declared.
    Declared(ActionClass),
}

impl DeclaredAction {
    /// Reads a stored class. A missing one means nothing was declared.
    #[must_use]
    pub fn from_stored(class: Option<ActionClass>) -> Self {
        class.map_or(Self::Undeclared, Self::Declared)
    }

    /// The class as stored, with `None` for nothing declared.
    #[must_use]
    pub fn stored(self) -> Option<ActionClass> {
        match self {
            Self::Undeclared => None,
            Self::Declared(class) => Some(class),
        }
    }

    /// Whether it may be high risk. True for a high-risk class and for
    /// nothing declared.
    #[must_use]
    pub fn may_be_high_risk(self) -> bool {
        match self {
            Self::Undeclared => true,
            Self::Declared(class) => class.is_high_risk(),
        }
    }

    /// The class's name, or `undeclared`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Undeclared => "undeclared",
            Self::Declared(class) => class.as_str(),
        }
    }

    /// The riskier of this and `other`.
    ///
    /// Nothing declared ranks highest, then any high-risk class, then the
    /// rest. When both rank the same, this one is kept. So a class can only
    /// go up, never across to another class of the same rank.
    #[must_use]
    pub fn stricter(self, other: Self) -> Self {
        if other.risk_rank() > self.risk_rank() {
            return other;
        }
        self
    }

    fn risk_rank(self) -> u8 {
        match self {
            Self::Undeclared => 2,
            Self::Declared(class) if class.is_high_risk() => 1,
            Self::Declared(_) => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Plain paths take their class from the method. A path naming admin,
    /// billing or notify wins over the method, so `GET /billing/invoices` is
    /// financial and `POST /admin/roles` is admin.
    #[test]
    fn classify_prefers_path_risk_over_method() {
        assert_eq!(
            ActionClass::classify(HttpMethod::Get, "/reports"),
            ActionClass::Read
        );
        assert_eq!(
            ActionClass::classify(HttpMethod::Post, "/orders"),
            ActionClass::Write
        );
        assert_eq!(
            ActionClass::classify(HttpMethod::Delete, "/orders/1"),
            ActionClass::Delete
        );
        assert_eq!(
            ActionClass::classify(HttpMethod::Post, "/admin/roles"),
            ActionClass::Admin
        );
        assert_eq!(
            ActionClass::classify(HttpMethod::Get, "/billing/invoices"),
            ActionClass::Financial
        );
        assert_eq!(
            ActionClass::classify(HttpMethod::Post, "/notify/email"),
            ActionClass::Communicate
        );
    }

    /// GET paths containing action keywords only inside unrelated words stay
    /// reads, avoiding an administrative or financial classification by substring.
    #[test]
    fn a_word_inside_another_does_not_classify_the_path() {
        for path in [
            "/badminton/scores",
            "/payload",
            "/rebilling-notes",
            "/console",
            "/sendgrid-status",
        ] {
            assert_eq!(
                ActionClass::classify(HttpMethod::Get, path),
                ActionClass::Read,
                "{path}"
            );
        }
    }

    /// Whole segments, their regular forms and the words of a hyphenated
    /// or camel-cased segment all count.
    #[test]
    fn whole_words_and_their_forms_classify_the_path() {
        for (path, class) in [
            ("/admins", ActionClass::Admin),
            ("/api/v1/user-roles", ActionClass::Admin),
            ("/administrator/tools", ActionClass::Admin),
            ("/adminPanel", ActionClass::Admin),
            ("/policies", ActionClass::Admin),
            ("/payments/42", ActionClass::Financial),
            ("/bills", ActionClass::Financial),
            ("/sendEmail", ActionClass::Communicate),
            ("/messaging/threads", ActionClass::Communicate),
            ("/user_settings", ActionClass::Configure),
            ("/policy", ActionClass::Configure),
        ] {
            assert_eq!(
                ActionClass::classify(HttpMethod::Get, path),
                class,
                "{path}"
            );
        }
    }

    /// Every action class retains its expected distinct storage name, keeping
    /// read permissions distinguishable from higher-risk actions.
    #[test]
    fn every_action_class_has_its_own_stored_name() {
        let classes = [
            (ActionClass::Read, "read"),
            (ActionClass::Write, "write"),
            (ActionClass::Delete, "delete"),
            (ActionClass::Configure, "configure"),
            (ActionClass::Communicate, "communicate"),
            (ActionClass::Financial, "financial"),
            (ActionClass::Admin, "admin"),
        ];

        for (class, name) in classes {
            assert_eq!(class.as_str(), name);
        }

        let mut seen: Vec<&str> = classes.iter().map(|(_, name)| *name).collect();
        seen.sort_unstable();
        let total = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), total);
    }

    /// An operator declares `POST /search` a read and `POST /orders`
    /// financial. Those declarations win over the guess from the method. An
    /// undeclared `POST /payments` is still guessed as financial.
    #[test]
    fn a_routes_declared_class_replaces_the_path_guess() {
        assert_eq!(
            ActionClass::for_route(
                HttpMethod::Post,
                "/search",
                DeclaredAction::Declared(ActionClass::Read)
            ),
            ActionClass::Read,
            "the operator knows a search is a read"
        );
        assert_eq!(
            ActionClass::for_route(
                HttpMethod::Post,
                "/orders",
                DeclaredAction::Declared(ActionClass::Financial)
            ),
            ActionClass::Financial,
            "and that an order moves money, which the path does not say"
        );
        assert_eq!(
            ActionClass::for_route(HttpMethod::Post, "/payments", DeclaredAction::Undeclared),
            ActionClass::Financial
        );
    }

    /// DELETE overrides lower-risk route declarations while retaining an admin
    /// declaration, so a route label cannot downgrade a destructive request.
    #[test]
    fn a_delete_is_never_declared_down() {
        for declared in [
            ActionClass::Read,
            ActionClass::Write,
            ActionClass::Communicate,
        ] {
            assert_eq!(
                ActionClass::for_route(
                    HttpMethod::Delete,
                    "/orders/1",
                    DeclaredAction::Declared(declared)
                ),
                ActionClass::Delete
            );
        }
        assert_eq!(
            ActionClass::for_route(
                HttpMethod::Delete,
                "/accounts/1",
                DeclaredAction::Declared(ActionClass::Admin)
            ),
            ActionClass::Admin
        );
    }

    /// A query mentioning reads leaves a POST to the payments path classified
    /// as financial.
    #[test]
    fn a_calls_query_never_changes_its_class() {
        assert_eq!(
            ActionClass::for_call(
                HttpMethod::Post,
                "/payments?note=read",
                DeclaredAction::Undeclared
            ),
            ActionClass::Financial
        );
    }

    fn keyword() -> impl Strategy<Value = &'static str> {
        let all: Vec<&'static str> = PATH_WORDS
            .iter()
            .flat_map(|(_, keywords)| keywords.iter().copied())
            .collect();
        proptest::sample::select(all)
    }

    proptest! {
        /// Whatever keyword a path holds, letters glued to it that make no
        /// regular form leave a word that is not the keyword, so a `GET`
        /// of it stays a read.
        #[test]
        fn a_keyword_glued_inside_a_word_never_classifies(
            keyword in keyword(),
            before in "[xqz]{0,3}",
            after in "[xqz]{0,3}",
        ) {
            prop_assume!(!before.is_empty() || !after.is_empty());
            let path = format!("/api/{before}{keyword}{after}/42");

            prop_assert_eq!(ActionClass::classify(HttpMethod::Get, &path), ActionClass::Read);
        }

        /// Whatever keyword stands as a whole segment, among segments that
        /// name nothing, a `GET` of the path is never a plain read.
        #[test]
        fn a_keyword_as_a_whole_segment_always_classifies(
            keyword in keyword(),
            before in "[0-9]{1,4}",
            after in "[0-9]{1,4}",
        ) {
            let path = format!("/{before}/{keyword}/{after}");

            prop_assert_ne!(ActionClass::classify(HttpMethod::Get, &path), ActionClass::Read);
        }
    }
}
