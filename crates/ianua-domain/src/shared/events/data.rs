//! Structured event payload for audit and cross-service transport.
//!
//! A payload is an ordered list of named [`FieldValue`]s. Each value is one of
//! three things, so an audit reader can read it without a lookup:
//!
//! - a [`FieldValue::Text`] scalar, such as a status, a count or a timestamp
//! - a [`FieldValue::Reference`] to an entity, with its `kind`, `id` and a
//!   human `label`. The label is taken when the event is written, so it stays
//!   true after the entity is renamed or deleted.
//! - a [`FieldValue::Change`], a `from` → `to` transition for a mutation
//!
//! The type depends on no serialization framework. An adapter maps it to
//! JSON at the boundary.
//!
//! A value never carries a secret. A key that names secret material trips a
//! debug assertion, whichever builder adds it. Such keys are `password`,
//! `api_key`, `private_key`, or anything ending in `_token`, `_secret`,
//! `_password`, `_cookie` or `_otp`. [`is_sensitive_key`] holds the full list.

/// The kind of entity a [`Reference`] points at. The UI uses it as a hint
/// and to build links.
///
/// It wraps a static string instead of being one central enum. So a domain
/// names its own kinds without editing a shared list. Common kinds have
/// constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefKind(&'static str);

impl RefKind {
    /// A user.
    pub const USER: Self = Self("user");
    /// An organization user.
    pub const ORG_USER: Self = Self("org_user");
    /// A platform operator.
    pub const OPERATOR: Self = Self("operator");
    /// An organization.
    pub const ORGANIZATION: Self = Self("organization");
    /// A tenant.
    pub const TENANT: Self = Self("tenant");
    /// An authorization role.
    pub const ROLE: Self = Self("role");
    /// A user group.
    pub const GROUP: Self = Self("group");
    /// A custom user attribute a tenant declared.
    pub const USER_ATTRIBUTE: Self = Self("user_attribute");
    /// An agent identity.
    pub const AGENT: Self = Self("agent");
    /// An OAuth/OIDC client.
    pub const CLIENT: Self = Self("client");
    /// An upstream connection.
    pub const CONNECTION: Self = Self("connection");
    /// A signing or encryption key.
    pub const KEY: Self = Self("key");
    /// A delegation.
    pub const DELEGATION: Self = Self("delegation");
    /// An agent credential.
    pub const CREDENTIAL: Self = Self("credential");
    /// A proxied route.
    pub const ROUTE: Self = Self("route");
    /// A consumer: a non-human caller a tenant lets through.
    pub const CONSUMER: Self = Self("consumer");
    /// A gateway service: a backend routes forward to.
    pub const SERVICE: Self = Self("service");
    /// A stream route: a port the proxy listens on below HTTP.
    pub const STREAM_ROUTE: Self = Self("stream_route");
    /// A resource type in a tenant's permission catalogue.
    pub const RESOURCE_TYPE: Self = Self("resource_type");
    /// A webhook subscription.
    pub const WEBHOOK: Self = Self("webhook");
    /// A messaging schema.
    pub const SCHEMA: Self = Self("schema");
    /// A session.
    pub const SESSION: Self = Self("session");
    /// A plan subscription.
    pub const SUBSCRIPTION: Self = Self("subscription");
    /// An agent run.
    pub const RUN: Self = Self("run");
    /// An approval request.
    pub const APPROVAL: Self = Self("approval");
    /// A model provider.
    pub const PROVIDER: Self = Self("provider");
    /// A registered tool.
    pub const TOOL: Self = Self("tool");

    /// Names a kind a domain defines itself.
    #[must_use]
    pub const fn new(kind: &'static str) -> Self {
        Self(kind)
    }

    /// The kind's stable string form.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

/// An entity a payload points at: its kind, its id, and a human label captured
/// when the event fired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    kind: RefKind,
    id: String,
    label: String,
}

impl Reference {
    /// Builds a reference from a kind, an id, and a write-time label.
    #[must_use]
    pub fn new(kind: RefKind, id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            kind,
            id: id.into(),
            label: label.into(),
        }
    }

    /// The entity kind.
    #[must_use]
    pub fn kind(&self) -> RefKind {
        self.kind
    }

    /// The entity id, for linking and filtering.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The human label as it was at write time.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
}

/// A `from` → `to` transition. Either side may be absent: a creation has no
/// `from`, a deletion no `to`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    from: Option<String>,
    to: Option<String>,
}

impl Change {
    /// A change with both sides present.
    #[must_use]
    pub fn new(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            from: Some(from.into()),
            to: Some(to.into()),
        }
    }

    /// A change from optional sides. `None` where a side does not apply.
    #[must_use]
    pub fn between(from: Option<String>, to: Option<String>) -> Self {
        Self { from, to }
    }

    /// The prior value, if any.
    #[must_use]
    pub fn from(&self) -> Option<&str> {
        self.from.as_deref()
    }

    /// The new value, if any.
    #[must_use]
    pub fn to(&self) -> Option<&str> {
        self.to.as_deref()
    }
}

/// One payload value: a scalar, an entity reference, or a transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue {
    /// A plain scalar, such as a status, a count or a timestamp.
    Text(String),
    /// An entity, readable and linkable.
    Reference(Reference),
    /// A `from` → `to` transition.
    Change(Change),
}

impl FieldValue {
    /// The value's primary string: a scalar's text, a reference's id, or a
    /// change's new value. So a lookup by id works whether the field is a
    /// scalar or a reference.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Text(s) => Some(s),
            Self::Reference(r) => Some(r.id()),
            Self::Change(c) => c.to(),
        }
    }
}

/// Whether a key names something that must never appear in a payload.
///
/// It checks a list of secret words against the whole key and against its
/// last word. So `scim_token` and `signing_secret` are caught like `token`
/// and `secret`. Ids that name a credential, such as `key_id`,
/// `credential_id` or `client_id`, are allowed. Only the secret values are
/// refused.
#[must_use]
pub fn is_sensitive_key(key: &str) -> bool {
    const SECRET_WORDS: &[&str] = &["password", "secret", "token", "cookie", "otp"];
    const DENIED: &[&str] = &[
        "password",
        "secret",
        "client_secret",
        "token",
        "access_token",
        "refresh_token",
        "private_key",
        "cookie",
        "otp",
        "otp_code",
        "recovery_codes",
        "api_key",
    ];
    let key = key.to_ascii_lowercase();
    let last_word = key.rsplit('_').next().unwrap_or(&key);
    DENIED.contains(&key.as_str()) || SECRET_WORDS.contains(&last_word)
}

/// A structured event payload: named values in insertion order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventData {
    fields: Vec<(String, FieldValue)>,
}

impl EventData {
    /// Creates a new empty payload.
    #[must_use]
    pub fn new() -> Self {
        Self { fields: Vec::new() }
    }

    /// Creates an explicitly empty payload.
    #[must_use]
    pub fn empty() -> Self {
        Self::new()
    }

    /// Adds a scalar field.
    ///
    /// # Panics
    ///
    /// - In debug builds, if `key` names secret material by [`is_sensitive_key`].
    #[must_use]
    pub fn field(mut self, key: &str, value: impl Into<String>) -> Self {
        self.push(key, FieldValue::Text(value.into()));
        self
    }

    /// Adds a scalar field only when `value` is `Some`.
    ///
    /// # Panics
    ///
    /// - In debug builds, if `key` names secret material by [`is_sensitive_key`].
    #[must_use]
    pub fn optional(mut self, key: &str, value: Option<impl Into<String>>) -> Self {
        if let Some(v) = value {
            self.push(key, FieldValue::Text(v.into()));
        }
        self
    }

    /// Adds an entity reference.
    ///
    /// # Panics
    ///
    /// - In debug builds, if `key` names secret material by [`is_sensitive_key`].
    #[must_use]
    pub fn reference(mut self, key: &str, value: Reference) -> Self {
        self.push(key, FieldValue::Reference(value));
        self
    }

    /// Adds an entity reference only when `value` is `Some`.
    ///
    /// # Panics
    ///
    /// - In debug builds, if `key` names secret material by [`is_sensitive_key`].
    #[must_use]
    pub fn optional_reference(mut self, key: &str, value: Option<Reference>) -> Self {
        if let Some(v) = value {
            self.push(key, FieldValue::Reference(v));
        }
        self
    }

    /// Adds a `from` → `to` change with both sides present.
    ///
    /// # Panics
    ///
    /// - In debug builds, if `key` names secret material by [`is_sensitive_key`].
    #[must_use]
    pub fn change(mut self, key: &str, from: impl Into<String>, to: impl Into<String>) -> Self {
        self.push(key, FieldValue::Change(Change::new(from, to)));
        self
    }

    /// Adds a change from optional sides.
    ///
    /// # Panics
    ///
    /// - In debug builds, if `key` names secret material by [`is_sensitive_key`].
    #[must_use]
    pub fn change_between(mut self, key: &str, from: Option<String>, to: Option<String>) -> Self {
        self.push(key, FieldValue::Change(Change::between(from, to)));
        self
    }

    /// Adds one field, refusing in debug builds a key that names secret
    /// material, whichever builder it came through.
    fn push(&mut self, key: &str, value: FieldValue) {
        debug_assert!(!is_sensitive_key(key), "secret key in event payload: {key}");
        self.fields.push((key.to_owned(), value));
    }

    /// The fields, in insertion order.
    #[must_use]
    pub fn fields(&self) -> &[(String, FieldValue)] {
        &self.fields
    }

    /// The primary string of a field, as [`FieldValue::as_str`] gives it. A
    /// lookup by id works whether the field is a scalar or a reference.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| v.as_str())
    }

    /// The full typed value of a field.
    #[must_use]
    pub fn value(&self, key: &str) -> Option<&FieldValue> {
        self.fields.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Whether the payload has no fields.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// The number of fields.
    #[must_use]
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Rebuilds a payload from typed fields, as an adapter does when it
    /// parses stored JSON.
    #[must_use]
    pub fn from_fields(fields: Vec<(String, FieldValue)>) -> Self {
        Self { fields }
    }

    /// Rebuilds a payload from plain string pairs, each value a scalar.
    #[must_use]
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Self {
        Self {
            fields: pairs
                .into_iter()
                .map(|(k, v)| (k, FieldValue::Text(v)))
                .collect(),
        }
    }
}

impl Default for EventData {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A payload built with `status` then `count` holds both, each readable
    /// by its key.
    #[test]
    fn scalar_fields_chain_in_order() {
        let data = EventData::new()
            .field("status", "pending")
            .field("count", "8");

        assert_eq!(data.len(), 2);
        assert_eq!(data.get("status"), Some("pending"));
        assert_eq!(data.get("count"), Some("8"));
    }

    /// A sign-in with no known IP but a known user agent records the agent
    /// and leaves out `ip` entirely, with no empty field for it.
    #[test]
    fn optional_skips_none() {
        let data = EventData::new()
            .field("id", "x")
            .optional("ip", None::<String>)
            .optional("agent", Some("curl/7.0".to_owned()));

        assert_eq!(data.len(), 2);
        assert_eq!(data.get("agent"), Some("curl/7.0"));
    }

    /// A reference to the role "Billing Admin" keeps its kind, its id and
    /// its label, so the audit log can show and link it.
    #[test]
    fn a_reference_carries_kind_id_and_label() {
        let data = EventData::new().reference(
            "role",
            Reference::new(RefKind::ROLE, "role-123", "Billing Admin"),
        );

        let FieldValue::Reference(r) = data.value("role").unwrap() else {
            panic!("expected a reference");
        };
        assert_eq!(r.kind(), RefKind::ROLE);
        assert_eq!(r.id(), "role-123");
        assert_eq!(r.label(), "Billing Admin");
    }

    /// A `user` field holds a reference labelled `alice@corp.com`. Reading
    /// it by key gives the id `user-9`, the same as when the field was a
    /// plain id.
    #[test]
    fn get_returns_the_id_for_a_reference_so_id_lookups_survive() {
        let data = EventData::new().reference(
            "user",
            Reference::new(RefKind::USER, "user-9", "alice@corp.com"),
        );
        assert_eq!(
            data.get("user"),
            Some("user-9"),
            "an id-keyed lookup still resolves the id after the field became a reference"
        );
    }

    /// A plan change from Starter to Business keeps both sides. Reading the
    /// field by key gives the new value, Business.
    #[test]
    fn a_change_records_both_sides() {
        let data = EventData::new().change("plan", "Starter", "Business");
        let FieldValue::Change(c) = data.value("plan").unwrap() else {
            panic!("expected a change");
        };
        assert_eq!(c.from(), Some("Starter"));
        assert_eq!(c.to(), Some("Business"));
        assert_eq!(
            data.get("plan"),
            Some("Business"),
            "get yields the new value"
        );
    }

    /// A name set for the first time is a change with no `from` and `Acme`
    /// as `to`.
    #[test]
    fn change_between_allows_an_absent_side() {
        let created = EventData::new().change_between("name", None, Some("Acme".to_owned()));
        let FieldValue::Change(c) = created.value("name").unwrap() else {
            panic!("expected a change");
        };
        assert_eq!(c.from(), None);
        assert_eq!(c.to(), Some("Acme"));
    }

    /// Two stored string pairs come back as two text fields, readable by key.
    #[test]
    fn from_pairs_reconstitutes_scalars() {
        let data = EventData::from_pairs(vec![
            ("key1".to_owned(), "val1".to_owned()),
            ("key2".to_owned(), "val2".to_owned()),
        ]);
        assert_eq!(data.len(), 2);
        assert_eq!(data.get("key1"), Some("val1"));
    }

    /// `password`, `Token`, `scim_token` and `signing_secret` count as
    /// secret. `client_id`, `key_id` and `token_id` only name a credential,
    /// so they do not.
    #[test]
    fn sensitive_keys_are_recognised() {
        assert!(is_sensitive_key("password"));
        assert!(is_sensitive_key("client_secret"));
        assert!(is_sensitive_key("Token"));
        assert!(!is_sensitive_key("client_id"));
        assert!(!is_sensitive_key("key_id"));
        assert!(!is_sensitive_key("credential_id"));
        assert!(is_sensitive_key("scim_token"));
        assert!(is_sensitive_key("signing_secret"));
        assert!(is_sensitive_key("bearer_token"));
        assert!(!is_sensitive_key("token_id"));
    }

    /// Adding a password field to event data triggers the debug guard before
    /// that field can be included in the completed payload.
    #[test]
    #[should_panic(expected = "secret key in event payload")]
    fn a_secret_key_trips_the_guard() {
        let _ = EventData::new().field("password", "hunter2");
    }

    /// A stored audit row with `status` and `count` is read back. Both fields
    /// are kept, so the screen does not show an event that recorded nothing.
    #[test]
    fn a_payload_rebuilt_from_stored_fields_keeps_them() {
        let stored = vec![
            ("status".to_owned(), FieldValue::Text("active".to_owned())),
            ("count".to_owned(), FieldValue::Text("2".to_owned())),
        ];

        let payload = EventData::from_fields(stored);

        assert_eq!(payload.len(), 2);
        assert_eq!(
            payload.value("status").and_then(FieldValue::as_str),
            Some("active")
        );
        assert!(!payload.is_empty());
    }
}
