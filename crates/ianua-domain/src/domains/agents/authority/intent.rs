//! Holds a token to its stated purpose, not only to its capabilities.
//!
//! When a delegation or token is made, the app's `IntentCompiler` port reads
//! an [`IntentStatement`]. It gives back an [`IntentEnvelope`], the
//! [`ActionClass`]es the purpose allows, and an [`IntentDigest`] of the
//! statement. Under [`DriftPolicy::Enforce`] the envelope goes into the task
//! token. The proxy then refuses any request whose class is outside it, even
//! one the capabilities allow. Ann's agent may read the ledger to reconcile
//! it. It also holds delete rights, but a delete is off purpose and refused.
//! `Warn` watches for drift and reports it without blocking. `Off` does
//! neither.
//!
//! No model runs per request. The statement is read once, in the adapter.
//! Each request is then checked by whether its class is in the envelope. An
//! MCP tool call takes the classes its grant puts on the tool's name, since
//! every such call is the same `POST`.
//!
//! A purpose only narrows, never grants. A sub-delegation's envelope must sit
//! inside its parent's ([`IntentEnvelope::subset_of`]).
//!
//! The domain cannot tie the classes to the statement. Reading the statement
//! happens in the adapter, so the domain takes the statement, its digest and
//! the classes as three inputs and trusts the adapter for the link between
//! them. What it does check is that every purpose sits inside the one above
//! it, so a wrong reading can only narrow what the person gave.

use crate::domains::agents::authority::capability::{
    CapabilitySet, McpGrant, PubSub, TopicCapability,
};
use crate::domains::agents::execution::tool::ToolName;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_range;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{ActionClass, DeclaredAction, HttpMethod};

text_value! {
    /// A natural-language statement of what a token is for.
    pub struct IntentStatement;
}

impl TextValue for IntentStatement {
    const FIELD: &'static str = "intent";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.free_text(Self::MAX_LEN)
    }
}

impl IntentStatement {
    /// Maximum length of an intent statement.
    const MAX_LEN: usize = 1000;
}

/// A 32-byte fingerprint of an intent, such as a hash of its embedding.
///
/// The adapter decides how the digest is made. The domain only keeps and
/// compares the bytes, so no model types reach it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IntentDigest([u8; 32]);

impl IntentDigest {
    /// Wraps a 32-byte digest.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The action classes a purpose allows a token to use.
///
/// Each request is allowed only when its class is in the set. This refuses
/// requests a capability check would let through. Ann's agent holds delete
/// rights but its purpose is to read, so a delete is refused.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IntentEnvelope {
    allowed: Vec<ActionClass>,
}

impl IntentEnvelope {
    /// Builds an envelope from the classes a purpose allows. They are kept
    /// sorted, each one once.
    #[must_use]
    pub fn new(classes: impl IntoIterator<Item = ActionClass>) -> Self {
        let mut allowed: Vec<ActionClass> = classes.into_iter().collect();
        allowed.sort_unstable();
        allowed.dedup();
        Self { allowed }
    }

    /// The allowed action classes.
    #[must_use]
    pub fn allowed(&self) -> &[ActionClass] {
        &self.allowed
    }

    /// Whether the envelope allows no class at all. A purpose that implies
    /// no class allows nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }

    /// Whether the envelope allows `class`.
    #[must_use]
    pub fn permits(&self, class: ActionClass) -> bool {
        self.allowed.contains(&class)
    }

    /// Whether the envelope allows an HTTP request, classed by its method
    /// and path.
    #[must_use]
    pub fn permits_action(&self, method: HttpMethod, path: &str) -> bool {
        self.permits(ActionClass::classify(method, path))
    }

    /// Whether the envelope allows a request to a route. The class is the
    /// one the route declares, when it declares one.
    #[must_use]
    pub fn permits_route_action(
        &self,
        method: HttpMethod,
        path: &str,
        declared: DeclaredAction,
    ) -> bool {
        self.permits(ActionClass::for_route(method, path, declared))
    }

    /// Whether the envelope allows a call to the MCP tool `name` under
    /// `grant`.
    ///
    /// Every class a matching pattern carries must be allowed. A tool the
    /// grant does not name is refused. Ann's agent may write. A call to
    /// `github_delete_repo`, granted as a delete, is refused although the
    /// JSON-RPC request is a plain `POST`.
    #[must_use]
    pub fn permits_mcp_tool(&self, grant: &McpGrant, name: &ToolName) -> bool {
        let classes = grant.tool_classes(name);
        !classes.is_empty() && classes.iter().all(|class| self.permits(*class))
    }

    /// `requested`, cut down to what this envelope's purpose can use.
    ///
    /// - Topic rights: publishing is kept only when the envelope writes or
    ///   communicates. Subscribing is kept only when it reads.
    /// - Resource relations: one that may write is kept only when the envelope
    ///   writes or deletes. A reading one is kept only when it reads.
    /// - MCP tools: one is kept only when the envelope allows its class. See
    ///   [`McpGrant::narrowed_to_classes`] for a tool that still marks a kept
    ///   one.
    /// - Route access is all kept. Each route request is checked against this
    ///   envelope when it arrives.
    #[must_use]
    pub fn narrow(&self, requested: &CapabilitySet) -> CapabilitySet {
        let allowed = self.messaging_rights();
        let reads = self.permits(ActionClass::Read);
        let writes = self.permits(ActionClass::Write) || self.permits(ActionClass::Delete);
        let messaging = requested
            .messaging()
            .iter()
            .filter_map(|cap| {
                let rights = narrowed_rights(cap.rights(), allowed?)?;
                Some(TopicCapability::new(cap.pattern().clone(), rights))
            })
            .collect();
        let resources = requested
            .resources()
            .iter()
            .filter(|cap| {
                if cap.relation().may_write() {
                    writes
                } else {
                    reads
                }
            })
            .cloned()
            .collect();
        CapabilitySet::new(requested.http().to_vec(), messaging)
            .with_resources(resources)
            .with_mcp(
                requested
                    .mcp()
                    .narrowed_to_classes(|class| self.permits(class)),
            )
    }

    /// Whether every class this envelope allows, `other` allows too. A
    /// sub-delegation may narrow its parent's purpose this way, never widen
    /// it.
    #[must_use]
    pub fn subset_of(&self, other: &Self) -> bool {
        self.allowed.iter().all(|c| other.permits(*c))
    }

    /// The messaging rights this envelope allows. Publishing comes with
    /// writing or communicating, and subscribing with reading. `None` when
    /// it allows neither.
    fn messaging_rights(&self) -> Option<PubSub> {
        let publishes = self.permits(ActionClass::Write) || self.permits(ActionClass::Communicate);
        let reads = self.permits(ActionClass::Read);
        match (publishes, reads) {
            (true, true) => Some(PubSub::Both),
            (true, false) => Some(PubSub::Publish),
            (false, true) => Some(PubSub::Subscribe),
            (false, false) => None,
        }
    }

    /// The classes both envelopes permit.
    #[must_use]
    pub fn intersect(&self, other: &Self) -> Self {
        Self::new(self.allowed.iter().copied().filter(|c| other.permits(*c)))
    }
}

/// The part of `rights` that `allowed` also covers. `None` when nothing is
/// left.
fn narrowed_rights(rights: PubSub, allowed: PubSub) -> Option<PubSub> {
    let publish = allowed.covers(PubSub::Publish) && rights.covers(PubSub::Publish);
    let subscribe = allowed.covers(PubSub::Subscribe) && rights.covers(PubSub::Subscribe);
    match (publish, subscribe) {
        (true, true) => Some(PubSub::Both),
        (true, false) => Some(PubSub::Publish),
        (false, true) => Some(PubSub::Subscribe),
        (false, false) => None,
    }
}

/// How much drift from its purpose an agent may show before it counts, in
/// basis points from 0 to 10000.
///
/// An integer keeps the value comparable and hashable, with no floats in the
/// domain. The adapter's scorer gives its score on the same 0 to 10000
/// scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "u16"))]
pub struct DriftThreshold(u16);

#[cfg(feature = "serde")]
impl TryFrom<u16> for DriftThreshold {
    type Error = DomainError;

    /// Reads a threshold through `from_basis_points`, so a stored threshold
    /// above 100% drift is refused.
    fn try_from(basis_points: u16) -> Result<Self, Self::Error> {
        Self::from_basis_points(basis_points)
    }
}

impl DriftThreshold {
    /// The highest threshold, 100% drift.
    const MAX_BASIS_POINTS: u16 = 10_000;

    /// The threshold used when a person names none: 20% drift.
    pub const DEFAULT: Self = Self(2_000);

    /// Makes a threshold from basis points.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `basis_points` is above 10000.
    pub fn from_basis_points(basis_points: u16) -> Result<Self, DomainError> {
        validate_range("drift_threshold", basis_points, 0..=Self::MAX_BASIS_POINTS)?;
        Ok(Self(basis_points))
    }

    /// The threshold in basis points.
    #[must_use]
    pub fn basis_points(&self) -> u16 {
        self.0
    }

    /// Whether an observed drift `score`, in basis points, is above this
    /// threshold.
    #[must_use]
    pub fn is_breached_by(&self, score: u16) -> bool {
        score > self.0
    }
}

/// What happens when an agent drifts from its purpose while it runs.
///
/// Drift is watched outside the request path. It adds to the envelope check,
/// and does not replace it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DriftPolicy {
    /// Drift is not watched.
    Off,
    /// Drift past the threshold raises a drift event but blocks nothing.
    Warn(DriftThreshold),
    /// Drift past the threshold suspends the agent. A check that cannot
    /// finish refuses.
    Enforce(DriftThreshold),
}

impl DriftPolicy {
    /// The threshold, when drift is watched.
    #[must_use]
    pub fn threshold(&self) -> Option<DriftThreshold> {
        match self {
            Self::Off => None,
            Self::Warn(t) | Self::Enforce(t) => Some(*t),
        }
    }

    /// How strongly this policy acts. `Off` is lowest, then `Warn`, then
    /// `Enforce`.
    const fn rank(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::Warn(_) => 1,
            Self::Enforce(_) => 2,
        }
    }

    /// Whether this policy monitors at least as strictly as `other`.
    ///
    /// It must act at least as strongly, and its threshold must be no higher.
    /// Only `Enforce` puts the envelope into the token. A child that keeps
    /// the envelope but moves to `Warn` would get a token with no purpose
    /// check. A higher threshold lets more drift pass. A child that keeps
    /// `Enforce` at 100% would never be suspended. One that swaps `Warn` at
    /// 20% for `Enforce` at 50% would miss drift the parent warns about.
    #[must_use]
    pub fn at_least_as_strict_as(self, other: Self) -> bool {
        self.rank() >= other.rank() && self.sensitive_as(other)
    }

    /// Whether this policy reacts to drift no later than `other` does.
    fn sensitive_as(self, other: Self) -> bool {
        match (self.threshold(), other.threshold()) {
            (Some(mine), Some(theirs)) => mine.basis_points() <= theirs.basis_points(),
            _ => true,
        }
    }
}

/// What reading an intent gives: the cut-down scope, the digest and the
/// envelope.
///
/// The scope keeps only what was asked for, the delegator holds and the
/// purpose implies, all three. It is worked out once, when the token is
/// minted. The proxy checks requests against it like any other scope. The
/// digest is used to watch for drift.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CompiledIntent {
    scope: CapabilitySet,
    digest: IntentDigest,
    envelope: IntentEnvelope,
}

impl CompiledIntent {
    /// Puts together a cut-down scope, its intent digest and the envelope of
    /// classes the intent allows.
    #[must_use]
    pub fn new(scope: CapabilitySet, digest: IntentDigest, envelope: IntentEnvelope) -> Self {
        Self {
            scope,
            digest,
            envelope,
        }
    }

    /// The cut-down scope the token is held to.
    #[must_use]
    pub fn scope(&self) -> &CapabilitySet {
        &self.scope
    }

    /// The intent digest.
    #[must_use]
    pub fn digest(&self) -> &IntentDigest {
        &self.digest
    }

    /// The action classes the intent allows.
    #[must_use]
    pub fn envelope(&self) -> &IntentEnvelope {
        &self.envelope
    }
}

/// The purpose a delegation is held to: the stated intent, its digest, its
/// envelope and how drift is watched.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IntentBinding {
    statement: IntentStatement,
    digest: IntentDigest,
    drift_policy: DriftPolicy,
    #[cfg_attr(feature = "serde", serde(default))]
    envelope: IntentEnvelope,
}

impl IntentBinding {
    /// Binds a delegation to a stated intent, its envelope and a drift
    /// policy.
    #[must_use]
    pub fn new(
        statement: IntentStatement,
        digest: IntentDigest,
        drift_policy: DriftPolicy,
        envelope: IntentEnvelope,
    ) -> Self {
        Self {
            statement,
            digest,
            drift_policy,
            envelope,
        }
    }

    /// The stated intent.
    #[must_use]
    pub fn statement(&self) -> &IntentStatement {
        &self.statement
    }

    /// The intent digest.
    #[must_use]
    pub fn digest(&self) -> &IntentDigest {
        &self.digest
    }

    /// How drift is watched.
    #[must_use]
    pub fn drift_policy(&self) -> DriftPolicy {
        self.drift_policy
    }

    /// The action classes the token is held to.
    #[must_use]
    pub fn envelope(&self) -> &IntentEnvelope {
        &self.envelope
    }

    /// Whether the envelope allows an HTTP request, classed by its method
    /// and path. This is the purpose check made on each request.
    #[must_use]
    pub fn permits_action(&self, method: HttpMethod, path: &str) -> bool {
        self.envelope.permits_action(method, path)
    }

    /// Whether the envelope allows `class`.
    #[must_use]
    pub fn permits(&self, class: ActionClass) -> bool {
        self.envelope.permits(class)
    }

    /// Whether the envelope allows a call to the MCP tool `name` under
    /// `grant`. This is the purpose check made on each tool call.
    #[must_use]
    pub fn permits_mcp_tool(&self, grant: &McpGrant, name: &ToolName) -> bool {
        self.envelope.permits_mcp_tool(grant, name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::{RoutingAction, SystemPermission};

    /// An empty statement and one of 1001 characters are refused. "Book a
    /// flight for the offsite" is kept.
    #[test]
    fn intent_statement_is_validated() {
        assert!(IntentStatement::new("").is_err());
        assert!(IntentStatement::new("a".repeat(1001)).is_err());
        assert!(IntentStatement::new("book a flight for the offsite").is_ok());
    }

    /// A threshold of 10001 basis points is refused. At 7500, a score of
    /// 7501 counts as drift and a score of exactly 7500 does not.
    #[test]
    fn threshold_rejects_out_of_range_and_detects_breach() {
        assert!(DriftThreshold::from_basis_points(10_001).is_err());
        let threshold = DriftThreshold::from_basis_points(7_500).unwrap();
        assert!(threshold.is_breached_by(7_501));
        assert!(!threshold.is_breached_by(7_500));
    }

    /// A threshold above 10000 basis points cannot be deserialized either
    /// on its own or inside an enforcing drift policy.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_threshold_above_full_drift_is_refused() {
        assert!(serde_json::from_str::<DriftThreshold>("10001").is_err());
        assert!(serde_json::from_str::<DriftPolicy>(r#"{"Enforce":10001}"#).is_err());
    }

    /// A `Warn` policy at 7500 basis points is written out and read back. It
    /// comes back the same policy with the same threshold.
    #[cfg(feature = "serde")]
    #[test]
    fn a_threshold_reads_back_what_it_writes() {
        let policy = DriftPolicy::Warn(DriftThreshold::from_basis_points(7_500).unwrap());

        let json = serde_json::to_string(&policy).unwrap();

        assert_eq!(serde_json::from_str::<DriftPolicy>(&json).unwrap(), policy);
    }

    /// `Off` has no threshold. `Warn` and `Enforce` at 5000 basis points
    /// both report 5000.
    #[test]
    fn drift_policy_exposes_threshold_only_when_monitoring() {
        let threshold = DriftThreshold::from_basis_points(5_000).unwrap();
        assert_eq!(DriftPolicy::Off.threshold(), None);
        assert_eq!(DriftPolicy::Warn(threshold).threshold(), Some(threshold));
        assert_eq!(DriftPolicy::Enforce(threshold).threshold(), Some(threshold));
    }

    /// A compiled intent made from an empty scope, a digest and a read-only
    /// envelope hands back each of the three as given.
    #[test]
    fn compiled_intent_carries_scope_and_digest() {
        let digest = IntentDigest::new([7u8; 32]);
        let compiled = CompiledIntent::new(
            CapabilitySet::empty(),
            digest,
            IntentEnvelope::new([ActionClass::Read]),
        );
        assert!(compiled.scope().is_empty());
        assert_eq!(compiled.digest(), &digest);
        assert!(compiled.envelope().permits(ActionClass::Read));
    }

    /// Delete, configure, financial and admin actions count as high risk.
    /// Read, write and communicate do not.
    #[test]
    fn high_risk_covers_destructive_financial_admin_and_configure() {
        for class in [
            ActionClass::Delete,
            ActionClass::Configure,
            ActionClass::Financial,
            ActionClass::Admin,
        ] {
            assert!(class.is_high_risk(), "{class:?} must be high risk");
        }
        for class in [
            ActionClass::Read,
            ActionClass::Write,
            ActionClass::Communicate,
        ] {
            assert!(!class.is_high_risk(), "{class:?} must be low risk");
        }
    }

    /// A read-and-write envelope allows ordinary reads and writes but
    /// refuses deletes and admin actions. An empty envelope refuses a read.
    #[test]
    fn envelope_permits_only_its_classes_and_deny_by_default_when_empty() {
        let env = IntentEnvelope::new([ActionClass::Read, ActionClass::Write]);
        assert!(env.permits_action(HttpMethod::Get, "/reports"));
        assert!(env.permits_action(HttpMethod::Post, "/orders"));
        assert!(!env.permits_action(HttpMethod::Delete, "/orders/1"));
        assert!(!env.permits_action(HttpMethod::Post, "/admin/roles"));

        let empty = IntentEnvelope::default();
        assert!(empty.is_empty());
        assert!(!empty.permits_action(HttpMethod::Get, "/anything"));
    }

    /// A read-only envelope sits inside one that reads, writes and deletes.
    /// The wider one does not sit inside the read-only one.
    #[test]
    fn envelope_subset_is_the_intent_attenuation_law() {
        let broad =
            IntentEnvelope::new([ActionClass::Read, ActionClass::Write, ActionClass::Delete]);
        let narrow = IntentEnvelope::new([ActionClass::Read]);
        assert!(narrow.subset_of(&broad));
        assert!(!broad.subset_of(&narrow));
    }

    /// A binding with a read-only envelope permits reading the ledger
    /// and refuses deleting the same resource.
    #[test]
    fn intent_binding_gates_actions_by_envelope() {
        let binding = IntentBinding::new(
            IntentStatement::new("read the orders ledger").unwrap(),
            IntentDigest::new([1u8; 32]),
            DriftPolicy::Enforce(DriftThreshold::from_basis_points(0).unwrap()),
            IntentEnvelope::new([ActionClass::Read]),
        );
        assert!(binding.permits_action(HttpMethod::Get, "/orders/ledger"));
        assert!(!binding.permits_action(HttpMethod::Delete, "/orders/ledger"));
    }

    /// A digest is made from bytes with 7 first and 9 last. It hands back
    /// those exact bytes, since a presented token is compared against them.
    #[test]
    fn a_digest_reports_the_bytes_it_was_built_from() {
        let mut bytes = [0u8; 32];
        bytes[0] = 7;
        bytes[31] = 9;

        let digest = IntentDigest::new(bytes);

        assert_eq!(digest.as_bytes(), &bytes);
        assert_ne!(digest.as_bytes(), &[0u8; 32]);
    }

    /// An envelope for read and write is not empty and lists exactly those
    /// two. An envelope with no class is empty and allows nothing.
    #[test]
    fn an_envelope_reports_the_classes_it_allows() {
        let envelope = IntentEnvelope::new([ActionClass::Read, ActionClass::Write]);

        assert!(!envelope.is_empty());
        assert_eq!(envelope.allowed(), [ActionClass::Read, ActionClass::Write]);
        assert!(envelope.permits(ActionClass::Read));
        assert!(!envelope.permits(ActionClass::Delete));

        let nothing = IntentEnvelope::new([]);
        assert!(nothing.is_empty());
        assert!(!nothing.permits(ActionClass::Read));
    }

    /// Thresholds of 0 and 2500 report the same numbers back. At 2500, a
    /// score of 2501 counts as drift and 2500 does not.
    #[test]
    fn a_threshold_reports_the_basis_points_it_was_set_to() {
        let strict = DriftThreshold::from_basis_points(0).unwrap();
        let lenient = DriftThreshold::from_basis_points(2_500).unwrap();

        assert_eq!(strict.basis_points(), 0);
        assert_eq!(lenient.basis_points(), 2_500);
        assert!(lenient.is_breached_by(2_501));
        assert!(!lenient.is_breached_by(2_500));
    }

    /// At the same threshold, enforcement is at least as strict as warning
    /// or no monitoring. Warning is less strict than enforcement, and no
    /// monitoring is less strict than either.
    #[test]
    fn a_drift_policy_may_not_be_downgraded_by_a_sub_delegation() {
        let threshold = DriftThreshold::from_basis_points(1_000).unwrap();
        let off = DriftPolicy::Off;
        let warn = DriftPolicy::Warn(threshold);
        let enforce = DriftPolicy::Enforce(threshold);

        assert!(enforce.at_least_as_strict_as(warn));
        assert!(enforce.at_least_as_strict_as(off));
        assert!(warn.at_least_as_strict_as(off));
        assert!(enforce.at_least_as_strict_as(enforce));

        assert!(!warn.at_least_as_strict_as(enforce), "warn ships no gate");
        assert!(!off.at_least_as_strict_as(warn));
        assert!(!off.at_least_as_strict_as(enforce));
    }

    /// Enforcement at a higher drift threshold does not satisfy a stricter
    /// enforcing or warning policy. Lower-threshold enforcement satisfies
    /// both weaker enforcement and warning at the same threshold.
    #[test]
    fn a_laxer_threshold_is_not_as_strict() {
        let tight = DriftThreshold::from_basis_points(2_000).unwrap();
        let loose = DriftThreshold::from_basis_points(10_000).unwrap();

        assert!(!DriftPolicy::Enforce(loose).at_least_as_strict_as(DriftPolicy::Enforce(tight)));
        assert!(!DriftPolicy::Enforce(loose).at_least_as_strict_as(DriftPolicy::Warn(tight)));
        assert!(DriftPolicy::Enforce(tight).at_least_as_strict_as(DriftPolicy::Enforce(loose)));
        assert!(DriftPolicy::Enforce(tight).at_least_as_strict_as(DriftPolicy::Warn(tight)));
    }

    /// An intent compiled to view routes hands back that same scope. The
    /// minted token is held to it, so it must not come back empty.
    #[test]
    fn a_compiled_intent_reports_the_scope_it_narrowed_to() {
        let scope = CapabilitySet::new(
            vec![SystemPermission::Routing(RoutingAction::View)],
            Vec::new(),
        );

        let compiled = CompiledIntent::new(
            scope.clone(),
            IntentDigest::new([2u8; 32]),
            IntentEnvelope::new([ActionClass::Read]),
        );

        assert_eq!(compiled.scope(), &scope);
        assert!(!compiled.scope().is_empty());
    }

    mod narrowing {
        use super::*;
        use crate::domains::agents::authority::capability::{
            McpTool, McpToolPattern, Relation, ResourceCapability, ResourceRef, TopicPattern,
        };
        use crate::domains::authorization::permission::{RoutingAction, SystemPermission};

        fn requested() -> CapabilitySet {
            CapabilitySet::new(
                vec![SystemPermission::Routing(RoutingAction::View)],
                vec![TopicCapability::new(
                    TopicPattern::new("agents.>").unwrap(),
                    PubSub::Both,
                )],
            )
            .with_resources(vec![
                ResourceCapability::new(
                    Relation::new("reader").unwrap(),
                    ResourceRef::new("doc:1").unwrap(),
                ),
                ResourceCapability::new(
                    Relation::new("editor").unwrap(),
                    ResourceRef::new("doc:2").unwrap(),
                ),
            ])
        }

        /// A read-only purpose cuts topic rights down to subscribe and keeps
        /// only the reader relation. Route access stays, since each route
        /// request is checked when it arrives.
        #[test]
        fn a_read_purpose_keeps_only_reading() {
            let narrowed = IntentEnvelope::new([ActionClass::Read]).narrow(&requested());

            assert_eq!(narrowed.messaging()[0].rights(), PubSub::Subscribe);
            assert_eq!(narrowed.resources().len(), 1);
            assert_eq!(narrowed.resources()[0].relation().as_str(), "reader");
            assert_eq!(
                narrowed.http().len(),
                1,
                "route access is decided per request"
            );
        }

        /// A write-only purpose cuts topic rights down to publish and keeps
        /// only the editor relation. The reader relation is dropped.
        #[test]
        fn a_write_purpose_keeps_publishing_and_editing_but_not_reading() {
            let narrowed = IntentEnvelope::new([ActionClass::Write]).narrow(&requested());

            assert_eq!(narrowed.messaging()[0].rights(), PubSub::Publish);
            assert_eq!(narrowed.resources().len(), 1);
            assert_eq!(narrowed.resources()[0].relation().as_str(), "editor");
        }

        /// Narrowing requested topic and document rights to an admin-only
        /// purpose removes both kinds of rights.
        #[test]
        fn a_purpose_using_none_of_it_keeps_none_of_it() {
            let narrowed = IntentEnvelope::new([ActionClass::Admin]).narrow(&requested());

            assert!(narrowed.messaging().is_empty());
            assert!(narrowed.resources().is_empty());
        }

        /// A purpose that reads, writes and deletes narrows a request. The
        /// result never holds more than was asked for.
        #[test]
        fn narrowing_never_widens() {
            let narrowed =
                IntentEnvelope::new([ActionClass::Read, ActionClass::Write, ActionClass::Delete])
                    .narrow(&requested());

            assert!(narrowed.subset_of(&requested()));
        }

        fn mcp_tool(name: &str, class: ActionClass) -> McpTool {
            McpTool::new(McpToolPattern::new(name).unwrap(), class)
        }

        fn named(value: &str) -> ToolName {
            ToolName::new(value).unwrap()
        }

        fn github() -> McpGrant {
            McpGrant::new(
                vec![
                    mcp_tool("github_get_*", ActionClass::Read),
                    mcp_tool("github_*", ActionClass::Write),
                    mcp_tool("github_delete_repo", ActionClass::Delete),
                ],
                Vec::new(),
                Vec::new(),
            )
        }

        /// Narrowing GitHub tool rights to a read-only purpose keeps the
        /// issue-reading tool and removes the repository-delete tool.
        #[test]
        fn a_read_purpose_keeps_only_read_tools() {
            let read_only = McpGrant::new(
                vec![
                    mcp_tool("github_get_issue", ActionClass::Read),
                    mcp_tool("github_delete_repo", ActionClass::Delete),
                ],
                Vec::new(),
                Vec::new(),
            );
            let requested = CapabilitySet::empty().with_mcp(read_only);

            let narrowed = IntentEnvelope::new([ActionClass::Read]).narrow(&requested);

            assert!(narrowed.permits_tool(&named("github_get_issue")));
            assert!(!narrowed.permits_tool(&named("github_delete_repo")));
        }

        /// A write-only purpose refuses a repository-delete tool after
        /// narrowing the grant, while allowing the issue-creation tool.
        #[test]
        fn a_write_purpose_refuses_a_tool_granted_as_a_delete() {
            let envelope = IntentEnvelope::new([ActionClass::Write]);
            let narrowed = envelope.narrow(&CapabilitySet::empty().with_mcp(github()));

            assert!(!envelope.permits_mcp_tool(narrowed.mcp(), &named("github_delete_repo")));
            assert!(envelope.permits_mcp_tool(narrowed.mcp(), &named("github_create_issue")));
        }

        /// A read-only purpose allows a call to `github_get_issue`, granted
        /// as a read. It refuses `shell_exec`, which the grant does not name.
        #[test]
        fn a_read_purpose_allows_a_read_tool_and_refuses_an_unnamed_one() {
            let envelope = IntentEnvelope::new([ActionClass::Read]);
            let reads = McpGrant::new(
                vec![mcp_tool("github_get_*", ActionClass::Read)],
                Vec::new(),
                Vec::new(),
            );

            assert!(envelope.permits_mcp_tool(&reads, &named("github_get_issue")));
            assert!(!envelope.permits_mcp_tool(&reads, &named("shell_exec")));
        }

        /// A read-only purpose refuses a tool matching both a read pattern
        /// and a broader write pattern because both classes apply.
        #[test]
        fn a_tool_under_two_patterns_needs_both_classes() {
            let envelope = IntentEnvelope::new([ActionClass::Read]);

            assert!(!envelope.permits_mcp_tool(&github(), &named("github_get_issue")));
        }
    }
}
