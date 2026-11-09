//! What a check found: one place, how serious it is, and why.

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;

use crate::source::Place;

/// How much a finding matters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Severity {
    /// Broken: an adapter that cannot build, a port nothing implements.
    High,
    /// A gap: something offered that nothing reaches.
    Medium,
    /// Worth a look.
    Low,
    /// For the record.
    Info,
}

impl Severity {
    /// Every severity, the most serious first.
    pub(crate) const ALL: [Self; 4] = [Self::High, Self::Medium, Self::Low, Self::Info];

    /// The name used on the command line and in reports.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }

    /// The severity named `text`.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|severity| severity.as_str() == text)
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The part of the codebase a check looks at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Area {
    /// What the domain offers and whether the app reaches it.
    Reach,
    /// Whether the adapters implement and drive the app.
    Adapters,
    /// Where events, rights and data classes go.
    Flow,
    /// Places that should agree and do not.
    Logic,
    /// The audit's own reading.
    Meta,
}

impl Area {
    /// A short title for the area.
    pub(crate) fn title(self) -> &'static str {
        match self {
            Self::Reach => "domain to app reach",
            Self::Adapters => "app to adapters",
            Self::Flow => "data flow",
            Self::Logic => "logic conflicts",
            Self::Meta => "audit",
        }
    }
}

/// One check the audit runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Check {
    /// A public creator or change of an aggregate or operation value no use
    /// case calls.
    UnreachedBehaviour,
    /// A public `ensure_*` rule nothing calls.
    UnreachedEnsure,
    /// A caller proof no use case builds or passes.
    UnreachedProof,
    /// An event no domain change or called observation builds.
    UnraisedEvent,
    /// An event only an adapter builds.
    AdapterRaisedEvent,
    /// A port no adapter implements.
    UnimplementedPort,
    /// An adapter missing a method its port requires.
    MissingPortMethod,
    /// An adapter method its port no longer has.
    StalePortMethod,
    /// A use case no adapter constructs or calls.
    UnwiredUseCase,
    /// A `Ports` field an adapter's wiring never sets.
    UnsetPortsField,
    /// A field an adapter's wiring sets that the `Ports` struct no longer has.
    UnknownPortsField,
    /// An event nothing listens to: not notified, not consumed.
    UnheardEvent,
    /// A right granted in a role that no rule checks.
    UncheckedPermission,
    /// A data class stored on a type and never compared.
    UncomparedDataClass,
    /// A use case creating what another one checks a plan limit for first,
    /// without that check.
    MissingLimitPath,
    /// A status moved out of a state its machine says is final.
    ReopenedFinalState,
    /// A change of a stored aggregate a use case calls that checks no right
    /// and takes no caller proof.
    UncheckedChange,
    /// A command with a path that writes to a store and succeeds without
    /// dispatching an event.
    SuccessWithoutEvent,
    /// A capability a deployment may not have, needed where nothing asks
    /// whether it is there.
    GateDeadEnd,
    /// A decision rule that answers with less proof when a capability is
    /// off than when it is on.
    WeakerWhenOff,
    /// A decision rule whose rows its tests do not all reach.
    UntestedTable,
    /// A file that does not parse.
    ParseFailed,
    /// An allowlist entry that matched no finding.
    UnusedAllow,
}

impl Check {
    /// Every check, in report order.
    pub(crate) const ALL: [Self; 23] = [
        Self::UnreachedBehaviour,
        Self::UnreachedEnsure,
        Self::UnreachedProof,
        Self::UnraisedEvent,
        Self::AdapterRaisedEvent,
        Self::UnimplementedPort,
        Self::MissingPortMethod,
        Self::StalePortMethod,
        Self::UnwiredUseCase,
        Self::UnsetPortsField,
        Self::UnknownPortsField,
        Self::UnheardEvent,
        Self::UncheckedPermission,
        Self::UncomparedDataClass,
        Self::MissingLimitPath,
        Self::ReopenedFinalState,
        Self::UncheckedChange,
        Self::SuccessWithoutEvent,
        Self::GateDeadEnd,
        Self::WeakerWhenOff,
        Self::UntestedTable,
        Self::ParseFailed,
        Self::UnusedAllow,
    ];

    /// The id used in reports and the allowlist.
    pub(crate) fn id(self) -> &'static str {
        match self {
            Self::UnreachedBehaviour => "reach.behaviour",
            Self::UnreachedEnsure => "reach.ensure",
            Self::UnreachedProof => "reach.proof",
            Self::UnraisedEvent => "reach.event-unraised",
            Self::AdapterRaisedEvent => "reach.event-adapter-only",
            Self::UnimplementedPort => "adapters.port-unimplemented",
            Self::MissingPortMethod => "adapters.method-missing",
            Self::StalePortMethod => "adapters.method-stale",
            Self::UnwiredUseCase => "adapters.use-case-unwired",
            Self::UnsetPortsField => "adapters.ports-field-unset",
            Self::UnknownPortsField => "adapters.ports-field-unknown",
            Self::UnheardEvent => "flow.event-unheard",
            Self::UncheckedPermission => "flow.permission-unchecked",
            Self::UncomparedDataClass => "flow.data-class-uncompared",
            Self::MissingLimitPath => "limits.path-missing",
            Self::ReopenedFinalState => "status.final-reopened",
            Self::UncheckedChange => "rights.unchecked-change",
            Self::SuccessWithoutEvent => "records.success-without-event",
            Self::GateDeadEnd => "gates.dead-end",
            Self::WeakerWhenOff => "rules.weaker-when-off",
            Self::UntestedTable => "rules.table-untested",
            Self::ParseFailed => "meta.parse-failed",
            Self::UnusedAllow => "meta.allow-unused",
        }
    }

    /// The check with id `id`.
    pub(crate) fn parse(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|check| check.id() == id)
    }

    /// How serious its findings are.
    pub(crate) fn severity(self) -> Severity {
        match self {
            Self::UnimplementedPort
            | Self::MissingPortMethod
            | Self::UnsetPortsField
            | Self::UnknownPortsField
            | Self::MissingLimitPath
            | Self::ReopenedFinalState
            | Self::UncheckedChange
            | Self::SuccessWithoutEvent
            | Self::GateDeadEnd
            | Self::WeakerWhenOff => Severity::High,
            Self::UnreachedBehaviour
            | Self::UnreachedEnsure
            | Self::UnreachedProof
            | Self::UnraisedEvent
            | Self::StalePortMethod
            | Self::UnwiredUseCase
            | Self::UncheckedPermission => Severity::Medium,
            Self::AdapterRaisedEvent | Self::UncomparedDataClass | Self::UntestedTable => {
                Severity::Low
            }
            Self::UnheardEvent | Self::ParseFailed | Self::UnusedAllow => Severity::Info,
        }
    }

    /// The part of the codebase it looks at.
    pub(crate) fn area(self) -> Area {
        match self {
            Self::UnreachedBehaviour
            | Self::UnreachedEnsure
            | Self::UnreachedProof
            | Self::UnraisedEvent
            | Self::AdapterRaisedEvent => Area::Reach,
            Self::UnimplementedPort
            | Self::MissingPortMethod
            | Self::StalePortMethod
            | Self::UnwiredUseCase
            | Self::UnsetPortsField
            | Self::UnknownPortsField => Area::Adapters,
            Self::UnheardEvent | Self::UncheckedPermission | Self::UncomparedDataClass => {
                Area::Flow
            }
            Self::MissingLimitPath
            | Self::ReopenedFinalState
            | Self::UncheckedChange
            | Self::SuccessWithoutEvent
            | Self::GateDeadEnd
            | Self::WeakerWhenOff
            | Self::UntestedTable => Area::Logic,
            Self::ParseFailed | Self::UnusedAllow => Area::Meta,
        }
    }

    /// What its findings mean, in one line.
    pub(crate) fn title(self) -> &'static str {
        match self {
            Self::UnreachedBehaviour => "aggregate creators and changes no use case calls",
            Self::UnreachedEnsure => "public ensure_* rules nothing calls",
            Self::UnreachedProof => "caller proofs no use case builds or passes",
            Self::UnraisedEvent => "events no domain change or called observation raises",
            Self::AdapterRaisedEvent => "events only an adapter builds",
            Self::UnimplementedPort => "ports no adapter implements",
            Self::MissingPortMethod => "adapter impls missing a port method",
            Self::StalePortMethod => "adapter methods the port no longer has",
            Self::UnwiredUseCase => "use cases no adapter constructs or calls",
            Self::UnsetPortsField => "Ports fields the wiring never sets",
            Self::UnknownPortsField => "fields the wiring sets that Ports no longer has",
            Self::UnheardEvent => "events nothing listens to",
            Self::UncheckedPermission => "permissions no rule checks",
            Self::UncomparedDataClass => "data classes stored and never compared",
            Self::MissingLimitPath => "creates another path guards with a plan limit, unguarded",
            Self::ReopenedFinalState => "statuses moved out of a final state",
            Self::UncheckedChange => "changes a use case calls that check no right",
            Self::SuccessWithoutEvent => "commands that save raised events and succeed unrecorded",
            Self::GateDeadEnd => "paths and rules needing a capability nothing asks is set up",
            Self::WeakerWhenOff => {
                "rules that let someone in with less proof when a capability is off"
            }
            Self::UntestedTable => "decision rules whose rows their tests do not all reach",
            Self::ParseFailed => "files that do not parse",
            Self::UnusedAllow => "allowlist entries that matched nothing",
        }
    }
}

/// One thing a check found.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Finding {
    /// The check that found it.
    #[serde(serialize_with = "check_id")]
    pub(crate) check: Check,
    /// How serious it is.
    pub(crate) severity: Severity,
    /// Where it is.
    #[serde(flatten)]
    pub(crate) place: Place,
    /// What it is about, such as `Topic::archive`; the allowlist matches it.
    pub(crate) subject: String,
    /// What is wrong, in one line.
    pub(crate) message: String,
    /// More lines, when one is not enough: every `file:line` on each side
    /// of a conflict, why it matters and the usual fix.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) detail: Vec<String>,
}

impl Finding {
    /// A finding of `check` at `place`.
    pub(crate) fn new(
        check: Check,
        place: Place,
        subject: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            check,
            severity: check.severity(),
            place,
            subject: subject.into(),
            message: message.into(),
            detail: Vec::new(),
        }
    }

    /// The finding with `lines` of detail.
    pub(crate) fn with_detail(mut self, lines: impl IntoIterator<Item = String>) -> Self {
        self.detail.extend(lines);
        self
    }

    /// `file:line`, or the file alone for a whole-file finding.
    pub(crate) fn location(&self) -> String {
        match self.place.line {
            0 => self.place.file.clone(),
            line => format!("{}:{line}", self.place.file),
        }
    }
}

/// A conclusion a check did not draw: what it was about, and the point the
/// reader could not read that it would have rested on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Unsaid {
    /// The check that held back.
    #[serde(serialize_with = "check_id")]
    pub(crate) check: Check,
    /// What the conclusion was about, as a finding's subject would say it.
    pub(crate) subject: String,
    /// Where the point it rested on is.
    #[serde(flatten)]
    pub(crate) place: Place,
    /// What that point is, and why it was not read.
    pub(crate) why: String,
}

impl Unsaid {
    /// A conclusion of `check` about `subject` left unsaid, resting on what
    /// `why` says at `place`.
    pub(crate) fn new(
        check: Check,
        subject: impl Into<String>,
        place: Place,
        why: impl Into<String>,
    ) -> Self {
        Self {
            check,
            subject: subject.into(),
            place,
            why: why.into(),
        }
    }
}

/// What some checks found, with the conclusions each left unsaid because
/// they rested on what the reader marked not read.
#[derive(Clone, Debug, Default)]
pub(crate) struct Found {
    /// The findings.
    pub(crate) findings: Vec<Finding>,
    /// Per check, how many conclusions it did not draw.
    pub(crate) silenced: BTreeMap<Check, usize>,
    /// Each conclusion not drawn, with the point it rested on.
    pub(crate) unsaid: Vec<Unsaid>,
}

impl Found {
    /// Counts one conclusion it did not draw, with the point it rested on.
    pub(crate) fn leave_unsaid(&mut self, unsaid: Unsaid) {
        *self.silenced.entry(unsaid.check).or_default() += 1;
        self.unsaid.push(unsaid);
    }

    /// Takes in what `other` found.
    pub(crate) fn absorb(&mut self, other: Self) {
        self.findings.extend(other.findings);
        for (check, count) in other.silenced {
            *self.silenced.entry(check).or_default() += count;
        }
        self.unsaid.extend(other.unsaid);
    }
}

impl From<Vec<Finding>> for Found {
    fn from(findings: Vec<Finding>) -> Self {
        Self {
            findings,
            silenced: BTreeMap::new(),
            unsaid: Vec::new(),
        }
    }
}

fn check_id<S: serde::Serializer>(check: &Check, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(check.id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_check_id_parses_back_to_its_check() {
        for check in Check::ALL {
            assert_eq!(Check::parse(check.id()), Some(check));
        }
    }

    #[test]
    fn severities_sort_the_most_serious_first() {
        let mut severities = vec![Severity::Info, Severity::High, Severity::Low];

        severities.sort();

        assert_eq!(severities, [Severity::High, Severity::Low, Severity::Info]);
    }
}
