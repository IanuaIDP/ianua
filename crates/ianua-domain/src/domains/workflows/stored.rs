//! How a workflow's values are written out and read back in.
//!
//! Most of them derive their shape. A value with a rule of its own is read
//! back through the constructor that keeps it, from a plain shape declared
//! here, so a stored graph, mapping, condition or step that breaks a rule
//! is refused rather than repaired. Workflow data is written as the value
//! it holds, a map as its fields in order, since a JSON object keeps no
//! order; a data path and a step key as the text they are written in; a
//! call count as its number.

use crate::domains::agents::oversight::approval::ApprovalAction;
use crate::domains::workflows::data::{DataPath, FieldName, FlowData, FlowValue};
use crate::domains::workflows::design::condition::{Clause, ConditionRule, Matching, Test};
use crate::domains::workflows::design::graph::{Edge, WorkflowGraph};
use crate::domains::workflows::design::node::{
    AgentRunParams, AgentRunStep, LoopParams, LoopStep, Mapping, Node, NodeKey, Source, WaitStep,
    WaitUntil, WorkflowApprovalStep,
};
use crate::domains::workflows::design::working_hours::{
    WorkingHours, WorkingHoursParams, weekday_numbered,
};
use crate::domains::workflows::execution::step::CallTries;
use crate::shared::errors::DomainError;
use crate::types::{DeclaredAction, Lifetime, Timezone};

/// The one field a stored map is written under.
const MAP_FIELDS: &str = "map";

/// The instants inside a stored value, written in RFC 3339 to the
/// microsecond, as a database keeps every time it holds in a column. A step
/// that started at the very moment its execution last changed then still
/// reads as having started inside the execution's life, whichever of the
/// two is kept where.
pub(crate) mod instant {
    use time::OffsetDateTime;

    /// Writes `at`, its nanoseconds cut to whole microseconds.
    pub(crate) fn serialize<S: serde::Serializer>(
        at: &OffsetDateTime,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let nanos = at.nanosecond();
        let micros = at
            .replace_nanosecond(nanos.saturating_sub(nanos.rem_euclid(1_000)))
            .map_err(<S::Error as serde::ser::Error>::custom)?;
        time::serde::rfc3339::serialize(&micros, serializer)
    }

    /// Reads an instant written in RFC 3339.
    pub(crate) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<OffsetDateTime, D::Error> {
        time::serde::rfc3339::deserialize(deserializer)
    }
}

/// A graph as it is stored, before [`WorkflowGraph::new`] has checked it.
#[derive(serde::Deserialize)]
pub(crate) struct GraphWire {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
}

impl TryFrom<GraphWire> for WorkflowGraph {
    type Error = DomainError;

    fn try_from(wire: GraphWire) -> Result<Self, Self::Error> {
        Self::new(wire.nodes, wire.edges)
    }
}

/// A mapping as it is stored, before [`Mapping::new`] has checked it.
#[derive(serde::Deserialize)]
pub(crate) struct MappingWire {
    fields: Vec<(FieldName, Source)>,
}

impl TryFrom<MappingWire> for Mapping {
    type Error = DomainError;

    fn try_from(wire: MappingWire) -> Result<Self, Self::Error> {
        Self::new(wire.fields)
    }
}

/// An approval step as it is stored, before [`WorkflowApprovalStep::new`]
/// has checked it.
#[derive(serde::Deserialize)]
pub(crate) struct ApprovalStepWire {
    summary: ApprovalAction,
    action_class: DeclaredAction,
    window: Lifetime,
    #[serde(default)]
    also_ask: crate::domains::workflows::design::also_ask::AlsoAsk,
    #[serde(default)]
    covers: crate::domains::workflows::design::node::Covering,
}

impl TryFrom<ApprovalStepWire> for WorkflowApprovalStep {
    type Error = DomainError;

    fn try_from(wire: ApprovalStepWire) -> Result<Self, Self::Error> {
        Self::new(wire.summary, wire.action_class, wire.window)
            .map(|step| step.also_asking(wire.also_ask).covering(wire.covers))
    }
}

/// A wait as it is stored, before [`WaitStep::new`] has checked it: a
/// time to wait, or working hours to wait for.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub(crate) enum WaitStepWire {
    /// Waits this long.
    Elapsed {
        /// How long.
        duration: Lifetime,
    },
    /// Waits for working hours.
    WorkingHours {
        /// The schedule and timezone defining when this wait may finish.
        working_hours: WorkingHours,
    },
}

impl TryFrom<WaitStepWire> for WaitStep {
    type Error = DomainError;

    fn try_from(wire: WaitStepWire) -> Result<Self, Self::Error> {
        match wire {
            WaitStepWire::Elapsed { duration } => Self::new(duration),
            WaitStepWire::WorkingHours { working_hours } => {
                Ok(Self::for_working_hours(working_hours))
            }
        }
    }
}

impl From<WaitStep> for WaitStepWire {
    fn from(wait: WaitStep) -> Self {
        match wait.until() {
            WaitUntil::Elapsed(duration) => Self::Elapsed {
                duration: *duration,
            },
            WaitUntil::WorkingHours(hours) => Self::WorkingHours {
                working_hours: hours.clone(),
            },
        }
    }
}

/// Working hours as they are stored, the days numbered from Monday at 1,
/// before [`WorkingHours::new`] has checked them.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct WorkingHoursWire {
    days: Vec<u8>,
    opens: u16,
    closes: u16,
    timezone: Timezone,
}

impl TryFrom<WorkingHoursWire> for WorkingHours {
    type Error = DomainError;

    fn try_from(wire: WorkingHoursWire) -> Result<Self, Self::Error> {
        let days = wire
            .days
            .into_iter()
            .map(|day| {
                weekday_numbered(day)
                    .ok_or_else(|| DomainError::corrupt_row("workflow", "a working day past seven"))
            })
            .collect::<Result<Vec<_>, DomainError>>()?;
        Self::new(WorkingHoursParams {
            days,
            opens: wire.opens,
            closes: wire.closes,
            timezone: wire.timezone,
        })
    }
}

impl From<WorkingHours> for WorkingHoursWire {
    fn from(hours: WorkingHours) -> Self {
        Self {
            days: hours
                .days()
                .iter()
                .map(|day| day.number_from_monday())
                .collect(),
            opens: hours.opens(),
            closes: hours.closes(),
            timezone: hours.timezone().clone(),
        }
    }
}

impl TryFrom<AgentRunParams> for AgentRunStep {
    type Error = DomainError;

    fn try_from(params: AgentRunParams) -> Result<Self, Self::Error> {
        Self::new(params)
    }
}

impl TryFrom<LoopParams> for LoopStep {
    type Error = DomainError;

    fn try_from(params: LoopParams) -> Result<Self, Self::Error> {
        Self::new(params)
    }
}

/// A clause as it is stored, before [`Clause::new`] has checked it.
#[derive(serde::Deserialize)]
pub(crate) struct ClauseWire {
    path: DataPath,
    test: Test,
}

impl TryFrom<ClauseWire> for Clause {
    type Error = DomainError;

    fn try_from(wire: ClauseWire) -> Result<Self, Self::Error> {
        Self::new(wire.path, wire.test)
    }
}

/// A condition as it is stored, before [`ConditionRule::new`] has checked
/// it.
#[derive(serde::Deserialize)]
pub(crate) struct ConditionRuleWire {
    matching: Matching,
    clauses: Vec<Clause>,
}

impl TryFrom<ConditionRuleWire> for ConditionRule {
    type Error = DomainError;

    fn try_from(wire: ConditionRuleWire) -> Result<Self, Self::Error> {
        Self::new(wire.matching, wire.clauses)
    }
}

/// A step key is written as its text.
impl serde::Serialize for NodeKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// A step key is read back through [`NodeKey::new`].
impl<'de> serde::Deserialize<'de> for NodeKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::new(text).map_err(<D::Error as serde::de::Error>::custom)
    }
}

/// A data path is written as its steps between dots.
impl serde::Serialize for DataPath {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// A data path is read back through [`DataPath::parse`].
impl<'de> serde::Deserialize<'de> for DataPath {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(&text).map_err(<D::Error as serde::de::Error>::custom)
    }
}

/// A call count is written as its number.
impl serde::Serialize for CallTries {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.get())
    }
}

/// A call count is read back through [`CallTries::from_stored`].
impl<'de> serde::Deserialize<'de> for CallTries {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let tries = <u8 as serde::Deserialize>::deserialize(deserializer)?;
        Self::from_stored(tries).map_err(<D::Error as serde::de::Error>::custom)
    }
}

/// Workflow data is written as the value it holds: null, a boolean, a
/// number, text or a list as themselves, and a map as `{"map": [[name,
/// value], ...]}`, its fields in their order.
impl serde::Serialize for FlowData {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.value() {
            FlowValue::Null => serializer.serialize_unit(),
            FlowValue::Bool(value) => serializer.serialize_bool(value),
            FlowValue::Number(value) => serializer.serialize_f64(value),
            FlowValue::Text(text) => serializer.serialize_str(text),
            FlowValue::List(items) => serializer.collect_seq(items),
            FlowValue::Map(entries) => {
                serializer.collect_map(std::iter::once((MAP_FIELDS, MapFields(entries))))
            }
        }
    }
}

/// The fields of a stored map, written as a list of name and value pairs.
struct MapFields<'a>(&'a [(FieldName, FlowData)]);

impl serde::Serialize for MapFields<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0)
    }
}

/// Workflow data is read back through its own constructors, so data past
/// its limits on depth and size, or a map naming a field twice, is
/// refused.
impl<'de> serde::Deserialize<'de> for FlowData {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(FlowDataVisitor)
    }
}

/// Reads one stored value of workflow data.
struct FlowDataVisitor;

impl<'de> serde::de::Visitor<'de> for FlowDataVisitor {
    type Value = FlowData;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("workflow data")
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<FlowData, E> {
        Ok(FlowData::null())
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<FlowData, E> {
        Ok(FlowData::null())
    }

    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<FlowData, E> {
        Ok(FlowData::bool(value))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<FlowData, E> {
        FlowData::number(value as f64).map_err(E::custom)
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<FlowData, E> {
        FlowData::number(value as f64).map_err(E::custom)
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<FlowData, E> {
        FlowData::number(value).map_err(E::custom)
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<FlowData, E> {
        FlowData::text(value).map_err(E::custom)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut items: A) -> Result<FlowData, A::Error> {
        let mut read = Vec::new();
        while let Some(item) = items.next_element::<FlowData>()? {
            read.push(item);
        }
        FlowData::list(read).map_err(<A::Error as serde::de::Error>::custom)
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<FlowData, A::Error> {
        let Some(key) = map.next_key::<String>()? else {
            return Err(<A::Error as serde::de::Error>::custom(
                "a stored map names no fields",
            ));
        };
        if key != MAP_FIELDS {
            return Err(<A::Error as serde::de::Error>::unknown_field(
                &key,
                &[MAP_FIELDS],
            ));
        }
        let fields: Vec<(FieldName, FlowData)> = map.next_value()?;
        FlowData::map(fields).map_err(<A::Error as serde::de::Error>::custom)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use time::OffsetDateTime;

    use super::*;
    use crate::domains::workflows::execution::step::Underway;

    fn field(name: &str) -> FieldName {
        FieldName::new(name).unwrap()
    }

    /// An order with its fields in the order they were written reads back
    /// in that order, its map written as name and value pairs.
    #[test]
    fn data_reads_back_as_it_was_written() {
        let order = FlowData::map(vec![
            (field("total"), FlowData::number(41.5).unwrap()),
            (field("id"), FlowData::text("o-1").unwrap()),
            (
                field("lines"),
                FlowData::list(vec![FlowData::bool(true), FlowData::null()]).unwrap(),
            ),
        ])
        .unwrap();

        let written = serde_json::to_value(&order).unwrap();

        assert_eq!(
            written,
            json!({"map": [["total", 41.5], ["id", "o-1"], ["lines", [true, null]]]})
        );
        assert_eq!(serde_json::from_value::<FlowData>(written).unwrap(), order);
    }

    /// Deserialization rejects duplicate fields and an object that omits the
    /// stored map wrapper.
    #[test]
    fn data_breaking_its_rules_is_refused() {
        let twice = json!({"map": [["id", 1], ["id", 2]]});
        let bare = json!({"id": 1});

        assert!(serde_json::from_value::<FlowData>(twice).is_err());
        assert!(serde_json::from_value::<FlowData>(bare).is_err());
    }

    /// A stored graph cannot deserialize when an edge targets a missing step.
    #[test]
    fn a_graph_breaking_its_rules_is_refused() {
        let stray = json!({
            "nodes": [{
                "key": "wait",
                "name": "Wait",
                "kind": {"wait": {"duration": 60}},
                "join": "all"
            }],
            "edges": [{"from": "wait", "port": "next", "to": "gone"}]
        });

        assert!(serde_json::from_value::<WorkflowGraph>(stray).is_err());
    }

    /// A timer deadline with fractional microseconds reads back truncated to
    /// whole microseconds.
    #[test]
    fn an_instant_is_stored_to_the_microsecond() {
        let at = OffsetDateTime::UNIX_EPOCH
            .replace_nanosecond(1_234_567)
            .unwrap();
        let wait = Underway::Timer { until: at };

        let read: Underway = serde_json::from_value(serde_json::to_value(&wait).unwrap()).unwrap();

        assert_eq!(
            read,
            Underway::Timer {
                until: at.replace_nanosecond(1_234_000).unwrap()
            }
        );
    }

    /// Stored values reject the reserved trigger key, an empty path segment
    /// and a fourth call attempt. A valid indexed path retains its text.
    #[test]
    fn values_breaking_their_rules_are_refused() {
        assert!(serde_json::from_value::<NodeKey>(json!("trigger")).is_err());
        assert!(serde_json::from_value::<DataPath>(json!("orders..total")).is_err());
        assert!(serde_json::from_value::<CallTries>(json!(4)).is_err());
        assert_eq!(
            serde_json::to_value(DataPath::parse("orders.0.total").unwrap()).unwrap(),
            json!("orders.0.total")
        );
    }
}
