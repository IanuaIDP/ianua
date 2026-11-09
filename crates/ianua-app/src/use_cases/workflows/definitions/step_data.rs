//! Step data: for each step of a version, the data it may read from the
//! trigger and the steps before it, so a builder picks values by name and
//! meaning instead of typing paths.
//!
//! It reads the same rule publishing holds a step to: a step reads only the
//! trigger and steps that can come before it. What an action gives back is
//! as its operation's guide describes it; what a service event carries, as
//! its event's guide does. Data whose shape only a run shows, such as a
//! webhook's body or a code step's answer, is offered whole.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::data::DataPath;
use ianua_domain::domains::workflows::design::graph::WorkflowGraph;
use ianua_domain::domains::workflows::design::node::{
    HandsOn, Node, NodeKey, NodeKind, TRIGGER_FIELD,
};
use ianua_domain::domains::workflows::execution::ANSWER_FIELD;
use ianua_domain::domains::workflows::guardrail::{CHECKED_FIELD, FINDINGS_FIELD, FOUND_FIELD};
use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::domains::workflows::integration::guide::{OperationGuide, OutputNote};
use ianua_domain::domains::workflows::triggers::Trigger;
use ianua_domain::types::{Text, WorkflowId};

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::{IntegrationCatalog, WorkflowStore};
use crate::use_case::Query;
use crate::use_cases::workflows::definitions::get::WhichVersion;
use crate::use_cases::workflows::lookup::designed_version;

/// The version whose steps' data is read.
pub struct StepDataRequest {
    /// The automation definition whose data dependencies are inspected.
    pub workflow_id: WorkflowId,
    /// The graph revision whose available step data is computed.
    pub version: WhichVersion,
}

/// What one step may read.
#[derive(Debug, Clone, PartialEq)]
pub struct StepData {
    /// The step.
    pub key: NodeKey,
    /// The trigger first, then each step that can come before it, with the
    /// values each hands on.
    pub earlier: Vec<EarlierData>,
}

/// Where readable data comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataSource {
    /// The trigger that started the run.
    Trigger,
    /// A step before it.
    Step(NodeKey),
}

/// The values one source hands on.
#[derive(Debug, Clone, PartialEq)]
pub struct EarlierData {
    /// Where they come from.
    pub source: DataSource,
    /// Each value, at its full path.
    pub values: Vec<ReadableValue>,
}

/// One value a step may read.
#[derive(Debug, Clone, PartialEq)]
pub struct ReadableValue {
    /// Its full path, starting at the trigger or the step, as a step's
    /// input names it.
    pub path: DataPath,
    /// What it is, when an integration describes it.
    pub description: Option<Text>,
    /// Whether its shape is described, or only a run shows it.
    pub shape: ValueShape,
}

/// Whether a value's shape is known before a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueShape {
    /// It is the value at this path, as described.
    Described,
    /// It is everything at this path, whose shape only a run shows.
    Whole,
}

/// The ports [`StepDataUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct StepDataPorts {
    /// Keeps the versions.
    pub workflows: Arc<dyn WorkflowStore>,
    /// What the integrations say their operations and events give back.
    pub catalog: Arc<dyn IntegrationCatalog>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads what each step of a version may read.
pub struct StepDataUseCase {
    ports: StepDataPorts,
}

impl StepDataUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: StepDataPorts) -> Self {
        Self { ports }
    }

    /// The guides of every integration an action of `graph` uses, by
    /// integration.
    async fn guides_of(
        &self,
        graph: &WorkflowGraph,
    ) -> Result<HashMap<IntegrationKey, Vec<OperationGuide>>, AppError> {
        let mut guides = HashMap::new();
        for (_, step) in graph.action_steps() {
            if guides.contains_key(step.integration()) {
                continue;
            }
            let read = self
                .ports
                .catalog
                .guides(step.integration())
                .await
                .or_internal()?;
            guides.insert(step.integration().clone(), read);
        }
        Ok(guides)
    }

    /// What the trigger hands on.
    async fn trigger_values(&self, trigger: &Trigger) -> Result<Vec<ReadableValue>, AppError> {
        let Trigger::Service(on) = trigger else {
            return whole(TRIGGER_FIELD);
        };
        let guides = self
            .ports
            .catalog
            .event_guides(on.integration())
            .await
            .or_internal()?;
        let Some(guide) = guides.iter().find(|guide| guide.event() == on.event()) else {
            return whole(TRIGGER_FIELD);
        };
        described(TRIGGER_FIELD, guide.outputs())
    }
}

impl Query for StepDataUseCase {
    type Caller = CallerContext;
    type Input = StepDataRequest;
    type Output = Result<Vec<StepData>, AppError>;

    /// What each step of the version `request` names may read, in the
    /// graph's order, for the person `ctx` names.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view workflows.
    /// - `AppError::NotFound` when the tenant has no such workflow or
    ///   version.
    /// - `AppError::Internal` when the store or the catalog fails.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: StepDataRequest,
    ) -> Result<Vec<StepData>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        WorkflowControl::new(&authority)
            .ensure_may(WorkflowAction::View)
            .map_err(AppError::from_domain)?;
        let version = match request.version {
            WhichVersion::Latest => None,
            WhichVersion::Number(number) => Some(number),
        };
        let workflow = designed_version(
            self.ports.workflows.as_ref(),
            &ctx.tenant(),
            &request.workflow_id,
            version,
        )
        .await?;
        let guides = self.guides_of(workflow.graph()).await?;
        let trigger = EarlierData {
            source: DataSource::Trigger,
            values: self.trigger_values(workflow.trigger()).await?,
        };
        workflow
            .graph()
            .nodes()
            .iter()
            .map(|node| step_data(workflow.graph(), node, &trigger, &guides))
            .collect()
    }
}

/// What `node` of `graph` may read: the trigger, then each step before it
/// that hands anything on.
fn step_data(
    graph: &WorkflowGraph,
    node: &Node,
    trigger: &EarlierData,
    guides: &HashMap<IntegrationKey, Vec<OperationGuide>>,
) -> Result<StepData, AppError> {
    let mut earlier = vec![trigger.clone()];
    for before in graph.ancestors(node.key()) {
        let values = handed_on(before, guides)?;
        if values.is_empty() {
            continue;
        }
        earlier.push(EarlierData {
            source: DataSource::Step(before.key().clone()),
            values,
        });
    }
    Ok(StepData {
        key: node.key().clone(),
        earlier,
    })
}

/// The values `node` hands on to the steps after it.
fn handed_on(
    node: &Node,
    guides: &HashMap<IntegrationKey, Vec<OperationGuide>>,
) -> Result<Vec<ReadableValue>, AppError> {
    let root = node.key().as_field().as_str();
    match HandsOn::of(node.kind()) {
        HandsOn::Nothing => Ok(Vec::new()),
        HandsOn::Whole => whole(root),
        HandsOn::Answer => named(root, [ANSWER_FIELD]),
        HandsOn::Fields(fields) => named(root, fields.iter().map(|field| field.as_str())),
        HandsOn::Guarded => named(root, [CHECKED_FIELD, FINDINGS_FIELD, FOUND_FIELD]),
        HandsOn::OperationOutputs => {
            let NodeKind::Action(step) = node.kind() else {
                return whole(root);
            };
            let guide = guides.get(step.integration()).and_then(|guides| {
                guides
                    .iter()
                    .find(|guide| guide.operation() == step.operation())
            });
            match guide {
                Some(guide) => described(root, guide.outputs()),
                None => whole(root),
            }
        }
    }
}

/// Everything at `root`, whose shape only a run shows.
fn whole(root: &str) -> Result<Vec<ReadableValue>, AppError> {
    Ok(vec![ReadableValue {
        path: DataPath::parse(root).or_internal()?,
        description: None,
        shape: ValueShape::Whole,
    }])
}

/// The values `names` under `root`, undescribed.
fn named<'a>(
    root: &str,
    names: impl IntoIterator<Item = &'a str>,
) -> Result<Vec<ReadableValue>, AppError> {
    names
        .into_iter()
        .map(|name| {
            Ok(ReadableValue {
                path: DataPath::parse(&format!("{root}.{name}")).or_internal()?,
                description: None,
                shape: ValueShape::Described,
            })
        })
        .collect()
}

/// The values `outputs` describe, under `root`.
fn described(root: &str, outputs: &[OutputNote]) -> Result<Vec<ReadableValue>, AppError> {
    outputs
        .iter()
        .map(|output| {
            Ok(ReadableValue {
                path: DataPath::parse(&format!("{root}.{}", output.path())).or_internal()?,
                description: Some(output.description().clone()),
                shape: ValueShape::Described,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::workflows::design::graph::Edge;
    use ianua_domain::domains::workflows::design::node::Port;
    use ianua_domain::domains::workflows::design::workflow::Workflow;
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::caller_person;
    use crate::test_support::workflows::{FakeWorkflowStore, draft_by, tidy_step};
    use crate::test_support::{block_on, test_ctx};

    fn key(value: &str) -> NodeKey {
        NodeKey::new(value).unwrap()
    }

    /// Ann's draft tidies data, then tidies it again from what the first
    /// step built.
    fn two_tidies() -> Workflow<ResolvedTenant> {
        draft_by(
            &caller_person(),
            vec![tidy_step("first"), tidy_step("second")],
            vec![Edge::new(key("first"), Port::Next, key("second"))],
        )
    }

    fn read(
        workflow: &Workflow<ResolvedTenant>,
        authorities: FakeTenantAuthorities,
    ) -> Result<Vec<StepData>, AppError> {
        let use_case = StepDataUseCase::new(StepDataPorts {
            workflows: Arc::new(FakeWorkflowStore::holding(std::slice::from_ref(workflow))),
            tenant_authorities: Arc::new(authorities),
            ..StepDataPorts::fakes()
        });
        let request = StepDataRequest {
            workflow_id: *workflow.id(),
            version: WhichVersion::Latest,
        };
        block_on(use_case.execute(&test_ctx(), request))
    }

    fn viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)])
    }

    /// The first step reads only the trigger, whole. The second also reads
    /// the fields the first builds, by name.
    #[test]
    fn each_step_reads_the_trigger_and_the_steps_before_it() {
        let data = read(&two_tidies(), viewer()).unwrap();

        assert_eq!(data[0].earlier.len(), 1);
        assert_eq!(data[0].earlier[0].source, DataSource::Trigger);
        assert_eq!(data[0].earlier[0].values[0].shape, ValueShape::Whole);
        assert_eq!(data[1].earlier.len(), 2);
        assert_eq!(data[1].earlier[1].source, DataSource::Step(key("first")));
        assert!(
            data[1].earlier[1]
                .values
                .iter()
                .all(|value| value.path.to_string().starts_with("first."))
        );
    }

    /// An authority refusal prevents reading a workflow's available step data.
    #[test]
    fn reading_step_data_needs_the_right_to_view() {
        let result = read(
            &two_tidies(),
            FakeTenantAuthorities::refusing(Refusal::Forbidden),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
