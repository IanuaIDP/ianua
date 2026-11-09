//! Evaluations: a workflow tried against saved sample cases, before it is
//! published and after each change, so a new prompt, model or step that
//! does worse is caught.
//!
//! An author saves an [`EvaluationSet`](set::EvaluationSet) for a workflow:
//! sample cases, each an input and the checks its results must pass (see
//! [`check`]). An [`Evaluation`](run::Evaluation) runs every case as a test
//! run of the draft, the same test a person starts by hand, so nothing
//! outside changes, and records per case whether it passed, failed with
//! what differed, or could not run. A set may hold publishing back until
//! the draft's last evaluation passed; that gate is off unless its author
//! turns it on.
//!
//! The checks are decided by the data alone. Grading an answer with a
//! model, and evaluating an agent on its own outside a workflow, are not
//! built yet.

pub mod case;
pub mod check;
pub mod outcome;
pub mod run;
pub mod set;
pub mod view;

#[cfg(test)]
pub(crate) mod tests {
    use crate::domains::agents::authority::capability::CapabilitySet;
    use crate::domains::authorization::permission::{
        DataAccessAction, SystemPermission, WorkflowAction,
    };
    use crate::domains::data_classification::level::DataClassLevel;
    use crate::domains::workflows::control::WorkflowControl;
    use crate::domains::workflows::data::{DataPath, FlowData};
    use crate::domains::workflows::design::workflow::Workflow;
    use crate::domains::workflows::evaluation::case::{CaseName, CaseParams, EvaluationCase};
    use crate::domains::workflows::evaluation::check::{Expectation, ExpectedText};
    use crate::domains::workflows::evaluation::set::{EvaluationSet, PublishGate, SetParams};
    use crate::domains::workflows::execution::record::ExecutionRecord;
    use crate::domains::workflows::execution::tests::fixtures::{ann, copy, draft, managing};
    use crate::domains::workflows::execution::{ActingAuthority, WorkflowExecution};
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::authority::assumed_authority;
    use crate::types::{Label, TenantId};

    /// Ann's draft: one step that hands the trigger's data on as `answer`.
    pub(crate) fn workflow() -> Workflow<ResolvedTenant> {
        draft(vec![copy("tidy", &[("answer", "trigger")])], Vec::new())
    }

    /// Ann edits her draft, which makes a new revision of it.
    pub(crate) fn edit(workflow: &mut Workflow<ResolvedTenant>) {
        workflow
            .rename(&managing(&ann()), Label::new("name", "Parcels").unwrap())
            .unwrap();
    }

    /// Ann, who may change and run workflows and read confidential data.
    pub(crate) fn evaluator() -> WorkflowControl<'static> {
        WorkflowControl::new(assumed_authority(
            &ann(),
            TenantId::new(),
            &[
                SystemPermission::Workflows(WorkflowAction::Manage),
                SystemPermission::Data(DataAccessAction::Confidential),
            ],
            &[],
        ))
    }

    /// Ann, who may only view workflows and is cleared for internal data.
    pub(crate) fn viewer() -> WorkflowControl<'static> {
        WorkflowControl::new(assumed_authority(
            &ann(),
            TenantId::new(),
            &[SystemPermission::Workflows(WorkflowAction::View)],
            &[],
        ))
    }

    /// A case on `input` at `exposure` making `check`.
    fn case(name: &str, exposure: DataClassLevel, check: Expectation) -> EvaluationCase {
        EvaluationCase::new(CaseParams {
            name: CaseName::new(name).unwrap(),
            input: FlowData::text("my parcel is late").unwrap(),
            exposure,
            checks: vec![check],
        })
        .unwrap()
    }

    /// A case expecting the tidy step to hand on text about the parcel.
    pub(crate) fn case_named(name: &str) -> EvaluationCase {
        let check = Expectation::Contains {
            at: DataPath::parse("tidy.answer").unwrap(),
            text: ExpectedText::new("parcel").unwrap(),
        };
        case(name, DataClassLevel::Internal, check)
    }

    /// A case expecting `at` to hold exactly the text "refund".
    pub(crate) fn case_expecting(name: &str, at: &str) -> EvaluationCase {
        let check = Expectation::Equals {
            at: DataPath::parse(at).unwrap(),
            value: FlowData::text("refund").unwrap(),
        };
        case(name, DataClassLevel::Internal, check)
    }

    /// A passing case whose input its author marked confidential.
    pub(crate) fn confidential_case(name: &str) -> EvaluationCase {
        let check = Expectation::Contains {
            at: DataPath::parse("tidy.answer").unwrap(),
            text: ExpectedText::new("parcel").unwrap(),
        };
        case(name, DataClassLevel::Confidential, check)
    }

    /// `workflow`'s set holding `cases`, with the gate off.
    pub(crate) fn set_with(
        workflow: &Workflow<ResolvedTenant>,
        cases: Vec<EvaluationCase>,
    ) -> EvaluationSet<ResolvedTenant> {
        let params = SetParams {
            cases,
            gate: PublishGate::Off,
        };
        EvaluationSet::create(workflow, &evaluator(), params).unwrap()
    }

    /// `workflow`'s set of `count` passing cases, behind `gate`.
    pub(crate) fn set_of_cases(
        workflow: &Workflow<ResolvedTenant>,
        count: usize,
        gate: PublishGate,
    ) -> EvaluationSet<ResolvedTenant> {
        let cases = (0..count)
            .map(|index| case_named(&format!("case {index}")))
            .collect();
        EvaluationSet::create(workflow, &evaluator(), SetParams { cases, gate }).unwrap()
    }

    /// `workflow`'s set of one passing case, behind `gate`.
    pub(crate) fn set_of(
        workflow: &Workflow<ResolvedTenant>,
        gate: PublishGate,
    ) -> EvaluationSet<ResolvedTenant> {
        set_of_cases(workflow, 1, gate)
    }

    /// The test run of `case` of `workflow`, for Ann.
    pub(crate) fn tested(
        workflow: &Workflow<ResolvedTenant>,
        case: &EvaluationCase,
    ) -> (WorkflowExecution<ResolvedTenant>, Vec<ExecutionRecord>) {
        let tests_workflows = CapabilitySet::new(
            vec![
                SystemPermission::Workflows(WorkflowAction::Update),
                SystemPermission::Workflows(WorkflowAction::Run),
            ],
            Vec::new(),
        );
        WorkflowExecution::start_case(
            workflow,
            ActingAuthority::assumed(ann(), tests_workflows),
            case,
            &[],
        )
        .unwrap()
    }
}
