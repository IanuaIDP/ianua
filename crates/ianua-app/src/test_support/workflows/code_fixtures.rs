//! What the code step tests share: a step running a sandbox version's code,
//! a version whose bundle is ready, a run waiting on its code, and a runner
//! answering as a test says.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::agents::authority::capability::CapabilitySet;
use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
use ianua_domain::domains::workflows::data::{DataPath, FieldName, FlowData};
use ianua_domain::domains::workflows::design::node::{
    CodeStep, Join, Mapping, Node, NodeKind, Source,
};
use ianua_domain::domains::workflows::execution::{
    ActingAuthority, CodeRun, CodeStart, WorkflowExecution,
};
use ianua_domain::domains::workflows::sandbox::Sandbox;
use ianua_domain::domains::workflows::sandbox::build::{Bundle, BundleDigest};
use ianua_domain::domains::workflows::sandbox::version::SandboxVersion;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{Human, Label, SandboxVersionId, UntrustedText};

use crate::ports::TenantScoped;
use crate::ports::workflows::{CodeRan, CodeRequest, CodeRunner};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::workflows::graphs::{draft_by, person, published_by, step};
use crate::test_support::workflows::runs::started_by;
use crate::test_support::workflows::sandboxes::{python_sandbox, version_of};

/// A step running `version`'s code on the trigger's `ok` field.
///
/// # Panics
///
/// Never: the names and the mapping are fixed.
#[must_use]
pub fn code_step(name: &str, version: SandboxVersionId) -> Node {
    let inputs = Mapping::new(vec![(
        FieldName::new("ok").expect("a field name"),
        Source::Input(DataPath::parse("trigger.ok").expect("a path")),
    )])
    .expect("one mapped field");
    Node::new(
        step(name),
        Label::new("name", name).expect("a step name"),
        NodeKind::Code(CodeStep::new(version, inputs)),
        Join::All,
    )
}

/// Version 1 of a fresh Python sandbox, its bundle ready.
#[must_use]
pub fn ready_version() -> SandboxVersion<ResolvedTenant> {
    ready_in_sandbox().1
}

/// A fresh Python sandbox and its version 1, whose bundle is ready.
///
/// # Panics
///
/// Never: the bundle holds the one package the version pins.
#[must_use]
pub fn ready_in_sandbox() -> (Sandbox<ResolvedTenant>, SandboxVersion<ResolvedTenant>) {
    let mut sandbox = python_sandbox();
    let mut version = version_of(&mut sandbox);
    let digest = BundleDigest::new("ab".repeat(32)).expect("a digest");
    let bundle = Bundle::new(digest, 4096, Vec::new()).expect("a bundle");
    version
        .finish_build(bundle)
        .expect("a building version is built");
    (sandbox, version)
}

/// A run `acting_for` started of a workflow whose one step `clean` runs
/// `version`'s code, and the run that step waits on.
///
/// # Panics
///
/// Panics if the code step does not start.
#[must_use]
pub fn code_under_way(
    acting_for: &Human,
    version: SandboxVersionId,
) -> (WorkflowExecution<ResolvedTenant>, CodeRun) {
    let author = person("author@corp.test");
    let workflow = published_by(
        &author,
        draft_by(&author, vec![code_step("clean", version)], Vec::new()),
    );
    let mut execution = started_by(acting_for, &workflow);
    let holds = CapabilitySet::new(
        vec![SystemPermission::Workflows(WorkflowAction::Run)],
        Vec::new(),
    );
    let started = execution
        .begin_code(
            &step("clean"),
            &ActingAuthority::assumed(acting_for.clone(), holds),
        )
        .expect("the code step is ready");
    let CodeStart::Run(run, _) = started else {
        panic!("the code step was refused");
    };
    (execution, run)
}

/// A runner giving every run the same answer, and keeping what each run
/// was handed.
pub struct FakeCodeRunner {
    answer: CodeRan,
    handed: Mutex<Vec<FlowData>>,
}

impl TenantScoped for FakeCodeRunner {}

impl FakeCodeRunner {
    /// A runner answering `answer`.
    #[must_use]
    pub fn answering(answer: CodeRan) -> Self {
        Self {
            answer,
            handed: Mutex::new(Vec::new()),
        }
    }

    /// What each run was handed, in order.
    ///
    /// # Panics
    ///
    /// When a test panicked while holding the record.
    #[must_use]
    pub fn handed(&self) -> Vec<FlowData> {
        self.handed.lock().unwrap().clone()
    }
}

#[async_trait]
impl CodeRunner for FakeCodeRunner {
    async fn run(&self, _tenant_id: &ScopedTenant, request: CodeRequest<'_>) -> CodeRan {
        self.handed.lock().unwrap().push(request.input.clone());
        self.answer.clone()
    }
}

impl Fake for Arc<dyn CodeRunner> {
    fn fake() -> Self {
        Arc::new(FakeCodeRunner::answering(CodeRan::Unavailable(
            UntrustedText::record("no sandbox in this test"),
        )))
    }
}
