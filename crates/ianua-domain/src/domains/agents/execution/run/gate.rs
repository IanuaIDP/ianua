//! The check on every tool call a run makes. It decides whether the run may
//! make the call at all, and whether a person must approve it first.

use crate::domains::agents::authority::capability::ActionApproval;
use crate::domains::agents::authority::delegation::ActingUnder;
use crate::domains::agents::authority::intent::IntentEnvelope;
use crate::domains::agents::execution::run::target::ResolvedCall;
use crate::domains::agents::execution::tool::ToolName;
use crate::domains::data_classification::level::DataClassLevel;
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::types::ActionClass;

/// What the check allows: a call that may run now, or one a person must
/// approve first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// The call may run.
    Proceed,
    /// The call may run once a person approves it.
    NeedsApproval,
}

/// Why the check refuses a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallRefusal {
    /// The run acts under no delegation, so nothing could authorize the call.
    NoAuthority,
    /// The tool given is not the one the call names, or is disabled.
    UnknownTool,
    /// The values the call gave do not fill the tool's path exactly.
    UnfilledPath,
    /// The run was not started with this tool.
    NotGranted,
    /// The tool's action, or the action at the path the call goes to, lies
    /// outside the run's declared purpose.
    OutsidePurpose,
    /// The tool may receive less sensitive data than the run has read.
    WouldLeak {
        /// The most sensitive data the run has read.
        exposure: DataClassLevel,
        /// The most sensitive data the tool may receive.
        clearance: DataClassLevel,
    },
}

impl CallRefusal {
    /// The reason recorded on the run's step.
    #[must_use]
    pub fn reason(self) -> String {
        match self {
            Self::NoAuthority => {
                "the run acts under no delegation, so it may not call tools".to_owned()
            }
            Self::UnknownTool => "no such tool, or the tool is disabled".to_owned(),
            Self::UnfilledPath => "the call's values do not fill the tool's path".to_owned(),
            Self::NotGranted => "the run was not given this tool".to_owned(),
            Self::OutsidePurpose => "the tool's action is outside the run's purpose".to_owned(),
            Self::WouldLeak {
                exposure,
                clearance,
            } => format!(
                "the run has read {} data and the tool is cleared only for {} data",
                exposure.as_str(),
                clearance.as_str()
            ),
        }
    }
}

impl From<CallRefusal> for DomainError {
    fn from(refusal: CallRefusal) -> Self {
        Self::forbidden(refusal.reason())
    }
}

/// The parts of a run the call check reads.
pub(super) struct CallGate<'a> {
    pub(super) delegation: &'a ActingUnder,
    pub(super) granted_tools: &'a [ToolName],
    pub(super) purpose: &'a IntentEnvelope,
    pub(super) exposure: DataClassLevel,
    pub(super) approval_classes: &'a [ActionClass],
    pub(super) approval: ActionApproval,
}

impl CallGate<'_> {
    /// Admits `call`, or says why not.
    pub(super) fn admit<T: TenantScope>(
        &self,
        call: &ResolvedCall<'_, T>,
    ) -> Result<Admission, CallRefusal> {
        if matches!(self.delegation, ActingUnder::NoDelegation) {
            return Err(CallRefusal::NoAuthority);
        }
        let tool = call.tool();
        if !self.granted_tools.contains(tool.name()) {
            return Err(CallRefusal::NotGranted);
        }
        let classes = call.classes();
        if !classes.iter().all(|class| self.purpose.permits(*class)) {
            return Err(CallRefusal::OutsidePurpose);
        }
        if tool.classification() < self.exposure {
            return Err(CallRefusal::WouldLeak {
                exposure: self.exposure,
                clearance: tool.classification(),
            });
        }
        let needs_approval = classes
            .iter()
            .any(|class| self.admission_for(*class) == Admission::NeedsApproval);
        if needs_approval {
            return Ok(Admission::NeedsApproval);
        }
        Ok(Admission::Proceed)
    }

    /// Whether an action of `class` needs approval.
    ///
    /// It does under a delegation that asks for approval on every action. It
    /// does for a high-risk class, and for a class the starter listed.
    pub(super) fn admission_for(&self, class: ActionClass) -> Admission {
        let every_action = self.approval == ActionApproval::PerAction;
        if every_action || class.is_high_risk() || self.approval_classes.contains(&class) {
            return Admission::NeedsApproval;
        }
        Admission::Proceed
    }
}
