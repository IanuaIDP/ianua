//! Who may change a workflow or its accounts, and who may decide its steps.

use crate::domains::agents::oversight::approval::{Presence, PresenceProof};
use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::granter::HeldByGranter;
use crate::domains::authorization::permission::{SystemPermission, WorkflowAction};
use crate::domains::data_classification::level::DataClassLevel;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::Human;

/// A person acting on a workflow, with what they hold.
///
/// A version runs with the authority of whoever publishes it, so changing
/// one changes what that authority does. Sam may only view workflows.
/// Without this check, he rewrites Ann's draft.
#[derive(Debug, Clone, Copy)]
pub struct WorkflowControl<'a> {
    authority: &'a TenantAuthority,
}

impl<'a> WorkflowControl<'a> {
    /// The person `authority` names, acting with what it says they hold.
    #[must_use]
    pub fn new(authority: &'a TenantAuthority) -> Self {
        Self { authority }
    }

    /// The person acting.
    #[must_use]
    pub fn by(&self) -> &'a Human {
        self.authority.who()
    }

    /// What the tenant's records say the person holds.
    pub(crate) fn authority(&self) -> &'a TenantAuthority {
        self.authority
    }

    /// What they may hand on: their standing rights.
    #[must_use]
    pub fn holds(&self) -> HeldByGranter<'a> {
        self.authority.standing()
    }

    /// Refuses `action` unless the person holds the workflow right for it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when they do not hold it.
    pub fn ensure_may(&self, action: WorkflowAction) -> Result<(), DomainError> {
        if self.holds_workflow(action) {
            return Ok(());
        }
        Err(DomainError::forbidden(message!(
            "workflows-this-needs-a-workflow-right-the",
            "this needs a workflow right the person does not hold"
        )))
    }

    /// Whether the person holds the workflow right for `action`.
    #[must_use]
    pub fn holds_workflow(&self, action: WorkflowAction) -> bool {
        self.authority.holds(SystemPermission::Workflows(action))
    }
}

/// A person deciding an approval step, with what they hold, the most
/// sensitive data they may see, and whether they proved they are present.
///
/// Its clearance and presence come from proofs, never from the request.
/// Bob is cleared for public data. If the request said "restricted", he
/// would read the payroll figures a step shows. If it said "present", a
/// thief with his session would approve a payment.
#[derive(Debug, Clone, Copy)]
pub struct StepApprover<'a> {
    control: WorkflowControl<'a>,
    clearance: DataClassLevel,
    presence: Presence,
}

impl<'a> StepApprover<'a> {
    /// The person `control` names, cleared for what their rights clear them
    /// for, who did not prove they are present just now.
    #[must_use]
    pub fn of(control: WorkflowControl<'a>) -> Self {
        Self {
            control,
            clearance: control.authority().data_clearance(),
            presence: Presence::NotProven,
        }
    }

    /// The person `control` names, who proved they are present just now
    /// with `proof`: a fresh code from their own second factor, or a sign-in
    /// made a moment ago, as an agent's approver proves it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `proof` is for another account, or
    ///   a sign-in no longer fresh.
    pub fn present(
        control: WorkflowControl<'a>,
        proof: PresenceProof<'_>,
    ) -> Result<Self, DomainError> {
        if !proof.proves(control.by()) {
            return Err(DomainError::forbidden(message!(
                "workflows-the-proof-of-presence-is-not",
                "the proof of presence is not the approver's own, or not recent"
            )));
        }
        Ok(Self {
            presence: Presence::Proven,
            ..Self::of(control)
        })
    }

    /// `control`'s person, cleared for `clearance` and with `presence`, as a
    /// test says, without the proofs behind them.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn assumed(
        control: WorkflowControl<'a>,
        clearance: DataClassLevel,
        presence: Presence,
    ) -> Self {
        Self {
            control,
            clearance,
            presence,
        }
    }

    /// The person deciding.
    #[must_use]
    pub fn by(&self) -> &'a Human {
        self.control.by()
    }

    /// Whether they proved they are present just now.
    #[must_use]
    pub fn presence(&self) -> Presence {
        self.presence
    }

    /// Refuses a person who may not decide approval steps, or who is cleared
    /// below `exposure`, the data the step shows them.
    ///
    /// A step at confidential pauses before a payment and shows the figures.
    /// Without the clearance check, Sam, cleared for public data, reads them.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when they do not hold the workflow
    ///   approve right.
    /// - [`DomainError::Forbidden`] when their clearance is below `exposure`.
    pub(crate) fn ensure_entitled(&self, exposure: DataClassLevel) -> Result<(), DomainError> {
        self.control.ensure_may(WorkflowAction::Approve)?;
        if self.clearance < exposure {
            return Err(DomainError::forbidden(message!(
                "workflows-the-approver-is-not-cleared-for",
                "the approver is not cleared for the data the step shows"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::mfa::enrollment::answer_for;
    use crate::domains::authentication::sessions::fresh_sign_in::fresh_proof_of;
    use crate::domains::tenant::control::principal_of;
    use crate::test_support::authority::assumed_authority;
    use crate::types::{HumanAccount, PersonKey, TenantId, UserId};

    fn sam() -> Human {
        Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new("sam@corp.test").unwrap(),
        )
    }

    /// Workflow viewing rights cannot authorize an update, while the update
    /// right passes the permission check.
    #[test]
    fn a_workflow_change_needs_the_right_for_it() {
        let sam = sam();
        let view = [SystemPermission::Workflows(WorkflowAction::View)];
        let update = [SystemPermission::Workflows(WorkflowAction::Update)];
        let with =
            |system| WorkflowControl::new(assumed_authority(&sam, TenantId::new(), system, &[]));

        assert!(matches!(
            with(&view).ensure_may(WorkflowAction::Update),
            Err(DomainError::Forbidden(_))
        ));
        assert!(with(&update).ensure_may(WorkflowAction::Update).is_ok());
    }

    fn approving(by: &Human) -> WorkflowControl<'_> {
        WorkflowControl::new(assumed_authority(
            by,
            TenantId::new(),
            &[SystemPermission::Workflows(WorkflowAction::Approve)],
            &[],
        ))
    }

    /// Sam signs in again just now and decides a step. He counts as present.
    /// Deciding without that proof, he does not.
    #[test]
    fn an_approver_is_present_only_with_a_fresh_proof_of_their_own() {
        let sam = sam();
        let fresh = fresh_proof_of(principal_of(sam.account()));

        let present =
            StepApprover::present(approving(&sam), PresenceProof::SignIn(&fresh)).unwrap();
        let unproven = StepApprover::of(approving(&sam));

        assert_eq!(present.presence(), Presence::Proven);
        assert_eq!(unproven.presence(), Presence::NotProven);
    }

    /// Sam answers a fresh code from his own second factor, as he would to
    /// approve an agent's payment. He counts as present for a workflow's
    /// step too.
    #[test]
    fn a_fresh_code_from_the_approvers_own_factor_proves_presence() {
        let sam = sam();
        let code = answer_for(principal_of(sam.account()));

        let present = StepApprover::present(approving(&sam), PresenceProof::Code(&code)).unwrap();

        assert_eq!(present.presence(), Presence::Proven);
    }

    /// Another person's fresh sign-in or factor code cannot establish the
    /// approver's presence.
    #[test]
    fn a_proof_of_someone_elses_presence_is_refused() {
        let sam = sam();
        let ann = Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new("ann@corp.test").unwrap(),
        );
        let fresh = fresh_proof_of(principal_of(ann.account()));
        let code = answer_for(principal_of(ann.account()));

        let by_sign_in = StepApprover::present(approving(&sam), PresenceProof::SignIn(&fresh));
        let by_code = StepApprover::present(approving(&sam), PresenceProof::Code(&code));

        assert!(matches!(by_sign_in, Err(DomainError::Forbidden(_))));
        assert!(matches!(by_code, Err(DomainError::Forbidden(_))));
    }
}
