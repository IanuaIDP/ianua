//! Who sends a policy to review, and who may approve it.
//!
//! A policy decides who reaches what. One person writing, submitting and
//! approving it alone could quietly drop the rule that asks admins for a
//! second factor. So a second person approves, whenever the tenant has one
//! who may.

use crate::domains::authorization::authority::TenantAuthority;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::Human;

/// Who sent a policy to review, or that nobody has yet.
///
/// It keeps the person behind the account, not only the account. Ann sends
/// a policy to review from her tenant account. Without the person, she
/// approves it from her organization account, which shares her address, as
/// if she were a second person.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Submission {
    /// It was never sent to review, or went back to draft.
    #[default]
    NotSubmitted,
    /// This person sent it to review, through this account.
    By(Human),
}

impl Submission {
    /// Whether `person` sent it to review, through any of their accounts.
    #[must_use]
    pub fn is_by(&self, person: &Human) -> bool {
        match self {
            Self::NotSubmitted => false,
            Self::By(submitter) => submitter.is_same_person_as(person),
        }
    }
}

/// Whether anyone in the tenant other than the approver may activate
/// policies, as the authorizer finds it now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtherApprovers {
    /// Someone else may.
    Exist,
    /// Nobody else may. A tenant with a single admin is not locked out of
    /// changing its own policy.
    NoneInTenant,
}

/// The person approving a policy, what they may use now, and whether anyone
/// else could approve it instead.
///
/// Only [`TenantAccess::policy_approver`] makes one, so "nobody else could
/// approve it" is worked out from the tenant's records, never claimed.
///
/// [`TenantAccess::policy_approver`]: crate::domains::authorization::authority::TenantAccess::policy_approver
#[derive(Debug, Clone, Copy)]
pub struct PolicyApprover<'a> {
    approver: &'a TenantAuthority,
    others: OtherApprovers,
}

impl<'a> PolicyApprover<'a> {
    /// `approver`, with `others` as the tenant's records say.
    pub(crate) fn new(approver: &'a TenantAuthority, others: OtherApprovers) -> Self {
        Self { approver, others }
    }

    /// `approver`, with `others` as a test says, without the records
    /// behind it.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn assumed(approver: &'a TenantAuthority, others: OtherApprovers) -> Self {
        Self::new(approver, others)
    }

    /// The person approving, with what they may use now. Approving hands
    /// nothing out, so an active break-glass grant counts.
    #[must_use]
    pub fn authority(&self) -> &'a TenantAuthority {
        self.approver
    }

    /// Whether anyone else in the tenant may activate policies.
    #[must_use]
    pub fn others(&self) -> OtherApprovers {
        self.others
    }
}

/// Refuses an approval by the person who sent the policy to review, through
/// any of their accounts, while someone else in the tenant could approve it.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when `approver` sent it to review and
///   another approver exists.
pub(crate) fn ensure_second_person(
    submitted: &Submission,
    approver: &PolicyApprover<'_>,
) -> Result<(), DomainError> {
    if submitted.is_by(approver.approver.who()) && approver.others == OtherApprovers::Exist {
        return Err(DomainError::forbidden(message!(
            "authorization-a-policy-is-approved-by-someone",
            "a policy is approved by someone other than the person who sent it to review"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::authority::assumed_authority;
    use crate::types::{HumanAccount, OrgUserId, PersonKey, TenantId, UserId};

    fn person(account: HumanAccount, address: &str) -> Human {
        Human::new(account, PersonKey::new(address).unwrap())
    }

    fn tenant_user(address: &str) -> Human {
        person(HumanAccount::User(UserId::new()), address)
    }

    fn approver(who: &Human, others: OtherApprovers) -> PolicyApprover<'static> {
        PolicyApprover::new(assumed_authority(who, TenantId::new(), &[], &[]), others)
    }

    /// Ann cannot approve her own submission when another approver exists;
    /// Bob can approve it.
    #[test]
    fn a_policy_needs_a_second_person_when_there_is_one() {
        let ann = tenant_user("ann@acme.test");
        let bob = tenant_user("bob@acme.test");
        let submitted = Submission::By(ann.clone());

        let by_ann = ensure_second_person(&submitted, &approver(&ann, OtherApprovers::Exist));
        let by_bob = ensure_second_person(&submitted, &approver(&bob, OtherApprovers::Exist));

        assert!(matches!(by_ann, Err(DomainError::Forbidden(_))));
        assert!(by_bob.is_ok());
    }

    /// Ann's organization account cannot serve as a second person to approve
    /// her tenant account's submission when another approver exists.
    #[test]
    fn a_second_account_of_the_submitter_is_not_a_second_person() {
        let anns_tenant_account = tenant_user("ann@acme.test");
        let anns_org_account = person(HumanAccount::OrgUser(OrgUserId::new()), "Ann@acme.test");
        let submitted = Submission::By(anns_tenant_account);

        let approved = ensure_second_person(
            &submitted,
            &approver(&anns_org_account, OtherApprovers::Exist),
        );

        assert!(matches!(approved, Err(DomainError::Forbidden(_))));
    }

    /// Ann is the tenant's only admin. She approves her own policy, so the
    /// tenant can still change it.
    #[test]
    fn a_sole_admin_approves_their_own_policy() {
        let ann = tenant_user("ann@acme.test");

        let approved = ensure_second_person(
            &Submission::By(ann.clone()),
            &approver(&ann, OtherApprovers::NoneInTenant),
        );

        assert!(approved.is_ok());
    }
}
