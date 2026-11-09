//! Consent and erasure for the people who administer an organization, by
//! the same rules a tenant's people have: a member agrees or asks to be
//! erased only from their own sign-in, the last owner never erases
//! themselves, and an erasure waits out a grace period the member can
//! cancel from a mailed link.

/// What a member agreed to, and when they withdrew it.
pub mod consent;
/// A member's request to have their data deleted for good.
pub mod erasure;

use crate::domains::organization::members::control::{Carried, OrgControl};
use crate::domains::organization::members::org_user::OrgUser;
use crate::message;
use crate::shared::errors::DomainError;

/// Refuses `by` unless it is `member`, acting now through their own
/// signed-in session.
///
/// A key a member minted acts for them in scripts, but it is not the
/// person: a consent or an erasure is their own word, given in person.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when `by` is not an active member of the
///   organization acting through a session that is theirs.
/// - [`DomainError::Forbidden`] when `by` is another member, or acts
///   through a key.
pub(crate) fn ensure_in_person(member: &OrgUser, by: &OrgControl<'_>) -> Result<(), DomainError> {
    by.ensure_genuine(member.organization_id())?;
    let in_session = matches!(by.carries(), Carried::Session(_));
    if !by.is_member(member.id()) || !in_session {
        return Err(DomainError::forbidden(message!(
            "organization-only-the-member-themselves-signed-in",
            "only the member themselves, signed in, may do this"
        )));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::domains::organization::members::control::tests::{
        acting, founder, key_of, member_of, session_of,
    };
    use crate::domains::organization::members::org_user::OrgUserRow;
    use crate::domains::organization::status::{OrgStanding, OrganizationStatus};
    use crate::types::Joining;

    /// A second copy of `member` as stored now, to act through while the
    /// first is changed.
    pub(crate) fn copy_of(member: &OrgUser) -> OrgUser {
        OrgUser::reconstitute(OrgUserRow {
            id: *member.id(),
            organization_id: *member.organization_id(),
            email: member.email().clone(),
            display_name: member.display_name().clone(),
            password_hash: member.password_hash().clone(),
            status: member.status(),
            role: member.role(),
            email_standing: member.address().standing(),
            locale: member.locale().clone(),
            timezone: member.timezone().clone(),
            created_at: member.created_at(),
            updated_at: member.updated_at(),
            joining: Joining::from_stored(member.joined_at()),
            credentials_changed_at: member.credentials_changed_at(),
            vouching: member.vouching(),
        })
        .unwrap()
    }

    /// Sam, signed in, acts in person for himself.
    #[test]
    fn a_member_signed_in_acts_in_person_for_themselves() {
        let sam = member_of(&founder());
        let session = session_of(&sam);

        assert!(ensure_in_person(&sam, &acting(&sam, &session)).is_ok());
    }

    /// Sam's API key cannot satisfy the check that he is acting in person.
    #[test]
    fn a_key_never_acts_in_person() {
        let sam = member_of(&founder());
        let key = key_of(&sam, &["org:tenants:view"]);
        let through_key = OrgControl::new(
            OrgStanding::new(*sam.organization_id(), OrganizationStatus::Active),
            &sam,
            Carried::Key(&key),
        );

        let refused = ensure_in_person(&sam, &through_key);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// An owner's session cannot satisfy another member's in-person check.
    #[test]
    fn nobody_acts_in_person_for_another() {
        let ann = founder();
        let sam = member_of(&ann);
        let session = session_of(&ann);

        let refused = ensure_in_person(&sam, &acting(&ann, &session));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }
}
