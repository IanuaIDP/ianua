//! What a new password may not repeat, and when an account must change
//! its password before it goes on.
//!
//! A tenant user's password lives in the credential store, not on the
//! account, so these rules read what the store keeps: the earlier hashes,
//! who set the current password and when.

use time::OffsetDateTime;

use crate::domains::authentication::credentials::password::PasswordHasher;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::PasswordHash;
use crate::types::password_policy::{PasswordExpiry, ReuseLimit};

/// Who set an account's current password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PasswordOrigin {
    /// The holder chose it: at sign-up, from an invitation, a reset link or
    /// a change of their own.
    ChosenByHolder,
    /// Someone acting on the account set it, such as an admin resetting it.
    /// The admin knows it, so the holder must replace it at their next
    /// sign-in.
    SetByAdmin,
}

impl PasswordOrigin {
    /// The stable name storage keeps.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChosenByHolder => "chosen_by_holder",
            Self::SetByAdmin => "set_by_admin",
        }
    }
}

/// An account's current password as the credential store keeps it: who
/// set it and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurrentPassword {
    /// Who set it.
    pub origin: PasswordOrigin,
    /// When it was set.
    pub changed_at: OffsetDateTime,
}

impl CurrentPassword {
    /// Whether a sign-in with this password at `now` must change it first,
    /// under the boundary's `expiry`.
    ///
    /// Sam resets Ann's password to `Welcome-2024` and tells her on the
    /// phone. Until she replaces it, Sam can sign in as her. So a password
    /// an admin set is changed at the next sign-in, before anything else.
    /// A password past the boundary's age is changed too.
    #[must_use]
    pub fn due(&self, expiry: PasswordExpiry, now: OffsetDateTime) -> PasswordDue {
        if self.origin == PasswordOrigin::SetByAdmin {
            return PasswordDue::ChangeRequired(ChangeReason::SetByAdmin);
        }
        if expiry.is_due(self.changed_at, now) {
            return PasswordDue::ChangeRequired(ChangeReason::Expired);
        }
        PasswordDue::Current
    }
}

/// Whether a password sign-in may go on, or must change the password first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordDue {
    /// The password stands.
    Current,
    /// The password must be replaced before the sign-in goes on.
    ChangeRequired(ChangeReason),
}

/// Why a password must be replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeReason {
    /// Someone acting on the account set it, so they know it.
    SetByAdmin,
    /// It reached the age the boundary allows.
    Expired,
}

impl ChangeReason {
    /// The stable name a record or an answer carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SetByAdmin => "set_by_admin",
            Self::Expired => "expired",
        }
    }
}

/// Refuses `password` when it matches one of the newest `limit` hashes in
/// `earlier`.
///
/// `earlier` holds the current password's hash and the retired ones,
/// newest first. Each hash is salted, so the new password is checked
/// against each, never hashed and compared. Mallory phished Ann's password,
/// and Ann's admin made her change it. Without this, Ann sets it straight
/// back and Mallory's copy works again.
///
/// # Errors
///
/// - [`DomainError::Validation`] when it matches one of them.
/// - The error `hasher` gives when it cannot check a stored hash.
pub fn ensure_not_reused(
    password: &str,
    earlier: &[PasswordHash],
    limit: ReuseLimit,
    hasher: &impl PasswordHasher,
) -> Result<(), DomainError> {
    for hash in earlier.iter().take(usize::from(limit.count())) {
        if hasher.verify(password, hash)? {
            return Err(DomainError::invalid(message!(
                "authentication-this-password-was-used-recently-choose",
                "this password was used recently; choose another"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::test_support::fakes::FakeHasher;
    use crate::types::password_policy::ExpiryDays;

    fn hashes(passwords: &[&str]) -> Vec<PasswordHash> {
        passwords
            .iter()
            .map(|password| FakeHasher.hash(password).unwrap())
            .collect()
    }

    /// A history limit of three prevents Ann from choosing her current password again.
    #[test]
    fn a_recent_password_is_refused() {
        let earlier = hashes(&["phished", "older", "oldest"]);
        let three = ReuseLimit::new(3).unwrap();

        let refused = ensure_not_reused("phished", &earlier, three, &FakeHasher);

        assert!(matches!(refused, Err(DomainError::Validation(_))));
    }

    /// Under a limit of two, Ann's third-newest password may come back, and
    /// a new one is always taken.
    #[test]
    fn a_password_older_than_the_limit_may_come_back() {
        let earlier = hashes(&["now", "before", "long_ago"]);
        let two = ReuseLimit::new(2).unwrap();

        assert!(ensure_not_reused("long_ago", &earlier, two, &FakeHasher).is_ok());
        assert!(ensure_not_reused("fresh", &earlier, two, &FakeHasher).is_ok());
    }

    /// With no limit, even the current password may be set again.
    #[test]
    fn no_limit_refuses_nothing() {
        let earlier = hashes(&["now"]);

        assert!(ensure_not_reused("now", &earlier, ReuseLimit::NONE, &FakeHasher).is_ok());
    }

    /// An administrator-set password requires a change even when passwords never expire.
    #[test]
    fn a_password_an_admin_set_must_change_at_the_next_sign_in() {
        let now = crate::shared::clock::now();
        let set_by_sam = CurrentPassword {
            origin: PasswordOrigin::SetByAdmin,
            changed_at: now,
        };

        assert_eq!(
            set_by_sam.due(PasswordExpiry::Never, now),
            PasswordDue::ChangeRequired(ChangeReason::SetByAdmin)
        );
    }

    /// Ann chose her password 91 days ago. Under a 90-day expiry it must
    /// change; under none it stands.
    #[test]
    fn an_old_password_must_change_only_under_an_expiry() {
        let now = crate::shared::clock::now();
        let chosen = CurrentPassword {
            origin: PasswordOrigin::ChosenByHolder,
            changed_at: now - Duration::days(91),
        };
        let ninety = PasswordExpiry::After(ExpiryDays::new(90).unwrap());

        assert_eq!(
            chosen.due(ninety, now),
            PasswordDue::ChangeRequired(ChangeReason::Expired)
        );
        assert_eq!(chosen.due(PasswordExpiry::Never, now), PasswordDue::Current);
    }
}
