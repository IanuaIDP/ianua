//! Whether a password appears in known data breaches, and what a sign-in
//! and a new password do about it.

use crate::domains::authentication::operations::password_login::Lookup;
use crate::message;
use crate::shared::errors::DomainError;

/// Whether a password has appeared in known data breaches.
///
/// Found by checking the start of the password's SHA-1 hash against the
/// `HaveIBeenPwned` k-anonymity API. Only the first 5 hex characters of the
/// hash are sent, never the full hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BreachStatus {
    /// The password was not found in any known breach database.
    Clean,

    /// The password was found in known breaches. The count says how many
    /// times it appeared across all indexed breaches.
    ///
    /// Even a count of 1 means the password is compromised. An attacker with
    /// the breach data can try it directly.
    Breached(u64),
}

impl BreachStatus {
    /// Whether the password is known to be compromised.
    #[must_use]
    pub fn is_breached(&self) -> bool {
        matches!(self, Self::Breached(_))
    }

    /// The number of times the password appeared in breaches. Zero for a
    /// clean password.
    #[must_use]
    pub fn occurrence_count(&self) -> u64 {
        match self {
            Self::Clean => 0,
            Self::Breached(count) => *count,
        }
    }
}

/// What a password sign-in does about breached passwords.
///
/// Set once for the deployment, not per tenant. Setting a new password is
/// held to each boundary's own [`BreachedPasswordCheck`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BreachPolicy {
    /// Check the password, record a breach, and treat it as a risk signal.
    /// Someone with a second factor must use it. Someone without one confirms
    /// by email. The sign-in is not refused, because a holder who passes
    /// either step is still the owner.
    StepUp,

    /// Check the password and record a breach. Ask for nothing extra.
    Record,

    /// Don't check passwords against breach data at all.
    Off,
}

impl BreachPolicy {
    /// Whether sign-in passwords are checked against breach data.
    #[must_use]
    pub fn checks_passwords(self) -> bool {
        !matches!(self, Self::Off)
    }
}

/// What setting a new password does about one found in known breaches.
///
/// Each tenant and each organization chooses it. It applies wherever a
/// password is set: sign-up, a change, a reset link, an admin's reset and
/// an invitation, for tenant users and organization members alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BreachedPasswordCheck {
    /// Don't look the new password up.
    Off,
    /// Look it up and take it, but tell the person it is breached.
    Warn,
    /// Look it up and refuse it when it is breached, or when the lookup
    /// could not be made. NIST SP 800-63B asks for this.
    Block,
}

impl BreachedPasswordCheck {
    /// Whether a new password is looked up in breach data.
    #[must_use]
    pub fn checks_passwords(self) -> bool {
        !matches!(self, Self::Off)
    }

    /// What setting a password whose breach lookup gave `found` comes to.
    ///
    /// Mallory bought a list of leaked passwords, and Ann's favourite is on
    /// it. Under `Block` she is made to choose another, so the list does
    /// not open her account. A lookup that could not be made, or timed
    /// out, refuses the password under `Block` with a "try again": a
    /// tenant that blocks breached passwords never takes one it could not
    /// check. Under `Warn` the password goes through as unchecked, and the
    /// caller records the gap, as a sign-in records a check that could not
    /// run.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] under `Block` when the password is
    ///   breached, or when the lookup could not be made.
    pub fn judge(self, found: &Lookup<BreachStatus>) -> Result<NewPasswordBreach, DomainError> {
        let status = match (self, found) {
            (Self::Off, _) => return Ok(NewPasswordBreach::NotChecked),
            (Self::Block, Lookup::Unavailable) => {
                return Err(DomainError::invalid(message!(
                    "authentication-this-password-could-not-be-checked",
                    "this password could not be checked against known data breaches; try again"
                )));
            }
            (Self::Warn, Lookup::Unavailable) => return Ok(NewPasswordBreach::Unchecked),
            (Self::Warn | Self::Block, Lookup::Unknown) => BreachStatus::Clean,
            (Self::Warn | Self::Block, Lookup::Known(status)) => *status,
        };
        match (self, status) {
            (_, BreachStatus::Clean) => Ok(NewPasswordBreach::Clean),
            (Self::Block, BreachStatus::Breached(_)) => Err(DomainError::invalid(message!(
                "authentication-this-password-appears-in-known-data",
                "this password appears in known data breaches; choose another"
            ))),
            (Self::Off | Self::Warn, BreachStatus::Breached(count)) => {
                Ok(NewPasswordBreach::Breached(count))
            }
        }
    }
}

/// What the breach check found for a new password it let through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewPasswordBreach {
    /// The boundary does not check.
    NotChecked,
    /// The breach service could not be reached.
    Unchecked,
    /// Not found in any breach.
    Clean,
    /// Found this many times. The person is warned to choose another.
    Breached(u64),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A password found in twelve breaches is refused under `Block`; `Warn`
    /// returns the breach count, and an absent match is clean under either policy.
    #[test]
    fn a_breached_new_password_is_refused_or_warned_about() {
        let found = Lookup::Known(BreachStatus::Breached(12));

        assert!(matches!(
            BreachedPasswordCheck::Block.judge(&found),
            Err(DomainError::Validation(_))
        ));
        assert_eq!(
            BreachedPasswordCheck::Warn.judge(&found).unwrap(),
            NewPasswordBreach::Breached(12)
        );
    }

    /// A clean password is taken under every choice that checks.
    #[test]
    fn a_clean_new_password_is_taken() {
        let found = Lookup::Known(BreachStatus::Clean);

        for check in [BreachedPasswordCheck::Warn, BreachedPasswordCheck::Block] {
            assert_eq!(check.judge(&found).unwrap(), NewPasswordBreach::Clean);
        }
    }

    /// An unavailable breach lookup produces a validation error under `Block`.
    #[test]
    fn an_unanswered_lookup_refuses_the_password_under_block() {
        let judged = BreachedPasswordCheck::Block.judge(&Lookup::Unavailable);

        assert!(matches!(judged, Err(DomainError::Validation(_))));
    }

    /// The breach service is down where the tenant only warns. The new
    /// password is taken as unchecked, so nobody is stopped from resetting
    /// theirs.
    #[test]
    fn an_unanswered_lookup_lets_the_password_through_under_warn() {
        assert_eq!(
            BreachedPasswordCheck::Warn
                .judge(&Lookup::Unavailable)
                .unwrap(),
            NewPasswordBreach::Unchecked
        );
    }

    /// With the check off, nothing is looked up and nothing refused, even
    /// a breached password.
    #[test]
    fn with_the_check_off_nothing_is_refused() {
        let check = BreachedPasswordCheck::Off;

        assert!(!check.checks_passwords());
        assert_eq!(
            check
                .judge(&Lookup::Known(BreachStatus::Breached(3)))
                .unwrap(),
            NewPasswordBreach::NotChecked
        );
    }

    /// Both `StepUp` and `Record` look the password up in breach data. Only
    /// `Off` signs people in without checking.
    #[test]
    fn only_the_off_policy_skips_the_check() {
        assert!(BreachPolicy::StepUp.checks_passwords());
        assert!(BreachPolicy::Record.checks_passwords());
        assert!(!BreachPolicy::Off.checks_passwords());
    }

    /// A password missing from every breach list is reported as safe, so it
    /// never triggers the breach response.
    #[test]
    fn clean_is_not_breached() {
        assert!(!BreachStatus::Clean.is_breached());
    }

    /// A clean password reports a count of 0, so a caller can show the count
    /// without matching on the variant.
    #[test]
    fn clean_has_zero_occurrences() {
        assert_eq!(BreachStatus::Clean.occurrence_count(), 0);
    }

    /// A password seen 42 times in breaches is reported as compromised.
    #[test]
    fn breached_is_breached() {
        assert!(BreachStatus::Breached(42).is_breached());
    }

    /// A password seen 1337 times reports exactly 1337, so the count shown to
    /// the user is the one the breach service gave.
    #[test]
    fn breached_carries_count() {
        assert_eq!(BreachStatus::Breached(1337).occurrence_count(), 1337);
    }

    /// A password seen in a single breach still counts as compromised. One
    /// leak is enough for an attacker to try it.
    #[test]
    fn breached_with_one_is_still_breached() {
        assert!(BreachStatus::Breached(1).is_breached());
    }

    /// A clean status written to JSON reads back as clean.
    #[cfg(feature = "serde")]
    #[test]
    fn clean_roundtrips_through_json() {
        let status = BreachStatus::Clean;
        let json = serde_json::to_string(&status).unwrap();
        let restored: BreachStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, restored);
    }

    /// A breached status with a count of 999 reads back from JSON with the
    /// same count.
    #[cfg(feature = "serde")]
    #[test]
    fn breached_roundtrips_through_json() {
        let status = BreachStatus::Breached(999);
        let json = serde_json::to_string(&status).unwrap();
        let restored: BreachStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, restored);
    }

    /// Each policy is written as `"StepUp"`, `"Record"` or `"Off"` and read
    /// back from the same text. Renaming a variant fails here instead of
    /// breaking saved settings.
    #[cfg(feature = "serde")]
    #[test]
    fn breach_policy_is_stored_under_its_variant_name() {
        assert_eq!(
            serde_json::to_string(&BreachPolicy::StepUp).unwrap(),
            r#""StepUp""#
        );
        assert_eq!(
            serde_json::to_string(&BreachPolicy::Record).unwrap(),
            r#""Record""#
        );
        assert_eq!(
            serde_json::to_string(&BreachPolicy::Off).unwrap(),
            r#""Off""#
        );
        assert_eq!(
            serde_json::from_str::<BreachPolicy>(r#""StepUp""#).unwrap(),
            BreachPolicy::StepUp
        );
        assert_eq!(
            serde_json::from_str::<BreachPolicy>(r#""Record""#).unwrap(),
            BreachPolicy::Record
        );
        assert_eq!(
            serde_json::from_str::<BreachPolicy>(r#""Off""#).unwrap(),
            BreachPolicy::Off
        );
    }
}
