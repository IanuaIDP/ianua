//! A sign-up waiting for its founder to prove their mailbox.
//!
//! Nothing is founded on the form alone. Mallory fills in the sign-up form
//! with Globex's name and a throwaway address. If that founded an
//! organization at once, she would hold the name `globex` for good and set
//! a workspace being built, all without reaching any mailbox. So the form
//! only keeps what was asked for, and mails a link. The organization, its
//! first workspace and its owner are founded when the link comes back,
//! with the owner's address proven by it.

use time::{Duration, OffsetDateTime};

use crate::domains::identity::account::verified_email::VerifiedEmail;
use crate::shared::errors::DomainError;
use crate::types::{
    DisplayName, Email, Label, Lifetime, Locale, PasswordHash, Timezone, TokenHash,
};

/// The longest a sign-up link works: a day.
const LONGEST_LINK: Duration = Duration::days(1);

/// What the founder asked for: the names, their own name and password,
/// and where the first workspace lives in time and language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignupDetails {
    /// The company's name, which the organization is named and slugged
    /// after.
    pub company_name: Label,
    /// The first workspace's name, which it is named and slugged after.
    pub tenant_name: Label,
    /// The founder's name, shown in the dashboard.
    pub admin_display_name: DisplayName,
    /// The hash of the founder's password, checked against the rules a new
    /// organization starts with.
    pub password_hash: PasswordHash,
    /// The first workspace's timezone.
    pub timezone: Timezone,
    /// The first workspace's language.
    pub locale: Locale,
}

/// A sign-up waiting for the link mailed to its address to come back.
#[derive(Debug)]
pub struct PendingSignup {
    email: Email,
    details: SignupDetails,
    token_hash: TokenHash,
    requested_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

/// A pending sign-up as it was stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSignupRow {
    /// The address the link was mailed to.
    pub email: Email,
    /// What the founder asked for.
    pub details: SignupDetails,
    /// The hash of the token the link carries.
    pub token_hash: TokenHash,
    /// When the sign-up was asked for.
    pub requested_at: OffsetDateTime,
    /// When the link stops working.
    pub expires_at: OffsetDateTime,
}

/// A sign-up whose link came back in time: the founder's address, proven,
/// and what they asked for.
#[derive(Debug)]
pub struct ConfirmedSignup {
    /// The founder's address, proven by the link.
    pub email: VerifiedEmail,
    /// What the founder asked for.
    pub details: SignupDetails,
}

impl PendingSignup {
    /// A sign-up for `email`, asking for `details`, whose link carries the
    /// token hashed as `token_hash` and works for `lifetime`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `lifetime` is longer than a day.
    pub fn request(
        email: Email,
        details: SignupDetails,
        token_hash: TokenHash,
        lifetime: Lifetime,
    ) -> Result<Self, DomainError> {
        lifetime.ensure_at_most(LONGEST_LINK, "a sign-up link")?;
        let now = crate::shared::clock::now();
        Ok(Self {
            email,
            details,
            token_hash,
            requested_at: now,
            expires_at: lifetime.ends_after(now),
        })
    }

    /// Rebuilds a stored sign-up.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the link ends before it was
    ///   asked for, or works longer than a day.
    pub fn reconstitute(row: PendingSignupRow) -> Result<Self, DomainError> {
        if row.expires_at <= row.requested_at {
            return Err(DomainError::corrupt_row(
                "pending sign-up",
                "the link ends before it was asked for",
            ));
        }
        if row.expires_at > row.requested_at.saturating_add(LONGEST_LINK) {
            return Err(DomainError::corrupt_row(
                "pending sign-up",
                "the link works longer than a day",
            ));
        }
        Ok(Self {
            email: row.email,
            details: row.details,
            token_hash: row.token_hash,
            requested_at: row.requested_at,
            expires_at: row.expires_at,
        })
    }

    /// The sign-up as it is stored.
    #[must_use]
    pub fn to_row(&self) -> PendingSignupRow {
        PendingSignupRow {
            email: self.email.clone(),
            details: self.details.clone(),
            token_hash: self.token_hash.clone(),
            requested_at: self.requested_at,
            expires_at: self.expires_at,
        }
    }

    /// The address the link goes to.
    #[must_use]
    pub fn email(&self) -> &Email {
        &self.email
    }

    /// What the founder asked for.
    #[must_use]
    pub fn details(&self) -> &SignupDetails {
        &self.details
    }

    /// The hash of the token the link carries.
    #[must_use]
    pub fn token_hash(&self) -> &TokenHash {
        &self.token_hash
    }

    /// When the link stops working.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// The sign-up, confirmed by its link coming back at `now`, or `None`
    /// once the link has run out.
    ///
    /// The link reached the address, so the address is proven. The store
    /// hands a sign-up out once, so a link works once.
    #[must_use]
    pub fn confirm(self, now: OffsetDateTime) -> Option<ConfirmedSignup> {
        if now >= self.expires_at {
            return None;
        }
        Some(ConfirmedSignup {
            email: VerifiedEmail::proven(self.email),
            details: self.details,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::config::DisplayNameLimits;
    use crate::shared::model::row_check::refused_as_corrupt;

    /// What Ann asks for when she signs Acme up.
    fn details() -> SignupDetails {
        SignupDetails {
            company_name: Label::new("company_name", "Acme Corp").unwrap(),
            tenant_name: Label::new("tenant_name", "Production").unwrap(),
            admin_display_name: DisplayName::new("Ann", &DisplayNameLimits::default()).unwrap(),
            password_hash: PasswordHash::from_stored("argon2-hash".to_owned()),
            timezone: Timezone::new("UTC").unwrap(),
            locale: Locale::new("en-US").unwrap(),
        }
    }

    /// Ann's sign-up, its link working for `hours`.
    fn asked(hours: i64) -> Result<PendingSignup, DomainError> {
        PendingSignup::request(
            Email::new("ann@acme.com").unwrap(),
            details(),
            TokenHash::from_stored("hash".to_owned()),
            Lifetime::seconds(hours * 3600).unwrap(),
        )
    }

    /// Ann's link comes back within the day. Her address counts as proven,
    /// and what she asked for is handed on to be founded.
    #[test]
    fn a_link_back_in_time_proves_the_address() {
        let pending = asked(24).unwrap();
        let now = crate::shared::clock::now();

        let confirmed = pending.confirm(now).unwrap();

        assert_eq!(confirmed.email.as_email().as_str(), "ann@acme.com");
        assert_eq!(confirmed.details, details());
    }

    /// A one-day link used two days later returns no confirmed signup.
    #[test]
    fn a_link_past_its_day_founds_nothing() {
        let pending = asked(24).unwrap();
        let later = crate::shared::clock::now() + Duration::days(2);

        assert!(pending.confirm(later).is_none());
    }

    /// A sign-up link may work a day at most.
    #[test]
    fn a_link_longer_than_a_day_is_refused() {
        assert!(matches!(asked(25), Err(DomainError::Validation(_))));
    }

    /// A stored sign-up loads back as it was saved.
    #[test]
    fn a_stored_sign_up_loads_back() {
        let pending = asked(24).unwrap();

        let loaded = PendingSignup::reconstitute(pending.to_row()).unwrap();

        assert_eq!(loaded.to_row(), pending.to_row());
    }

    /// A stored link that ends before it was asked for is refused as
    /// corrupt.
    #[test]
    fn a_stored_link_ending_before_it_began_is_corrupt() {
        let mut row = asked(24).unwrap().to_row();
        row.expires_at = row.requested_at;

        assert!(refused_as_corrupt(&PendingSignup::reconstitute(row)));
    }

    /// A stored link that works longer than a day is refused as corrupt.
    #[test]
    fn a_stored_link_longer_than_a_day_is_corrupt() {
        let mut row = asked(24).unwrap().to_row();
        row.expires_at = row.requested_at + Duration::days(3);

        assert!(refused_as_corrupt(&PendingSignup::reconstitute(row)));
    }
}
