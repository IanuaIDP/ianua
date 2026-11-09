//! How long a client's tokens last: the platform's terms, or the client's
//! own.
//!
//! A tenant may give its banking app five-minute access tokens and its
//! internal dashboard an hour. Every term is bounded, so no setting hands
//! out a token that works for a week.

use time::Duration;

use crate::shared::errors::DomainError;
use crate::types::Lifetime;

/// The longest a refresh token family lives: ninety days.
const LONGEST_FAMILY: Duration = Duration::days(90);

/// The longest an access token or an ID token lives: a day.
const LONGEST_TOKEN: Duration = Duration::hours(24);

/// How long refresh tokens last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshLifetimes {
    idle: Lifetime,
    family: Lifetime,
}

impl RefreshLifetimes {
    /// Each token lasts `idle` unless used; a family lasts `family` from its
    /// first token, however often it is rotated.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `idle` is longer than `family`, or
    ///   `family` longer than ninety days.
    pub fn new(idle: Lifetime, family: Lifetime) -> Result<Self, DomainError> {
        family.ensure_at_most(LONGEST_FAMILY, "a refresh token family")?;
        idle.ensure_at_most(family.duration(), "a refresh token's idle time")?;
        Ok(Self { idle, family })
    }

    /// How long each token lasts unless used.
    #[must_use]
    pub fn idle(self) -> Lifetime {
        self.idle
    }

    /// How long a family lasts from its first token.
    #[must_use]
    pub fn family(self) -> Lifetime {
        self.family
    }
}

/// How long each kind of token a client is handed lasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenTerms {
    access: Lifetime,
    id_token: Lifetime,
    refresh: RefreshLifetimes,
}

impl TokenTerms {
    /// Access tokens lasting `access`, ID tokens `id_token`, and refresh
    /// tokens as `refresh` says.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `access` or `id_token` is longer
    ///   than a day.
    pub fn new(
        access: Lifetime,
        id_token: Lifetime,
        refresh: RefreshLifetimes,
    ) -> Result<Self, DomainError> {
        access.ensure_at_most(LONGEST_TOKEN, "an access token")?;
        id_token.ensure_at_most(LONGEST_TOKEN, "an ID token")?;
        Ok(Self {
            access,
            id_token,
            refresh,
        })
    }

    /// How long an access token lasts.
    #[must_use]
    pub fn access(self) -> Lifetime {
        self.access
    }

    /// How long an ID token lasts.
    #[must_use]
    pub fn id_token(self) -> Lifetime {
        self.id_token
    }

    /// How long refresh tokens last.
    #[must_use]
    pub fn refresh(self) -> RefreshLifetimes {
        self.refresh
    }
}

/// Whose terms a client's tokens follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientTokenLifetimes {
    /// The platform's, as the deployment sets them.
    PlatformDefault,
    /// The client's own.
    Own(TokenTerms),
}

impl ClientTokenLifetimes {
    /// The terms the client's tokens get, `platform` being the platform's.
    #[must_use]
    pub fn or_platform(self, platform: TokenTerms) -> TokenTerms {
        match self {
            Self::PlatformDefault => platform,
            Self::Own(terms) => terms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seconds(value: i64) -> Lifetime {
        Lifetime::seconds(value).unwrap()
    }

    /// An hour of idle time and a family of a day.
    fn refresh() -> RefreshLifetimes {
        RefreshLifetimes::new(seconds(3600), seconds(86_400)).unwrap()
    }

    /// An idle time longer than the family, or a family over ninety days,
    /// is refused.
    #[test]
    fn refresh_lifetimes_out_of_order_are_refused() {
        let day = seconds(86_400);
        let hour = seconds(3600);
        let year = seconds(365 * 86_400);

        assert!(RefreshLifetimes::new(day, hour).is_err());
        assert!(RefreshLifetimes::new(hour, year).is_err());
    }

    /// Token terms with a week-long access-token lifetime fail validation
    /// because access tokens are limited to a day.
    #[test]
    fn an_access_token_lives_at_most_a_day() {
        let week = seconds(7 * 86_400);

        let result = TokenTerms::new(week, seconds(300), refresh());

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// The banking app has its own five-minute access tokens; the dashboard
    /// follows the platform's hour.
    #[test]
    fn a_client_follows_its_own_terms_or_the_platforms() {
        let platform = TokenTerms::new(seconds(3600), seconds(3600), refresh()).unwrap();
        let banking = TokenTerms::new(seconds(300), seconds(300), refresh()).unwrap();

        let own = ClientTokenLifetimes::Own(banking).or_platform(platform);
        let default = ClientTokenLifetimes::PlatformDefault.or_platform(platform);

        assert_eq!(own.access(), seconds(300));
        assert_eq!(default.access(), seconds(3600));
    }
}
