//! The one-time code that carries a single sign-on back to the dashboard.

use std::marker::PhantomData;

use time::{Duration, OffsetDateTime};

use crate::domains::authentication::sessions::session::Session;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::types::{Lifetime, SessionId, TokenHash, Usage};

/// The longest a sign-in code may live. It covers one redirect.
pub(crate) const SIGN_IN_CODE_LONGEST: Duration = Duration::minutes(5);

/// A one-time code standing in for a session opened by single sign-on.
///
/// After the identity provider answers, the browser is sent back to the
/// dashboard with this code in the address, never the session's token. The
/// dashboard then swaps the code for the token, out of the address bar. Only the
/// code's hash is kept. The code works once and lapses at the end of the
/// short lifetime it was issued with. So a code read later from browser
/// history or a log is of no use.
///
/// It is also bound to the dashboard that started the sign-in. That
/// dashboard keeps a value of its own and shows it again with the code, so
/// a code sent to someone else's browser is of no use to them either:
/// nobody can sign Ann into Mallory's account by handing her Mallory's code.
#[derive(Debug)]
pub struct SignInCode<T: TenantScope> {
    token_hash: TokenHash,
    dashboard_hash: TokenHash,
    session_id: SessionId,
    expires_at: OffsetDateTime,
    usage: Usage,
    _scope: PhantomData<T>,
}

/// Persisted state for repository hydration.
pub struct SignInCodeRow {
    /// One-way hash of the code the browser carries.
    pub token_hash: TokenHash,
    /// One-way hash of the value the dashboard that started the sign-in
    /// keeps.
    pub dashboard_hash: TokenHash,
    /// The session the code stands in for.
    pub session_id: SessionId,
    /// When the code lapses.
    pub expires_at: OffsetDateTime,
    /// Whether the code was swapped for its session, and when.
    pub usage: Usage,
}

/// Who a sign-in code is for: whoever holds the code, from the dashboard
/// that started the sign-in.
pub struct CodeHolders {
    /// One-way hash of the code the browser carries.
    pub code: TokenHash,
    /// One-way hash of the value the dashboard that started the sign-in
    /// keeps.
    pub dashboard: TokenHash,
}

impl<T: TenantScope> SignInCode<T> {
    /// Stands in for `session`, for whoever holds the code `holders` names
    /// and shows the dashboard's value with it.
    ///
    /// The session may still owe a second factor, which the dashboard then
    /// asks for. It must be active and in date. A code for a suspended,
    /// revoked or expired session would carry nothing anyone may use.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the session is not active or has
    ///   expired.
    /// - [`DomainError::Validation`] when `lifetime` is longer than
    ///   `SIGN_IN_CODE_LONGEST`.
    pub fn issue(
        session: &Session<T>,
        holders: CodeHolders,
        lifetime: Lifetime,
    ) -> Result<Self, DomainError> {
        let now = crate::shared::clock::now();
        if !session.status().is_active() || session.is_expired(now) {
            return Err(DomainError::forbidden(message!(
                "authentication-a-sign-in-code-stands-in",
                "a sign-in code stands in only for a live session"
            )));
        }
        lifetime.ensure_at_most(SIGN_IN_CODE_LONGEST, "a sign-in code")?;
        Ok(Self {
            token_hash: holders.code,
            dashboard_hash: holders.dashboard,
            session_id: *session.id(),
            expires_at: lifetime.ends_after(now),
            usage: Usage::Unused,
            _scope: PhantomData,
        })
    }

    /// Rebuilds a sign-in code from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the code was used
    ///   at or after it lapsed.
    pub fn reconstitute(row: SignInCodeRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            token_hash: row.token_hash,
            dashboard_hash: row.dashboard_hash,
            session_id: row.session_id,
            expires_at: row.expires_at,
            usage: row.usage,
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &SignInCodeRow) -> Result<(), DomainError> {
        RowCheck::of("sign-in code")
            .holds(
                row.usage.used_at().is_none_or(|at| at < row.expires_at),
                "used after it lapsed",
            )
            .finish()
    }

    /// One-way hash of the code the browser carries.
    #[must_use]
    pub fn token_hash(&self) -> &TokenHash {
        &self.token_hash
    }

    /// One-way hash of the value the dashboard that started the sign-in
    /// keeps.
    #[must_use]
    pub fn dashboard_hash(&self) -> &TokenHash {
        &self.dashboard_hash
    }

    /// The session the code stands in for.
    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// When the code lapses.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// When the code was swapped for its session, if it has been.
    #[must_use]
    pub fn consumed_at(&self) -> Option<OffsetDateTime> {
        self.usage.used_at()
    }

    /// Whether the code, still unused, is good at `now`.
    #[must_use]
    pub fn is_live_at(&self, now: OffsetDateTime) -> bool {
        !self.usage.is_used() && now < self.expires_at
    }

    /// Spends the code at `now` for the dashboard whose value hashes to
    /// `dashboard`, and gives back the session it stands in for. This is the
    /// only way it is used.
    ///
    /// A refused code is left as it was.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the code was used already or has
    ///   lapsed, or the dashboard is not the one that started the sign-in.
    pub fn redeem(
        &mut self,
        now: OffsetDateTime,
        dashboard: &TokenHash,
    ) -> Result<RedeemedSignInCode, DomainError> {
        if *dashboard != self.dashboard_hash {
            return Err(DomainError::forbidden(message!(
                "authentication-this-sign-in-was-started-in",
                "this sign-in was started in another browser"
            )));
        }
        if !self.is_live_at(now) {
            return Err(DomainError::forbidden(message!(
                "authentication-the-sign-in-code-is-spent",
                "the sign-in code is spent or lapsed"
            )));
        }
        self.usage = Usage::Used { at: now };
        Ok(RedeemedSignInCode {
            session_id: self.session_id,
        })
    }
}

/// A sign-in code spent just now, naming the session it stands in for.
///
/// Only [`SignInCode::redeem`] makes one. It is what lets
/// [`Session::hand_over`] carry on a single sign-on that still owes a
/// second factor. It is neither `Clone` nor `Copy`, so one code hands over
/// one session.
#[derive(Debug, PartialEq, Eq)]
pub struct RedeemedSignInCode {
    session_id: SessionId,
}

impl RedeemedSignInCode {
    /// The session the code stood in for.
    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::sessions::session::tests::{holder_of, test_session};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;

    fn code_for(
        session: &Session<ResolvedTenant>,
        lifetime: Duration,
    ) -> Result<SignInCode<ResolvedTenant>, DomainError> {
        SignInCode::issue(
            session,
            CodeHolders {
                code: TokenHash::from_stored("hash".to_owned()),
                dashboard: dashboard(),
            },
            Lifetime::new(lifetime).unwrap(),
        )
    }

    /// The hash of the value Ann's dashboard keeps.
    fn dashboard() -> TokenHash {
        TokenHash::from_stored("dashboard".to_owned())
    }

    fn code() -> SignInCode<ResolvedTenant> {
        code_for(&test_session(), Duration::seconds(60)).unwrap()
    }

    /// Ann comes back from single sign-on still owing her code. The sign-in
    /// code stands in for her session, which asks for the code next.
    #[test]
    fn a_code_stands_in_for_a_session_still_owing_a_factor() {
        let session = test_session();

        let code = code_for(&session, Duration::seconds(60)).unwrap();

        assert_eq!(code.session_id(), session.id());
    }

    /// A revoked session cannot issue a sign-in code.
    #[test]
    fn no_code_stands_in_for_a_revoked_session() {
        let mut session = test_session();
        session.revoke(&holder_of(&session)).unwrap();

        assert!(matches!(
            code_for(&session, Duration::seconds(60)),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A sign-in code asked to live for an hour is refused. Five minutes is
    /// the most, enough for one redirect.
    #[test]
    fn a_sign_in_code_lives_at_most_five_minutes() {
        assert!(matches!(
            code_for(&test_session(), Duration::hours(1)),
            Err(DomainError::Validation(_))
        ));
    }

    /// Ann comes back from her identity provider with a fresh code. It is
    /// still good.
    #[test]
    fn a_fresh_code_is_live() {
        assert!(code().is_live_at(crate::shared::clock::now()));
    }

    /// A code with a sixty-second lifetime is no longer live after sixty-one seconds.
    #[test]
    fn a_code_lapses_after_a_minute() {
        let later = crate::shared::clock::now() + Duration::seconds(61);

        assert!(!code().is_live_at(later));
    }

    /// Redemption returns the code's session and records its use time.
    /// Reusing it one second later is refused.
    #[test]
    fn a_sign_in_code_works_once() {
        let mut code = code();
        let now = crate::shared::clock::now();

        let swapped = code.redeem(now, &dashboard()).unwrap();
        let replayed = code.redeem(now + Duration::seconds(1), &dashboard());

        assert_eq!(swapped.session_id(), code.session_id());
        assert!(matches!(replayed, Err(DomainError::Forbidden(_))));
        assert_eq!(code.consumed_at(), Some(now));
    }

    /// A code tried after it lapsed is refused and stays unspent.
    #[test]
    fn a_lapsed_code_is_refused_and_left_unspent() {
        let mut code = code();
        let later = crate::shared::clock::now() + Duration::seconds(61);

        assert!(matches!(
            code.redeem(later, &dashboard()),
            Err(DomainError::Forbidden(_))
        ));
        assert_eq!(code.consumed_at(), None);
    }

    /// A code presented with another browser's binding is refused and left unspent.
    #[test]
    fn a_code_from_another_browser_is_refused_and_left_unspent() {
        let mut code = code();
        let anns_dashboard = TokenHash::from_stored("someone else".to_owned());

        let result = code.redeem(crate::shared::clock::now(), &anns_dashboard);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(code.consumed_at(), None);
    }

    /// A stored code says it was used after it lapsed. Nothing spends a
    /// lapsed code, so loading it is refused as a corrupt row.
    #[test]
    fn a_stored_code_used_after_it_lapsed_is_refused() {
        let expires_at = crate::shared::clock::now();

        let stored = SignInCode::<ResolvedTenant>::reconstitute(SignInCodeRow {
            token_hash: TokenHash::from_stored("hash".to_owned()),
            dashboard_hash: dashboard(),
            session_id: SessionId::new(),
            expires_at,
            usage: Usage::Used {
                at: expires_at + Duration::seconds(1),
            },
        });

        assert!(refused_as_corrupt(&stored));
    }
}
