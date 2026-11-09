//! Carrying a session on under a new token: a refresh, or handing over a
//! single sign-on once its code is spent.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authentication::events::login::SignInCodeExchanged;
use crate::domains::authentication::events::session::TokenRefreshed;
use crate::domains::authentication::sessions::account_check::SessionCheck;
use crate::domains::authentication::sessions::session::{RotationRefused, Session, SessionOrigin};
use crate::domains::authentication::sessions::sign_in_code::RedeemedSignInCode;
use crate::domains::authentication::sessions::status::SessionStatus;
use crate::isolation::scope::TenantScope;
use crate::shared::events::raised::Raised;
use crate::types::{SessionId, TokenHash};

impl<T: TenantScope> Session<T> {
    /// Replaces and revokes `parent`, linking its successor through `parent_id`.
    /// Preserves expiry, sign-in time, trusted device and credential-change continuity.
    /// Reusing the parent's token afterwards requires revoking all the user's sessions.
    /// Only a parent admitted by `check` can rotate; pending factors, suspension and
    /// account or credential changes cannot be bypassed by refreshing.
    /// Raises `authentication.token_refreshed`, recorded after the successor is saved.
    ///
    /// # Errors
    /// [`RotationRefused::NotUsable`] when [`SessionCheck::admits`] refuses the parent.
    /// [`RotationRefused::Transition`] if revoking the parent fails.
    pub fn rotate(
        parent: &mut Session<T>,
        new_id: SessionId,
        new_refresh_token_hash: TokenHash,
        check: &SessionCheck<'_, T>,
    ) -> Result<Self, RotationRefused> {
        if !check.admits(parent) {
            return Err(RotationRefused::NotUsable);
        }
        let mut child = Self::carried_on(parent, new_id, new_refresh_token_hash, check.now)?;
        child.raised.raise(TokenRefreshed {
            session_id: parent.id,
            new_session_id: child.id,
            occurred_at: check.now,
        });
        Ok(child)
    }

    /// A new session that carries on the sign-in a single sign-on opened,
    /// under a token handed to the person, once `code` was spent for it.
    ///
    /// The provider's sign-in opened a session whose token nobody was shown.
    /// It may still owe a second factor the tenant asks for, and that factor
    /// is answered on the session this hands over. So, unlike
    /// [`rotate`](Self::rotate), this carries on a sign-in that is not
    /// finished. The new session owes what the provider's did, and counts
    /// for nothing until it is answered.
    ///
    /// Only the provider's own session, never carried on before, is handed
    /// over, and only for the code that stands in for it. Mallory holds a
    /// half-finished password sign-in of Ann's. Without these checks, she
    /// would swap it for a fresh token and a fresh window to guess the code.
    /// The rest is held to `check` as a refresh is: the session is active
    /// and in date, the account may still sign in and has not changed how
    /// since, and the sign-in has not sat idle.
    ///
    /// The new session raises `authentication.sign_in_code_exchanged`. It is
    /// recorded only once the new session is kept.
    ///
    /// # Errors
    ///
    /// - [`RotationRefused::NotUsable`] when `code` stands in for another
    ///   session, `parent` was carried on before, or `check` does not hold.
    /// - [`RotationRefused::Transition`] when the parent cannot be revoked.
    pub fn hand_over(
        parent: &mut Session<T>,
        code: &RedeemedSignInCode,
        new_id: SessionId,
        new_refresh_token_hash: TokenHash,
        check: &SessionCheck<'_, T>,
    ) -> Result<Self, RotationRefused> {
        let handed = code.session_id() == &parent.id
            && parent.parent_id == SessionOrigin::SignIn
            && check.admits_unfinished(parent);
        if !handed {
            return Err(RotationRefused::NotUsable);
        }
        let mut child = Self::carried_on(parent, new_id, new_refresh_token_hash, check.now)?;
        child.raised.raise(SignInCodeExchanged {
            user_id: child.user_id,
            occurred_at: check.now,
        });
        Ok(child)
    }

    /// `parent` carried on at `now` as `new_id` under a new token, with its
    /// sign-in, its client and its end. `parent` is retired in the same step.
    fn carried_on(
        parent: &mut Session<T>,
        new_id: SessionId,
        new_refresh_token_hash: TokenHash,
        now: OffsetDateTime,
    ) -> Result<Self, RotationRefused> {
        parent.retire()?;
        Ok(Self {
            id: new_id,
            user_id: parent.user_id,
            refresh_token_hash: new_refresh_token_hash,
            parent_id: SessionOrigin::RotatedFrom(parent.id),
            ip_address: parent.ip_address.clone(),
            user_agent: parent.user_agent.clone(),
            signed_in_from: parent.signed_in_from,
            progress: parent.progress.carried(),
            status: SessionStatus::Active,
            channel: parent.channel,
            signed_in_at: parent.signed_in_at,
            created_at: now,
            last_active_at: now,
            expires_at: parent.expires_at,
            kept_through: parent.kept_through,
            last_use: parent.last_use.clone(),
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }
}
