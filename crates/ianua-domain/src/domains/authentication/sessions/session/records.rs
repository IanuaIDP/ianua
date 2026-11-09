//! What a session raises for the audit trail, beside its own changes: the
//! sign-in it opened, a factor it took, a token issued under it, a theft of
//! its token, and the end of it.

use time::OffsetDateTime;

use crate::domains::authentication::events::app_session::AppTokenIssued;
use crate::domains::authentication::events::login::LoginSucceeded;
use crate::domains::authentication::events::mfa::MfaVerified;
use crate::domains::authentication::events::session::{RevocationReason, SessionRevoked};
use crate::domains::authentication::sessions::session::Session;
use crate::isolation::scope::TenantScope;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raises, SavedFor};
use crate::types::{EventLabel, Fact, Label, ServiceId};

impl<T: TenantScope> Session<T> {
    /// Records that this session's refresh token came back after it was
    /// swapped, so a copy of it is in someone else's hands. Raises
    /// `authentication.session_revoked` for token theft, naming the holder
    /// as `holder_label`, since the platform ends their sessions, not they.
    ///
    /// Nothing about this session changes: it was retired when its token
    /// was swapped. Every session of its holder ends with it, in storage.
    pub fn record_token_theft(&mut self, holder_label: EventLabel) {
        self.raised.raise(SessionRevoked {
            session_id: self.id,
            user_id: self.user_id,
            user_label: Some(holder_label),
            reason: RevocationReason::TokenTheft,
            occurred_at: crate::shared::clock::now(),
        });
    }

    /// Raises the end of this session because its holder's account was shut
    /// out, naming the holder as `holder_label`: the record's actor is the
    /// one who shut the account out.
    pub(super) fn raise_ended_with_account(&mut self, holder_label: EventLabel) {
        self.raised.raise(SessionRevoked {
            session_id: self.id,
            user_id: self.user_id,
            user_label: Some(holder_label),
            reason: RevocationReason::AccountStateChange,
            occurred_at: crate::shared::clock::now(),
        });
    }

    /// Raises the end of this session, for `reason`, by its holder or an
    /// admin, who is the record's actor and so is not named again.
    pub(super) fn raise_ended(&mut self, reason: RevocationReason) {
        self.raised.raise(SessionRevoked {
            session_id: self.id,
            user_id: self.user_id,
            user_label: None,
            reason,
            occurred_at: crate::shared::clock::now(),
        });
    }

    /// Records that the sign-in which opened this session succeeded, after
    /// `auth_duration_ms`, as the application timed it. Raises
    /// `authentication.login_succeeded` with how the person signed in and
    /// from where.
    ///
    /// Nothing about the session changes. Each way of signing in asks for
    /// it once the session it opened is kept.
    pub fn record_sign_in(&mut self, auth_duration_ms: Fact<u32>) {
        self.raised.raise(LoginSucceeded {
            session_id: self.id,
            auth_method: self.auth_method(),
            ip_address: self.ip_address.clone(),
            auth_duration_ms,
            occurred_at: crate::shared::clock::now(),
        });
    }

    /// Records that a short-lived token was issued under this session for
    /// the service `service` names, as `service_name`, lapsing at
    /// `expires_at`. Raises `authentication.app_token_issued`.
    ///
    /// Nothing about the session changes. The token is made outside the
    /// domain and never recorded.
    pub fn record_app_token(
        &mut self,
        service: &ServiceId,
        service_name: &Label,
        expires_at: OffsetDateTime,
    ) {
        self.raised.raise(AppTokenIssued {
            session_id: self.id,
            service_id: *service,
            service_name: service_name.clone(),
            expires_at,
            occurred_at: crate::shared::clock::now(),
        });
    }

    /// Records that the holder proved a second factor on this session.
    /// Raises `authentication.mfa_verified`.
    ///
    /// Nothing about the session changes: [`answer`](Self::answer) took the
    /// factor. A sign-in that proves its factor as part of signing in, such
    /// as a passkey, is recorded as the sign-in instead.
    pub fn record_factor_verified(&mut self) {
        let assurance = self.assurance_level();
        self.raised.raise(MfaVerified {
            session_id: self.id,
            assurance,
            occurred_at: crate::shared::clock::now(),
        });
    }
}

impl<T: TenantScope> Raises for Session<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}
