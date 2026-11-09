//! The grant an ID token is issued for: a code just swapped, a refresh
//! carrying a grant on (OpenID Connect Core 12.2), or a device approval
//! just collected.
//!
//! Each says whom the token is about, the scopes the person granted, how
//! they signed in when that is known, the session the grant was given in,
//! and the nonce, which only a code carries. None of it is written by the
//! caller: a token refreshed long after the sign-in states the sign-in its
//! session recorded, or none, never one a use case made up.

use time::OffsetDateTime;

use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
use crate::domains::authentication::sessions::session::Session;
use crate::domains::identity::account::user::User;
use crate::domains::oauth::clients::client::OAuthClient;
use crate::domains::oauth::grants::authorization_code::{AuthorizationCode, NonceSent};
use crate::domains::oauth::grants::device_authorization::DeviceAuthorization;
use crate::domains::oauth::grants::id_token::{AuthMethodReference, amr_for};
use crate::domains::oauth::grants::jwt_access_token::SignInFacts;
use crate::domains::oauth::grants::refresh_token::{GrantedIn, NextRefresh};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{OAuthClientId, Scope, SessionId, UserId};

/// The grant an ID token is issued for.
pub enum IdTokenGrant<'a, T: TenantScope> {
    /// A code the client just swapped: the sign-in it was consented in, its
    /// session and its nonce.
    Code(&'a AuthorizationCode<T>),
    /// A refresh carrying a grant on, with the session the grant was given
    /// in as the store has it. It carries no nonce.
    Refresh {
        /// What the refresh hands on.
        next: &'a NextRefresh,
        /// The session the grant was given in.
        session: GrantSession<'a, T>,
    },
    /// A device approval the client just collected. There is no session to
    /// name and no nonce, and the sign-in on the second screen is not at
    /// hand.
    Device(&'a DeviceAuthorization<T>),
}

/// The session a refreshed grant was given in, as the store has it.
pub enum GrantSession<'a, T: TenantScope> {
    /// It is kept: the token states the sign-in it recorded.
    Kept(&'a Session<T>),
    /// It is no longer kept, or the grant was given on a device: the token
    /// states no sign-in.
    NotKept,
}

/// How the person behind an ID token signed in, and the session the grant
/// was given in, as the token states them.
#[derive(Debug, Clone)]
pub struct StatedSignIn {
    /// `auth_time`, `acr`, `amr` and `aal`, when the sign-in is known.
    pub(crate) facts: SignInFacts,
    /// `sid`, when the grant was given in a session.
    pub(crate) granted_in: GrantedIn,
}

/// What an ID token states about its grant.
pub(crate) struct StatedGrant<'a> {
    /// `sub`.
    pub(crate) subject: UserId,
    /// The scopes the person granted.
    pub(crate) scopes: &'a [Scope],
    /// How they signed in, and where.
    pub(crate) sign_in: StatedSignIn,
    /// The nonce the request sent.
    pub(crate) nonce: NonceSent,
}

impl<'a, T: TenantScope> IdTokenGrant<'a, T> {
    /// What the grant states, for an ID token to `client` about `account`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when a code was not swapped yet, or a
    ///   device approval not collected.
    /// - [`DomainError::Forbidden`] when the grant went to another client
    ///   or is for another account.
    /// - [`DomainError::Forbidden`] when a refresh names a session other
    ///   than the one its grant was given in.
    pub(crate) fn stated(
        self,
        client: &OAuthClient<T>,
        account: &User<T>,
    ) -> Result<StatedGrant<'a>, DomainError> {
        let holder = TokenHolder { client, account };
        match self {
            Self::Code(code) => from_code(code, &holder),
            Self::Refresh { next, session } => from_refresh(next, &session, &holder),
            Self::Device(device) => from_device(device, &holder),
        }
    }
}

/// The client an ID token goes to and the account it is about.
struct TokenHolder<'h, T: TenantScope> {
    client: &'h OAuthClient<T>,
    account: &'h User<T>,
}

/// Refuses a grant given to another client or for another account.
fn ensure_held_by<T: TenantScope>(
    holder: &TokenHolder<'_, T>,
    client_id: &OAuthClientId,
    user_id: &UserId,
) -> Result<(), DomainError> {
    if client_id != holder.client.id() {
        return Err(DomainError::forbidden(message!(
            "oauth-the-grant-was-issued-to-another",
            "the grant was issued to another client"
        )));
    }
    if user_id != holder.account.id() {
        return Err(DomainError::forbidden(message!(
            "oauth-the-grant-was-issued-for-another",
            "the grant was issued for another account"
        )));
    }
    Ok(())
}

/// What a swapped code states.
fn from_code<'a, T: TenantScope>(
    code: &'a AuthorizationCode<T>,
    holder: &TokenHolder<'_, T>,
) -> Result<StatedGrant<'a>, DomainError> {
    if !code.is_consumed() {
        return Err(DomainError::forbidden(message!(
            "oauth-an-id-token-comes-only-from",
            "an ID token comes only from a code swapped for tokens"
        )));
    }
    ensure_held_by(holder, code.client_id(), code.user_id())?;
    Ok(StatedGrant {
        subject: *code.user_id(),
        scopes: code.scopes(),
        sign_in: StatedSignIn {
            facts: SignInFacts::of_code(code),
            granted_in: GrantedIn::Session(*code.session_id()),
        },
        nonce: code.nonce().clone(),
    })
}

/// What a refresh states: the sign-in of the session its grant was given
/// in, while that is kept.
fn from_refresh<'a, T: TenantScope>(
    next: &'a NextRefresh,
    session: &GrantSession<'_, T>,
    holder: &TokenHolder<'_, T>,
) -> Result<StatedGrant<'a>, DomainError> {
    ensure_held_by(holder, next.client_id(), next.user_id())?;
    Ok(StatedGrant {
        subject: *next.user_id(),
        scopes: next.scopes(),
        sign_in: StatedSignIn {
            facts: refreshed_sign_in(next, session)?,
            granted_in: next.granted_in(),
        },
        nonce: NonceSent::NotSent,
    })
}

/// The sign-in `session` recorded, when it is the one `next`'s grant was
/// given in.
fn refreshed_sign_in<T: TenantScope>(
    next: &NextRefresh,
    session: &GrantSession<'_, T>,
) -> Result<SignInFacts, DomainError> {
    let GrantSession::Kept(session) = session else {
        return Ok(SignInFacts::NotStated);
    };
    let same = next.granted_in() == GrantedIn::Session(*session.id())
        && session.user_id() == next.user_id();
    if !same {
        return Err(DomainError::forbidden(message!(
            "oauth-the-session-is-not-the-one",
            "the session is not the one the grant was given in"
        )));
    }
    let progress = session.progress();
    Ok(SignInFacts::Stated {
        auth_time: session.signed_in_at(),
        assurance: session.assurance_level(),
        amr: amr_for(progress.method(), progress.factor()),
    })
}

/// What a collected device approval states.
fn from_device<'a, T: TenantScope>(
    device: &'a DeviceAuthorization<T>,
    holder: &TokenHolder<'_, T>,
) -> Result<StatedGrant<'a>, DomainError> {
    let Some(collected_by) = device.collected_by() else {
        return Err(DomainError::forbidden(message!(
            "oauth-an-id-token-follows-a-device",
            "an ID token follows a device approval only once it was collected"
        )));
    };
    ensure_held_by(holder, device.client_id(), collected_by)?;
    Ok(StatedGrant {
        subject: *collected_by,
        scopes: device.scopes(),
        sign_in: StatedSignIn {
            facts: SignInFacts::NotStated,
            granted_in: GrantedIn::DeviceApproval,
        },
        nonce: NonceSent::NotSent,
    })
}

impl StatedSignIn {
    /// How the person signed in, when that is known.
    #[must_use]
    pub fn facts(&self) -> &SignInFacts {
        &self.facts
    }

    /// The session the grant was given in, named as `sid`, if any.
    #[must_use]
    pub fn session(&self) -> Option<&SessionId> {
        self.granted_in.session()
    }

    /// When the person signed in (`auth_time`), when that is known: the
    /// sign-in itself, never the time the token was issued.
    #[must_use]
    pub fn auth_time(&self) -> Option<OffsetDateTime> {
        match &self.facts {
            SignInFacts::Stated { auth_time, .. } => Some(*auth_time),
            SignInFacts::NotStated => None,
        }
    }

    /// The assurance the sign-in reached, when it is known. It is written
    /// as `acr` and as `aal`, which is no standard claim: the platform's own
    /// proxy reads it instead of working it out from `amr`.
    #[must_use]
    pub fn assurance(&self) -> Option<AssuranceLevel> {
        match &self.facts {
            SignInFacts::Stated { assurance, .. } => Some(*assurance),
            SignInFacts::NotStated => None,
        }
    }

    /// How the person proved who they are, as RFC 8176 Authentication
    /// Methods References: the first method and the second factor the
    /// session recorded. Empty when that is not known.
    #[must_use]
    pub fn amr(&self) -> &[AuthMethodReference] {
        match &self.facts {
            SignInFacts::Stated { amr, .. } => amr,
            SignInFacts::NotStated => &[],
        }
    }
}

#[cfg(feature = "serde")]
mod json {
    //! The JSON an ID token's sign-in is written as, inside its claims.

    use serde::ser::{Serialize, SerializeMap, Serializer};

    use crate::domains::oauth::grants::id_token_grant::StatedSignIn;
    use crate::domains::oauth::grants::jwt_access_token::SignInFacts;

    impl Serialize for StatedSignIn {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut map = serializer.serialize_map(None)?;
            if let SignInFacts::Stated {
                auth_time,
                assurance,
                amr,
            } = &self.facts
            {
                map.serialize_entry("auth_time", &auth_time.unix_timestamp())?;
                map.serialize_entry("acr", assurance.acr())?;
                map.serialize_entry("amr", amr)?;
                map.serialize_entry("aal", assurance)?;
            }
            if let Some(session) = self.granted_in.session() {
                map.serialize_entry("sid", session)?;
            }
            map.end()
        }
    }
}
