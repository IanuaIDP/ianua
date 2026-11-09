//! Apps registering themselves as OAuth clients (RFC 7591) and managing
//! their own registration afterwards (RFC 7592).
//!
//! Nobody registers without an initial access token the tenant handed out:
//! an open registration endpoint would let anyone put a consent screen in
//! the tenant's name in front of its people. The token is limited in time
//! and uses. A client registered this way holds a registration access token
//! of its own, with which it reads, changes or deletes its registration,
//! and nothing else.
//!
//! What it registers is held to more than an admin's client: it asks
//! people for consent like any third party, and it never acts as itself,
//! since nobody checked who runs it.

use std::marker::PhantomData;

use time::{Duration, OffsetDateTime};

use crate::domains::oauth::clients::client::{GrantType, NewOAuthClient, OAuthClientChange};
use crate::domains::oauth::clients::rules::acts_as_itself;
use crate::domains::oauth::clients::settings::{ClientSettings, ConsentPrompt, SettingsChange};
use crate::domains::oauth::control::{OAuthControl, OAuthRight};
use crate::domains::oauth::events::clients::{InitialAccessTokenIssued, InitialAccessTokenRevoked};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::numeric::validate_range;
use crate::types::{InitialAccessTokenId, Label, Lifetime, OAuthClientId, Revocation, TokenHash};

/// The most registrations one initial access token allows.
const MOST_USES: u32 = 1000;

/// The longest an initial access token lives: thirty days.
const LONGEST_LIFETIME: Duration = Duration::days(30);

/// A token the tenant hands out so apps may register themselves as
/// clients: a set number of times, until it expires or is revoked.
///
/// Only its hash is kept; the raw token is shown once.
#[derive(Debug)]
pub struct InitialAccessToken<T: TenantScope> {
    id: InitialAccessTokenId,
    name: Label,
    token_hash: TokenHash,
    uses_left: u32,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    revocation: Revocation,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// What an initial access token is issued with.
pub struct NewInitialAccessToken {
    /// The caller-selected identity used to track registrations and revoke further use.
    pub id: InitialAccessTokenId,
    /// What it is for, such as `"MCP clients"`.
    pub name: Label,
    /// The hash of the raw token.
    pub token_hash: TokenHash,
    /// How many apps may register with it, from 1 to 1000.
    pub uses: u32,
    /// How long it works, at most thirty days.
    pub lifetime: Lifetime,
}

/// An initial access token as storage keeps it, checked again by
/// [`InitialAccessToken::reconstitute`].
pub struct InitialAccessTokenRow {
    /// The persisted identity tying remaining registrations to this credential.
    pub id: InitialAccessTokenId,
    /// What it is for.
    pub name: Label,
    /// The hash of the raw token.
    pub token_hash: TokenHash,
    /// How many registrations it still allows.
    pub uses_left: u32,
    /// When it was issued.
    pub created_at: OffsetDateTime,
    /// When it stops working.
    pub expires_at: OffsetDateTime,
    /// Whether it was revoked, and when.
    pub revocation: Revocation,
}

impl<T: TenantScope> InitialAccessToken<T> {
    /// Issues a token, as `control` allows. Raises
    /// `oauth.initial_access_token_issued`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not create clients.
    /// - [`DomainError::Validation`] when it allows no use or more than a
    ///   thousand, or lives longer than thirty days.
    pub fn issue(
        new: NewInitialAccessToken,
        control: &OAuthControl<'_>,
    ) -> Result<Self, DomainError> {
        control.ensure_may(OAuthRight::Create)?;
        validate_range("uses", new.uses, 1..=MOST_USES)?;
        new.lifetime
            .ensure_at_most(LONGEST_LIFETIME, "an initial access token")?;
        let now = crate::shared::clock::now();
        let mut token = Self {
            id: new.id,
            name: new.name,
            token_hash: new.token_hash,
            uses_left: new.uses,
            created_at: now,
            expires_at: new.lifetime.ends_after(now),
            revocation: Revocation::InForce,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        token.raised.raise(InitialAccessTokenIssued {
            token_id: token.id,
            name: token.name.clone(),
            occurred_at: now,
        });
        Ok(token)
    }

    /// Rebuilds a token from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row expires before it was
    ///   issued, was revoked before it was issued, or allows more than a
    ///   thousand uses.
    pub fn reconstitute(row: InitialAccessTokenRow) -> Result<Self, DomainError> {
        RowCheck::of("initial access token")
            .holds(
                row.created_at < row.expires_at,
                "expires before it was issued",
            )
            .in_order_if(
                row.created_at,
                row.revocation.revoked_at(),
                "revoked before it was issued",
            )
            .holds(
                row.uses_left <= MOST_USES,
                "allows more than a thousand uses",
            )
            .finish()?;
        Ok(Self {
            id: row.id,
            name: row.name,
            token_hash: row.token_hash,
            uses_left: row.uses_left,
            created_at: row.created_at,
            expires_at: row.expires_at,
            revocation: row.revocation,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The stable identity used to look up or revoke this registration credential.
    #[must_use]
    pub fn id(&self) -> &InitialAccessTokenId {
        &self.id
    }

    /// What it is for.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// The hash a presented token is found by.
    #[must_use]
    pub fn token_hash(&self) -> &TokenHash {
        &self.token_hash
    }

    /// How many registrations it still allows.
    #[must_use]
    pub fn uses_left(&self) -> u32 {
        self.uses_left
    }

    /// When it was issued.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When it stops working.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// Whether it was revoked, and when.
    #[must_use]
    pub fn revocation(&self) -> Revocation {
        self.revocation
    }

    /// Spends one use at `now`, for an app registering with the token, and
    /// hands the admission [`OAuthClient::register`](crate::domains::oauth::clients::client::OAuthClient::register)
    /// takes.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Unauthorized`] when it was revoked, has expired or
    ///   has no use left.
    pub fn admit(&mut self, now: OffsetDateTime) -> Result<RegistrationAdmission, DomainError> {
        let spent = self.revocation.is_revoked() || now >= self.expires_at || self.uses_left == 0;
        if spent {
            return Err(DomainError::unauthorized(message!(
                "oauth-this-initial-access-token-no-longer",
                "this initial access token no longer registers clients"
            )));
        }
        self.uses_left = self.uses_left.saturating_sub(1);
        Ok(RegistrationAdmission { token: self.id })
    }

    /// Revokes the token for good, as `control` allows. Raises
    /// `oauth.initial_access_token_revoked`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not revoke clients.
    /// - [`DomainError::InvalidTransition`] when it was revoked already.
    pub fn revoke(&mut self, control: &OAuthControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(OAuthRight::Revoke)?;
        if self.revocation.is_revoked() {
            return Err(DomainError::invalid_transition(message!(
                "oauth-this-initial-access-token-was-revoked",
                "this initial access token was revoked already"
            )));
        }
        let now = crate::shared::clock::now();
        self.revocation = Revocation::Revoked { at: now };
        self.raised.raise(InitialAccessTokenRevoked {
            token_id: self.id,
            name: self.name.clone(),
            occurred_at: now,
        });
        Ok(())
    }
}

impl<T: TenantScope> Raises for InitialAccessToken<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// Proof that an app presented a working initial access token, and spent
/// one of its uses. Only [`InitialAccessToken::admit`] makes one.
#[derive(Debug)]
pub struct RegistrationAdmission {
    token: InitialAccessTokenId,
}

impl RegistrationAdmission {
    /// Consumes this admission and names the initial access token it spent.
    #[must_use]
    pub(super) fn into_token(self) -> InitialAccessTokenId {
        self.token
    }
}

/// Everything an app registers itself with (RFC 7591 2), once the caller
/// generated its ids, its registration access token and, for a client
/// holding one, its secret.
pub struct ClientRegistration {
    /// The client as it asked to be registered: its credential from
    /// `token_endpoint_auth_method` and its keys or generated secret, and
    /// the rest of its metadata.
    pub client: NewOAuthClient,
    /// The hash of the registration access token handed back to it.
    pub registration_token: TokenHash,
}

/// Who manages a client's registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientManagement {
    /// The tenant's admins alone.
    ByAdmins,
    /// The client itself too, with its registration access token (RFC
    /// 7592). The admins still may.
    ByItself {
        /// The hash of its registration access token.
        registration_token: TokenHash,
        /// The initial access token it registered with, so the clients
        /// registered with a leaked one can be found.
        admitted_with: InitialAccessTokenId,
    },
}

impl ClientManagement {
    /// Whether `presented` is the registration access token of a client
    /// that manages itself. A client the admins registered has none.
    #[must_use]
    pub fn admits(&self, presented: &TokenHash) -> bool {
        matches!(
            self,
            Self::ByItself { registration_token, .. } if registration_token == presented
        )
    }
}

/// Proof that a request came from a self-registered client holding its
/// registration access token. Only
/// [`OAuthClient::managed_by_itself`](crate::domains::oauth::clients::client::OAuthClient::managed_by_itself)
/// makes one.
#[derive(Debug)]
pub struct SelfManagement {
    client: OAuthClientId,
}

impl SelfManagement {
    /// The proof for `client`, once its registration access token matched.
    pub(crate) fn of(client: OAuthClientId) -> Self {
        Self { client }
    }

    /// The client it proves.
    #[must_use]
    pub fn client(&self) -> &OAuthClientId {
        &self.client
    }
}

/// Refuses what no app may register for itself: skipping consent, or
/// grants on which it acts as itself.
pub(crate) fn ensure_self_registrable(
    grant_types: &[GrantType],
    settings: &ClientSettings,
) -> Result<(), DomainError> {
    ensure_asks_consent(settings.consent)?;
    if acts_as_itself(grant_types) {
        return Err(DomainError::forbidden(message!(
            "oauth-an-app-registering-itself-may-not",
            "an app registering itself may not act as itself; an admin registers machine clients"
        )));
    }
    Ok(())
}

/// Refuses a change no client may make to itself: making itself
/// first-party.
pub(crate) fn ensure_self_change(change: &OAuthClientChange) -> Result<(), DomainError> {
    let OAuthClientChange::Settings(setting) = change else {
        return Ok(());
    };
    let SettingsChange::Consent(consent) = setting.as_ref() else {
        return Ok(());
    };
    ensure_asks_consent(*consent)
}

/// Refuses a first-party setting from anyone but an admin.
fn ensure_asks_consent(consent: ConsentPrompt) -> Result<(), DomainError> {
    match consent {
        ConsentPrompt::AskPerson => Ok(()),
        ConsentPrompt::FirstParty => Err(DomainError::forbidden(message!(
            "oauth-only-an-admin-makes-a-client",
            "only an admin makes a client first-party, so people are not asked to consent"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::{ApiKeyAction, SystemPermission};
    use crate::domains::oauth::control::tests::{holding, key_admin};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::builders::label;
    use crate::test_support::events::raised_names;

    /// A token for `uses` registrations over a day.
    fn new_token(uses: u32) -> NewInitialAccessToken {
        NewInitialAccessToken {
            id: InitialAccessTokenId::new(),
            name: label("MCP clients"),
            token_hash: TokenHash::from_stored("iat-hash".to_owned()),
            uses,
            lifetime: Lifetime::seconds(86_400).unwrap(),
        }
    }

    /// A token for `uses` registrations, issued by an admin.
    fn issued(uses: u32) -> InitialAccessToken<ResolvedTenant> {
        InitialAccessToken::issue(new_token(uses), &key_admin()).unwrap()
    }

    /// A caller with only viewing permission cannot issue an initial access
    /// token. The issuance is forbidden.
    #[test]
    fn a_token_is_issued_only_with_the_right_to_create_clients() {
        let sam = holding(&[SystemPermission::ApiKeys(ApiKeyAction::View)]);

        let result = InitialAccessToken::<ResolvedTenant>::issue(new_token(5), &sam);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A token for two registrations admits two apps, then refuses the
    /// third.
    #[test]
    fn a_token_admits_as_many_apps_as_it_allows() {
        let mut token = issued(2);
        let now = crate::shared::clock::now();

        assert!(token.admit(now).is_ok());
        assert!(token.admit(now).is_ok());
        assert!(matches!(
            token.admit(now),
            Err(DomainError::Unauthorized(_))
        ));
    }

    /// An initial access token rejects admission at its expiry instant.
    /// A revoked token also rejects admission as unauthorized.
    #[test]
    fn an_expired_or_revoked_token_admits_nobody() {
        let mut expired = issued(5);
        let mut revoked = issued(5);
        revoked.revoke(&key_admin()).unwrap();

        let late = expired.admit(expired.expires_at());
        let after_revoke = revoked.admit(crate::shared::clock::now());

        assert!(matches!(late, Err(DomainError::Unauthorized(_))));
        assert!(matches!(after_revoke, Err(DomainError::Unauthorized(_))));
    }

    /// A token for no registrations, or for more than a thousand, is
    /// refused.
    #[test]
    fn a_token_allows_one_to_a_thousand_uses() {
        let none = InitialAccessToken::<ResolvedTenant>::issue(new_token(0), &key_admin());
        let many = InitialAccessToken::<ResolvedTenant>::issue(new_token(1001), &key_admin());

        assert!(matches!(none, Err(DomainError::Validation(_))));
        assert!(matches!(many, Err(DomainError::Validation(_))));
    }

    /// Issuing and revoking a token are raised for the audit trail.
    #[test]
    fn issuing_and_revoking_are_raised() {
        let mut token = issued(5);
        token.revoke(&key_admin()).unwrap();

        assert_eq!(
            raised_names(&mut token),
            [
                "oauth.initial_access_token_issued",
                "oauth.initial_access_token_revoked"
            ]
        );
    }

    /// A stored token allowing more than a thousand uses is refused as
    /// corrupt.
    #[test]
    fn a_stored_token_with_too_many_uses_is_refused() {
        let token = issued(5);
        let row = InitialAccessTokenRow {
            id: token.id,
            name: token.name.clone(),
            token_hash: token.token_hash.clone(),
            uses_left: MOST_USES + 1,
            created_at: token.created_at,
            expires_at: token.expires_at,
            revocation: Revocation::InForce,
        };

        assert!(refused_as_corrupt(
            &InitialAccessToken::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// Self-registration forbids first-party consent settings and client
    /// credentials. Authorization-code registration with consent remains valid.
    #[test]
    fn an_app_cannot_register_itself_as_first_party_or_as_a_machine() {
        let first_party = ClientSettings {
            consent: ConsentPrompt::FirstParty,
            ..ClientSettings::platform_defaults()
        };
        let defaults = ClientSettings::platform_defaults();

        let skipped = ensure_self_registrable(&[GrantType::AuthorizationCode], &first_party);
        let machine = ensure_self_registrable(&[GrantType::ClientCredentials], &defaults);

        assert!(matches!(skipped, Err(DomainError::Forbidden(_))));
        assert!(matches!(machine, Err(DomainError::Forbidden(_))));
        assert!(ensure_self_registrable(&[GrantType::AuthorizationCode], &defaults).is_ok());
    }
}
