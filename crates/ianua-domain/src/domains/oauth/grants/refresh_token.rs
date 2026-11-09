//! Refresh tokens: what a client keeps to get new access tokens without the
//! person signing in again.
//!
//! Each refresh token works once. Using it hands out the next one, in the
//! same family, and retires it (rotation). Only one copy should ever exist,
//! so a retired token presented again means someone else holds a copy:
//! the whole family is revoked, the thief's copy and the person's alike
//! (OAuth 2.1 4.3.1, the OAuth security best practice 4.14).
//!
//! A public client proves nothing when it refreshes, so its tokens are
//! bound to the `DPoP` key it proved when the family began (RFC 9449 5): a
//! copied token is useless without that key.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::oauth::clients::client::{GrantType, OAuthClient};
use crate::domains::oauth::clients::lifetimes::RefreshLifetimes;
use crate::domains::oauth::events::grants::{RefreshTokenReused, TokenRevoked};
use crate::domains::oauth::grants::authorization_code::AuthorizationCode;
use crate::domains::oauth::grants::device_authorization::DeviceAuthorization;
use crate::domains::oauth::grants::refresh_terms::{
    RefreshIssue, RefreshRefusal, RefreshRequest, RefreshScopes,
};
use crate::domains::oauth::grants::token_binding::{SenderBinding, refresh_binding};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::types::{
    EventLabel, Lifetime, OAuthClientId, RefreshFamilyId, Scope, SessionId, TokenHash, UserId,
};

/// Where the grant a family carries on was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantedIn {
    /// In this signed-in session, through the authorization code flow.
    /// Signing out of it ends the family.
    Session(SessionId),
    /// On a second screen, approving a device.
    DeviceApproval,
}

impl GrantedIn {
    /// Reads the stored session column back. No session means a device
    /// approval.
    #[must_use]
    pub fn from_stored(session: Option<SessionId>) -> Self {
        session.map_or(Self::DeviceApproval, Self::Session)
    }

    /// The session, when the grant was given in one. Storage keeps it this
    /// way.
    #[must_use]
    pub fn session(&self) -> Option<&SessionId> {
        match self {
            Self::Session(session) => Some(session),
            Self::DeviceApproval => None,
        }
    }
}

/// Where a refresh token stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshState {
    /// It may be used once.
    Active,
    /// It was used at this time, and the next token replaced it.
    Rotated {
        /// When it was used.
        at: OffsetDateTime,
    },
    /// It was revoked at this time.
    Revoked {
        /// When it was revoked.
        at: OffsetDateTime,
    },
}

impl RefreshState {
    /// When the token stopped being usable, if it did.
    #[must_use]
    pub fn ended_at(self) -> Option<OffsetDateTime> {
        match self {
            Self::Active => None,
            Self::Rotated { at } | Self::Revoked { at } => Some(at),
        }
    }
}

/// A refresh token.
///
/// Only the hash is kept; the raw token goes to the client once.
#[derive(Debug)]
pub struct OAuthRefreshToken<T: TenantScope> {
    token_hash: TokenHash,
    family: RefreshFamilyId,
    client_id: OAuthClientId,
    user_id: UserId,
    scopes: Vec<Scope>,
    granted_in: GrantedIn,
    binding: SenderBinding,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    family_expires_at: OffsetDateTime,
    state: RefreshState,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// A refresh token as storage keeps it, checked again by
/// [`OAuthRefreshToken::reconstitute`].
#[derive(Debug, Clone)]
pub struct OAuthRefreshTokenRow {
    /// The token's hash.
    pub token_hash: TokenHash,
    /// The family it belongs to.
    pub family: RefreshFamilyId,
    /// The client it was issued to.
    pub client_id: OAuthClientId,
    /// The person the grant is for.
    pub user_id: UserId,
    /// The scopes it carries.
    pub scopes: Vec<Scope>,
    /// Where the grant was given.
    pub granted_in: GrantedIn,
    /// What it must be presented with.
    pub binding: SenderBinding,
    /// When it was issued.
    pub issued_at: OffsetDateTime,
    /// When it runs out unless used.
    pub expires_at: OffsetDateTime,
    /// When its family runs out.
    pub family_expires_at: OffsetDateTime,
    /// Where it stands.
    pub state: RefreshState,
}

/// What the token after a rotated one carries: the same family, client,
/// person, grant and binding, and the scopes the refresh kept.
#[derive(Debug, Clone)]
pub struct NextRefresh {
    family: RefreshFamilyId,
    client_id: OAuthClientId,
    user_id: UserId,
    scopes: Vec<Scope>,
    granted_in: GrantedIn,
    binding: SenderBinding,
    family_expires_at: OffsetDateTime,
    idle: Lifetime,
}

impl NextRefresh {
    /// The client the new tokens go to.
    #[must_use]
    pub fn client_id(&self) -> &OAuthClientId {
        &self.client_id
    }

    /// The person the new tokens are for.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// The scopes the new tokens carry.
    #[must_use]
    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// Where the grant was given.
    #[must_use]
    pub fn granted_in(&self) -> GrantedIn {
        self.granted_in
    }
}

impl<T: TenantScope> OAuthRefreshToken<T> {
    /// The first token of a family, for the grant `code` carried, once the
    /// client swapped it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the code was not swapped yet, or
    ///   `client` did not swap it, or may not refresh.
    pub fn from_code(
        issue: RefreshIssue,
        code: &AuthorizationCode<T>,
        client: &OAuthClient<T>,
    ) -> Result<Self, DomainError> {
        ensure_may_refresh(client, code.client_id())?;
        if !code.is_consumed() {
            return Err(DomainError::forbidden(message!(
                "oauth-a-refresh-token-follows-a-code",
                "a refresh token follows a code only once it was swapped"
            )));
        }
        let grant = Grant {
            client_id: *code.client_id(),
            user_id: *code.user_id(),
            scopes: code.scopes().to_vec(),
            granted_in: GrantedIn::Session(*code.session_id()),
            binding: refresh_binding(client, &issue.proof),
        };
        Ok(Self::first(issue.token_hash, grant, issue.lifetimes))
    }

    /// The first token of a family, for the person who approved `device`,
    /// once the client collected the approval.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the approval was not collected, or
    ///   `client` did not start the flow, or may not refresh.
    pub fn from_device(
        issue: RefreshIssue,
        device: &DeviceAuthorization<T>,
        client: &OAuthClient<T>,
    ) -> Result<Self, DomainError> {
        ensure_may_refresh(client, device.client_id())?;
        let Some(user_id) = device.collected_by() else {
            return Err(DomainError::forbidden(message!(
                "oauth-a-refresh-token-follows-a-device",
                "a refresh token follows a device approval only once it was collected"
            )));
        };
        let grant = Grant {
            client_id: *device.client_id(),
            user_id: *user_id,
            scopes: device.scopes().to_vec(),
            granted_in: GrantedIn::DeviceApproval,
            binding: refresh_binding(client, &issue.proof),
        };
        Ok(Self::first(issue.token_hash, grant, issue.lifetimes))
    }

    /// The first token of a new family for `grant`, issued now.
    fn first(token_hash: TokenHash, grant: Grant, lifetimes: RefreshLifetimes) -> Self {
        let now = crate::shared::clock::now();
        Self {
            token_hash,
            family: RefreshFamilyId::new(),
            client_id: grant.client_id,
            user_id: grant.user_id,
            scopes: grant.scopes,
            granted_in: grant.granted_in,
            binding: grant.binding,
            issued_at: now,
            expires_at: lifetimes.idle().ends_after(now),
            family_expires_at: lifetimes.family().ends_after(now),
            state: RefreshState::Active,
            raised: Raised::default(),
            _scope: PhantomData,
        }
    }

    /// The token that replaces a rotated one, issued now. It lasts its idle
    /// time, never past its family's end.
    #[must_use]
    pub fn rotated(token_hash: TokenHash, next: NextRefresh) -> Self {
        let now = crate::shared::clock::now();
        Self {
            token_hash,
            family: next.family,
            client_id: next.client_id,
            user_id: next.user_id,
            scopes: next.scopes,
            granted_in: next.granted_in,
            binding: next.binding,
            issued_at: now,
            expires_at: next.idle.ends_after(now).min(next.family_expires_at),
            family_expires_at: next.family_expires_at,
            state: RefreshState::Active,
            raised: Raised::default(),
            _scope: PhantomData,
        }
    }

    /// Rebuilds a refresh token from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when it runs out before it was
    ///   issued, outlives its family, or ended before it was issued.
    pub fn reconstitute(row: OAuthRefreshTokenRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            token_hash: row.token_hash,
            family: row.family,
            client_id: row.client_id,
            user_id: row.user_id,
            scopes: row.scopes,
            granted_in: row.granted_in,
            binding: row.binding,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
            family_expires_at: row.family_expires_at,
            state: row.state,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &OAuthRefreshTokenRow) -> Result<(), DomainError> {
        RowCheck::of("refresh token")
            .holds(
                row.issued_at < row.expires_at,
                "expires before it was issued",
            )
            .holds(
                row.expires_at <= row.family_expires_at,
                "outlives its family",
            )
            .in_order_if(
                row.issued_at,
                row.state.ended_at(),
                "ended before it was issued",
            )
            .finish()
    }

    /// The token as storage keeps it.
    #[must_use]
    pub fn to_row(&self) -> OAuthRefreshTokenRow {
        OAuthRefreshTokenRow {
            token_hash: self.token_hash.clone(),
            family: self.family,
            client_id: self.client_id,
            user_id: self.user_id,
            scopes: self.scopes.clone(),
            granted_in: self.granted_in,
            binding: self.binding.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            family_expires_at: self.family_expires_at,
            state: self.state,
        }
    }

    /// The token's hash.
    #[must_use]
    pub fn token_hash(&self) -> &TokenHash {
        &self.token_hash
    }

    /// The family it belongs to.
    #[must_use]
    pub fn family(&self) -> &RefreshFamilyId {
        &self.family
    }

    /// The person the grant is for.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// The scopes it carries.
    #[must_use]
    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// What it must be presented with.
    #[must_use]
    pub fn binding(&self) -> &SenderBinding {
        &self.binding
    }

    /// Where it stands.
    #[must_use]
    pub fn state(&self) -> RefreshState {
        self.state
    }

    /// When it runs out unless used.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// Whether it was issued to the client `client_id` names.
    #[must_use]
    pub fn belongs_to(&self, client_id: &OAuthClientId) -> bool {
        self.client_id == *client_id
    }

    /// Uses the token, at `now`, for `client`, as `request` asks, and hands
    /// what the next token carries.
    ///
    /// A token used already is reuse: it raises `oauth.refresh_token_reused`
    /// and the caller revokes the whole family.
    ///
    /// # Errors
    ///
    /// - The cases [`RefreshRefusal`] names.
    pub fn rotate(
        &mut self,
        client: &OAuthClient<T>,
        request: RefreshRequest,
        now: OffsetDateTime,
    ) -> Result<NextRefresh, RefreshRefusal> {
        if !self.belongs_to(client.id()) {
            return Err(RefreshRefusal::OtherClient);
        }
        if !client.is_active() || !client.supports_grant_type(GrantType::RefreshToken) {
            return Err(RefreshRefusal::ClientRefused);
        }
        if !self.binding.admits(&request.proof) {
            return Err(RefreshRefusal::UnprovedKey);
        }
        self.ensure_usable(client, now)?;
        let scopes = self.kept_scopes(request.scopes)?;
        self.state = RefreshState::Rotated { at: now };
        Ok(NextRefresh {
            family: self.family,
            client_id: self.client_id,
            user_id: self.user_id,
            scopes,
            granted_in: self.granted_in,
            binding: self.binding.clone(),
            family_expires_at: self.family_expires_at,
            idle: request.idle,
        })
    }

    /// Refuses a token that was used, revoked or ran out; a used one is
    /// raised as reuse.
    fn ensure_usable(
        &mut self,
        client: &OAuthClient<T>,
        now: OffsetDateTime,
    ) -> Result<(), RefreshRefusal> {
        match self.state {
            RefreshState::Rotated { .. } => Err(self.reused(client, now)),
            RefreshState::Revoked { .. } => Err(RefreshRefusal::Revoked),
            RefreshState::Active if now >= self.expires_at => Err(RefreshRefusal::Expired),
            RefreshState::Active => Ok(()),
        }
    }

    /// The refusal of a rotation storage turned down, at `now`, because
    /// another refresh with this same token rotated it first. Two refreshes
    /// presenting one token at once mean a copy is in use, so it is reuse
    /// like any other: it raises `oauth.refresh_token_reused`, and storage
    /// revoked the family as it turned the rotation down.
    #[must_use]
    pub fn lose_rotation(
        &mut self,
        client: &OAuthClient<T>,
        now: OffsetDateTime,
    ) -> RefreshRefusal {
        self.reused(client, now)
    }

    /// Raises the reuse of the token by `client` at `now`, and refuses it.
    fn reused(&mut self, client: &OAuthClient<T>, now: OffsetDateTime) -> RefreshRefusal {
        self.raised.raise(RefreshTokenReused {
            client_id: self.client_id,
            client_label: EventLabel::of(client.name().as_str()),
            occurred_at: now,
        });
        RefreshRefusal::Reused
    }

    /// The scopes the next token keeps: the grant's, or fewer.
    fn kept_scopes(&self, asked: RefreshScopes) -> Result<Vec<Scope>, RefreshRefusal> {
        match asked {
            RefreshScopes::AsGranted => Ok(self.scopes.clone()),
            RefreshScopes::Narrowed(scopes) if scopes.iter().all(|s| self.scopes.contains(s)) => {
                Ok(scopes)
            }
            RefreshScopes::Narrowed(_) => Err(RefreshRefusal::ScopeWidened),
        }
    }

    /// Revokes the token at `now`. A token already rotated or revoked keeps
    /// the time it stopped working.
    pub fn revoke(&mut self, now: OffsetDateTime) {
        if self.state == RefreshState::Active {
            self.state = RefreshState::Revoked { at: now };
        }
    }

    /// Revokes the token at `now` at the request of `client`, the one
    /// holding it (RFC 7009), and raises `oauth.token_revoked`. Storage
    /// ends the rest of its family. A token revoked already raises nothing
    /// again; one rotated still does, since its family may hold a working
    /// token.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `client` does not hold the token.
    pub fn revoke_by_holder(
        &mut self,
        client: &OAuthClient<T>,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        if !self.belongs_to(client.id()) {
            return Err(DomainError::forbidden(message!(
                "oauth-only-the-client-holding-a-token",
                "only the client holding a token may revoke it"
            )));
        }
        if let RefreshState::Revoked { .. } = self.state {
            return Ok(());
        }
        self.revoke(now);
        self.raised.raise(TokenRevoked {
            client_id: self.client_id,
            client_label: EventLabel::of(client.name().as_str()),
            occurred_at: now,
        });
        Ok(())
    }
}

/// Refuses `client` unless it is the one the grant went to, active, and
/// allowed to refresh.
fn ensure_may_refresh<T: TenantScope>(
    client: &OAuthClient<T>,
    granted_to: &OAuthClientId,
) -> Result<(), DomainError> {
    let may = client.id() == granted_to
        && client.is_active()
        && client.supports_grant_type(GrantType::RefreshToken);
    if may {
        return Ok(());
    }
    Err(DomainError::forbidden(message!(
        "oauth-this-client-may-not-refresh-this",
        "this client may not refresh this grant"
    )))
}

/// What a family carries on from the grant that started it.
struct Grant {
    client_id: OAuthClientId,
    user_id: UserId,
    scopes: Vec<Scope>,
    granted_in: GrantedIn,
    binding: SenderBinding,
}

impl<T: TenantScope> Raises for OAuthRefreshToken<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::oauth::clients::client::NewOAuthClient;
    use crate::domains::oauth::clients::credential::ClientCredential;
    use crate::domains::oauth::clients::settings::ClientSettings;
    use crate::domains::oauth::control::tests::key_admin;
    use crate::domains::oauth::grants::token_binding::{
        JwkThumbprint, PresentedCertificate, PresentedProof, ProvenKey,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::raised_names;
    use crate::types::{ClientId, RedirectUri};

    /// Ann's app, which may use the code flow and refresh its tokens.
    fn app() -> OAuthClient<ResolvedTenant> {
        OAuthClient::create(
            NewOAuthClient {
                id: OAuthClientId::new(),
                client_id_value: ClientId::new("web_app").unwrap(),
                credential: ClientCredential::Public,
                name: crate::test_support::builders::label("Web app"),
                redirect_uris: vec![RedirectUri::new("https://app.acme.com/cb").unwrap()],
                post_logout_redirect_uris: Vec::new(),
                grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
                scopes: vec![Scope::new("openid").unwrap(), Scope::new("read").unwrap()],
                settings: ClientSettings::platform_defaults(),
            },
            &key_admin(),
        )
        .unwrap()
    }

    /// An hour of idle time and a family of a day.
    fn lifetimes() -> RefreshLifetimes {
        RefreshLifetimes::new(
            Lifetime::seconds(3600).unwrap(),
            Lifetime::seconds(86_400).unwrap(),
        )
        .unwrap()
    }

    /// A token of `client`'s for Ann, carrying `openid` and `read`, bound
    /// as `binding` says.
    fn bound_token_for(
        client: &OAuthClient<ResolvedTenant>,
        binding: SenderBinding,
    ) -> OAuthRefreshToken<ResolvedTenant> {
        OAuthRefreshToken::first(
            TokenHash::from_stored("first".to_owned()),
            Grant {
                client_id: *client.id(),
                user_id: UserId::new(),
                scopes: vec![Scope::new("openid").unwrap(), Scope::new("read").unwrap()],
                granted_in: GrantedIn::Session(SessionId::new()),
                binding,
            },
            lifetimes(),
        )
    }

    /// A bearer token of `client`'s for Ann.
    fn token_for(client: &OAuthClient<ResolvedTenant>) -> OAuthRefreshToken<ResolvedTenant> {
        bound_token_for(client, SenderBinding::Bearer)
    }

    /// A refresh for the grant's scopes, the next token idle for an hour,
    /// proving nothing.
    fn as_granted() -> RefreshRequest {
        asking(RefreshScopes::AsGranted, hour())
    }

    /// A refresh for `scopes`, the next token idle for `idle`, proving
    /// nothing.
    fn asking(scopes: RefreshScopes, idle: Lifetime) -> RefreshRequest {
        RefreshRequest {
            scopes,
            idle,
            proof: PresentedProof::nothing(),
        }
    }

    /// Supplies a bounded lifetime for the replacement tokens in these rotation tests.
    fn hour() -> Lifetime {
        Lifetime::seconds(3600).unwrap()
    }

    /// Ann's app refreshes. The next token carries on the same family,
    /// person and scopes, and the used one is retired.
    #[test]
    fn rotating_hands_on_the_grant_and_retires_the_token() {
        let client = app();
        let mut token = token_for(&client);
        let now = crate::shared::clock::now();

        let next = token.rotate(&client, as_granted(), now).unwrap();
        let second = OAuthRefreshToken::<ResolvedTenant>::rotated(
            TokenHash::from_stored("second".to_owned()),
            next,
        );

        assert_eq!(token.state(), RefreshState::Rotated { at: now });
        assert_eq!(second.family(), token.family());
        assert_eq!(second.user_id(), token.user_id());
        assert_eq!(second.scopes(), token.scopes());
    }

    /// Presenting a refresh token after it was rotated returns a reuse
    /// refusal and raises one refresh-token-reused event.
    #[test]
    fn a_used_token_presented_again_is_reuse() {
        let client = app();
        let mut token = token_for(&client);
        let now = crate::shared::clock::now();
        token.rotate(&client, as_granted(), now).unwrap();

        let again = token.rotate(&client, as_granted(), now);

        assert_eq!(again.unwrap_err(), RefreshRefusal::Reused);
        assert_eq!(raised_names(&mut token), ["oauth.refresh_token_reused"]);
    }

    /// Reporting a lost rotation after the token was rotated returns a reuse
    /// refusal and raises one refresh-token-reused event.
    #[test]
    fn a_rotation_lost_to_another_refresh_is_reuse() {
        let client = app();
        let mut token = token_for(&client);
        let now = crate::shared::clock::now();
        token.rotate(&client, as_granted(), now).unwrap();

        let refusal = token.lose_rotation(&client, now);

        assert_eq!(refusal, RefreshRefusal::Reused);
        assert_eq!(raised_names(&mut token), ["oauth.refresh_token_reused"]);
    }

    /// A refresh token issued to one client rejects rotation by another
    /// with the other-client refusal.
    #[test]
    fn another_client_cannot_use_the_token() {
        let client = app();
        let mut token = token_for(&client);

        let result = token.rotate(&app(), as_granted(), crate::shared::clock::now());

        assert_eq!(result.unwrap_err(), RefreshRefusal::OtherClient);
    }

    /// A refresh may ask for fewer scopes, never for more.
    #[test]
    fn a_refresh_may_narrow_but_not_widen_the_scopes() {
        let client = app();
        let now = crate::shared::clock::now();
        let read = vec![Scope::new("read").unwrap()];
        let admin = vec![Scope::new("admin").unwrap()];

        let narrowed = token_for(&client)
            .rotate(
                &client,
                asking(RefreshScopes::Narrowed(read.clone()), hour()),
                now,
            )
            .unwrap();
        let widened =
            token_for(&client).rotate(&client, asking(RefreshScopes::Narrowed(admin), hour()), now);

        assert_eq!(narrowed.scopes(), read.as_slice());
        assert_eq!(widened.unwrap_err(), RefreshRefusal::ScopeWidened);
    }

    /// A token past its idle time, or a revoked one, is refused.
    #[test]
    fn an_expired_or_revoked_token_is_refused() {
        let client = app();
        let mut expired = token_for(&client);
        let later = expired.expires_at();
        let mut revoked = token_for(&client);
        revoked.revoke(crate::shared::clock::now());

        let after_expiry = expired.rotate(&client, as_granted(), later);
        let after_revoke = revoked.rotate(&client, as_granted(), crate::shared::clock::now());

        assert_eq!(after_expiry.unwrap_err(), RefreshRefusal::Expired);
        assert_eq!(after_revoke.unwrap_err(), RefreshRefusal::Revoked);
    }

    /// Ann's app revokes its refresh token as she signs out of it. The
    /// revoke is recorded once; a second revoke records nothing more.
    #[test]
    fn the_holder_revoking_raises_oauth_token_revoked() {
        let client = app();
        let mut token = token_for(&client);
        let now = crate::shared::clock::now();

        token.revoke_by_holder(&client, now).unwrap();
        token.revoke_by_holder(&client, now).unwrap();

        assert_eq!(token.state(), RefreshState::Revoked { at: now });
        assert_eq!(raised_names(&mut token), ["oauth.token_revoked"]);
    }

    /// Another client's attempt to revoke a refresh token is forbidden.
    /// The token stays active and raises no events.
    #[test]
    fn another_client_cannot_revoke_the_token() {
        let mut token = token_for(&app());

        let result = token.revoke_by_holder(&app(), crate::shared::clock::now());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(token.state(), RefreshState::Active);
        assert!(raised_names(&mut token).is_empty());
    }

    /// However often it is rotated, no token outlives its family.
    #[test]
    fn a_rotated_token_never_outlives_its_family() {
        let client = app();
        let mut token = token_for(&client);
        let soon = crate::shared::clock::now() + Duration::minutes(30);
        let two_days = Lifetime::seconds(2 * 86_400).unwrap();

        let next = token
            .rotate(&client, asking(RefreshScopes::AsGranted, two_days), soon)
            .unwrap();
        let second = OAuthRefreshToken::<ResolvedTenant>::rotated(
            TokenHash::from_stored("second".to_owned()),
            next,
        );

        assert_eq!(second.expires_at(), token.family_expires_at);
    }

    /// A stored token that outlives its family is refused as corrupt; a
    /// sound one reads back as saved.
    #[test]
    fn a_stored_token_is_checked() {
        let token = token_for(&app());
        let sound = token.to_row();
        let mut outliving = token.to_row();
        outliving.expires_at = outliving.family_expires_at + Duration::SECOND;

        let read = OAuthRefreshToken::<ResolvedTenant>::reconstitute(sound).unwrap();

        assert_eq!(read.family(), token.family());
        assert!(refused_as_corrupt(
            &OAuthRefreshToken::<ResolvedTenant>::reconstitute(outliving)
        ));
    }

    /// The `DPoP` key of thumbprint `fill` repeated.
    fn key(fill: char) -> JwkThumbprint {
        JwkThumbprint::new(fill.to_string().repeat(43)).unwrap()
    }

    /// Rotating a bound refresh token with the wrong key is refused as
    /// unproved. A subsequent attempt proving the bound key succeeds.
    #[test]
    fn a_bound_refresh_token_needs_its_key() {
        let client = app();
        let mut token = bound_token_for(&client, SenderBinding::DpopKey(key('a')));
        let now = crate::shared::clock::now();
        let with_key = |thumbprint| RefreshRequest {
            proof: PresentedProof {
                dpop: ProvenKey::Proved(thumbprint),
                certificate: PresentedCertificate::NotShown,
            },
            ..as_granted()
        };

        let stolen = token.rotate(&client, with_key(key('m')), now);
        let ann = token.rotate(&client, with_key(key('a')), now);

        assert_eq!(stolen.unwrap_err(), RefreshRefusal::UnprovedKey);
        assert!(ann.is_ok());
    }

    /// A public client's first refresh token is bound to the key its
    /// request proved; a confidential client's stays bearer.
    #[test]
    fn only_a_public_clients_refresh_token_is_bound() {
        let proof = PresentedProof {
            dpop: ProvenKey::Proved(key('a')),
            certificate: PresentedCertificate::NotShown,
        };
        let confidential = OAuthClient::<ResolvedTenant>::create(
            NewOAuthClient {
                credential: ClientCredential::secret(TokenHash::from_stored("s".to_owned())),
                ..client_like(&app())
            },
            &key_admin(),
        )
        .unwrap();

        assert_eq!(
            refresh_binding(&app(), &proof),
            SenderBinding::DpopKey(key('a'))
        );
        assert_eq!(
            refresh_binding(&confidential, &proof),
            SenderBinding::Bearer
        );
    }

    /// A new client registered like `client`.
    fn client_like(client: &OAuthClient<ResolvedTenant>) -> NewOAuthClient {
        NewOAuthClient {
            id: OAuthClientId::new(),
            client_id_value: client.client_id_value().clone(),
            credential: client.credential().clone(),
            name: client.name().clone(),
            redirect_uris: client.redirect_uris().to_vec(),
            post_logout_redirect_uris: Vec::new(),
            grant_types: client.grant_types().to_vec(),
            scopes: client.scopes().to_vec(),
            settings: ClientSettings::platform_defaults(),
        }
    }
}
