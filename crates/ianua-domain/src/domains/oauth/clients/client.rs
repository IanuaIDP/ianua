use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::oauth::clients::credential::ClientCredential;
use crate::domains::oauth::clients::registration::{
    ClientManagement, ClientRegistration, RegistrationAdmission, SelfManagement,
    ensure_self_change, ensure_self_registrable,
};
use crate::domains::oauth::clients::rules::{
    acts_as_itself, ensure_fresh_credential, ensure_grants_fit, ensure_named_once,
    ensure_redirects_for, ensure_usable,
};
use crate::domains::oauth::clients::settings::{ClientSettings, SettingsChange};
use crate::domains::oauth::clients::status::OAuthClientStatus;
use crate::domains::oauth::control::{OAuthControl, OAuthRight};
use crate::domains::oauth::events::clients::{
    OAuthClientCreated, OAuthClientRegistered, OAuthClientRevoked, OAuthClientSecretRotated,
    OAuthClientUpdated,
};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::distinct::first_repeat;
use crate::types::{
    ClientId, Label, OAuthClientId, RedirectUri, RotationOverlap, Scope, TokenHash,
};

/// An `OAuth2` grant a client may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum GrantType {
    /// The authorization code flow, where a person signs in and approves.
    AuthorizationCode,

    /// Tokens for a machine acting as itself.
    ClientCredentials,

    /// Swapping a refresh token for a new access token.
    RefreshToken,

    /// The device authorization flow of RFC 8628.
    ///
    /// A person approves, on a second screen, a device that cannot show a
    /// browser. It hands out tokens for that person, so a client gets it
    /// only when it is listed.
    DeviceCode,

    /// Swapping a token the client was handed for a narrower one for
    /// another client's audience (RFC 8693), as a service calling the next
    /// one on a person's behalf. Only a confidential client an admin
    /// registered may use it.
    TokenExchange,
}

/// An `OAuth2` client of one tenant, for a third-party integration or a
/// machine.
///
/// It is read and written only through stores opened for its tenant. See
/// [`crate::isolation`].
#[derive(Debug, Clone)]
pub struct OAuthClient<T: TenantScope> {
    id: OAuthClientId,
    client_id_value: ClientId,
    credential: ClientCredential,
    name: Label,
    redirect_uris: Vec<RedirectUri>,
    post_logout_redirect_uris: Vec<RedirectUri>,
    grant_types: Vec<GrantType>,
    scopes: Vec<Scope>,
    settings: ClientSettings,
    management: ClientManagement,
    status: OAuthClientStatus,
    created_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// One change to an OAuth client's settings, made through
/// [`OAuthClient::update`] or, by the client itself,
/// [`OAuthClient::update_registration`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthClientChange {
    /// A new name.
    Rename(Label),
    /// New redirect URIs, replacing the old ones.
    RedirectTo(Vec<RedirectUri>),
    /// New addresses a person may be sent back to after signing out,
    /// replacing the old ones.
    AfterLogoutTo(Vec<RedirectUri>),
    /// New scopes it may ask for, replacing the old ones.
    Scopes(Vec<Scope>),
    /// A change to what it is set up with beyond those.
    Settings(Box<SettingsChange>),
}

impl From<SettingsChange> for OAuthClientChange {
    fn from(change: SettingsChange) -> Self {
        Self::Settings(Box::new(change))
    }
}

/// An OAuth client as storage keeps it, checked again by
/// [`OAuthClient::reconstitute`].
pub struct OAuthClientRow {
    /// The internal id.
    pub id: OAuthClientId,
    /// The public client id sent in OAuth requests.
    pub client_id_value: ClientId,
    /// How the client proves itself.
    pub credential: ClientCredential,
    /// The name shown in the OAuth settings.
    pub name: Label,
    /// The redirect URIs the authorization code flow may use.
    pub redirect_uris: Vec<RedirectUri>,
    /// Where a person may be sent back to after signing out.
    pub post_logout_redirect_uris: Vec<RedirectUri>,
    /// The grants it may use.
    pub grant_types: Vec<GrantType>,
    /// The scopes it may ask for.
    pub scopes: Vec<Scope>,
    /// What it is set up with beyond those.
    pub settings: ClientSettings,
    /// Who manages its registration.
    pub management: ClientManagement,
    /// Whether it is active or revoked.
    pub status: OAuthClientStatus,
    /// When this client was created.
    pub created_at: OffsetDateTime,
}

/// Everything an OAuth client is registered with.
pub struct NewOAuthClient {
    /// The internal identity used for storage and grants, separate from the public client identifier.
    pub id: OAuthClientId,
    /// The public client id.
    pub client_id_value: ClientId,
    /// How it proves itself: a secret's hash, its keys, its certificate, or
    /// nothing for a public client.
    pub credential: ClientCredential,
    /// Its display name.
    pub name: Label,
    /// Where it may be redirected after authorization.
    pub redirect_uris: Vec<RedirectUri>,
    /// Where a person may be sent back to after signing out.
    pub post_logout_redirect_uris: Vec<RedirectUri>,
    /// The grants it may use.
    pub grant_types: Vec<GrantType>,
    /// The scopes it may ask for.
    pub scopes: Vec<Scope>,
    /// What it is set up with beyond those.
    pub settings: ClientSettings,
}

impl<T: TenantScope> OAuthClient<T> {
    /// Creates an active OAuth client, managed by the tenant's admins.
    ///
    /// The client keeps only the hash of its secret. The raw secret is shown
    /// once, when the client is created. `control` is the person
    /// registering it. Raises `oauth.client_created`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Forbidden`] without client-creation rights.
    /// Returns [`DomainError::Validation`] for no grants, authorization-code grants
    /// without a redirect, duplicate redirects/sign-out addresses/scopes, public-client
    /// credentials or token exchange, or an old secret supplied at creation.
    pub fn create(client: NewOAuthClient, control: &OAuthControl<'_>) -> Result<Self, DomainError> {
        control.ensure_may(OAuthRight::Create)?;
        let mut client = Self::checked(client, ClientManagement::ByAdmins)?;
        client.raised.raise(OAuthClientCreated {
            client_id: client.id,
            name: client.name.clone(),
            occurred_at: client.created_at,
        });
        Ok(client)
    }

    /// Registers an app as a client on its own request (RFC 7591), once
    /// `admission` spent a use of an initial access token. It manages itself
    /// with the registration access token it was handed. Raises
    /// `oauth.client_registered`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when it asks to skip consent, or for
    ///   client credentials or token exchange.
    /// - The validation cases [`OAuthClient::create`] lists.
    pub fn register(
        registration: ClientRegistration,
        admission: RegistrationAdmission,
    ) -> Result<Self, DomainError> {
        let ClientRegistration {
            client,
            registration_token,
        } = registration;
        ensure_self_registrable(&client.grant_types, &client.settings)?;
        let management = ClientManagement::ByItself {
            registration_token,
            admitted_with: admission.into_token(),
        };
        let mut client = Self::checked(client, management)?;
        client.raised.raise(OAuthClientRegistered {
            client_id: client.id,
            name: client.name.clone(),
            occurred_at: client.created_at,
        });
        Ok(client)
    }

    /// An active client made from `new`, managed as `management` says, once
    /// it keeps every rule.
    fn checked(new: NewOAuthClient, management: ClientManagement) -> Result<Self, DomainError> {
        ensure_usable(&new.grant_types, &new.redirect_uris)?;
        ensure_grants_fit(&new.credential, &new.grant_types)?;
        ensure_fresh_credential(&new.credential)?;
        ensure_named_once("redirect URI", &new.redirect_uris)?;
        ensure_named_once("sign-out address", &new.post_logout_redirect_uris)?;
        ensure_named_once("scope", &new.scopes)?;
        Ok(Self {
            id: new.id,
            client_id_value: new.client_id_value,
            credential: new.credential,
            name: new.name,
            redirect_uris: new.redirect_uris,
            post_logout_redirect_uris: new.post_logout_redirect_uris,
            grant_types: new.grant_types,
            scopes: new.scopes,
            settings: new.settings,
            management,
            status: OAuthClientStatus::Active,
            created_at: crate::shared::clock::now(),
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Rebuilds an OAuth client from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row has no grant type.
    /// - [`DomainError::Infrastructure`] when the row uses the authorization
    ///   code flow with nowhere to redirect.
    /// - [`DomainError::Infrastructure`] when the row names a redirect URI,
    ///   a sign-out address or a scope twice.
    /// - [`DomainError::Infrastructure`] when the row is a public client
    ///   with client credentials or token exchange.
    /// - [`DomainError::Infrastructure`] when the row registered itself and
    ///   acts as itself.
    pub fn reconstitute(row: OAuthClientRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            client_id_value: row.client_id_value,
            credential: row.credential,
            name: row.name,
            redirect_uris: row.redirect_uris,
            post_logout_redirect_uris: row.post_logout_redirect_uris,
            grant_types: row.grant_types,
            scopes: row.scopes,
            settings: row.settings,
            management: row.management,
            status: row.status,
            created_at: row.created_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &OAuthClientRow) -> Result<(), DomainError> {
        let by_admins = row.management == ClientManagement::ByAdmins;
        RowCheck::of("OAuth client")
            .holds(
                ensure_usable(&row.grant_types, &row.redirect_uris).is_ok(),
                "no grant type, or the code flow with nowhere to redirect",
            )
            .holds(
                ensure_grants_fit(&row.credential, &row.grant_types).is_ok(),
                "a public client acting as itself",
            )
            .holds(
                by_admins || !acts_as_itself(&row.grant_types),
                "a self-registered client acting as itself",
            )
            .holds(
                first_repeat(row.redirect_uris.iter()).is_none(),
                "a redirect URI listed twice",
            )
            .holds(
                first_repeat(row.post_logout_redirect_uris.iter()).is_none(),
                "a sign-out address listed twice",
            )
            .holds(
                first_repeat(row.scopes.iter()).is_none(),
                "a scope listed twice",
            )
            .finish()
    }

    /// The internal id.
    #[must_use]
    pub fn id(&self) -> &OAuthClientId {
        &self.id
    }

    /// The public client id sent in OAuth requests.
    #[must_use]
    pub fn client_id_value(&self) -> &ClientId {
        &self.client_id_value
    }

    /// How the client proves itself.
    #[must_use]
    pub fn credential(&self) -> &ClientCredential {
        &self.credential
    }

    /// Whether this is a public client, which holds no secret.
    #[must_use]
    pub fn is_public(&self) -> bool {
        self.credential.is_public()
    }

    /// The name shown in the OAuth settings, such as `"CI/CD Pipeline"`.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// The redirect URIs the authorization code flow may use.
    #[must_use]
    pub fn redirect_uris(&self) -> &[RedirectUri] {
        &self.redirect_uris
    }

    /// Whether `presented` is one of this client's redirects, as
    /// [`RedirectUri::accepts`] matches them.
    #[must_use]
    pub fn accepts_redirect(&self, presented: &RedirectUri) -> bool {
        self.redirect_uris
            .iter()
            .any(|registered| registered.accepts(presented))
    }

    /// Where a person may be sent back to after signing out.
    #[must_use]
    pub fn post_logout_redirect_uris(&self) -> &[RedirectUri] {
        &self.post_logout_redirect_uris
    }

    /// Whether `presented` is one of this client's sign-out addresses.
    #[must_use]
    pub fn accepts_post_logout_redirect(&self, presented: &RedirectUri) -> bool {
        self.post_logout_redirect_uris
            .iter()
            .any(|registered| registered.accepts(presented))
    }

    /// The grants it may use.
    #[must_use]
    pub fn grant_types(&self) -> &[GrantType] {
        &self.grant_types
    }

    /// The scopes it may ask for.
    #[must_use]
    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// What it is set up with beyond its redirects, grants and scopes.
    #[must_use]
    pub fn settings(&self) -> &ClientSettings {
        &self.settings
    }

    /// Who manages its registration.
    #[must_use]
    pub fn management(&self) -> &ClientManagement {
        &self.management
    }

    /// Whether it is active or revoked.
    #[must_use]
    pub fn status(&self) -> OAuthClientStatus {
        self.status
    }

    /// When this client was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Whether the client may still be used to sign in.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == OAuthClientStatus::Active
    }

    /// Whether the client may use `grant_type`.
    #[must_use]
    pub fn supports_grant_type(&self, grant_type: GrantType) -> bool {
        self.grant_types.contains(&grant_type)
    }

    /// The first of `requested` this client was not given, if any.
    ///
    /// A client may only ask for scopes it was registered with.
    #[must_use]
    pub fn first_unallowed_scope<'a>(&self, requested: &'a [Scope]) -> Option<&'a Scope> {
        requested.iter().find(|scope| !self.scopes.contains(scope))
    }

    /// The proof that a request comes from this client itself, managing
    /// its registration with the registration access token `presented`
    /// (RFC 7592), as its hash.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Unauthorized`] when it did not register itself, is
    ///   revoked, or `presented` is not its token.
    pub fn managed_by_itself(&self, presented: &TokenHash) -> Result<SelfManagement, DomainError> {
        if !self.is_active() || !self.management.admits(presented) {
            return Err(DomainError::unauthorized(message!(
                "oauth-this-registration-access-token-does-not",
                "this registration access token does not manage the client"
            )));
        }
        Ok(SelfManagement::of(self.id))
    }

    /// Revokes the client for good, as `control` allows. Raises
    /// `oauth.client_revoked`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not revoke clients.
    /// - [`DomainError::InvalidTransition`] when it is already revoked.
    pub fn revoke(&mut self, control: &OAuthControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(OAuthRight::Revoke)?;
        self.apply_revocation()
    }

    /// Deletes its own registration (RFC 7592 2.3), as `by` proves the
    /// client asks. It is revoked like one an admin revokes. Raises
    /// `oauth.client_revoked`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` proves another client.
    /// - [`DomainError::InvalidTransition`] when it is already revoked.
    pub fn deregister(&mut self, by: &SelfManagement) -> Result<(), DomainError> {
        self.ensure_managed_by(by)?;
        self.apply_revocation()
    }

    /// Moves the client to revoked and raises it.
    fn apply_revocation(&mut self) -> Result<(), DomainError> {
        self.status = self.status.try_transition(OAuthClientStatus::Revoked)?;
        self.raised.raise(OAuthClientRevoked {
            client_id: self.id,
            name: self.name.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Makes every change in `changes`, in order, as `control` allows.
    /// Raises one `oauth.client_updated` for them all, naming the client as
    /// it is afterwards; a list with no change raises nothing.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not update clients.
    /// - [`DomainError::Conflict`] when the client is revoked.
    /// - [`DomainError::Validation`] when it uses the authorization code flow
    ///   and the new redirect URIs are empty.
    /// - [`DomainError::Validation`] when the new redirect URIs or scopes
    ///   name one twice.
    pub fn update(
        &mut self,
        changes: Vec<OAuthClientChange>,
        control: &OAuthControl<'_>,
    ) -> Result<(), DomainError> {
        self.ensure_editable(control)?;
        self.apply_all(changes)
    }

    /// Makes the changes the client asks for to its own registration
    /// (RFC 7592 2.2), as `by` proves. Raises `oauth.client_updated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` proves another client, or a
    ///   change makes it first-party.
    /// - The validation cases [`OAuthClient::update`] lists.
    pub fn update_registration(
        &mut self,
        changes: Vec<OAuthClientChange>,
        by: &SelfManagement,
    ) -> Result<(), DomainError> {
        self.ensure_managed_by(by)?;
        changes.iter().try_for_each(ensure_self_change)?;
        self.apply_all(changes)
    }

    /// Replaces the client's secret with `next`, keeping the old one for
    /// `overlap`, as `control` allows. Raises `oauth.client_secret_rotated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not update clients.
    /// - [`DomainError::Conflict`] when the client is revoked, or holds no
    ///   secret.
    /// - [`DomainError::Validation`] when `overlap` is longer than thirty
    ///   days.
    pub fn rotate_secret(
        &mut self,
        next: TokenHash,
        overlap: RotationOverlap,
        control: &OAuthControl<'_>,
    ) -> Result<(), DomainError> {
        self.ensure_editable(control)?;
        let ClientCredential::Secret(secret) = &self.credential else {
            return Err(DomainError::conflict(message!(
                "oauth-only-a-client-holding-a-secret",
                "only a client holding a secret has one to rotate"
            )));
        };
        let now = crate::shared::clock::now();
        self.credential = ClientCredential::Secret(secret.rotated(next, overlap, now)?);
        self.raised.raise(OAuthClientSecretRotated {
            client_id: self.id,
            name: self.name.clone(),
            occurred_at: now,
        });
        Ok(())
    }

    /// Makes every change and raises one update, unless there is none.
    fn apply_all(&mut self, changes: Vec<OAuthClientChange>) -> Result<(), DomainError> {
        if changes.is_empty() {
            return Ok(());
        }
        for change in changes {
            self.apply(change)?;
        }
        self.raised.raise(OAuthClientUpdated {
            client_id: self.id,
            name: self.name.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Makes one change, once the caller was found to be allowed.
    fn apply(&mut self, change: OAuthClientChange) -> Result<(), DomainError> {
        match change {
            OAuthClientChange::Rename(name) => self.name = name,
            OAuthClientChange::RedirectTo(uris) => self.replace_redirect_uris(uris)?,
            OAuthClientChange::AfterLogoutTo(uris) => {
                ensure_named_once("sign-out address", &uris)?;
                self.post_logout_redirect_uris = uris;
            }
            OAuthClientChange::Scopes(scopes) => {
                ensure_named_once("scope", &scopes)?;
                self.scopes = scopes;
            }
            OAuthClientChange::Settings(change) => self.settings.apply(*change),
        }
        Ok(())
    }

    /// Replaces where the authorization server may send this client's codes
    /// and tokens.
    fn replace_redirect_uris(&mut self, uris: Vec<RedirectUri>) -> Result<(), DomainError> {
        ensure_redirects_for(&self.grant_types, &uris)?;
        ensure_named_once("redirect URI", &uris)?;
        self.redirect_uris = uris;
        Ok(())
    }

    /// Refuses a change by someone without the update right, and any change
    /// to a revoked client.
    fn ensure_editable(&self, control: &OAuthControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(OAuthRight::Update)?;
        if self.is_active() {
            return Ok(());
        }
        Err(DomainError::conflict(message!(
            "oauth-a-revoked-client-cannot-be-changed",
            "a revoked client cannot be changed"
        )))
    }

    /// Refuses a proof made for another client.
    fn ensure_managed_by(&self, by: &SelfManagement) -> Result<(), DomainError> {
        if *by.client() == self.id {
            return Ok(());
        }
        Err(DomainError::forbidden(message!(
            "oauth-a-client-manages-only-its-own",
            "a client manages only its own registration"
        )))
    }
}

impl<T: TenantScope> Raises for OAuthClient<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::{ApiKeyAction, SystemPermission};
    use crate::domains::oauth::clients::credential::{ClientSecret, PreviousSecret, SecretSentBy};
    use crate::domains::oauth::clients::registration::{InitialAccessToken, NewInitialAccessToken};
    use crate::domains::oauth::clients::settings::{
        AccessTokenFormat, ClientLinks, ClientUri, ConsentPrompt,
    };
    use crate::domains::oauth::control::tests::{holding, key_admin};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::builders::label;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{HttpsUrl, InitialAccessTokenId, Lifetime};

    /// `client`, registered by someone who manages clients.
    fn registered(client: NewOAuthClient) -> Result<OAuthClient<ResolvedTenant>, DomainError> {
        OAuthClient::create(client, &key_admin())
    }

    /// Viewing permission does not authorize registering a client for the
    /// authorization-code flow. Sam's creation attempt is forbidden.
    #[test]
    fn a_client_is_registered_only_with_the_right_to_create_clients() {
        let sam = holding(&[SystemPermission::ApiKeys(ApiKeyAction::View)]);
        let new = new_client(
            vec![GrantType::AuthorizationCode],
            vec![RedirectUri::new("https://sam.example/callback").unwrap()],
        );

        let result = OAuthClient::<ResolvedTenant>::create(new, &sam);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A viewer cannot change a client's redirects, scopes or name. Each
    /// attempt is forbidden, and the original redirect remains registered.
    #[test]
    fn a_client_is_changed_only_with_the_right_to_update_clients() {
        let mut client = test_client();
        let sam = holding(&[SystemPermission::ApiKeys(ApiKeyAction::View)]);
        let his = vec![RedirectUri::new("https://sam.example/callback").unwrap()];

        let redirected = client.update(vec![OAuthClientChange::RedirectTo(his)], &sam);
        let widened = client.update(
            vec![OAuthClientChange::Scopes(vec![
                Scope::new("admin").unwrap(),
            ])],
            &sam,
        );
        let renamed = client.update(vec![OAuthClientChange::Rename(label("Sam's"))], &sam);

        assert!(matches!(redirected, Err(DomainError::Forbidden(_))));
        assert!(matches!(widened, Err(DomainError::Forbidden(_))));
        assert!(matches!(renamed, Err(DomainError::Forbidden(_))));
        assert_eq!(
            client.redirect_uris()[0].as_str(),
            "https://app.acme.com/callback"
        );
    }

    /// Update permission does not authorize client revocation. The forbidden
    /// attempt leaves the client active.
    #[test]
    fn a_client_is_revoked_only_with_the_right_to_revoke_clients() {
        let mut client = test_client();
        let sam = holding(&[SystemPermission::ApiKeys(ApiKeyAction::Update)]);

        let revoked = client.revoke(&sam);

        assert!(matches!(revoked, Err(DomainError::Forbidden(_))));
        assert!(client.is_active());
    }

    fn test_client() -> OAuthClient<ResolvedTenant> {
        registered(NewOAuthClient {
            id: OAuthClientId::new(),
            client_id_value: ClientId::new("client_abc123").unwrap(),
            credential: ClientCredential::secret(TokenHash::from_stored(
                "hashed_secret_xyz".to_owned(),
            )),
            name: label("CI/CD Pipeline"),
            redirect_uris: vec![RedirectUri::new("https://app.acme.com/callback").unwrap()],
            post_logout_redirect_uris: Vec::new(),
            grant_types: vec![GrantType::ClientCredentials],
            scopes: vec![
                Scope::new("projects:read").unwrap(),
                Scope::new("webhooks:write").unwrap(),
            ],
            settings: ClientSettings::platform_defaults(),
        })
        .unwrap()
    }

    fn new_client(grant_types: Vec<GrantType>, redirect_uris: Vec<RedirectUri>) -> NewOAuthClient {
        NewOAuthClient {
            id: OAuthClientId::new(),
            client_id_value: ClientId::new("client_abc123").unwrap(),
            credential: ClientCredential::secret(TokenHash::from_stored(
                "hashed_secret_xyz".to_owned(),
            )),
            name: label("Web app"),
            redirect_uris,
            post_logout_redirect_uris: Vec::new(),
            grant_types,
            scopes: Vec::new(),
            settings: ClientSettings::platform_defaults(),
        }
    }

    /// A single-page app registers as a public client with the code flow.
    /// It holds no secret, and its redirect is taken.
    #[test]
    fn a_public_client_registers_without_a_secret() {
        let client = registered(NewOAuthClient {
            credential: ClientCredential::Public,
            ..new_client(
                vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
                vec![RedirectUri::new("com.acme.app:/callback").unwrap()],
            )
        })
        .unwrap();

        assert!(client.is_public());
        assert_eq!(client.credential().secret_hash(), None);
    }

    /// Registering a public client for the client-credentials grant fails
    /// validation because it holds no credential.
    #[test]
    fn a_public_client_cannot_use_client_credentials() {
        let result = registered(NewOAuthClient {
            credential: ClientCredential::Public,
            ..new_client(vec![GrantType::ClientCredentials], Vec::new())
        });

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A CLI registered `http://127.0.0.1/callback`. Its redirect on any
    /// free port is one of its own.
    #[test]
    fn a_loopback_redirect_matches_any_port() {
        let client = registered(new_client(
            vec![GrantType::AuthorizationCode],
            vec![RedirectUri::new("http://127.0.0.1/callback").unwrap()],
        ))
        .unwrap();

        let asked = RedirectUri::new("http://127.0.0.1:51004/callback").unwrap();

        assert!(client.accepts_redirect(&asked));
    }

    /// An admin sets where people land after signing out. The client
    /// accepts those addresses and no other.
    #[test]
    fn sign_out_addresses_are_the_ones_set() {
        let mut client = test_client();
        let home = RedirectUri::new("https://app.acme.com/signed-out").unwrap();

        client
            .update(
                vec![OAuthClientChange::AfterLogoutTo(vec![home.clone()])],
                &key_admin(),
            )
            .unwrap();

        assert!(client.accepts_post_logout_redirect(&home));
        let elsewhere = RedirectUri::new("https://evil.test/").unwrap();
        assert!(!client.accepts_post_logout_redirect(&elsewhere));
    }

    /// An admin registers a client with no grant types. It is refused, since
    /// it could never get a token.
    #[test]
    fn a_client_must_be_allowed_some_grant() {
        let result = registered(new_client(Vec::new(), Vec::new()));

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A client using the authorization code flow is registered with no
    /// redirect URI. It is refused, since the code would have nowhere to go.
    #[test]
    fn an_authorization_code_client_needs_a_redirect() {
        let result = registered(new_client(vec![GrantType::AuthorizationCode], Vec::new()));

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// An admin removes the only redirect URI of a code flow client. It is
    /// refused and the URI stays.
    #[test]
    fn an_authorization_code_client_cannot_have_its_last_redirect_removed() {
        let mut client = registered(new_client(
            vec![GrantType::AuthorizationCode],
            vec![RedirectUri::new("https://app.acme.com/callback").unwrap()],
        ))
        .unwrap();

        let result = client.update(
            vec![OAuthClientChange::RedirectTo(Vec::new())],
            &key_admin(),
        );

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert_eq!(client.redirect_uris().len(), 1);
    }

    /// After a client is revoked, changing its name, scopes or redirects
    /// conflicts even for the administrator who revoked it.
    #[test]
    fn a_revoked_client_cannot_be_changed() {
        let mut client = test_client();
        let sam = key_admin();
        client.revoke(&sam).unwrap();

        let changes = [
            OAuthClientChange::Rename(label("New")),
            OAuthClientChange::Scopes(Vec::new()),
            OAuthClientChange::RedirectTo(Vec::new()),
        ];

        for change in changes {
            assert!(matches!(
                client.update(vec![change], &sam),
                Err(DomainError::Conflict(_))
            ));
        }
    }

    /// A "CI/CD Pipeline" client with client credentials starts active,
    /// keeps its id and two scopes, and may not use the code flow.
    #[test]
    fn create_produces_active_client() {
        let client = test_client();

        assert!(client.is_active());
        assert_eq!(client.name().as_str(), "CI/CD Pipeline");
        assert_eq!(client.client_id_value().as_str(), "client_abc123");
        assert_eq!(client.scopes().len(), 2);
        assert!(client.supports_grant_type(GrantType::ClientCredentials));
        assert!(!client.supports_grant_type(GrantType::AuthorizationCode));
    }

    /// An admin revokes a client. It is not active after that.
    #[test]
    fn revoke_is_permanent() {
        let mut client = test_client();
        client.revoke(&key_admin()).unwrap();
        assert!(!client.is_active());
    }

    /// An active client is renamed "Production Pipeline" and shows the new
    /// name.
    #[test]
    fn rename_updates_name() {
        let mut client = test_client();
        client
            .update(
                vec![OAuthClientChange::Rename(label("Production Pipeline"))],
                &key_admin(),
            )
            .unwrap();
        assert_eq!(client.name().as_str(), "Production Pipeline");
    }

    /// A client with two scopes is given only `billing:read`. It now holds
    /// that one scope.
    #[test]
    fn replacing_the_scopes_drops_the_old_ones() {
        let mut client = test_client();
        client
            .update(
                vec![OAuthClientChange::Scopes(vec![
                    Scope::new("billing:read").unwrap(),
                ])],
                &key_admin(),
            )
            .unwrap();
        assert_eq!(client.scopes().len(), 1);
    }

    /// A new client keeps the id and secret hash it was made with, so a
    /// presented secret is checked against the right hash.
    #[test]
    fn a_client_carries_its_id_and_the_secret_hash_it_is_verified_against() {
        let id = OAuthClientId::new();
        let client = registered(NewOAuthClient {
            id,
            ..new_client(vec![GrantType::ClientCredentials], Vec::new())
        })
        .unwrap();

        assert_eq!(*client.id(), id);
        assert_eq!(
            client.credential().secret_hash().map(TokenHash::as_str),
            Some("hashed_secret_xyz")
        );
    }

    /// A client's `/callback` is replaced by `/callback2`. Only the new URI
    /// is listed, so codes are not sent to the one the tenant removed.
    #[test]
    fn the_registered_redirects_are_the_ones_configured() {
        let mut client = test_client();

        assert_eq!(client.redirect_uris().len(), 1);
        assert_eq!(client.grant_types(), &[GrantType::ClientCredentials]);

        client
            .update(
                vec![OAuthClientChange::RedirectTo(vec![
                    RedirectUri::new("https://app.acme.com/callback2").unwrap(),
                ])],
                &key_admin(),
            )
            .unwrap();

        assert_eq!(client.redirect_uris().len(), 1);
        assert_eq!(
            client.redirect_uris()[0].as_str(),
            "https://app.acme.com/callback2"
        );
    }

    /// A client asks for `projects:read` and `admin` but was only given the
    /// first. `admin` is named as the scope it may not have.
    #[test]
    fn a_scope_the_client_was_not_given_is_named() {
        let client = test_client();
        let admin = Scope::new("admin").unwrap();
        let requested = [Scope::new("projects:read").unwrap(), admin.clone()];

        assert_eq!(client.first_unallowed_scope(&requested), Some(&admin));
        assert_eq!(client.first_unallowed_scope(&requested[..1]), None);
    }

    /// A stored code flow client has no redirect URI. It is refused as
    /// corrupt.
    #[test]
    fn a_stored_code_flow_client_with_nowhere_to_redirect_is_refused() {
        let mut row = stored(&test_client());
        row.redirect_uris = Vec::new();
        row.grant_types = vec![GrantType::AuthorizationCode];

        assert!(refused_as_corrupt(
            &OAuthClient::<ResolvedTenant>::reconstitute(row)
        ));
    }

    fn stored(client: &OAuthClient<ResolvedTenant>) -> OAuthClientRow {
        OAuthClientRow {
            id: client.id,
            client_id_value: client.client_id_value.clone(),
            credential: client.credential.clone(),
            name: client.name.clone(),
            redirect_uris: client.redirect_uris.clone(),
            post_logout_redirect_uris: client.post_logout_redirect_uris.clone(),
            grant_types: client.grant_types.clone(),
            scopes: client.scopes.clone(),
            settings: client.settings.clone(),
            management: client.management.clone(),
            status: client.status,
            created_at: client.created_at,
        }
    }

    /// Loading a stored client with a duplicate callback reports corrupt
    /// storage.
    #[test]
    fn a_stored_client_naming_a_redirect_uri_twice_is_refused() {
        let mut row = stored(&test_client());
        let callback = row.redirect_uris[0].clone();
        row.redirect_uris.push(callback);

        assert!(refused_as_corrupt(
            &OAuthClient::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored client listing the same scope twice is refused as corrupt.
    #[test]
    fn a_stored_client_naming_a_scope_twice_is_refused() {
        let mut row = stored(&test_client());
        row.scopes.push(Scope::new("projects:read").unwrap());

        assert!(refused_as_corrupt(
            &OAuthClient::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored self-registered client with client-credentials access violates
    /// registration rules and is refused as corrupt.
    #[test]
    fn a_stored_self_registered_machine_client_is_refused() {
        let mut row = stored(&test_client());
        row.management = ClientManagement::ByItself {
            registration_token: TokenHash::from_stored("rat".to_owned()),
            admitted_with: InitialAccessTokenId::new(),
        };

        assert!(refused_as_corrupt(
            &OAuthClient::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// The "CI/CD Pipeline" client, with its creation taken out.
    fn fresh_client() -> OAuthClient<ResolvedTenant> {
        let mut client = test_client();
        raised_names(&mut client);
        client
    }

    /// An admin registers "CI/CD Pipeline". The creation is raised for the
    /// audit trail.
    #[test]
    fn creating_raises_oauth_client_created() {
        let mut client = test_client();

        assert_eq!(raised_names(&mut client), ["oauth.client_created"]);
    }

    /// "CI/CD Pipeline" is read back from storage. Loading it is no change,
    /// so it has raised nothing.
    #[test]
    fn a_client_read_back_from_storage_has_raised_nothing() {
        let row = stored(&test_client());

        let mut read_back = OAuthClient::<ResolvedTenant>::reconstitute(row).unwrap();

        assert!(raised_names(&mut read_back).is_empty());
    }

    /// An admin revokes "CI/CD Pipeline". The revoke is raised.
    #[test]
    fn revoking_raises_oauth_client_revoked() {
        let mut client = fresh_client();

        client.revoke(&key_admin()).unwrap();

        assert_eq!(raised_names(&mut client), ["oauth.client_revoked"]);
    }

    /// An admin renames "CI/CD Pipeline" and narrows its scopes in one
    /// edit. One update is raised, naming the client by its new name.
    #[test]
    fn an_update_raises_one_oauth_client_updated_with_the_new_name() {
        let mut client = fresh_client();

        client
            .update(
                vec![
                    OAuthClientChange::Rename(label("Production Pipeline")),
                    OAuthClientChange::Scopes(vec![Scope::new("billing:read").unwrap()]),
                ],
                &key_admin(),
            )
            .unwrap();

        let events = raised(&mut client);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type().to_string(), "oauth.client_updated");
        let payload = events[0].payload();
        let Some(FieldValue::Reference(named)) = payload.value("client") else {
            panic!("the update does not name the client");
        };
        assert_eq!(named.label(), "Production Pipeline");
    }

    /// An admin sends an edit that changes nothing. Nothing is raised.
    #[test]
    fn an_update_with_no_change_raises_nothing() {
        let mut client = fresh_client();

        client.update(Vec::new(), &key_admin()).unwrap();

        assert!(raised_names(&mut client).is_empty());
    }

    /// A viewer's rename and revocation fail, as does an admin's removal of
    /// every redirect from a code-flow client. Neither client raises an event.
    #[test]
    fn a_refused_change_raises_nothing() {
        let mut client = fresh_client();
        let mut code_client = registered(new_client(
            vec![GrantType::AuthorizationCode],
            vec![RedirectUri::new("https://app.acme.com/callback").unwrap()],
        ))
        .unwrap();
        raised_names(&mut code_client);
        let sam = holding(&[SystemPermission::ApiKeys(ApiKeyAction::View)]);

        let renamed = client.update(vec![OAuthClientChange::Rename(label("Sam's"))], &sam);
        let revoked = client.revoke(&sam);
        let emptied = code_client.update(
            vec![OAuthClientChange::RedirectTo(Vec::new())],
            &key_admin(),
        );

        assert!(renamed.is_err());
        assert!(revoked.is_err());
        assert!(emptied.is_err());
        assert!(raised_names(&mut client).is_empty());
        assert!(raised_names(&mut code_client).is_empty());
    }

    /// The billing server's secret is rotated with a day's overlap. Both
    /// secrets work for now, and the rotation is raised.
    #[test]
    fn rotating_a_secret_keeps_the_old_one_for_the_overlap() {
        let mut client = fresh_client();
        let day = Lifetime::seconds(86_400).unwrap();
        let next = TokenHash::from_stored("next_secret".to_owned());

        client
            .rotate_secret(next.clone(), RotationOverlap::For(day), &key_admin())
            .unwrap();

        let accepted = client
            .credential()
            .secrets_accepted_at(crate::shared::clock::now());
        assert_eq!(accepted.len(), 2);
        assert_eq!(client.credential().secret_hash(), Some(&next));
        assert_eq!(raised_names(&mut client), ["oauth.client_secret_rotated"]);
    }

    /// A viewer's secret rotation is forbidden. Rotating a public client's
    /// secret conflicts even for an admin because that client has no secret.
    #[test]
    fn a_secret_is_rotated_only_by_an_admin_and_only_when_held() {
        let mut client = test_client();
        let mut spa = registered(NewOAuthClient {
            credential: ClientCredential::Public,
            ..new_client(
                vec![GrantType::AuthorizationCode],
                vec![RedirectUri::new("https://spa.acme.com/cb").unwrap()],
            )
        })
        .unwrap();
        let sam = holding(&[SystemPermission::ApiKeys(ApiKeyAction::View)]);
        let his = || TokenHash::from_stored("sams".to_owned());

        let by_sam = client.rotate_secret(his(), RotationOverlap::Immediate, &sam);
        let public = spa.rotate_secret(his(), RotationOverlap::Immediate, &key_admin());

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(matches!(public, Err(DomainError::Conflict(_))));
    }

    /// Creating a client with an accepted previous secret fails validation.
    /// Previous secrets can arise only through rotation.
    #[test]
    fn a_new_client_cannot_hold_an_old_secret() {
        let two = ClientCredential::Secret(ClientSecret::from_stored(
            TokenHash::from_stored("shown".to_owned()),
            PreviousSecret::AcceptedUntil {
                hash: TokenHash::from_stored("kept".to_owned()),
                until: crate::shared::clock::now() + time::Duration::days(30),
            },
            SecretSentBy::Basic,
        ));

        let result = registered(NewOAuthClient {
            credential: two,
            ..new_client(vec![GrantType::ClientCredentials], Vec::new())
        });

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// An admin gives the portal a logo, makes it first-party and has its
    /// access tokens issued as JWTs. The client keeps each setting.
    #[test]
    fn an_admin_changes_the_settings() {
        let mut client = test_client();
        let logo = ClientUri::At(HttpsUrl::new("https://app.acme.com/logo.png").unwrap());
        let links = ClientLinks {
            logo: logo.clone(),
            ..ClientLinks::none()
        };

        let changes = [
            SettingsChange::Links(links),
            SettingsChange::Consent(ConsentPrompt::FirstParty),
            SettingsChange::TokenFormat(AccessTokenFormat::Jwt),
        ];

        client
            .update(
                changes.into_iter().map(OAuthClientChange::from).collect(),
                &key_admin(),
            )
            .unwrap();

        assert_eq!(client.settings().links.logo, logo);
        assert_eq!(client.settings().consent, ConsentPrompt::FirstParty);
        assert_eq!(client.settings().token_format, AccessTokenFormat::Jwt);
    }

    /// An app registering itself through the registration endpoint, with
    /// the registration access token `rat`.
    fn self_registered(rat: &str) -> OAuthClient<ResolvedTenant> {
        let mut token = InitialAccessToken::<ResolvedTenant>::issue(
            NewInitialAccessToken {
                id: InitialAccessTokenId::new(),
                name: label("MCP clients"),
                token_hash: TokenHash::from_stored("iat".to_owned()),
                uses: 1,
                lifetime: Lifetime::seconds(3600).unwrap(),
            },
            &key_admin(),
        )
        .unwrap();
        let admission = token.admit(crate::shared::clock::now()).unwrap();
        OAuthClient::register(
            ClientRegistration {
                client: NewOAuthClient {
                    client_id_value: ClientId::new("cli_mcp").unwrap(),
                    credential: ClientCredential::Public,
                    name: label("Notes assistant"),
                    grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
                    ..new_client(
                        Vec::new(),
                        vec![RedirectUri::new("http://127.0.0.1/callback").unwrap()],
                    )
                },
                registration_token: TokenHash::from_stored(rat.to_owned()),
            },
            admission,
        )
        .unwrap()
    }

    /// An MCP app registers itself with an initial access token. It is
    /// active, managed by itself, and its registration is raised.
    #[test]
    fn an_app_registers_itself_with_an_initial_access_token() {
        let mut client = self_registered("rat");

        assert!(client.is_active());
        assert!(matches!(
            client.management(),
            ClientManagement::ByItself { .. }
        ));
        assert_eq!(raised_names(&mut client), ["oauth.client_registered"]);
    }

    /// The app renames itself with its registration access token, then
    /// deletes its registration.
    #[test]
    fn a_self_registered_client_manages_itself_with_its_token() {
        let mut client = self_registered("rat");
        let rat = TokenHash::from_stored("rat".to_owned());
        let by = client.managed_by_itself(&rat).unwrap();

        client
            .update_registration(vec![OAuthClientChange::Rename(label("Notes"))], &by)
            .unwrap();
        client.deregister(&by).unwrap();

        assert_eq!(client.name().as_str(), "Notes");
        assert!(!client.is_active());
    }

    /// A wrong registration token is unauthorized for self-registered and
    /// admin-created clients. Another client's management proof cannot
    /// deregister Notes, which remains active.
    #[test]
    fn only_the_clients_own_token_manages_it() {
        let mut notes = self_registered("notes-rat");
        let other = self_registered("other-rat");
        let guessed = TokenHash::from_stored("guess".to_owned());
        let others_proof = other
            .managed_by_itself(&TokenHash::from_stored("other-rat".to_owned()))
            .unwrap();

        let guess = notes.managed_by_itself(&guessed);
        let admin_made = test_client().managed_by_itself(&guessed);
        let crossed = notes.deregister(&others_proof);

        assert!(matches!(guess, Err(DomainError::Unauthorized(_))));
        assert!(matches!(admin_made, Err(DomainError::Unauthorized(_))));
        assert!(matches!(crossed, Err(DomainError::Forbidden(_))));
        assert!(notes.is_active());
    }

    /// A self-registered client cannot change its consent setting to
    /// first-party. The forbidden update preserves consent prompts.
    #[test]
    fn a_client_cannot_make_itself_first_party() {
        let mut client = self_registered("rat");
        let by = client
            .managed_by_itself(&TokenHash::from_stored("rat".to_owned()))
            .unwrap();

        let first_party =
            OAuthClientChange::from(SettingsChange::Consent(ConsentPrompt::FirstParty));

        let result = client.update_registration(vec![first_party], &by);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(client.settings().consent, ConsentPrompt::AskPerson);
    }
}
