//! OAuth consent: which scopes a user has given to which OAuth client.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::identity::account::control::{SignedInPerson, ensure_holder};
use crate::domains::oauth::clients::client::OAuthClient;
use crate::domains::oauth::events::consent::{OAuthConsentGranted, OAuthConsentRevoked};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::types::{EventLabel, OAuthClientId, Scope, UserId};

/// The scopes one user has given one OAuth client.
///
/// When a user approves a third-party app, the scopes they gave are kept
/// here. A later request for the same or fewer scopes is already covered.
/// One asking for more adds the new scopes to this consent.
#[derive(Debug)]
pub struct OAuthConsent<T: TenantScope> {
    /// The user who gave consent.
    user_id: UserId,
    /// The client it was given to.
    client_id: OAuthClientId,
    /// The scopes the user gave.
    scopes: Vec<Scope>,
    /// When consent was last given or changed.
    granted_at: OffsetDateTime,
    /// What it raised and was not taken yet.
    raised: Raised<T>,
    /// Which tenant scope this belongs to. See [`crate::isolation`].
    _scope: PhantomData<T>,
}

/// A consent as storage keeps it.
pub struct OAuthConsentRow {
    /// The user who gave it.
    pub user_id: UserId,
    /// The client it was given to.
    pub client_id: OAuthClientId,
    /// The scopes the user gave.
    pub scopes: Vec<Scope>,
    /// When consent was last given or changed.
    pub granted_at: OffsetDateTime,
}

impl<T: TenantScope> OAuthConsent<T> {
    /// Records that `user_id`, signed in as `by`, gives `client` these
    /// scopes. Raises `oauth.consent_granted`, naming `client` and how many
    /// scopes were given.
    ///
    /// Consent is the person's own. Without this check, an admin's session
    /// agrees for Ann that a reporting app may read her mail, and the app
    /// gets tokens for her without her ever being asked.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when someone other than `user_id` is
    ///   signed in.
    pub fn grant(
        user_id: UserId,
        client: &OAuthClient<T>,
        scopes: Vec<Scope>,
        by: &impl SignedInPerson<T>,
    ) -> Result<Self, DomainError> {
        ensure_holder(by, &user_id)?;
        let mut consent = Self {
            user_id,
            client_id: *client.id(),
            scopes,
            granted_at: crate::shared::clock::now(),
            raised: Raised::default(),
            _scope: PhantomData,
        };
        consent.raise_granted(client);
        Ok(consent)
    }

    /// Rebuilds a consent from storage.
    ///
    /// # Errors
    ///
    /// - Never fails today. No part of the row can contradict another, and
    ///   each part was read through its own checked type.
    pub fn reconstitute(row: OAuthConsentRow) -> Result<Self, DomainError> {
        Ok(Self {
            user_id: row.user_id,
            client_id: row.client_id,
            scopes: row.scopes,
            granted_at: row.granted_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The user who gave consent.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// The client it was given to.
    #[must_use]
    pub fn client_id(&self) -> &OAuthClientId {
        &self.client_id
    }

    /// The scopes the user gave.
    #[must_use]
    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// When consent was last given or changed.
    #[must_use]
    pub fn granted_at(&self) -> OffsetDateTime {
        self.granted_at
    }

    /// Whether every scope in `requested` was already given.
    #[must_use]
    pub fn covers_scopes(&self, requested: &[Scope]) -> bool {
        requested.iter().all(|s| self.scopes.contains(s))
    }

    /// Adds the scopes from `additional` that were not given yet to
    /// `client`, the client this consent was given to, for the person who
    /// gave it, signed in as `by`. Raises `oauth.consent_granted`, naming
    /// `client` and how many scopes the consent now holds.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when someone other than the person who
    ///   gave it is signed in.
    /// - [`DomainError::Conflict`] when `client` is not the client it was
    ///   given to.
    pub fn extend_scopes(
        &mut self,
        additional: &[Scope],
        client: &OAuthClient<T>,
        by: &impl SignedInPerson<T>,
    ) -> Result<(), DomainError> {
        ensure_holder(by, &self.user_id)?;
        self.ensure_given_to(client)?;
        for scope in additional {
            if !self.scopes.contains(scope) {
                self.scopes.push(scope.clone());
            }
        }
        self.granted_at = crate::shared::clock::now();
        self.raise_granted(client);
        Ok(())
    }

    /// Withdraws the consent given to `client` by removing every scope, for
    /// the person who gave it, signed in as `by`. Raises
    /// `oauth.consent_revoked`, naming `client`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when someone other than the person who
    ///   gave it is signed in.
    /// - [`DomainError::Conflict`] when `client` is not the client it was
    ///   given to.
    pub fn revoke(
        &mut self,
        client: &OAuthClient<T>,
        by: &impl SignedInPerson<T>,
    ) -> Result<(), DomainError> {
        ensure_holder(by, &self.user_id)?;
        self.ensure_given_to(client)?;
        self.scopes.clear();
        self.granted_at = crate::shared::clock::now();
        self.raised.raise(OAuthConsentRevoked {
            client_id: self.client_id,
            client_label: EventLabel::of(client.name().as_str()),
            occurred_at: self.granted_at,
        });
        Ok(())
    }

    /// Refuses a client other than the one this consent was given to, so
    /// a record never names one client for another's consent.
    fn ensure_given_to(&self, client: &OAuthClient<T>) -> Result<(), DomainError> {
        if *client.id() == self.client_id {
            return Ok(());
        }
        Err(DomainError::conflict(message!(
            "oauth-this-consent-was-given-to-another",
            "this consent was given to another client"
        )))
    }

    /// Raises the consent as it now stands, given to `client`.
    fn raise_granted(&mut self, client: &OAuthClient<T>) {
        self.raised.raise(OAuthConsentGranted {
            client_id: self.client_id,
            client_label: EventLabel::of(client.name().as_str()),
            scope_count: self.scopes.len(),
            occurred_at: self.granted_at,
        });
    }
}

impl<T: TenantScope> Raises for OAuthConsent<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::identity::account::user::tests::signed_in_as;
    use crate::domains::oauth::clients::client::{GrantType, NewOAuthClient};
    use crate::domains::oauth::clients::credential::ClientCredential;
    use crate::domains::oauth::clients::settings::ClientSettings;
    use crate::domains::oauth::control::tests::key_admin;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::test_support::builders::label;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{ClientId, TokenHash};

    fn scope(s: &str) -> Scope {
        Scope::new(s).unwrap()
    }

    /// A reporting app that may ask for `read`, `write` and `admin`.
    fn reporting_app() -> OAuthClient<ResolvedTenant> {
        OAuthClient::create(
            NewOAuthClient {
                id: OAuthClientId::new(),
                client_id_value: ClientId::new("reporting_app").unwrap(),
                credential: ClientCredential::secret(TokenHash::from_stored(
                    "hashed_secret".to_owned(),
                )),
                name: label("Reporting"),
                redirect_uris: Vec::new(),
                post_logout_redirect_uris: Vec::new(),
                grant_types: vec![GrantType::ClientCredentials],
                scopes: vec![scope("read"), scope("write"), scope("admin")],
                settings: ClientSettings::platform_defaults(),
            },
            &key_admin(),
        )
        .unwrap()
    }

    /// `user`'s consent to `client`, with its grant taken out.
    fn given_to(
        client: &OAuthClient<ResolvedTenant>,
        user: UserId,
        scopes: Vec<Scope>,
    ) -> OAuthConsent<ResolvedTenant> {
        let ann = signed_in_as::<ResolvedTenant>(user);
        let mut consent = OAuthConsent::grant(user, client, scopes, &ann).unwrap();
        raised_names(&mut consent);
        consent
    }

    fn given_by(user: UserId, scopes: Vec<Scope>) -> OAuthConsent<ResolvedTenant> {
        given_to(&reporting_app(), user, scopes)
    }

    fn test_consent() -> OAuthConsent<ResolvedTenant> {
        given_by(UserId::new(), vec![scope("read"), scope("write")])
    }

    /// A person signed in under another user ID cannot grant Ann's consent
    /// to the reporting app. The grant is forbidden.
    #[test]
    fn consent_is_given_only_by_the_person_signed_in() {
        let ann = UserId::new();
        let admin = signed_in_as::<ResolvedTenant>(UserId::new());

        let given = OAuthConsent::<ResolvedTenant>::grant(
            ann,
            &reporting_app(),
            vec![scope("read")],
            &admin,
        );

        assert!(matches!(given, Err(DomainError::Forbidden(_))));
    }

    /// Mallory cannot widen or withdraw Ann's consent. Both attempts are
    /// forbidden, preserve the read scope and raise no events.
    #[test]
    fn only_the_person_who_gave_consent_changes_it() {
        let ann = UserId::new();
        let app = reporting_app();
        let mut consent = given_to(&app, ann, vec![scope("read")]);
        let mallory = signed_in_as::<ResolvedTenant>(UserId::new());

        let widened = consent.extend_scopes(&[scope("admin")], &app, &mallory);
        let withdrawn = consent.revoke(&app, &mallory);

        assert!(matches!(widened, Err(DomainError::Forbidden(_))));
        assert!(matches!(withdrawn, Err(DomainError::Forbidden(_))));
        assert_eq!(consent.scopes(), &[scope("read")]);
        assert!(raised_names(&mut consent).is_empty());
    }

    /// Widening or withdrawing consent while supplying a different client
    /// conflicts, even for its holder. Neither attempt raises an event.
    #[test]
    fn a_consent_is_changed_only_through_the_client_it_was_given_to() {
        let ann = UserId::new();
        let mut consent = given_by(ann, vec![scope("read")]);
        let holder = signed_in_as::<ResolvedTenant>(ann);
        let other = reporting_app();

        let widened = consent.extend_scopes(&[scope("admin")], &other, &holder);
        let withdrawn = consent.revoke(&other, &holder);

        assert!(matches!(widened, Err(DomainError::Conflict(_))));
        assert!(matches!(withdrawn, Err(DomainError::Conflict(_))));
        assert!(raised_names(&mut consent).is_empty());
    }

    /// A user gave an app `read` and `write`. A later request for `read`, or
    /// for both, is already covered.
    #[test]
    fn covers_granted_scopes() {
        let consent = test_consent();

        assert!(consent.covers_scopes(&[scope("read")]));
        assert!(consent.covers_scopes(&[scope("read"), scope("write")]));
    }

    /// The app asks for `read` and `admin`. `admin` was never given, so the
    /// user must be asked again.
    #[test]
    fn does_not_cover_new_scope() {
        let consent = test_consent();

        assert!(!consent.covers_scopes(&[scope("read"), scope("admin")]));
    }

    /// The user approves `admin` too. The consent now holds three scopes and
    /// covers `admin`.
    #[test]
    fn extend_adds_new_scopes() {
        let (app, mut consent, holder) = read_and_write_given();

        consent
            .extend_scopes(&[scope("admin")], &app, &holder)
            .unwrap();

        assert_eq!(consent.scopes().len(), 3);
        assert!(consent.covers_scopes(&[scope("admin")]));
    }

    /// Approving `read` again adds nothing, so the consent still holds two
    /// scopes.
    #[test]
    fn extend_is_idempotent() {
        let (app, mut consent, holder) = read_and_write_given();

        consent
            .extend_scopes(&[scope("read")], &app, &holder)
            .unwrap();

        assert_eq!(consent.scopes().len(), 2);
    }

    /// The user withdraws consent. No scope is left, so even `read` needs
    /// asking again.
    #[test]
    fn revoke_clears_all() {
        let (app, mut consent, holder) = read_and_write_given();

        consent.revoke(&app, &holder).unwrap();

        assert!(consent.scopes().is_empty());
        assert!(!consent.covers_scopes(&[scope("read")]));
    }

    /// A consent keeps the user who gave it and the client it was given to.
    /// If either read back wrong, another app could reuse it, or use it for
    /// someone who never agreed.
    #[test]
    fn a_consent_names_the_user_who_gave_it_and_the_client_it_was_given_to() {
        let user = UserId::new();
        let app = reporting_app();

        let holder = signed_in_as::<ResolvedTenant>(user);

        let consent =
            OAuthConsent::<ResolvedTenant>::grant(user, &app, vec![scope("read")], &holder)
                .unwrap();

        assert_eq!(*consent.user_id(), user);
        assert_eq!(consent.client_id(), app.id());
    }

    /// The reporting app, a consent to it for `read` and `write` with its
    /// grant taken out, and the person who gave it, signed in.
    fn read_and_write_given() -> (
        OAuthClient<ResolvedTenant>,
        OAuthConsent<ResolvedTenant>,
        impl SignedInPerson<ResolvedTenant>,
    ) {
        let app = reporting_app();
        let user = UserId::new();
        let consent = given_to(&app, user, vec![scope("read"), scope("write")]);
        (app, consent, signed_in_as::<ResolvedTenant>(user))
    }

    /// The count of scopes an event says were given.
    fn scope_count(event: &DomainEvent) -> Option<String> {
        event.payload().get("scope_count").map(str::to_owned)
    }

    /// Ann gives the reporting app `read`. The grant is raised, naming the
    /// app and one scope.
    #[test]
    fn granting_raises_oauth_consent_granted() {
        let ann = UserId::new();
        let app = reporting_app();

        let holder = signed_in_as::<ResolvedTenant>(ann);

        let mut consent = OAuthConsent::grant(ann, &app, vec![scope("read")], &holder).unwrap();

        let events = raised(&mut consent);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type().to_string(), "oauth.consent_granted");
        assert_eq!(scope_count(&events[0]), Some("1".to_owned()));
        let payload = events[0].payload();
        let Some(FieldValue::Reference(client)) = payload.value("client") else {
            panic!("the grant does not name the app");
        };
        assert_eq!(client.label(), "Reporting");
    }

    /// Ann adds `admin` to the `read` and `write` she gave. The grant is
    /// raised again, counting all three scopes the consent now holds.
    #[test]
    fn widening_raises_oauth_consent_granted_with_every_scope() {
        let (app, mut consent, holder) = read_and_write_given();

        consent
            .extend_scopes(&[scope("admin")], &app, &holder)
            .unwrap();

        let events = raised(&mut consent);
        assert_eq!(events[0].event_type().to_string(), "oauth.consent_granted");
        assert_eq!(scope_count(&events[0]), Some("3".to_owned()));
    }

    /// Ann withdraws her consent. The withdrawal is raised.
    #[test]
    fn withdrawing_raises_oauth_consent_revoked() {
        let (app, mut consent, holder) = read_and_write_given();

        consent.revoke(&app, &holder).unwrap();

        assert_eq!(raised_names(&mut consent), ["oauth.consent_revoked"]);
    }

    /// Ann's consent is read back from storage. Loading it is no change, so
    /// it has raised nothing.
    #[test]
    fn a_consent_read_back_from_storage_has_raised_nothing() {
        let given = test_consent();
        let row = OAuthConsentRow {
            user_id: given.user_id,
            client_id: given.client_id,
            scopes: given.scopes.clone(),
            granted_at: given.granted_at,
        };

        let mut read_back = OAuthConsent::<ResolvedTenant>::reconstitute(row).unwrap();

        assert!(raised_names(&mut read_back).is_empty());
    }
}
