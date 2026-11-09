use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authorization::key_authority::KeyCharter;
use crate::domains::authorization::permission::SystemPermission;
use crate::domains::identity::sealed::Sealed;
use crate::domains::oauth::control::{OAuthControl, OAuthRight};
use crate::domains::oauth::events::clients::{
    ApiKeyCreated, ApiKeyExpired, ApiKeyPaused, ApiKeyResumed, ApiKeyRevoked, ApiKeyUpdated,
    ApiKeyUsedFromNewCountry,
};
use crate::isolation::scope::{ResolvedTenant, TenantScope};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;
use crate::types::{
    ActorRef, ApiKeyId, CountryCode, Expiry, Fact, IpAddress, KeyPrefix, Label, Scope, TenantId,
    TokenHash,
};

/// The most countries a key remembers signing in from.
pub const MOST_COUNTRIES: usize = 16;

/// An API key one tenant gives to a machine.
///
/// API keys are their own way to sign in, apart from OAuth clients. They
/// have their own scopes, expiry and audit trail.
///
/// It is read and written only through stores opened for its tenant. See
/// [`crate::isolation`].
///
/// The raw key looks like `ik_live_{slug}_{lookup}_{secret}`.
/// - The `ik_live_` start lets secret scanners find leaked keys in git.
/// - The slug is readable, which helps when debugging.
/// - `ik_live_{slug}_{lookup}` is the [`KeyPrefix`], kept in plain text to
///   find the key.
/// - The whole key is kept only as a hash.
#[derive(Debug)]
pub struct ApiKey<T: TenantScope> {
    id: ApiKeyId,
    name: Label,
    key_prefix: KeyPrefix,
    key_hash: TokenHash,
    scopes: Vec<Scope>,
    created_by: ActorRef,
    expires_at: Expiry,
    last_used_at: Option<OffsetDateTime>,
    last_used_ip: Option<IpAddress>,
    seen_countries: Vec<CountryCode>,
    created_at: OffsetDateTime,
    standing: KeyStanding,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// Whether an API key may sign in, apart from its expiry.
///
/// Pat's workflow sees the deploy key used from a new country and pauses
/// it. The pipeline stops at once, and nothing about the key is lost: once
/// someone has looked, they resume it and it works again as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStanding {
    /// It signs in until it expires.
    Working,
    /// It was paused at this moment, and signs in again once resumed.
    Paused(OffsetDateTime),
}

/// Whether [`ApiKey::note_country`] changed the countries a key remembers,
/// so a use that changed nothing else need not be written down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CountryNoted {
    /// No country, or one the key signed in from before: nothing changed.
    Unchanged,
    /// A country the key never signed in from, now remembered.
    Added,
}

/// One change to an API key, made through [`ApiKey::update`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiKeyChange {
    /// A new name.
    Rename(Label),
    /// New scopes the key may be spent on, replacing the old ones.
    Scopes(Vec<Scope>),
}

/// An API key as storage keeps it, checked again by
/// [`ApiKey::reconstitute`].
pub struct ApiKeyRow {
    /// The key's id.
    pub id: ApiKeyId,
    /// The name shown in the API keys list.
    pub name: Label,
    /// The start of the key, kept in plain text to find it.
    pub key_prefix: KeyPrefix,
    /// The hash of the whole key.
    pub key_hash: TokenHash,
    /// The permissions the key may be spent on.
    pub scopes: Vec<Scope>,
    /// Who created the key.
    pub created_by: ActorRef,
    /// When the key expires, or that it never does.
    pub expires_at: Expiry,
    /// When the key last signed in, if ever.
    pub last_used_at: Option<OffsetDateTime>,
    /// The IP address of the last sign-in, when known.
    pub last_used_ip: Option<IpAddress>,
    /// The countries the key has signed in from, oldest first, at most
    /// [`MOST_COUNTRIES`].
    pub seen_countries: Vec<CountryCode>,
    /// When the key was created.
    pub created_at: OffsetDateTime,
    /// Whether it is paused.
    pub standing: KeyStanding,
}

/// Everything an API key is issued with.
pub struct NewApiKey {
    /// The caller-selected identity used for later lookup and revocation.
    pub id: ApiKeyId,
    /// Its display name.
    pub name: Label,
    /// The visible start of the key.
    pub key_prefix: KeyPrefix,
    /// The hash of the full key.
    pub key_hash: TokenHash,
    /// What it may do.
    pub scopes: Vec<Scope>,
    /// When it stops working, if ever.
    pub expires_at: Expiry,
    /// The latest it may stop working: the end of the key it is made
    /// through, or `Expiry::Never` when that key has none or it is made
    /// through no key.
    pub ends_by: Expiry,
}

impl<T: TenantScope> ApiKey<T> {
    /// Creates an active API key.
    ///
    /// The key keeps only the hash of the raw key. The raw key is shown
    /// once, when it is created, and never stored.
    ///
    /// `control` is the person creating it, who is recorded as its creator.
    /// A key carries no permission they do not hold themselves. Raises
    /// `oauth.api_key_created`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not create keys, a
    ///   scope reaches a permission they do not hold, or the key would
    ///   outlive the key it is made through.
    /// - [`DomainError::Validation`] when `scopes` is empty, a scope names
    ///   no permission this system checks, or the expiry is not ahead of
    ///   now.
    pub fn create(key: NewApiKey, control: &OAuthControl<'_>) -> Result<Self, DomainError> {
        let now = crate::shared::clock::now();
        ensure_may_create(&key, control, now)?;
        let NewApiKey {
            id,
            name,
            key_prefix,
            key_hash,
            scopes,
            expires_at,
            ..
        } = key;
        Ok(Self {
            id,
            name,
            key_prefix,
            key_hash,
            scopes,
            created_by: control.actor(),
            expires_at,
            last_used_at: None,
            last_used_ip: None,
            seen_countries: Vec::new(),
            created_at: now,
            standing: KeyStanding::Working,
            raised: Raised::default(),
            _scope: PhantomData,
        }
        .created())
    }

    /// This new key, having raised its creation.
    fn created(mut self) -> Self {
        self.raised.raise(ApiKeyCreated {
            key_id: self.id,
            name: self.name.clone(),
            occurred_at: self.created_at,
        });
        self
    }

    /// Rebuilds an API key from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row grants nothing, or
    ///   names a scope that is no permission.
    /// - [`DomainError::Infrastructure`] when the row has the address of a
    ///   use that never happened.
    /// - [`DomainError::Infrastructure`] when the row says the key was used,
    ///   expires or was paused before it was created.
    pub fn reconstitute(row: ApiKeyRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            name: row.name,
            key_prefix: row.key_prefix,
            key_hash: row.key_hash,
            scopes: row.scopes,
            created_by: row.created_by,
            expires_at: row.expires_at,
            last_used_at: row.last_used_at,
            last_used_ip: row.last_used_ip,
            seen_countries: row.seen_countries,
            created_at: row.created_at,
            standing: row.standing,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &ApiKeyRow) -> Result<(), DomainError> {
        let check = RowCheck::of("API key").holds(
            validate_scopes(&row.scopes).is_ok(),
            "a key that grants nothing",
        );
        Self::check_uses(check, row)
            .in_order_if(
                row.created_at,
                row.last_used_at,
                "used before it was created",
            )
            .holds(
                row.expires_at
                    .instant()
                    .is_none_or(|at| row.created_at < at),
                "expires before it was created",
            )
            .holds(
                match row.standing {
                    KeyStanding::Working => true,
                    KeyStanding::Paused(at) => row.created_at <= at,
                },
                "paused before it was created",
            )
            .finish()
    }

    /// `check` with the rules on where a stored key was used from added.
    fn check_uses(check: RowCheck, row: &ApiKeyRow) -> RowCheck {
        check
            .holds(
                row.last_used_ip.is_none() || row.last_used_at.is_some(),
                "an address of a use that never happened",
            )
            .holds(
                row.seen_countries.len() <= MOST_COUNTRIES
                    && first_repeat(row.seen_countries.iter()).is_none(),
                "more countries than a key keeps, or one twice",
            )
    }

    /// The key's id.
    #[must_use]
    pub fn id(&self) -> &ApiKeyId {
        &self.id
    }

    /// The name shown in the API keys list, such as `"CI/CD Pipeline"`.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// The start of the key, kept in plain text to find it quickly.
    #[must_use]
    pub fn key_prefix(&self) -> &KeyPrefix {
        &self.key_prefix
    }

    /// The hash a presented key is checked against.
    #[must_use]
    pub fn key_hash(&self) -> &TokenHash {
        &self.key_hash
    }

    /// The permissions the key may be spent on.
    #[must_use]
    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// Who created the key.
    ///
    /// A tenant user or an org user can create a key. The [`ActorRef`] keeps
    /// the two apart. A bare id could not, so a key Ann made as an org user
    /// would sign in as a tenant user who does not exist.
    #[must_use]
    pub fn created_by(&self) -> &ActorRef {
        &self.created_by
    }

    /// When the key stops working, or that it never does.
    #[must_use]
    pub fn expires_at(&self) -> Expiry {
        self.expires_at
    }

    /// When the key last signed in, if ever.
    #[must_use]
    pub fn last_used_at(&self) -> Option<OffsetDateTime> {
        self.last_used_at
    }

    /// The IP address of the last sign-in, when known.
    #[must_use]
    pub fn last_used_ip(&self) -> Option<&IpAddress> {
        self.last_used_ip.as_ref()
    }

    /// When the key was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Whether the key is paused.
    #[must_use]
    pub fn standing(&self) -> KeyStanding {
        self.standing
    }

    /// Whether the key may sign in at `now`.
    ///
    /// Revoking a key deletes it. So a key that exists works until it
    /// expires, unless it is paused.
    #[must_use]
    pub fn is_active(&self, now: OffsetDateTime) -> bool {
        self.standing == KeyStanding::Working && !self.expires_at.has_passed(now)
    }

    /// Pauses the key, as `control` allows: it signs in no more until it is
    /// resumed. Taking access away needs the right to revoke keys. Raises
    /// `oauth.api_key_paused`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not revoke keys.
    /// - [`DomainError::InvalidTransition`] when the key is paused already.
    pub fn pause(&mut self, control: &OAuthControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(OAuthRight::Revoke)?;
        if self.standing != KeyStanding::Working {
            return Err(DomainError::invalid_transition(message!(
                "oauth-the-key-is-paused-already",
                "the key is paused already"
            )));
        }
        let now = crate::shared::clock::now();
        self.standing = KeyStanding::Paused(now);
        self.raised.raise(ApiKeyPaused {
            key_id: self.id,
            name: self.name.clone(),
            occurred_at: now,
        });
        Ok(())
    }

    /// Resumes a paused key, as `control` allows, so it signs in again.
    /// Giving its access back needs the right to update keys and every
    /// permission the key carries, as making it did. Raises
    /// `oauth.api_key_resumed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not update keys, or
    ///   the key carries a permission they do not hold.
    /// - [`DomainError::InvalidTransition`] when the key is not paused.
    pub fn resume(&mut self, control: &OAuthControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(OAuthRight::Update)?;
        ensure_grantable(&self.scopes, control.holds().system())?;
        if self.standing == KeyStanding::Working {
            return Err(DomainError::invalid_transition(message!(
                "oauth-the-key-is-not-paused",
                "the key is not paused"
            )));
        }
        self.standing = KeyStanding::Working;
        self.raised.raise(ApiKeyResumed {
            key_id: self.id,
            name: self.name.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Records a successful sign-in with this key, from `ip` when the
    /// address is known.
    pub fn record_usage(&mut self, ip: &Fact<IpAddress>) {
        self.last_used_at = Some(crate::shared::clock::now());
        self.last_used_ip = ip.known().cloned();
    }

    /// Notes that the key signed in from `country`, when it could be
    /// placed, and says whether the key now remembers a country it did not.
    /// A country it never signed in from before raises
    /// `oauth.api_key_used_from_new_country`, unless it is the key's first:
    /// a new key's first country is where it lives, not news.
    ///
    /// Ann's deploy key always runs in Germany. One night it signs in from
    /// another country, and a workflow pauses it until someone looks. The
    /// key keeps its last [`MOST_COUNTRIES`] countries, oldest dropped
    /// first.
    pub fn note_country(&mut self, country: Fact<CountryCode>) -> CountryNoted {
        let Fact::Known(country) = country else {
            return CountryNoted::Unchanged;
        };
        if self.seen_countries.contains(&country) {
            return CountryNoted::Unchanged;
        }
        if !self.seen_countries.is_empty() {
            self.raised.raise(ApiKeyUsedFromNewCountry {
                key_id: self.id,
                name: self.name.clone(),
                country: country.clone(),
                occurred_at: crate::shared::clock::now(),
            });
        }
        if self.seen_countries.len() >= MOST_COUNTRIES {
            self.seen_countries.remove(0);
        }
        self.seen_countries.push(country);
        CountryNoted::Added
    }

    /// The countries the key has signed in from, oldest first.
    #[must_use]
    pub fn seen_countries(&self) -> &[CountryCode] {
        &self.seen_countries
    }

    /// Makes every change in `changes`, in order, as `control` allows.
    /// Raises one `oauth.api_key_updated` for them all, naming the key as it
    /// is afterwards; a list with no change raises nothing.
    ///
    /// New scopes need the person changing them to hold everything the key
    /// carries now and everything it is to carry. They widen a key only as
    /// far as they reach themselves, and narrow only a key they could have
    /// made.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not update keys.
    /// - [`DomainError::Forbidden`] when the key now carries a permission the
    ///   person does not hold.
    /// - [`DomainError::Validation`] when new scopes are empty.
    /// - [`DomainError::Validation`] when a new scope names no permission
    ///   this system checks.
    /// - [`DomainError::Forbidden`] when a new scope reaches a permission the
    ///   person does not hold.
    pub fn update(
        &mut self,
        changes: Vec<ApiKeyChange>,
        control: &OAuthControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(OAuthRight::Update)?;
        if changes.is_empty() {
            return Ok(());
        }
        for change in changes {
            self.apply(change, control)?;
        }
        self.raised.raise(ApiKeyUpdated {
            key_id: self.id,
            name: self.name.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Revokes the key for good, as `control` allows. A revoked key is
    /// deleted, so nothing about it changes here. Raises
    /// `oauth.api_key_revoked`, taken once the key is removed from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not revoke keys.
    pub fn revoke(&mut self, control: &OAuthControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(OAuthRight::Revoke)?;
        self.raised.raise(ApiKeyRevoked {
            key_id: self.id,
            name: self.name.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Makes one change, as the person `control` names may.
    fn apply(
        &mut self,
        change: ApiKeyChange,
        control: &OAuthControl<'_>,
    ) -> Result<(), DomainError> {
        match change {
            ApiKeyChange::Rename(name) => self.name = name,
            ApiKeyChange::Scopes(scopes) => self.replace_scopes(scopes, control)?,
        }
        Ok(())
    }

    /// Replaces the scopes the key may be spent on, once the person holds
    /// what it carries now and what it is to carry.
    fn replace_scopes(
        &mut self,
        scopes: Vec<Scope>,
        control: &OAuthControl<'_>,
    ) -> Result<(), DomainError> {
        let held = control.holds().system();
        ensure_grantable(&self.scopes, held).map_err(|_| {
            DomainError::forbidden(message!(
                "oauth-the-key-carries-more-than-the",
                "the key carries more than the person changing it holds"
            ))
        })?;
        validate_scopes(&scopes)?;
        ensure_grantable(&scopes, held)?;
        self.scopes = scopes;
        Ok(())
    }
}

impl<T: TenantScope> Raises for ApiKey<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// The API keys one expiry sweep deleted, across every tenant, and when it
/// ran.
///
/// The sweep removes keys straight from storage, with no key loaded, so
/// this stands in for them: it raises the expiry of each.
#[derive(Debug)]
pub struct ExpiredApiKeys {
    keys: Vec<(TenantId, ApiKeyId, Label)>,
    at: OffsetDateTime,
}

impl ExpiredApiKeys {
    /// The keys `keys` names, each with the tenant it was in and its name,
    /// as deleted by a sweep at `at`.
    #[must_use]
    pub fn swept(keys: Vec<(TenantId, ApiKeyId, Label)>, at: OffsetDateTime) -> Self {
        Self { keys, at }
    }

    /// How many keys expired.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether no key expired.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// One `oauth.api_key_expired` per key, in the order the sweep gave
    /// them, each in the tenant the key was in.
    #[must_use]
    pub fn events(self) -> Vec<DomainEvent> {
        let at = self.at;
        self.keys
            .into_iter()
            .flat_map(|(tenant_id, key_id, name)| {
                let mut raised = Raised::<ResolvedTenant>::default();
                raised.raise(ApiKeyExpired {
                    key_id,
                    name,
                    occurred_at: at,
                });
                raised.take(&SweptFrom(tenant_id))
            })
            .collect()
    }
}

/// The tenant a swept key was deleted from.
struct SweptFrom(TenantId);

impl SavedFor for SweptFrom {
    fn saved_for(&self) -> TenantId {
        self.0
    }
}

impl<T: TenantScope> Sealed for ApiKey<T> {}

impl<T: TenantScope> KeyCharter for ApiKey<T> {
    fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    fn creator(&self) -> &ActorRef {
        &self.created_by
    }

    fn works_at(&self, now: OffsetDateTime) -> bool {
        self.is_active(now)
    }
}

/// Refuses a new key its maker has no right to create, whose scopes they
/// could not grant, or whose expiry cannot hold.
fn ensure_may_create(
    key: &NewApiKey,
    control: &OAuthControl<'_>,
    now: OffsetDateTime,
) -> Result<(), DomainError> {
    control.ensure_may(OAuthRight::Create)?;
    validate_scopes(&key.scopes)?;
    ensure_grantable(&key.scopes, control.holds().system())?;
    ensure_unexpired(&key.expires_at, now)?;
    ensure_within_parent(key.expires_at, key.ends_by)
}

/// Refuses a key whose expiry has already passed at `now`.
fn ensure_unexpired(expires_at: &Expiry, now: OffsetDateTime) -> Result<(), DomainError> {
    if expires_at.has_passed(now) {
        return Err(DomainError::invalid(message!(
            "oauth-the-key-s-expiry-has-already",
            "the key's expiry has already passed"
        )));
    }
    Ok(())
}

/// Refuses `expires_at` for a key made through a key that ends at
/// `ends_by`, sooner than it would. A leaked key would otherwise make a
/// child that outlives it.
fn ensure_within_parent(expires_at: Expiry, ends_by: Expiry) -> Result<(), DomainError> {
    let Some(ceiling) = ends_by.instant() else {
        return Ok(());
    };
    if expires_at.instant().is_none_or(|at| at > ceiling) {
        return Err(DomainError::forbidden(message!(
            "organization-a-key-minted-through-a-key",
            "a key minted through a key ends no later than that key"
        )));
    }
    Ok(())
}

/// Refuses a scope that reaches a permission the person granting the key
/// does not hold, so a key never does more than they could.
fn ensure_grantable(scopes: &[Scope], granted_by: &[SystemPermission]) -> Result<(), DomainError> {
    let beyond = scopes
        .iter()
        .find(|scope| !SystemPermission::may_grant_scope(granted_by, scope));
    let Some(beyond) = beyond else {
        return Ok(());
    };
    Err(DomainError::forbidden(message!(
        "oauth-a-key-may-carry-only-what",
        format!("a key may carry only what its granter holds, and {beyond} is beyond that")
    )))
}

/// Refuses a scope list a key could never spend.
///
/// A key gets in only where a scope names the permission the endpoint needs.
/// A scope like `projects:read` names no permission, so every request with
/// it fails. An empty list fails them all. Saying so when the key is written
/// is clearer than failing at each call.
///
/// # Errors
///
/// - [`DomainError::Validation`] when the list is empty.
/// - [`DomainError::Validation`] naming the first scope that names no
///   permission.
fn validate_scopes(scopes: &[Scope]) -> Result<(), DomainError> {
    validate_count("scopes", scopes.len(), 1..=usize::MAX)?;

    let unknown = scopes
        .iter()
        .find(|s| !SystemPermission::is_recognized_scope(s));

    let Some(unknown) = unknown else {
        return Ok(());
    };

    Err(DomainError::invalid(message!(
        "oauth-scope-names-no-permission",
        format!("scope names no permission: {unknown}")
    )))
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::authorization::permission::{ApiKeyAction, MetricsAction};
    use crate::domains::oauth::control::tests::{holding, key_admin};
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::builders::label;
    use crate::test_support::events::raised_names;

    fn scope(s: &str) -> Scope {
        Scope::new(s).unwrap()
    }

    /// A key made by someone who manages keys and holds every permission.
    fn created(key: NewApiKey) -> Result<ApiKey<ResolvedTenant>, DomainError> {
        ApiKey::create(key, &key_admin())
    }

    fn new_key(scopes: Vec<Scope>) -> NewApiKey {
        NewApiKey {
            id: ApiKeyId::new(),
            name: label("Ops"),
            key_prefix: KeyPrefix::new("ik_live_acme_ops").unwrap(),
            key_hash: TokenHash::from_stored("hash".to_owned()),
            scopes,
            expires_at: Expiry::Never,
            ends_by: Expiry::Never,
        }
    }

    /// Ann's deploy key signs in from Germany first: that is where it
    /// lives, remembered but raising nothing. Germany again changes
    /// nothing. France, never seen before, raises the new-country event
    /// and is remembered.
    #[test]
    fn a_key_signing_in_from_a_new_country_is_recorded() {
        let mut key = created(new_key(vec![scope("idp:metrics:view")])).unwrap();
        raised_names(&mut key);
        let germany = || Fact::Known(CountryCode::new("DE").unwrap());

        let first = key.note_country(germany());
        let again = key.note_country(germany());
        let before_france = raised_names(&mut key);
        let france = key.note_country(Fact::Known(CountryCode::new("FR").unwrap()));

        assert_eq!(
            (first, again, france),
            (
                CountryNoted::Added,
                CountryNoted::Unchanged,
                CountryNoted::Added
            )
        );
        assert!(before_france.is_empty());
        assert_eq!(
            raised_names(&mut key),
            ["oauth.api_key_used_from_new_country"]
        );
        assert_eq!(key.seen_countries().len(), 2);
    }

    /// Sam holds metrics viewing and key management, so creating a key for
    /// user management or adding that scope is forbidden. His existing key
    /// retains only metrics viewing.
    #[test]
    fn a_key_carries_only_what_its_granter_holds() {
        let sam = holding(&[
            SystemPermission::Metrics(MetricsAction::View),
            SystemPermission::ManageApiKeys,
        ]);
        let mut viewing_key =
            ApiKey::<ResolvedTenant>::create(new_key(vec![scope("idp:metrics:view")]), &sam)
                .unwrap();

        let minted =
            ApiKey::<ResolvedTenant>::create(new_key(vec![scope("idp:users:manage")]), &sam);
        let widened = viewing_key.update(
            vec![ApiKeyChange::Scopes(vec![scope("idp:users:manage")])],
            &sam,
        );

        assert!(matches!(minted, Err(DomainError::Forbidden(_))));
        assert!(matches!(widened, Err(DomainError::Forbidden(_))));
        assert_eq!(viewing_key.scopes(), &[scope("idp:metrics:view")]);
    }

    /// Holding metrics viewing and API-key viewing does not permit creating
    /// a metrics key. Creation is forbidden without its own permission.
    #[test]
    fn a_key_is_made_only_with_the_right_to_create_keys() {
        let sam = holding(&[
            SystemPermission::Metrics(MetricsAction::View),
            SystemPermission::ApiKeys(ApiKeyAction::View),
        ]);

        let made = ApiKey::<ResolvedTenant>::create(new_key(vec![scope("idp:metrics:view")]), &sam);

        assert!(matches!(made, Err(DomainError::Forbidden(_))));
    }

    /// Ann makes a key. It records her as its creator, not a name the
    /// caller filled in.
    #[test]
    fn a_key_records_the_person_who_made_it_as_its_creator() {
        let ann = key_admin();

        let key = ApiKey::<ResolvedTenant>::create(new_key(vec![scope("idp:metrics:view")]), &ann)
            .unwrap();

        assert_eq!(key.created_by().audit_label(), ann.actor().audit_label());
    }

    /// A caller who may only view keys cannot rename one. The forbidden
    /// attempt preserves the CI Pipeline name.
    #[test]
    fn a_key_is_renamed_only_with_the_right_to_update_keys() {
        let mut key = test_key();
        let sam = holding(&[SystemPermission::ApiKeys(ApiKeyAction::View)]);

        let renamed = key.update(vec![ApiKeyChange::Rename(label("unused, delete me"))], &sam);

        assert!(matches!(renamed, Err(DomainError::Forbidden(_))));
        assert_eq!(key.name().as_str(), "CI Pipeline");
    }

    /// Updating keys and viewing metrics do not permit narrowing a key that
    /// grants user management. The forbidden change preserves that scope.
    #[test]
    fn a_key_is_narrowed_only_by_someone_who_holds_what_it_carries() {
        let mut key = created(new_key(vec![scope("idp:users:manage")])).unwrap();
        let sam = holding(&[
            SystemPermission::Metrics(MetricsAction::View),
            SystemPermission::ApiKeys(ApiKeyAction::Update),
        ]);

        let narrowed = key.update(
            vec![ApiKeyChange::Scopes(vec![scope("idp:metrics:view")])],
            &sam,
        );

        assert!(matches!(narrowed, Err(DomainError::Forbidden(_))));
        assert_eq!(key.scopes(), &[scope("idp:users:manage")]);
    }

    fn test_key() -> ApiKey<ResolvedTenant> {
        created(NewApiKey {
            id: ApiKeyId::new(),
            name: label("CI Pipeline"),
            key_prefix: KeyPrefix::new("ik_live_acme_ci").unwrap(),
            key_hash: TokenHash::from_stored("hashed_full_key".to_owned()),
            scopes: vec![scope("idp:routing:view"), scope("idp:webhooks:update")],
            expires_at: Expiry::Never,
            ends_by: Expiry::Never,
        })
        .unwrap()
    }

    fn expiring_key() -> ApiKey<ResolvedTenant> {
        created(NewApiKey {
            id: ApiKeyId::new(),
            name: label("Temp Key"),
            key_prefix: KeyPrefix::new("ik_live_acme_temp").unwrap(),
            key_hash: TokenHash::from_stored("hashed_temp".to_owned()),
            scopes: vec![scope("idp:routing:view")],
            expires_at: Expiry::At(crate::shared::clock::now() + Duration::hours(24)),
            ends_by: Expiry::Never,
        })
        .unwrap()
    }

    /// A "CI Pipeline" key that never expires starts active, with its prefix
    /// and two scopes, and has never been used.
    #[test]
    fn create_produces_active_key() {
        let key = test_key();
        let now = crate::shared::clock::now();

        assert!(key.is_active(now));
        assert_eq!(key.name().as_str(), "CI Pipeline");
        assert_eq!(key.key_prefix().as_str(), "ik_live_acme_ci");
        assert_eq!(key.scopes().len(), 2);
        assert_eq!(key.expires_at(), Expiry::Never);
        assert!(key.last_used_at().is_none());
        assert!(key.last_used_ip().is_none());
    }

    /// A key that expires in 24 hours is active now and keeps its expiry
    /// time.
    #[test]
    fn create_with_expiration() {
        let key = expiring_key();
        let now = crate::shared::clock::now();

        assert!(key.is_active(now));
        assert!(matches!(key.expires_at(), Expiry::At(_)));
    }

    /// An admin creates a key that expired an hour ago. It is refused, so a
    /// key never starts out expired.
    #[test]
    fn a_key_whose_expiry_has_passed_is_not_created() {
        let key = created(NewApiKey {
            id: ApiKeyId::new(),
            name: label("Old Key"),
            key_prefix: KeyPrefix::new("ik_live_acme_old").unwrap(),
            key_hash: TokenHash::from_stored("hash".to_owned()),
            scopes: vec![scope("idp:routing:view")],
            expires_at: Expiry::At(crate::shared::clock::now() - Duration::hours(1)),
            ends_by: Expiry::Never,
        });

        assert!(
            matches!(key, Err(DomainError::Validation(_))),
            "a key is never born expired"
        );
    }

    /// Tess gives the contractor's key an end. An end at this very instant
    /// is refused, since the key would never work; a second later is the
    /// earliest end there is.
    #[test]
    fn the_earliest_end_of_a_new_key_is_just_ahead_of_now() {
        let now = crate::shared::clock::now();
        let _frozen = crate::shared::clock::freeze(now);
        let ending_at = |end| NewApiKey {
            expires_at: Expiry::At(end),
            ..new_key(vec![scope("idp:routing:view")])
        };

        let at_this_instant = created(ending_at(now));
        let a_second_ahead = created(ending_at(now + Duration::seconds(1)));

        assert!(matches!(at_this_instant, Err(DomainError::Validation(_))));
        assert!(a_second_ahead.is_ok());
    }

    /// The contractor's key may make keys, and ends on Friday. Keys it
    /// makes end by Friday at the latest: one ending at that instant is
    /// made, one a second later or one that never ends is refused, so a
    /// leaked key cannot leave a successor behind it. A key a person makes
    /// is held to no end.
    #[test]
    fn a_key_made_through_a_key_ends_no_later_than_that_key() {
        let friday = crate::shared::clock::now() + Duration::days(4);
        let through_the_contractors_key = |expires_at| NewApiKey {
            expires_at,
            ends_by: Expiry::At(friday),
            ..new_key(vec![scope("idp:routing:view")])
        };

        let on_friday = created(through_the_contractors_key(Expiry::At(friday)));
        let a_second_later = created(through_the_contractors_key(Expiry::At(
            friday + Duration::seconds(1),
        )));
        let for_ever = created(through_the_contractors_key(Expiry::Never));
        let by_a_person = created(new_key(vec![scope("idp:routing:view")]));

        assert!(on_friday.is_ok());
        assert!(matches!(a_second_later, Err(DomainError::Forbidden(_))));
        assert!(matches!(for_ever, Err(DomainError::Forbidden(_))));
        assert_eq!(by_a_person.unwrap().expires_at(), Expiry::Never);
    }

    /// A key that never expires is still active a hundred years from now.
    #[test]
    fn non_expiring_key_always_active() {
        let key = test_key();
        let far_future = crate::shared::clock::now() + Duration::days(365 * 100);

        assert!(key.is_active(far_future));
    }

    /// A key signs in from 10.0.0.1. It records the time and that address.
    #[test]
    fn record_usage_sets_timestamp_and_ip() {
        let mut key = test_key();

        key.record_usage(&Fact::Known(IpAddress::new("10.0.0.1").unwrap()));

        assert!(key.last_used_at().is_some());
        assert_eq!(key.last_used_ip().map(IpAddress::as_str), Some("10.0.0.1"));
    }

    /// A key signs in with no known address. It records the time and no
    /// address.
    #[test]
    fn record_usage_without_ip() {
        let mut key = test_key();

        key.record_usage(&Fact::Unknown);

        assert!(key.last_used_at().is_some());
        assert!(key.last_used_ip().is_none());
    }

    /// "CI Pipeline" is renamed "Production Pipeline" and shows the new
    /// name.
    #[test]
    fn rename_updates_name() {
        let mut key = test_key();

        key.update(
            vec![ApiKeyChange::Rename(label("Production Pipeline"))],
            &key_admin(),
        )
        .unwrap();

        assert_eq!(key.name().as_str(), "Production Pipeline");
    }

    /// A key with two scopes is given just `idp:metrics:view`. It now holds
    /// that one scope, not three.
    #[test]
    fn replacing_scopes_replaces_them_all() {
        let mut key = test_key();

        key.update(
            vec![ApiKeyChange::Scopes(vec![scope("idp:metrics:view")])],
            &key_admin(),
        )
        .unwrap();

        assert_eq!(key.scopes().len(), 1);
    }

    /// A key with the scope `projects:read` is refused. That scope names no
    /// permission, so every request with it would fail.
    #[test]
    fn create_rejects_a_scope_naming_no_permission() {
        let err = created(NewApiKey {
            id: ApiKeyId::new(),
            name: label("Legacy"),
            key_prefix: KeyPrefix::new("ik_live_acme_legacy").unwrap(),
            key_hash: TokenHash::from_stored("hash".to_owned()),
            scopes: vec![scope("projects:read")],
            expires_at: Expiry::Never,
            ends_by: Expiry::Never,
        })
        .unwrap_err();

        assert!(matches!(err, DomainError::Validation(_)));
    }

    /// A key with no scopes is refused, since it could do nothing.
    #[test]
    fn create_rejects_an_empty_scope_list() {
        let err = created(NewApiKey {
            id: ApiKeyId::new(),
            name: label("Toothless"),
            key_prefix: KeyPrefix::new("ik_live_acme_none").unwrap(),
            key_hash: TokenHash::from_stored("hash".to_owned()),
            scopes: vec![],
            expires_at: Expiry::Never,
            ends_by: Expiry::Never,
        })
        .unwrap_err();

        assert!(matches!(err, DomainError::Validation(_)));
    }

    /// Changing a key's scopes to `projects:read` is refused, and the key
    /// keeps its two scopes.
    #[test]
    fn a_refused_scope_change_leaves_the_key_untouched() {
        let mut key = test_key();

        assert!(
            key.update(
                vec![ApiKeyChange::Scopes(vec![scope("projects:read")])],
                &key_admin()
            )
            .is_err()
        );
        assert_eq!(key.scopes().len(), 2);
    }

    /// A key an org user made, last used from 192.168.1.1, is loaded from
    /// storage. Every field reads back, and the creator is still the org
    /// user.
    #[test]
    fn reconstitute_preserves_all_fields() {
        let id = ApiKeyId::new();
        let user = ActorRef::OrgUser(crate::types::OrgUserId::new());
        let now = crate::shared::clock::now();

        let key = ApiKey::<ResolvedTenant>::reconstitute(ApiKeyRow {
            id,
            name: label("Test Key"),
            key_prefix: KeyPrefix::new("ik_live_test").unwrap(),
            key_hash: TokenHash::from_stored("hash789".to_owned()),
            scopes: vec![Scope::new("idp:routing:view").unwrap()],
            created_by: user.clone(),
            expires_at: Expiry::At(now + Duration::days(30)),
            last_used_at: Some(now),
            last_used_ip: Some(IpAddress::new("192.168.1.1").unwrap()),
            seen_countries: Vec::new(),
            created_at: now,
            standing: KeyStanding::Working,
        })
        .unwrap();

        assert_eq!(*key.id(), id);
        assert_eq!(key.name().as_str(), "Test Key");
        assert_eq!(key.key_prefix().as_str(), "ik_live_test");
        assert_eq!(key.key_hash().as_str(), "hash789");
        assert_eq!(key.created_by().audit_label(), user.audit_label());
        assert!(matches!(key.expires_at(), Expiry::At(_)));
        assert_eq!(
            key.last_used_ip().map(IpAddress::as_str),
            Some("192.168.1.1")
        );
    }

    /// One second before expiry the key is active. At the expiry instant it
    /// is not, so it never signs in after the time the tenant set.
    #[test]
    fn a_key_stops_being_active_at_the_instant_it_expires() {
        let key = expiring_key();
        let expiry = key.expires_at().instant().expect("an expiring key");

        assert!(key.is_active(expiry - Duration::seconds(1)));
        assert!(!key.is_active(expiry));
    }

    fn stored(key: &ApiKey<ResolvedTenant>) -> ApiKeyRow {
        ApiKeyRow {
            id: key.id,
            name: key.name.clone(),
            key_prefix: key.key_prefix.clone(),
            key_hash: key.key_hash.clone(),
            scopes: key.scopes.clone(),
            created_by: key.created_by.clone(),
            expires_at: key.expires_at,
            last_used_at: key.last_used_at,
            last_used_ip: key.last_used_ip.clone(),
            seen_countries: key.seen_countries.clone(),
            created_at: key.created_at,
            standing: key.standing,
        }
    }

    /// Ann pauses the deploy key: it signs in no more and the pause is
    /// raised. She resumes it, and it signs in again.
    #[test]
    fn a_paused_key_stops_signing_in_until_it_is_resumed() {
        let mut key = fresh_key();
        let now = crate::shared::clock::now();

        key.pause(&key_admin()).unwrap();
        let while_paused = key.is_active(now);
        key.resume(&key_admin()).unwrap();

        assert!(!while_paused);
        assert!(key.is_active(now));
        assert_eq!(
            raised_names(&mut key),
            ["oauth.api_key_paused", "oauth.api_key_resumed"]
        );
    }

    /// Sam's revoke permission allows pausing a user-management key. Resuming
    /// it is forbidden because he lacks its scope, so the key stays paused.
    #[test]
    fn a_key_is_resumed_only_by_someone_who_holds_what_it_carries() {
        let mut key = created(new_key(vec![scope("idp:users:manage")])).unwrap();
        let sam = holding(&[
            SystemPermission::Metrics(MetricsAction::View),
            SystemPermission::ApiKeys(ApiKeyAction::Revoke),
            SystemPermission::ApiKeys(ApiKeyAction::Update),
        ]);

        key.pause(&sam).unwrap();
        let resumed = key.resume(&sam);

        assert!(matches!(resumed, Err(DomainError::Forbidden(_))));
        assert!(matches!(key.standing(), KeyStanding::Paused(_)));
    }

    /// A key is not paused twice, nor resumed while working.
    #[test]
    fn only_a_working_key_pauses_and_only_a_paused_key_resumes() {
        let mut key = fresh_key();

        let resumed = key.resume(&key_admin());
        key.pause(&key_admin()).unwrap();
        let paused_again = key.pause(&key_admin());

        assert!(matches!(resumed, Err(DomainError::InvalidTransition(_))));
        assert!(matches!(
            paused_again,
            Err(DomainError::InvalidTransition(_))
        ));
    }

    /// A stored key with no scopes is refused as corrupt.
    #[test]
    fn a_stored_key_that_grants_nothing_is_refused() {
        let mut row = stored(&test_key());
        row.scopes.clear();

        assert!(refused_as_corrupt(&ApiKey::<ResolvedTenant>::reconstitute(
            row
        )));
    }

    /// A stored key has a last-use address but no last-use time. It is
    /// refused as corrupt.
    #[test]
    fn a_stored_key_with_the_address_of_a_use_that_never_happened_is_refused() {
        let mut row = stored(&test_key());
        row.last_used_at = None;
        row.last_used_ip = Some(IpAddress::new("203.0.113.9").unwrap());

        assert!(refused_as_corrupt(&ApiKey::<ResolvedTenant>::reconstitute(
            row
        )));
    }

    /// "CI Pipeline", with its creation taken out.
    fn fresh_key() -> ApiKey<ResolvedTenant> {
        let mut key = test_key();
        raised_names(&mut key);
        key
    }

    /// An admin makes "CI Pipeline". The creation is raised.
    #[test]
    fn creating_raises_oauth_api_key_created() {
        let mut key = test_key();

        assert_eq!(raised_names(&mut key), ["oauth.api_key_created"]);
    }

    /// "CI Pipeline" is read back from storage and signs in. Neither is a
    /// change worth a record, so nothing is raised.
    #[test]
    fn a_key_read_back_from_storage_has_raised_nothing() {
        let mut read_back = ApiKey::<ResolvedTenant>::reconstitute(stored(&test_key())).unwrap();

        read_back.record_usage(&Fact::Unknown);

        assert!(raised_names(&mut read_back).is_empty());
    }

    /// An admin renames "CI Pipeline" and narrows it in one edit. One
    /// update is raised.
    #[test]
    fn an_update_raises_one_oauth_api_key_updated() {
        let mut key = fresh_key();

        key.update(
            vec![
                ApiKeyChange::Rename(label("Production Pipeline")),
                ApiKeyChange::Scopes(vec![scope("idp:metrics:view")]),
            ],
            &key_admin(),
        )
        .unwrap();

        assert_eq!(raised_names(&mut key), ["oauth.api_key_updated"]);
    }

    /// An admin sends an edit that changes nothing. Nothing is raised.
    #[test]
    fn an_update_with_no_change_raises_nothing() {
        let mut key = fresh_key();

        key.update(Vec::new(), &key_admin()).unwrap();

        assert!(raised_names(&mut key).is_empty());
    }

    /// An admin revokes "CI Pipeline". The revoke is raised.
    #[test]
    fn revoking_raises_oauth_api_key_revoked() {
        let mut key = fresh_key();

        key.revoke(&key_admin()).unwrap();

        assert_eq!(raised_names(&mut key), ["oauth.api_key_revoked"]);
    }

    /// A viewer's rename and revocation attempts fail, as does an admin's
    /// addition of an unknown scope. None raises an event.
    #[test]
    fn a_refused_change_raises_nothing() {
        let mut key = fresh_key();
        let sam = holding(&[SystemPermission::ApiKeys(ApiKeyAction::View)]);

        let renamed = key.update(vec![ApiKeyChange::Rename(label("Sam's"))], &sam);
        let revoked = key.revoke(&sam);
        let unknown = key.update(
            vec![ApiKeyChange::Scopes(vec![scope("projects:read")])],
            &key_admin(),
        );

        assert!(renamed.is_err());
        assert!(revoked.is_err());
        assert!(unknown.is_err());
        assert!(raised_names(&mut key).is_empty());
    }

    /// A sweep deleted Acme's "CI Pipeline" and Globex's "Nightly". One
    /// expiry is raised for each, in that order, each in its own tenant.
    #[test]
    fn a_sweep_raises_oauth_api_key_expired_for_each_key_in_its_tenant() {
        let acme = TenantId::new();
        let globex = TenantId::new();
        let sweep = ExpiredApiKeys::swept(
            vec![
                (acme, ApiKeyId::new(), label("CI Pipeline")),
                (globex, ApiKeyId::new(), label("Nightly")),
            ],
            crate::shared::clock::now(),
        );

        let events = sweep.events();

        let names: Vec<String> = events.iter().map(|e| e.event_type().to_string()).collect();
        assert_eq!(names, ["oauth.api_key_expired", "oauth.api_key_expired"]);
        assert_eq!(events[0].tenant_id(), Some(&acme));
        assert_eq!(events[1].tenant_id(), Some(&globex));
    }
}
