//! Organization API keys, which let machines sign in for org-level
//! automation such as CI/CD, scripts and Terraform.
//!
//! Key format: `oak_{org_slug}_{secret}`
//! - The `oak_` prefix lets secret scanners find leaked keys in git.
//! - The org slug helps when debugging.
//! - The secret is hashed and never stored in plain text.

use time::OffsetDateTime;

use crate::domains::organization::events::access::{OrgApiKeyCreated, OrgApiKeyRevoked};
use crate::domains::organization::members::control::{Carried, OrgControl, ensure_platform_or_may};
use crate::domains::organization::members::permission::{OrgApiKeyAction, OrgPermission};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{RaisedEvents, RaisesComplete};
use crate::shared::model::row_check::RowCheck;
use crate::shared::model::transition::{InvalidTransition, checked};
use crate::shared::validation::numeric::validate_count;
use crate::types::{
    ActedBy, EventLabel, Expiry, KeyPrefix, Label, OrgApiKeyId, OrgUserId, OrganizationId, Scope,
    TokenHash,
};

/// Whether an organization API key still authenticates.
///
/// A revoked key stays on record so its past use can be audited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrgApiKeyStatus {
    /// The key works.
    Active,
    /// The key was revoked and authenticates nothing.
    Revoked,
}

impl OrgApiKeyStatus {
    /// Moves to `to` if a key in this status may. The only move is from
    /// active to revoked.
    ///
    /// # Errors
    ///
    /// - [`InvalidTransition`] for any other move.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
        checked(self, to, |from, to| {
            from == Self::Active && to == Self::Revoked
        })
    }
}

/// What a key was minted through: its creator's session, or another key.
///
/// A key minted through a key lives no longer than it, and revoking that
/// key is how the keys minted through it are found. Without the record, a
/// leaked key mints a child, the leaked key is revoked, and the child keeps
/// working.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintedThrough {
    /// The creator's own signed-in session.
    Session,
    /// Another key of the creator's, named by its id.
    Key(OrgApiKeyId),
}

/// An organization-scoped API key.
#[derive(Debug, Clone)]
pub struct OrgApiKey {
    id: OrgApiKeyId,
    organization_id: OrganizationId,
    name: Label,
    key_prefix: KeyPrefix,
    key_hash: TokenHash,
    scopes: Vec<Scope>,
    created_by: OrgUserId,
    minted_through: MintedThrough,
    expires_at: Expiry,
    last_used_at: Option<OffsetDateTime>,
    status: OrgApiKeyStatus,
    created_at: OffsetDateTime,
    raised: RaisedEvents,
}

/// Parameters for creating a new org API key.
pub struct CreateOrgApiKeyParams {
    /// Unique ID.
    pub id: OrgApiKeyId,
    /// The owning organization.
    pub organization_id: OrganizationId,
    /// Human-readable name, such as "CI/CD Pipeline".
    pub name: Label,
    /// Scannable prefix stored in plaintext.
    pub key_prefix: KeyPrefix,
    /// HMAC hash of the full key.
    pub key_hash: TokenHash,
    /// What the key may do, as `org:<domain>:<action>` scopes.
    pub scopes: Vec<Scope>,
    /// When the key stops working, or that it never does.
    pub expires_at: Expiry,
}

/// A key as stored, for rebuilding it with [`OrgApiKey::reconstitute`].
pub struct OrgApiKeyRow {
    /// Unique ID.
    pub id: OrgApiKeyId,
    /// The owning organization.
    pub organization_id: OrganizationId,
    /// Human-readable name.
    pub name: Label,
    /// Scannable prefix.
    pub key_prefix: KeyPrefix,
    /// HMAC hash.
    pub key_hash: TokenHash,
    /// What the key may do.
    pub scopes: Vec<Scope>,
    /// Who created this key.
    pub created_by: OrgUserId,
    /// What the key was minted through.
    pub minted_through: MintedThrough,
    /// When the key stops working, or that it never does.
    pub expires_at: Expiry,
    /// Last used timestamp.
    pub last_used_at: Option<OffsetDateTime>,
    /// Whether the key still authenticates.
    pub status: OrgApiKeyStatus,
    /// When created.
    pub created_at: OffsetDateTime,
}

impl OrgApiKey {
    /// Creates a new active org API key, minted by `by`.
    ///
    /// The key acts as its creator, so it never carries more than they do
    /// now. Sam may only view tenants. Without this check he mints a key
    /// that manages them. A key minting a key passes on no more than its own
    /// scopes, and ends no later than it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] if `by` may not mint keys in the
    ///   organization.
    /// - [`DomainError::Validation`] if the scopes are empty, or one names no
    ///   permission on this plane.
    /// - [`DomainError::Forbidden`] if a scope reaches a permission `by`
    ///   does not carry.
    /// - [`DomainError::Validation`] if the expiry has already passed. A key
    ///   that is expired when made is a mistake.
    /// - [`DomainError::Forbidden`] if `by` acts through a key and the new
    ///   key would end later than it, or never.
    pub fn create(params: CreateOrgApiKeyParams, by: &OrgControl<'_>) -> Result<Self, DomainError> {
        by.ensure_may(
            &params.organization_id,
            OrgPermission::ApiKeys(OrgApiKeyAction::Create),
        )?;
        validate_scopes(&params.scopes)?;
        ensure_grantable(&params.scopes, &by.held())?;
        if params.expires_at.has_passed(crate::shared::clock::now()) {
            return Err(DomainError::invalid(message!(
                "oauth-the-key-s-expiry-has-already",
                "the key's expiry has already passed"
            )));
        }
        ensure_within_parent(params.expires_at, by)?;

        let mut key = Self {
            id: params.id,
            organization_id: params.organization_id,
            name: params.name,
            key_prefix: params.key_prefix,
            key_hash: params.key_hash,
            scopes: params.scopes,
            created_by: *by.by().id(),
            minted_through: minted_through(by),
            expires_at: params.expires_at,
            last_used_at: None,
            status: OrgApiKeyStatus::Active,
            created_at: crate::shared::clock::now(),
            raised: RaisedEvents::default(),
        };
        key.raise_created();
        Ok(key)
    }

    /// Raises the key's creation, naming it by its name.
    fn raise_created(&mut self) {
        self.raised.raise_organization(OrgApiKeyCreated {
            organization_id: self.organization_id,
            key_id: self.id,
            name: self.name.clone(),
            occurred_at: self.created_at,
        });
    }

    /// Rebuilds an organization API key from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row grants nothing, or names
    ///   a scope that is no permission.
    /// - [`DomainError::Infrastructure`] when the row says the key was used,
    ///   or expires, before it was created.
    /// - [`DomainError::Infrastructure`] when the row says the key was
    ///   minted through itself.
    pub fn reconstitute(row: OrgApiKeyRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            organization_id: row.organization_id,
            name: row.name,
            key_prefix: row.key_prefix,
            key_hash: row.key_hash,
            scopes: row.scopes,
            created_by: row.created_by,
            minted_through: row.minted_through,
            expires_at: row.expires_at,
            last_used_at: row.last_used_at,
            status: row.status,
            created_at: row.created_at,
            raised: RaisedEvents::default(),
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &OrgApiKeyRow) -> Result<(), DomainError> {
        RowCheck::of("organization API key")
            .holds(
                validate_scopes(&row.scopes).is_ok(),
                "a key that grants nothing, or a scope naming no permission",
            )
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
                row.minted_through != MintedThrough::Key(row.id),
                "minted through itself",
            )
            .finish()
    }

    /// The key's unique ID.
    #[must_use]
    pub fn id(&self) -> &OrgApiKeyId {
        &self.id
    }

    /// The owning organization.
    #[must_use]
    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// Human-readable name.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// The scannable prefix, such as `oak_acme_01J...`.
    #[must_use]
    pub fn key_prefix(&self) -> &KeyPrefix {
        &self.key_prefix
    }

    /// The HMAC hash of the full key.
    #[must_use]
    pub fn key_hash(&self) -> &TokenHash {
        &self.key_hash
    }

    /// What the key may do.
    #[must_use]
    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// Who created this key.
    #[must_use]
    pub fn created_by(&self) -> &OrgUserId {
        &self.created_by
    }

    /// What the key was minted through: its creator's session, or the key
    /// whose revocation should also revoke this one.
    #[must_use]
    pub fn minted_through(&self) -> MintedThrough {
        self.minted_through
    }

    /// When the key stops working, or that it never does.
    #[must_use]
    pub fn expires_at(&self) -> Expiry {
        self.expires_at
    }

    /// When the key was last used.
    #[must_use]
    pub fn last_used_at(&self) -> Option<OffsetDateTime> {
        self.last_used_at
    }

    /// Whether the key still authenticates or was revoked, as storage keeps
    /// it.
    #[must_use]
    pub fn status(&self) -> OrgApiKeyStatus {
        self.status
    }

    /// Whether the key has been revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.status == OrgApiKeyStatus::Revoked
    }

    /// Whether the key is expired. It is from its expiry instant on.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at.has_passed(crate::shared::clock::now())
    }

    /// Whether the key is active, meaning neither revoked nor expired.
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.is_revoked() && !self.is_expired()
    }

    /// When the key was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Revokes the key, as `by` decides: its creator, a member who may
    /// revoke keys, or the platform, as when the creator leaves.
    /// Irreversible. Raises `organization.org_api_key_revoked`, naming the
    /// key by its name.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] if someone other than the creator
    ///   revokes it without the right.
    /// - [`DomainError::InvalidTransition`] if it is already revoked.
    pub fn revoke(&mut self, by: ActedBy<OrgControl<'_>>) -> Result<(), DomainError> {
        self.ensure_may_revoke(by)?;
        self.status = self.status.try_transition(OrgApiKeyStatus::Revoked)?;
        self.raised.raise_organization(OrgApiKeyRevoked {
            organization_id: self.organization_id,
            key_id: self.id,
            key_label: EventLabel::of(self.name.as_str()),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Refuses `by` revoking this key unless it is the creator, the
    /// platform, or a member who may revoke keys.
    fn ensure_may_revoke(&self, by: ActedBy<OrgControl<'_>>) -> Result<(), DomainError> {
        match by {
            ActedBy::By(control) if control.is_member(&self.created_by) => {
                control.ensure_genuine(&self.organization_id)
            }
            ActedBy::By(_) | ActedBy::Platform => ensure_platform_or_may(
                by,
                &self.organization_id,
                OrgPermission::ApiKeys(OrgApiKeyAction::Revoke),
            ),
        }
    }

    /// Records that the key was used now.
    pub fn record_usage(&mut self) {
        self.last_used_at = Some(crate::shared::clock::now());
    }
}

impl RaisesComplete for OrgApiKey {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

/// What `by` mints a key through.
fn minted_through(by: &OrgControl<'_>) -> MintedThrough {
    match by.carries() {
        Carried::Session(_) => MintedThrough::Session,
        Carried::Key(parent) => MintedThrough::Key(*parent.id()),
    }
}

/// Refuses `expires_at` for a key minted through a key that ends sooner.
/// A leaked key would otherwise mint a child that outlives it.
fn ensure_within_parent(expires_at: Expiry, by: &OrgControl<'_>) -> Result<(), DomainError> {
    let Carried::Key(parent) = by.carries() else {
        return Ok(());
    };
    let Some(ceiling) = parent.expires_at().instant() else {
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

/// Refuses a scope that reaches beyond what the key's creator holds.
fn ensure_grantable(scopes: &[Scope], granted_by: &[OrgPermission]) -> Result<(), DomainError> {
    let beyond = scopes
        .iter()
        .find(|scope| !OrgPermission::may_grant_scope(granted_by, scope));
    let Some(beyond) = beyond else {
        return Ok(());
    };
    Err(DomainError::forbidden(message!(
        "oauth-a-key-may-carry-only-what",
        format!("a key may carry only what its granter holds, and {beyond} is beyond that")
    )))
}

/// Rejects a scope list a key could never spend.
///
/// A key is admitted only where its scopes name the permission the endpoint
/// needs. So an unknown scope is refused on every request, and an empty list
/// refuses them all. It is better to say so when the key is made than at
/// every call that fails.
///
/// # Errors
///
/// - [`DomainError::Validation`] when the list is empty.
/// - [`DomainError::Validation`] naming the first scope that names no org
///   permission.
fn validate_scopes(scopes: &[Scope]) -> Result<(), DomainError> {
    validate_count("scopes", scopes.len(), 1..=usize::MAX)?;

    let unknown = scopes
        .iter()
        .find(|s| !OrgPermission::is_recognized_scope(s));

    let Some(unknown) = unknown else {
        return Ok(());
    };

    Err(DomainError::invalid(message!(
        "organization-scope-names-no-org-permission",
        format!("scope names no org permission: {unknown}")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::organization::lifecycle::tests::founding_of;
    use crate::domains::organization::members::control::tests::{acting, key_of, session_of};
    use crate::domains::organization::members::membership::OrgRole;
    use crate::domains::organization::members::org_user::{
        AddedBy, CreateOrgUserParams, OrgPassword, OrgUser,
    };
    use crate::domains::organization::status::{OrgStanding, OrganizationStatus};
    use crate::shared::config::DisplayNameLimits;
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::types::{DisplayName, Email};

    /// Acme, the organization every key here is minted for.
    fn acme() -> OrganizationId {
        OrganizationId::from_uuid(uuid::Uuid::from_u128(7))
    }

    fn params() -> CreateOrgApiKeyParams {
        CreateOrgApiKeyParams {
            id: OrgApiKeyId::new(),
            organization_id: acme(),
            name: Label::new("key_name", "CI Pipeline").unwrap(),
            key_prefix: KeyPrefix::new("oak_acme_01J").unwrap(),
            key_hash: TokenHash::from_stored("hash123".to_owned()),
            scopes: vec![Scope::new("org:tenants:view").unwrap()],
            expires_at: Expiry::Never,
        }
    }

    /// Someone in Acme with `role`.
    fn person(role: OrgRole) -> OrgUser {
        let params = |role| CreateOrgUserParams {
            id: OrgUserId::new(),
            organization_id: acme(),
            email: Email::new("ann@acme.com").unwrap(),
            display_name: DisplayName::new("Ann", &DisplayNameLimits::default()).unwrap(),
            password_hash: OrgPassword::NotSet,
            role,
        };
        let founder = OrgUser::create(
            params(OrgRole::Owner),
            AddedBy::Founding(founding_of(acme())),
        )
        .unwrap();
        if role == OrgRole::Owner {
            return founder;
        }
        let session = session_of(&founder);
        OrgUser::create(params(role), AddedBy::Member(acting(&founder, &session))).unwrap()
    }

    /// A key Ann, an owner of Acme, mints through her own session.
    fn created(params: CreateOrgApiKeyParams) -> Result<OrgApiKey, DomainError> {
        let ann = person(OrgRole::Owner);
        let session = session_of(&ann);
        OrgApiKey::create(params, &acting(&ann, &session))
    }

    /// A parent key with tenant-view and key-creation rights cannot grant
    /// tenant management or wildcard rights, but can grant tenant viewing.
    #[test]
    fn a_key_carries_only_what_its_creator_holds() {
        let ann = person(OrgRole::Owner);
        let parent = key_of(&ann, &["org:tenants:view", "org:api_keys:create"]);
        let by = OrgControl::new(
            OrgStanding::new(*ann.organization_id(), OrganizationStatus::Active),
            &ann,
            Carried::Key(&parent),
        );
        let wider = |scope: &str| CreateOrgApiKeyParams {
            scopes: vec![Scope::new(scope).unwrap()],
            ..params()
        };

        let managing = OrgApiKey::create(wider("org:tenants:manage"), &by);
        let wildcard = OrgApiKey::create(wider("org:tenants:*"), &by);
        let viewing = OrgApiKey::create(wider("org:tenants:view"), &by);

        assert!(matches!(managing, Err(DomainError::Forbidden(_))));
        assert!(matches!(wildcard, Err(DomainError::Forbidden(_))));
        assert!(viewing.is_ok());
    }

    /// A child key cannot expire after its parent or remain valid forever;
    /// an earlier expiry is accepted.
    #[test]
    fn a_key_minted_through_a_key_ends_no_later_than_it() {
        let ann = person(OrgRole::Owner);
        let tomorrow = crate::shared::clock::now() + time::Duration::days(1);
        let parent = dated_key_of(&ann, Expiry::At(tomorrow));
        let by = OrgControl::new(
            OrgStanding::new(*ann.organization_id(), OrganizationStatus::Active),
            &ann,
            Carried::Key(&parent),
        );
        let ending = |expires_at| CreateOrgApiKeyParams {
            expires_at,
            ..params()
        };
        let next_week = tomorrow + time::Duration::days(6);
        let tonight = tomorrow - time::Duration::hours(1);

        let never = OrgApiKey::create(ending(Expiry::Never), &by);
        let later = OrgApiKey::create(ending(Expiry::At(next_week)), &by);
        let sooner = OrgApiKey::create(ending(Expiry::At(tonight)), &by);

        assert!(matches!(never, Err(DomainError::Forbidden(_))));
        assert!(matches!(later, Err(DomainError::Forbidden(_))));
        assert!(sooner.is_ok());
    }

    /// Ann's script mints a key through her CI key. The child names that
    /// key as the one it was minted through, so revoking the parent can
    /// find it. A key Ann mints through her session names her session.
    #[test]
    fn a_key_records_what_it_was_minted_through() {
        let ann = person(OrgRole::Owner);
        let parent = key_of(&ann, &["org:tenants:view", "org:api_keys:create"]);
        let session = session_of(&ann);
        let by_key = OrgControl::new(
            OrgStanding::new(*ann.organization_id(), OrganizationStatus::Active),
            &ann,
            Carried::Key(&parent),
        );

        let child = OrgApiKey::create(params(), &by_key).unwrap();
        let direct = OrgApiKey::create(params(), &acting(&ann, &session)).unwrap();

        assert_eq!(child.minted_through(), MintedThrough::Key(*parent.id()));
        assert_eq!(direct.minted_through(), MintedThrough::Session);
    }

    /// A stored key names itself as the key it was minted through. Loading
    /// it is refused as a corrupt row, since no key mints itself.
    #[test]
    fn a_stored_key_minted_through_itself_is_refused() {
        let key = created(params()).unwrap();
        let row = OrgApiKeyRow {
            minted_through: MintedThrough::Key(key.id),
            ..stored(&key)
        };

        assert!(refused_as_corrupt(&OrgApiKey::reconstitute(row)));
    }

    /// A key `member` minted, able to mint keys, that ends at `expires_at`.
    fn dated_key_of(member: &OrgUser, expires_at: Expiry) -> OrgApiKey {
        let key = key_of(member, &["org:tenants:view", "org:api_keys:create"]);
        OrgApiKey::reconstitute(OrgApiKeyRow {
            expires_at,
            created_at: crate::shared::clock::now() - time::Duration::minutes(1),
            ..stored(&key)
        })
        .unwrap()
    }

    /// The row `key` would be stored as.
    fn stored(key: &OrgApiKey) -> OrgApiKeyRow {
        OrgApiKeyRow {
            id: key.id,
            organization_id: key.organization_id,
            name: key.name.clone(),
            key_prefix: key.key_prefix.clone(),
            key_hash: key.key_hash.clone(),
            scopes: key.scopes.clone(),
            created_by: key.created_by,
            minted_through: key.minted_through,
            expires_at: key.expires_at,
            last_used_at: key.last_used_at,
            status: key.status,
            created_at: key.created_at,
        }
    }

    /// A plain member cannot create a key even with scopes the member personally holds.
    #[test]
    fn a_plain_member_mints_no_key() {
        let sam = person(OrgRole::Member);
        let session = session_of(&sam);

        let result = OrgApiKey::create(params(), &acting(&sam, &session));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A plain member cannot revoke Ann's key; Ann can revoke it herself.
    #[test]
    fn only_the_creator_or_a_manager_revokes_a_key() {
        let ann = person(OrgRole::Owner);
        let sam = person(OrgRole::Member);
        let (anns, sams) = (session_of(&ann), session_of(&sam));
        let mut key = OrgApiKey::create(params(), &acting(&ann, &anns)).unwrap();

        let by_sam = key.revoke(ActedBy::By(acting(&sam, &sams)));
        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        key.revoke(ActedBy::By(acting(&ann, &anns))).unwrap();

        assert!(key.is_revoked());
    }

    /// A CI pipeline key is made with no expiry. It is active, not revoked
    /// and not expired.
    #[test]
    fn new_key_is_active() {
        let key = created(params()).unwrap();
        assert!(key.is_active());
        assert!(!key.is_revoked());
        assert!(!key.is_expired());
    }

    /// An admin revokes a leaked CI key. It reads as revoked and no longer
    /// active.
    #[test]
    fn revoked_key_is_not_active() {
        let mut key = created(params()).unwrap();
        key.revoke(ActedBy::Platform).unwrap();
        assert!(!key.is_active());
        assert!(key.is_revoked());
    }

    /// A key made to last one hour is checked an hour after it ran out. It
    /// reads as expired and no longer active, though nobody revoked it.
    #[test]
    fn expired_key_is_not_active() {
        let expiry = crate::shared::clock::now() + time::Duration::hours(1);
        let mut p = params();
        p.expires_at = Expiry::At(expiry);
        let key = created(p).unwrap();

        let _frozen = crate::shared::clock::freeze(expiry + time::Duration::hours(1));
        assert!(!key.is_active());
        assert!(key.is_expired());
    }

    /// An admin asks for a key that expired an hour ago. It is refused, since
    /// a key dead on arrival is a mistake.
    #[test]
    fn a_key_whose_expiry_has_passed_is_not_created() {
        let mut p = params();
        p.expires_at = Expiry::At(crate::shared::clock::now() - time::Duration::hours(1));

        assert!(matches!(created(p), Err(DomainError::Validation(_))));
    }

    /// An admin asks for a key with no scopes. It is refused, since such a
    /// key would be turned away by every endpoint.
    #[test]
    fn create_rejects_an_empty_scope_list() {
        let mut p = params();
        p.scopes = Vec::new();

        assert!(matches!(created(p), Err(DomainError::Validation(_))));
    }

    /// An admin asks for a key with `org:projects:read`, which names no org
    /// permission. It is refused when the key is made, not at every call.
    #[test]
    fn create_rejects_a_scope_naming_no_org_permission() {
        let mut p = params();
        p.scopes = vec![Scope::new("org:projects:read").unwrap()];

        assert!(matches!(created(p), Err(DomainError::Validation(_))));
    }

    /// Ann mints a key for Acme. It gives back its id, organization, prefix,
    /// hash and scopes as given, and names Ann as its creator, since lookup
    /// and checks rest on each of them.
    #[test]
    fn a_key_reports_the_prefix_hash_and_scopes_it_was_created_with() {
        let id = OrgApiKeyId::new();
        let ann = person(OrgRole::Owner);
        let session = session_of(&ann);
        let mut p = params();
        p.id = id;

        let key = OrgApiKey::create(p, &acting(&ann, &session)).unwrap();

        assert_eq!(*key.id(), id);
        assert_eq!(*key.organization_id(), acme());
        assert_eq!(key.key_prefix().as_str(), "oak_acme_01J");
        assert_eq!(key.key_hash().as_str(), "hash123");
        assert_eq!(key.scopes(), &[Scope::new("org:tenants:view").unwrap()]);
        assert_eq!(key.created_by(), ann.id());
    }

    /// A key id is rebuilt from a stored uuid. It gives back that uuid, so
    /// no two keys load under the same id.
    #[test]
    fn an_id_carries_the_uuid_it_was_built_from() {
        let raw = uuid::Uuid::now_v7();

        assert_eq!(OrgApiKeyId::from_uuid(raw).as_uuid(), &raw);
    }

    /// A key set to expire in an hour still works one second before then and
    /// is expired at that exact instant. A key with no expiry reports never.
    #[test]
    fn a_key_expires_at_the_instant_it_names() {
        let expiry = crate::shared::clock::now() + time::Duration::hours(1);
        let mut p = params();
        p.expires_at = Expiry::At(expiry);
        let key = created(p).unwrap();

        assert_eq!(key.expires_at(), Expiry::At(expiry));

        {
            let _frozen = crate::shared::clock::freeze(expiry - time::Duration::seconds(1));
            assert!(key.is_active());
        }

        let _frozen = crate::shared::clock::freeze(expiry);
        assert!(key.is_expired(), "the expiry instant is already outside");

        assert_eq!(created(params()).unwrap().expires_at(), Expiry::Never);
    }

    /// A new key has never been used. It is used five minutes later, and
    /// that moment is recorded, so it does not look abandoned.
    #[test]
    fn using_a_key_records_when_it_was_used() {
        let mut key = created(params()).unwrap();
        assert_eq!(key.last_used_at(), None);

        let used_at = crate::shared::clock::now() + time::Duration::minutes(5);
        let _frozen = crate::shared::clock::freeze(used_at);
        key.record_usage();

        assert_eq!(key.last_used_at(), Some(used_at));
    }

    /// An admin asks for an org key with the tenant scope `idp:users:view`.
    /// It is refused, since an org key can never use it.
    #[test]
    fn create_rejects_a_tenant_plane_scope() {
        let mut p = params();
        p.scopes = vec![Scope::new("idp:users:view").unwrap()];

        assert!(matches!(created(p), Err(DomainError::Validation(_))));
    }

    /// An admin revokes a key that is already revoked. It is refused and the
    /// key stays revoked.
    #[test]
    fn revoking_a_revoked_key_is_refused() {
        let mut key = created(params()).unwrap();
        key.revoke(ActedBy::Platform).unwrap();

        let second = key.revoke(ActedBy::Platform);

        assert!(matches!(second, Err(DomainError::InvalidTransition(_))));
        assert!(key.is_revoked());
    }

    /// An active key may move to revoked. A revoked key may not move back to
    /// active, so a leaked key stays dead.
    #[test]
    fn only_an_active_key_can_be_revoked() {
        assert_eq!(
            OrgApiKeyStatus::Active.try_transition(OrgApiKeyStatus::Revoked),
            Ok(OrgApiKeyStatus::Revoked)
        );
        assert!(
            OrgApiKeyStatus::Revoked
                .try_transition(OrgApiKeyStatus::Active)
                .is_err()
        );
    }

    /// An admin mints a key and later revokes it. Both are raised, each
    /// naming the key by its name; revoking it again is refused and raises
    /// nothing more.
    #[test]
    fn minting_and_revoking_raise_their_records_once() {
        let mut key = created(params()).unwrap();
        key.revoke(ActedBy::Platform).unwrap();
        let again = key.revoke(ActedBy::Platform);

        let events = key.take_events();
        let names: Vec<String> = events.iter().map(|e| e.event_type().to_string()).collect();
        assert!(again.is_err());
        assert_eq!(
            names,
            [
                "organization.org_api_key_created",
                "organization.org_api_key_revoked",
            ]
        );
        for event in &events {
            let payload = event.payload();
            let Some(FieldValue::Reference(named)) = payload.value("key") else {
                panic!("the key is not referenced");
            };
            assert_eq!(named.label(), key.name().as_str());
        }
    }

    /// A key is read back from storage. Loading it is no change, so it has
    /// raised nothing.
    #[test]
    fn a_key_read_back_from_storage_has_raised_nothing() {
        let mut key = OrgApiKey::reconstitute(stored(&created(params()).unwrap())).unwrap();

        assert!(key.take_events().is_empty());
    }
}
