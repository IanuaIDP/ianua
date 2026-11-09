//! What a SCIM provisioning test signs in with: the tenant's token, its
//! endpoint, the directory's caller and the ways a sign-in is refused, a
//! group the directory keeps, and the SCIM use cases others are built over.

use std::sync::Arc;

use ianua_domain::domains::authorization::group::{Group, GroupOrigin, GroupPlace, GroupRow};
use ianua_domain::domains::federation::scim::{
    ScimActivation, ScimEndpoint, ScimEndpointRow, ScimRemoval,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Enablement, GroupId, Label, Setting, TokenHash};

use crate::acting::ScimAuthorities;
use crate::acting::scim::{ScimActing, ScimActingPorts};
use crate::context::ScimCaller;
use crate::test_support::federation::{FakeScimStore, FakeScimTokenGenerator};
use crate::test_support::{Fake, test_ctx};
use crate::use_cases::scim::{groups, users};

/// The bearer token the test tenant's directory holds.
pub const SCIM_TOKEN: &str = "scim-token-1";

/// The test tenant's SCIM endpoint as stored: switched on, keeping the hash
/// of [`SCIM_TOKEN`], with no default role; users it makes sign in at once
/// and are switched off when removed.
#[must_use]
pub fn directory_row() -> ScimEndpointRow {
    ScimEndpointRow {
        bearer_token_hash: TokenHash::from_stored(format!("hash:{SCIM_TOKEN}")),
        enabled: Enablement::Enabled,
        default_role_id: Setting::Unset,
        auto_activate: ScimActivation::Immediate,
        deactivate_on_remove: ScimRemoval::Deactivate,
        last_sync_at: None,
        created_at: clock::now(),
    }
}

/// The test tenant's directory, calling with [`SCIM_TOKEN`].
#[must_use]
pub fn scim_caller() -> ScimCaller {
    ScimCaller::new(test_ctx().tenant(), Some(Secret::new(SCIM_TOKEN)))
}

/// A sign-in over `store`, checking tokens the way the fake generator
/// makes them.
#[must_use]
pub fn sign_in_over(store: &Arc<FakeScimStore>) -> Arc<dyn ScimAuthorities> {
    Arc::new(ScimActing::new(ScimActingPorts {
        scim_store: store.clone(),
        tokens: Arc::new(FakeScimTokenGenerator::new()),
    }))
}

/// A sign-in to the endpoint `row` describes, kept for the test tenant.
///
/// # Panics
///
/// If `row` is not a consistent endpoint. Tests pass rows that are.
#[must_use]
pub fn scim_sign_in_with(row: ScimEndpointRow) -> Arc<dyn ScimAuthorities> {
    let endpoint = ScimEndpoint::reconstitute(row).expect("a consistent endpoint");
    scim_sign_in(endpoint)
}

/// A sign-in to `endpoint`, kept for the test tenant.
#[must_use]
pub fn scim_sign_in(endpoint: ScimEndpoint<ResolvedTenant>) -> Arc<dyn ScimAuthorities> {
    sign_in_over(&Arc::new(FakeScimStore::holding(
        &test_ctx().tenant(),
        endpoint,
    )))
}

/// A sign-in to the test tenant's endpoint as [`directory_row`] stores it,
/// which [`scim_caller`] passes.
#[must_use]
pub fn signed_in() -> Arc<dyn ScimAuthorities> {
    scim_sign_in_with(directory_row())
}

/// The ways a directory's sign-in is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignInRefusal {
    /// The request carries no token.
    NoToken,
    /// The token is not one the tenant ever issued.
    WrongToken,
    /// The token was rotated away.
    RotatedToken,
    /// The tenant switched SCIM off.
    SwitchedOff,
}

impl SignInRefusal {
    /// Every way a sign-in is refused.
    pub const ALL: [Self; 4] = [
        Self::NoToken,
        Self::WrongToken,
        Self::RotatedToken,
        Self::SwitchedOff,
    ];
}

/// A sign-in and a caller that `refusal` turns away.
#[must_use]
pub fn refused_sign_in(refusal: SignInRefusal) -> (Arc<dyn ScimAuthorities>, ScimCaller) {
    let tenant = test_ctx().tenant();
    match refusal {
        SignInRefusal::NoToken => (signed_in(), ScimCaller::new(tenant, None)),
        SignInRefusal::WrongToken => (
            signed_in(),
            ScimCaller::new(tenant, Some(Secret::new("guessed"))),
        ),
        SignInRefusal::RotatedToken => (
            scim_sign_in_with(ScimEndpointRow {
                bearer_token_hash: TokenHash::from_stored("hash:scim-token-2".to_owned()),
                ..directory_row()
            }),
            scim_caller(),
        ),
        SignInRefusal::SwitchedOff => (
            scim_sign_in_with(ScimEndpointRow {
                enabled: Enablement::Disabled,
                ..directory_row()
            }),
            scim_caller(),
        ),
    }
}

/// A group named `name` that `origin` keeps, at the top of the tree with no
/// roles, as storage would hand it back.
///
/// # Panics
///
/// If `name` is not a valid label. Tests pass literals that are.
#[must_use]
pub fn kept_group(name: &str, origin: GroupOrigin) -> Group<ResolvedTenant> {
    let now = clock::now();
    Group::reconstitute(GroupRow {
        id: GroupId::new(),
        name: Label::new("displayName", name).expect("a valid group name"),
        origin,
        place: GroupPlace::TopLevel,
        role_ids: Vec::new(),
        created_at: now,
        updated_at: now,
    })
    .expect("a top-level group is a consistent row")
}

/// A directory nobody set SCIM up for: every call is refused as signed out.
impl Fake for Arc<dyn ScimAuthorities> {
    fn fake() -> Self {
        Arc::new(ScimActing::new(ScimActingPorts::fakes()))
    }
}

impl Fake for Arc<users::UpdateScimUseCase> {
    fn fake() -> Self {
        Arc::new(users::UpdateScimUseCase::new(Fake::fake()))
    }
}

impl Fake for Arc<groups::UpdateScimUseCase> {
    fn fake() -> Self {
        Arc::new(groups::UpdateScimUseCase::new(
            Fake::fake(),
            groups::MemberCap::default(),
        ))
    }
}
