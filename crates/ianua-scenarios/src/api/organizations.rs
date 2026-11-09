//! An organization as its owner runs it: how its members sign in, and
//! the identity provider that signs them in.

use super::{OrgPath, Request};
use crate::net::Call;
use crate::wire::organization::{
    AddIdentityProvider, ChangeIdentityProvider, IdentityProvider, OrgSignInSettings, Organization,
    OrganizationChange, PlanChoice, ReplaceOrgSignInSettings, SwitchIdentityProvider,
};

/// Reads the company through the caller's current membership or scoped key.
#[must_use]
pub fn get(org: &OrgPath) -> Request<Organization> {
    Request::of(Call::get(org.at("")))
}

/// Changes only the supplied company profile fields.
#[must_use]
pub fn change(org: &OrgPath, change: &OrganizationChange) -> Request<()> {
    Request::of(Call::patch(org.at("")).json(change))
}

/// Pauses the company and ends its members' current sessions.
#[must_use]
pub fn suspend(org: &OrgPath) -> Request<()> {
    Request::of(Call::post(org.at("/suspend")))
}

/// Lifts a suspension when the caller has authority over its origin.
#[must_use]
pub fn reactivate(org: &OrgPath) -> Request<()> {
    Request::of(Call::post(org.at("/reactivate")))
}

/// Closes the company permanently and archives its remaining tenants.
#[must_use]
pub fn close(org: &OrgPath) -> Request<()> {
    Request::of(Call::post(org.at("/close")))
}

/// `PUT …/subscription`: moves the organization to another plan. The
/// standing it answers is not read.
#[must_use]
pub fn choose_plan(org: &OrgPath, choice: &PlanChoice) -> Request<serde::de::IgnoredAny> {
    Request::of(Call::put(org.at("/subscription")).json(choice))
}

/// `GET …/auth-config`: how the organization's members sign in.
#[must_use]
pub fn sign_in_settings(org: &OrgPath) -> Request<OrgSignInSettings> {
    Request::of(Call::get(org.at("/auth-config")))
}

/// `PUT …/auth-config`: replaces them whole.
#[must_use]
pub fn replace_sign_in_settings(org: &OrgPath, replace: &ReplaceOrgSignInSettings) -> Request<()> {
    Request::of(Call::put(org.at("/auth-config")).json(replace))
}

/// `POST …/identity-provider`: adds the organization's identity provider,
/// disabled until switched on.
#[must_use]
pub fn add_identity_provider(
    org: &OrgPath,
    add: &AddIdentityProvider,
) -> Request<IdentityProvider> {
    Request::of(Call::post(org.at("/identity-provider")).json(add))
}

/// `PATCH …/identity-provider`: changes it, the caller proved again.
#[must_use]
pub fn change_identity_provider(
    org: &OrgPath,
    change: &ChangeIdentityProvider,
) -> Request<IdentityProvider> {
    Request::of(Call::patch(org.at("/identity-provider")).json(change))
}

/// `PUT …/identity-provider/status`: switches it on or off, the caller
/// proved again.
#[must_use]
pub fn switch_identity_provider(
    org: &OrgPath,
    switch: &SwitchIdentityProvider,
) -> Request<IdentityProvider> {
    Request::of(Call::put(org.at("/identity-provider/status")).json(switch))
}
