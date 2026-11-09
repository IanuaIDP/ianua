//! An organization's tenants: making one, reading it, changing it, moving
//! it through its life, copying parts of one into another, and how its
//! users sign in.

use super::{OrgPath, Request, TenantPath};
use crate::net::Call;
use crate::wire::Page;
use crate::wire::tenants::{
    CloneProgress, CloneSetup, CloneStarted, Compliance, EnvironmentChange, NewTenant,
    ReplaceCompliance, ReplaceSignInSettings, SignInSettings, Tenant, TenantChange, TenantMade,
};

/// `GET …/tenants`.
#[must_use]
pub fn list(org: &OrgPath) -> Request<Page<Tenant>> {
    Request::of(Call::get(org.at("/tenants")))
}

/// `POST …/tenants`: makes a tenant; its setup runs on.
#[must_use]
pub fn create(org: &OrgPath, tenant: &NewTenant) -> Request<TenantMade> {
    Request::of(Call::post(org.at("/tenants")).json(tenant))
}

/// `GET …/tenants/{tenant}`.
#[must_use]
pub fn get(tenant: &TenantPath) -> Request<Tenant> {
    Request::of(Call::get(tenant.at("")))
}

/// `PATCH …/tenants/{tenant}`.
#[must_use]
pub fn change(tenant: &TenantPath, change: &TenantChange) -> Request<()> {
    Request::of(Call::patch(tenant.at("")).json(change))
}

/// `POST …/tenants/{tenant}/suspend`: stops the tenant for now, ending its
/// users' sessions.
#[must_use]
pub fn suspend(tenant: &TenantPath) -> Request<()> {
    Request::of(Call::post(tenant.at("/suspend")))
}

/// `POST …/tenants/{tenant}/reactivate`: a suspended tenant back in use.
#[must_use]
pub fn reactivate(tenant: &TenantPath) -> Request<()> {
    Request::of(Call::post(tenant.at("/reactivate")))
}

/// `POST …/tenants/{tenant}/archive`: puts the tenant away, restorable
/// while its grace runs.
#[must_use]
pub fn archive(tenant: &TenantPath) -> Request<()> {
    Request::of(Call::post(tenant.at("/archive")))
}

/// `POST …/tenants/{tenant}/restore`: an archived tenant back in use.
#[must_use]
pub fn restore(tenant: &TenantPath) -> Request<()> {
    Request::of(Call::post(tenant.at("/restore")))
}

/// `DELETE …/tenants/{tenant}`: deletes an archived tenant once its grace
/// has passed; its teardown runs on.
#[must_use]
pub fn delete(tenant: &TenantPath) -> Request<()> {
    Request::of(Call::delete(tenant.at("")))
}

/// `POST …/tenant-clones`: copies parts of one tenant into another; the
/// copy runs on as a job.
#[must_use]
pub fn start_clone(org: &OrgPath, setup: &CloneSetup) -> Request<CloneStarted> {
    Request::of(Call::post(org.at("/tenant-clones")).json(setup))
}

/// `GET …/tenant-clones/{id}`: how a copy stands.
#[must_use]
pub fn clone_progress(org: &OrgPath, clone_id: &str) -> Request<CloneProgress> {
    Request::of(Call::get(org.at(&format!("/tenant-clones/{clone_id}"))))
}

/// `GET …/tenants/{tenant}/auth-config`.
#[must_use]
pub fn sign_in_settings(tenant: &TenantPath) -> Request<SignInSettings> {
    Request::of(Call::get(tenant.at("/auth-config")))
}

/// `GET …/compliance`: the tenant's compliance posture.
#[must_use]
pub fn compliance(tenant: &TenantPath) -> Request<Compliance> {
    Request::of(Call::get(tenant.at("/compliance")))
}

/// `PUT …/compliance`: replaces it whole, the caller proved again.
#[must_use]
pub fn replace_compliance(tenant: &TenantPath, replace: &ReplaceCompliance) -> Request<()> {
    Request::of(Call::put(tenant.at("/compliance")).json(replace))
}

/// `PUT …/tenants/{tenant}/auth-config`: replaces them whole.
#[must_use]
pub fn replace_sign_in_settings(
    tenant: &TenantPath,
    replace: &ReplaceSignInSettings,
) -> Request<()> {
    Request::of(Call::put(tenant.at("/auth-config")).json(replace))
}

/// `PUT …/tenants/{tenant}/environment`: labels the tenant as a stage of
/// the product it serves.
#[must_use]
pub fn change_environment(tenant: &TenantPath, change: &EnvironmentChange) -> Request<()> {
    Request::of(Call::put(tenant.at("/environment")).json(change))
}
