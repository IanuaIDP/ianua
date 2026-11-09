//! Sandboxes: the runtimes on offer, making one, saving its versions with
//! code written or imported, holding an agent or running the company's
//! own image from an allowed registry, reading them, trying a version on
//! sample input, and pushing one to a repository.

use super::{Request, TenantPath};
use crate::net::Call;
use crate::wire::sandboxes::{
    HeldAgentVersion, ImportedSandboxVersion, NewImageSandbox, NewImageVersion, NewPush,
    NewRegistry, NewSandbox, NewSandboxVersion, NewTrial, OfferedRuntime, Registry, Sandbox,
    SandboxDetail, SandboxVersion, Trial,
};

/// `POST …/sandboxes` with kind `image`: makes a sandbox for the
/// company's own image.
#[must_use]
pub fn create_image(tenant: &TenantPath, sandbox: &NewImageSandbox) -> Request<Sandbox> {
    Request::of(Call::post(tenant.at("/sandboxes")).json(sandbox))
}

/// `POST …/sandboxes/{id}/versions`: saves an image sandbox's next
/// version, pinned to the digest its tag points to now.
#[must_use]
pub fn save_image_version(
    tenant: &TenantPath,
    sandbox_id: &str,
    version: &NewImageVersion,
) -> Request<SandboxVersion> {
    Request::of(Call::post(tenant.at(&format!("/sandboxes/{sandbox_id}/versions"))).json(version))
}

/// `POST …/sandboxes/{id}/versions`: saves the sandbox's next version,
/// holding an agent whose answers its code checks.
#[must_use]
pub fn save_held_agent_version(
    tenant: &TenantPath,
    sandbox_id: &str,
    version: &HeldAgentVersion,
) -> Request<SandboxVersion> {
    Request::of(Call::post(tenant.at(&format!("/sandboxes/{sandbox_id}/versions"))).json(version))
}

/// `POST …/sandboxes/registries`: allows a registry for the tenant's image
/// sandboxes.
#[must_use]
pub fn allow_registry(tenant: &TenantPath, registry: &NewRegistry) -> Request<Registry> {
    Request::of(Call::post(tenant.at("/sandboxes/registries")).json(registry))
}

/// `POST …/sandboxes/{id}/versions/{version_id}/trials`: tries the version
/// on sample input.
#[must_use]
pub fn start_trial(
    tenant: &TenantPath,
    sandbox_id: &str,
    version_id: &str,
    trial: &NewTrial,
) -> Request<Trial> {
    let path = format!("/sandboxes/{sandbox_id}/versions/{version_id}/trials");
    Request::of(Call::post(tenant.at(&path)).json(trial))
}

/// `GET …/sandboxes/{id}/trials/{trial_id}`: how a trial went.
#[must_use]
pub fn trial(tenant: &TenantPath, sandbox_id: &str, trial_id: &str) -> Request<Trial> {
    Request::of(Call::get(
        tenant.at(&format!("/sandboxes/{sandbox_id}/trials/{trial_id}")),
    ))
}

/// `POST …/sandboxes`: makes a sandbox.
#[must_use]
pub fn create(tenant: &TenantPath, sandbox: &NewSandbox) -> Request<Sandbox> {
    Request::of(Call::post(tenant.at("/sandboxes")).json(sandbox))
}

/// `POST …/sandboxes/{id}/versions`: saves the sandbox's next version.
#[must_use]
pub fn save_version(
    tenant: &TenantPath,
    sandbox_id: &str,
    version: &NewSandboxVersion,
) -> Request<SandboxVersion> {
    Request::of(Call::post(tenant.at(&format!("/sandboxes/{sandbox_id}/versions"))).json(version))
}

/// `POST …/sandboxes/{id}/versions`: saves the sandbox's next version, its
/// code read from a repository's file.
#[must_use]
pub fn save_imported_version(
    tenant: &TenantPath,
    sandbox_id: &str,
    version: &ImportedSandboxVersion,
) -> Request<SandboxVersion> {
    Request::of(Call::post(tenant.at(&format!("/sandboxes/{sandbox_id}/versions"))).json(version))
}

/// `POST …/sandboxes/{id}/versions/{version_id}/pushes`: pushes a copy of
/// the version to a repository.
#[must_use]
pub fn push_version(
    tenant: &TenantPath,
    sandbox_id: &str,
    version_id: &str,
    push: &NewPush,
) -> Request<SandboxVersion> {
    let path = format!("/sandboxes/{sandbox_id}/versions/{version_id}/pushes");
    Request::of(Call::post(tenant.at(&path)).json(push))
}

/// `GET …/sandboxes/runtimes`: the runtimes a new version may pick.
#[must_use]
pub fn runtimes(tenant: &TenantPath) -> Request<Vec<OfferedRuntime>> {
    Request::of(Call::get(tenant.at("/sandboxes/runtimes")))
}

/// `GET …/sandboxes/{id}`: the sandbox and its newest versions.
#[must_use]
pub fn get(tenant: &TenantPath, sandbox_id: &str) -> Request<SandboxDetail> {
    Request::of(Call::get(tenant.at(&format!("/sandboxes/{sandbox_id}"))))
}
