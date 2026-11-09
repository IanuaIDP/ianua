//! Allow registry: an administrator who may connect accounts puts a
//! registry on the tenant's list, so sandbox versions may take the
//! company's own images from it, with the login they are pulled with.
//!
//! The password is sealed for the registry's row before anything is kept,
//! so only its sealed form reaches the domain and storage. A host is on
//! the list once.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::sandbox::image::RegistryHost;
use ianua_domain::domains::workflows::sandbox::registry::{
    AllowRegistryParams, ImageRegistry, RegistryLogin, RegistryUsername,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::ImageRegistryId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::workflows::ImageRegistryStore;
use crate::services::sealing::sealed_text;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::workflows::sandboxes::images::pulls::{ImagePulls, registry_login_place};

/// How images are pulled from the registry, as the administrator typed it.
pub enum WrittenLogin {
    /// With no login.
    Anonymous,
    /// As a user, with a password or token in the clear; it is sealed
    /// before it is kept.
    Password {
        /// The user images are pulled as.
        username: RegistryUsername,
        /// The password or token.
        password: Secret,
    },
}

/// A registry an administrator lets the tenant's sandboxes pull company
/// images from, and how to sign in to it.
pub struct AllowRequest {
    /// The registry's host, such as `registry.acme.example`.
    pub host: RegistryHost,
    /// How images are pulled from it.
    pub login: WrittenLogin,
}

/// The ports [`AllowUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AllowPorts {
    /// Keeps the tenant's registries.
    pub registries: Arc<dyn ImageRegistryStore>,
    /// Seals the password.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Whether the installation runs companies' images at all.
    pub pulls: ImagePulls,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Allows image registries.
pub struct AllowUseCase {
    ports: AllowPorts,
}

impl AllowUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AllowPorts) -> Self {
        Self { ports }
    }

    /// `written`, its password sealed for the registry `id` of `tenant`.
    async fn sealed(
        &self,
        tenant: &ScopedTenant,
        id: &ImageRegistryId,
        written: WrittenLogin,
    ) -> Result<RegistryLogin, AppError> {
        let WrittenLogin::Password { username, password } = written else {
            return Ok(RegistryLogin::Anonymous);
        };
        let place = registry_login_place(tenant, id);
        let password =
            sealed_text(self.ports.encryptor.as_ref(), password.expose(), &place).await?;
        Ok(RegistryLogin::Password { username, password })
    }
}

impl Command for AllowUseCase {
    type Caller = CallerContext;
    type Input = AllowRequest;
    type Output = Result<ImageRegistry<ResolvedTenant>, AppError>;

    /// Puts `request.host` on the tenant's list for the person `ctx` names.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without the right to connect accounts, or while companies' images are off.
    /// - `AppError::Conflict` when the host is on the list already; `Internal` on sealing, persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: AllowRequest,
    ) -> Result<ImageRegistry<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        control
            .ensure_may(WorkflowAction::ConnectAccounts)
            .map_err(AppError::from_domain)?;
        self.ports.pulls.ensure_on()?;
        let tenant = ctx.tenant();
        let id = ImageRegistryId::new();
        let login = self.sealed(&tenant, &id, request.login).await?;
        let params = AllowRegistryParams {
            id,
            host: request.host,
            login,
        };
        let mut registry = ImageRegistry::allow(params, &control).map_err(AppError::from_domain)?;
        self.ports
            .registries
            .insert(&tenant, &registry)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&ctx.actor(), registry.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(registry)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;

    use super::*;
    use crate::ports::workflows::OwnImages;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::workflows::FakeImageRegistryStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// What allowing wrote and recorded.
    struct Allowing {
        registries: Arc<FakeImageRegistryStore>,
        sink: Arc<FakeEventDispatcher>,
        own_images: OwnImages,
        holds: SystemPermission,
    }

    impl Allowing {
        fn new() -> Self {
            Self {
                registries: Arc::new(FakeImageRegistryStore::empty()),
                sink: Arc::new(FakeEventDispatcher::new()),
                own_images: OwnImages::On,
                holds: SystemPermission::Workflows(WorkflowAction::ConnectAccounts),
            }
        }

        fn allow(&self, login: WrittenLogin) -> Result<ImageRegistry<ResolvedTenant>, AppError> {
            let use_case = AllowUseCase::new(AllowPorts {
                registries: self.registries.clone(),
                encryptor: Arc::new(FakeEncryptor),
                pulls: ImagePulls::new(
                    self.registries.clone(),
                    Arc::new(FakeEncryptor),
                    self.own_images,
                ),
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[self.holds])),
            });
            let request = AllowRequest {
                host: RegistryHost::new("registry.acme.example").unwrap(),
                login,
            };
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.sink.clone()), request))
        }
    }

    fn robot() -> WrittenLogin {
        WrittenLogin::Password {
            username: RegistryUsername::new("robot$acme").unwrap(),
            password: Secret::new("s3cret token"),
        }
    }

    /// Ann allows Acme's registry with a robot login. What is kept is the
    /// password sealed for the registry's row, never the password, and the
    /// trail records the registry allowed.
    #[test]
    fn the_password_is_kept_sealed() {
        let allowing = Allowing::new();

        let allowed = allowing.allow(robot()).unwrap();

        let kept = allowing.registries.stored(allowed.id()).unwrap();
        let place = registry_login_place(&test_ctx().tenant(), allowed.id());
        let RegistryLogin::Password { password, .. } = kept.login() else {
            panic!("no login was kept");
        };
        assert_eq!(password, &FakeEncryptor::sealed_for("s3cret token", &place));
        assert_eq!(
            allowing.sink.records.lock().unwrap().as_slice(),
            ["workflows.image_registry_allowed"]
        );
    }

    /// The same host is allowed once; the second is a conflict.
    #[test]
    fn a_host_is_allowed_once() {
        let allowing = Allowing::new();
        allowing.allow(WrittenLogin::Anonymous).unwrap();

        let again = allowing.allow(robot());

        assert!(matches!(again, Err(AppError::Conflict(_))));
    }

    /// Bob may change workflows but not connect accounts, and is refused.
    #[test]
    fn changing_workflows_alone_allows_no_registry() {
        let allowing = Allowing {
            holds: SystemPermission::Workflows(WorkflowAction::Update),
            ..Allowing::new()
        };

        let refused = allowing.allow(robot());

        assert!(matches!(refused, Err(AppError::Forbidden(_))));
        assert!(allowing.registries.all().is_empty());
    }

    /// While the operator has companies' images off, no registry is
    /// allowed.
    #[test]
    fn no_registry_is_allowed_while_images_are_off() {
        let allowing = Allowing {
            own_images: OwnImages::Off,
            ..Allowing::new()
        };

        let refused = allowing.allow(robot());

        assert!(matches!(refused, Err(AppError::Forbidden(_))));
        assert!(allowing.registries.all().is_empty());
    }
}
