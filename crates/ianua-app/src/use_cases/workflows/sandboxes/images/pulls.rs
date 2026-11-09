//! The login a company's image is pulled with, opened only when it is
//! resolved, scanned or run, and the refusals that stop it first: an
//! installation that runs no company image, or a registry no longer on the
//! tenant's list.

use std::sync::Arc;

use ianua_domain::domains::workflows::sandbox::build::BuildFailure;
use ianua_domain::domains::workflows::sandbox::image::RegistryHost;
use ianua_domain::domains::workflows::sandbox::recipe::Program;
use ianua_domain::domains::workflows::sandbox::registry::{ImageRegistry, RegistryLogin};
use ianua_domain::domains::workflows::sandbox::version::SandboxVersion;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::ImageRegistryId;

use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{SealOwner, SealedField, SealedFor, SecretEncryptor};
use crate::ports::workflows::{ImageRegistryStore, OwnImages, PullLogin};
use crate::services::sealing::opened_text;
use crate::tenancy::ScopedTenant;

/// Opens the logins images are pulled with, for the registries a tenant
/// allowed, while the installation runs companies' images.
#[derive(Clone)]
pub struct ImagePulls {
    registries: Arc<dyn ImageRegistryStore>,
    encryptor: Arc<dyn SecretEncryptor>,
    own_images: OwnImages,
}

/// Whether an image may be pulled, and with what.
#[derive(Debug)]
pub(crate) enum Pull {
    /// It may, with this login.
    Allowed(PullLogin),
    /// It may not, for this reason.
    Refused(PullRefusal),
}

/// Why an image may not be pulled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PullRefusal {
    /// The installation runs no company image.
    Off,
    /// The image's registry is not on the tenant's list.
    NotAllowed,
}

impl PullRefusal {
    /// What a version's build comes to when its image may not be pulled.
    pub(crate) fn build_failure(self) -> BuildFailure {
        match self {
            Self::Off => BuildFailure::OwnImagesOff,
            Self::NotAllowed => BuildFailure::RegistryNotAllowed,
        }
    }

    /// Why a run of its version did not run.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::Off => "this installation runs no company images",
            Self::NotAllowed => "the image's registry is no longer on the tenant's list",
        }
    }

    /// The refusal a person saving a version is given.
    pub(crate) fn refusal(self) -> AppError {
        match self {
            Self::Off => own_images_off(),
            Self::NotAllowed => AppError::from_domain(DomainError::invalid(message!(
                "workflows-the-registry-is-not-allowed",
                "the image's registry is not on the tenant's list; an administrator allows it first"
            ))),
        }
    }
}

impl ImagePulls {
    /// Logins read from `registries` and opened through `encryptor`, while
    /// `own_images` says the installation runs companies' images.
    #[must_use]
    pub fn new(
        registries: Arc<dyn ImageRegistryStore>,
        encryptor: Arc<dyn SecretEncryptor>,
        own_images: OwnImages,
    ) -> Self {
        Self {
            registries,
            encryptor,
            own_images,
        }
    }

    /// Refuses anything to do with companies' images while the
    /// installation runs none.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` while companies' images are off.
    pub(crate) fn ensure_on(&self) -> Result<(), AppError> {
        match self.own_images {
            OwnImages::On => Ok(()),
            OwnImages::Off => Err(own_images_off()),
        }
    }

    /// How `version` is pulled: anonymously for code, whose runtime's image
    /// the platform offers, or with its registry's login for an image.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the store fails or the login does not
    ///   open.
    pub(crate) async fn for_version(
        &self,
        tenant: &ScopedTenant,
        version: &SandboxVersion<ResolvedTenant>,
    ) -> Result<Pull, AppError> {
        match version.recipe().program() {
            Program::Code(_) => Ok(Pull::Allowed(PullLogin::Anonymous)),
            Program::Image(own) => self.for_registry(tenant, own.image().registry()).await,
        }
    }

    /// How an image from `host` is pulled, if the tenant allowed it.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the store fails or the login does not
    ///   open.
    pub(crate) async fn for_registry(
        &self,
        tenant: &ScopedTenant,
        host: &RegistryHost,
    ) -> Result<Pull, AppError> {
        if self.own_images == OwnImages::Off {
            return Ok(Pull::Refused(PullRefusal::Off));
        }
        let Some(registry) = self
            .registries
            .find_by_host(tenant, host)
            .await
            .or_internal()?
        else {
            return Ok(Pull::Refused(PullRefusal::NotAllowed));
        };
        self.opened(tenant, &registry).await.map(Pull::Allowed)
    }

    /// `registry`'s login, its password opened for this one pull.
    async fn opened(
        &self,
        tenant: &ScopedTenant,
        registry: &ImageRegistry<ResolvedTenant>,
    ) -> Result<PullLogin, AppError> {
        let RegistryLogin::Password { username, password } = registry.login() else {
            return Ok(PullLogin::Anonymous);
        };
        let place = registry_login_place(tenant, registry.id());
        let password = opened_text(self.encryptor.as_ref(), password, &place)
            .await
            .or_internal()?;
        Ok(PullLogin::Password {
            username: username.clone(),
            password,
        })
    }
}

/// Where the password of the tenant's registry `id` is sealed.
pub(crate) fn registry_login_place(tenant: &ScopedTenant, id: &ImageRegistryId) -> SealedFor {
    SealedFor::new(SealOwner::from(tenant), SealedField::RegistryLogin, id)
}

fn own_images_off() -> AppError {
    AppError::Forbidden(message!(
        "workflows-company-images-are-off",
        "this installation runs no company images; its operator turns them on"
    ))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::sandbox::registry::{
        AllowRegistryParams, RegistryUsername,
    };

    use super::*;
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::block_on;
    use crate::test_support::workflows::{
        FakeImageRegistryStore, acme_registry_with_login, managing, person,
    };

    fn pulls(registries: FakeImageRegistryStore, own_images: OwnImages) -> ImagePulls {
        ImagePulls::new(Arc::new(registries), Arc::new(FakeEncryptor), own_images)
    }

    fn acme() -> RegistryHost {
        RegistryHost::new("registry.acme.example").unwrap()
    }

    /// Acme allowed its registry with a robot login. Pulling from it opens
    /// that login; pulling from another registry is refused.
    #[test]
    fn only_an_allowed_registry_is_pulled_from() {
        let tenant = crate::test_support::test_ctx().tenant();
        let registry = acme_registry_with_login(&tenant, "robot$acme", "s3cret token");
        let pulls = pulls(FakeImageRegistryStore::holding(&registry), OwnImages::On);

        let allowed = block_on(pulls.for_registry(&tenant, &acme())).unwrap();
        let other =
            block_on(pulls.for_registry(&tenant, &RegistryHost::new("ghcr.io").unwrap())).unwrap();

        let Pull::Allowed(PullLogin::Password { username, password }) = allowed else {
            panic!("the login was not opened");
        };
        assert_eq!(username, RegistryUsername::new("robot$acme").unwrap());
        assert_eq!(password.expose(), "s3cret token");
        assert!(matches!(other, Pull::Refused(PullRefusal::NotAllowed)));
    }

    /// While the operator has companies' images off, even an allowed
    /// registry is not pulled from.
    #[test]
    fn nothing_is_pulled_while_images_are_off() {
        let tenant = crate::test_support::test_ctx().tenant();
        let registry = acme_registry_with_login(&tenant, "robot$acme", "s3cret token");
        let pulls = pulls(FakeImageRegistryStore::holding(&registry), OwnImages::Off);

        let refused = block_on(pulls.for_registry(&tenant, &acme())).unwrap();

        assert!(matches!(refused, Pull::Refused(PullRefusal::Off)));
        assert!(pulls.ensure_on().is_err());
    }

    /// An anonymous registry is pulled from with no login.
    #[test]
    fn an_anonymous_registry_needs_no_login() {
        let tenant = crate::test_support::test_ctx().tenant();
        let registry = ImageRegistry::allow(
            AllowRegistryParams {
                id: ImageRegistryId::new(),
                host: acme(),
                login: RegistryLogin::Anonymous,
            },
            &managing(&person("ann@corp.test")),
        )
        .unwrap();
        let pulls = pulls(FakeImageRegistryStore::holding(&registry), OwnImages::On);

        let allowed = block_on(pulls.for_registry(&tenant, &acme())).unwrap();

        assert!(matches!(allowed, Pull::Allowed(PullLogin::Anonymous)));
    }
}
