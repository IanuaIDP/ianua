//! Companies' own images as the tests see them: allowed registries kept in
//! memory, a registry and a scanner answering as a test says, and the image
//! sandboxes and versions the tests start from.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::workflows::sandbox::image::{
    ImageDigest, ImageName, OwnImage, PinnedImage, RegistryHost,
};
use ianua_domain::domains::workflows::sandbox::network::NetworkAccess;
use ianua_domain::domains::workflows::sandbox::recipe::{Program, RunBudget};
use ianua_domain::domains::workflows::sandbox::registry::{
    AllowRegistryParams, ImageRegistry, ImageRegistryRow, RegistryLogin, RegistryUsername,
};
use ianua_domain::domains::workflows::sandbox::source::CodeSource;
use ianua_domain::domains::workflows::sandbox::version::SandboxVersion;
use ianua_domain::domains::workflows::sandbox::{
    CreateSandboxParams, Sandbox, SandboxKind, VersionDraft,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::types::{ImageRegistryId, Label, TenantId, UntrustedText};

use crate::ports::TenantScoped;
use crate::ports::workflows::{
    ImageRegistryStore, ImageResolver, ImageScanner, OwnImages, PullLogin, Resolving, Scanning,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::authentication::FakeEncryptor;
use crate::test_support::workflows::{managing, person};
use crate::test_support::{Fake, test_ctx};
use crate::use_cases::workflows::sandboxes::images::ImagePulls;
use crate::use_cases::workflows::sandboxes::images::pulls::registry_login_place;

/// `registry` read back from its row, as storage reads it.
fn registry_copy(registry: &ImageRegistry<ResolvedTenant>) -> ImageRegistry<ResolvedTenant> {
    ImageRegistry::reconstitute(ImageRegistryRow {
        id: *registry.id(),
        host: registry.host().clone(),
        login: registry.login().clone(),
        allowed_by: registry.allowed_by().clone(),
        created_at: Aggregate::created_at(registry),
        updated_at: Aggregate::updated_at(registry),
    })
    .expect("a kept registry reads back as itself")
}

/// In-memory registry store: registries kept under their tenant, a host
/// once per tenant.
#[derive(Default)]
pub struct FakeImageRegistryStore {
    registries: Mutex<Vec<(TenantId, ImageRegistry<ResolvedTenant>)>>,
}

impl TenantScoped for FakeImageRegistryStore {}

impl FakeImageRegistryStore {
    /// A store holding no registry.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `registry` in the test tenant.
    #[must_use]
    pub fn holding(registry: &ImageRegistry<ResolvedTenant>) -> Self {
        Self {
            registries: Mutex::new(vec![(test_ctx().tenant_id(), registry_copy(registry))]),
        }
    }

    /// The registry `id`, as the test tenant keeps it now.
    ///
    /// # Panics
    ///
    /// When a test panicked while holding the store.
    #[must_use]
    pub fn stored(&self, id: &ImageRegistryId) -> Option<ImageRegistry<ResolvedTenant>> {
        let tenant = test_ctx().tenant_id();
        self.registries
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, kept)| *owner == tenant && kept.id() == id)
            .map(|(_, kept)| registry_copy(kept))
    }

    /// Every registry kept, in every tenant.
    ///
    /// # Panics
    ///
    /// When a test panicked while holding the store.
    #[must_use]
    pub fn all(&self) -> Vec<ImageRegistry<ResolvedTenant>> {
        self.registries
            .lock()
            .unwrap()
            .iter()
            .map(|(_, kept)| registry_copy(kept))
            .collect()
    }

    /// The tenant's registries that `keep` holds for.
    fn of_tenant(
        &self,
        tenant: &ScopedTenant,
        keep: impl Fn(&ImageRegistry<ResolvedTenant>) -> bool,
    ) -> Vec<ImageRegistry<ResolvedTenant>> {
        self.registries
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, kept)| owner == &**tenant && keep(kept))
            .map(|(_, kept)| registry_copy(kept))
            .collect()
    }
}

#[async_trait]
impl ImageRegistryStore for FakeImageRegistryStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ImageRegistryId,
    ) -> Result<Option<ImageRegistry<ResolvedTenant>>, DomainError> {
        Ok(self.of_tenant(tenant_id, |kept| kept.id() == id).pop())
    }

    async fn find_by_host(
        &self,
        tenant_id: &ScopedTenant,
        host: &RegistryHost,
    ) -> Result<Option<ImageRegistry<ResolvedTenant>>, DomainError> {
        Ok(self.of_tenant(tenant_id, |kept| kept.host() == host).pop())
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<ImageRegistry<ResolvedTenant>>, DomainError> {
        let mut found = self.of_tenant(tenant_id, |_| true);
        found.sort_by(|one, other| one.host().as_str().cmp(other.host().as_str()));
        Ok(found)
    }

    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        registry: &ImageRegistry<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut registries = self.registries.lock().unwrap();
        let taken = registries
            .iter()
            .any(|(owner, kept)| owner == &**tenant_id && kept.host() == registry.host());
        if taken {
            return Err(DomainError::conflict("the registry is allowed already"));
        }
        registries.push((**tenant_id, registry_copy(registry)));
        Ok(())
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &ImageRegistryId,
    ) -> Result<(), DomainError> {
        self.registries
            .lock()
            .unwrap()
            .retain(|(owner, kept)| owner != &**tenant_id || kept.id() != id);
        Ok(())
    }
}

impl Fake for Arc<dyn ImageRegistryStore> {
    fn fake() -> Self {
        Arc::new(FakeImageRegistryStore::empty())
    }
}

impl Fake for ImagePulls {
    fn fake() -> Self {
        ImagePulls::new(
            Arc::new(FakeImageRegistryStore::empty()),
            Arc::new(FakeEncryptor),
            OwnImages::On,
        )
    }
}

/// Acme's registry `registry.acme.example`, allowed by Ann for `tenant`,
/// its images pulled as `username` with `password`, sealed as the fake
/// encryptor seals it.
///
/// # Panics
///
/// Never: the host, user and sealed form are all valid.
#[must_use]
pub fn acme_registry_with_login(
    tenant: &ScopedTenant,
    username: &str,
    password: &str,
) -> ImageRegistry<ResolvedTenant> {
    let id = ImageRegistryId::new();
    let login = RegistryLogin::Password {
        username: RegistryUsername::new(username).expect("a user"),
        password: FakeEncryptor::sealed_for(password, &registry_login_place(tenant, &id)),
    };
    ImageRegistry::allow(
        AllowRegistryParams {
            id,
            host: RegistryHost::new("registry.acme.example").expect("a registry"),
            login,
        },
        &managing(&person("ann@corp.test")),
    )
    .expect("Ann allows the registry")
}

/// A registry giving every name the same answer, and remembering who it was
/// asked as.
pub struct FakeImageResolver {
    answer: Resolving,
    asked_as: Mutex<Option<String>>,
}

impl FakeImageResolver {
    /// A registry answering `answer`.
    #[must_use]
    pub fn answering(answer: Resolving) -> Self {
        Self {
            answer,
            asked_as: Mutex::new(None),
        }
    }

    /// The user the last question was asked as; `anonymous` for none, and
    /// `None` when it was never asked.
    ///
    /// # Panics
    ///
    /// When a test panicked while holding the record.
    #[must_use]
    pub fn asked_as(&self) -> Option<String> {
        self.asked_as.lock().unwrap().clone()
    }
}

#[async_trait]
impl ImageResolver for FakeImageResolver {
    async fn resolve(&self, _name: &ImageName, login: &PullLogin) -> Resolving {
        let user = match login {
            PullLogin::Anonymous => "anonymous".to_owned(),
            PullLogin::Password { username, .. } => username.as_str().to_owned(),
        };
        *self.asked_as.lock().unwrap() = Some(user);
        self.answer.clone()
    }
}

impl Fake for Arc<dyn ImageResolver> {
    fn fake() -> Self {
        Arc::new(FakeImageResolver::answering(Resolving::Unavailable(
            UntrustedText::record("no registry in this test"),
        )))
    }
}

/// A scanner giving every image the same answer.
pub struct FakeImageScanner {
    answer: Scanning,
}

impl FakeImageScanner {
    /// A scanner answering `answer`.
    #[must_use]
    pub fn answering(answer: Scanning) -> Self {
        Self { answer }
    }
}

#[async_trait]
impl ImageScanner for FakeImageScanner {
    async fn scan(&self, _image: &PinnedImage, _login: &PullLogin) -> Scanning {
        self.answer.clone()
    }
}

impl Fake for Arc<dyn ImageScanner> {
    fn fake() -> Self {
        Arc::new(FakeImageScanner::answering(Scanning::NotSetUp))
    }
}

/// Ann's sandbox "Code generator" of Acme's own image, with no version yet.
///
/// # Panics
///
/// Never: Ann holds every workflow right.
#[must_use]
pub fn image_sandbox() -> Sandbox<ResolvedTenant> {
    Sandbox::create(
        CreateSandboxParams {
            name: Label::new("name", "Code generator").expect("a name"),
            kind: SandboxKind::OwnImage,
        },
        &managing(&person("ann@corp.test")),
    )
    .expect("Ann makes a sandbox")
}

/// Acme's code generator, `registry.acme.example/tools/codegen`, pinned to
/// a digest of `ef`s, 80 MiB.
///
/// # Panics
///
/// Never: the reference and size are valid.
#[must_use]
pub fn acme_codegen() -> OwnImage {
    let digest = ImageDigest::new(format!("sha256:{}", "ef".repeat(32))).expect("a digest");
    let name = ImageName::parse("registry.acme.example/tools/codegen:1.4").expect("a name");
    OwnImage::new(name.pinned(digest), 80 * 1024 * 1024).expect("an image")
}

/// Version 1 of a fresh [`image_sandbox`], running [`acme_codegen`], its
/// scan still to come.
///
/// # Panics
///
/// Never: the sandbox is active and Ann holds every workflow right.
#[must_use]
pub fn building_image_version() -> SandboxVersion<ResolvedTenant> {
    let draft = VersionDraft {
        program: Program::Image(acme_codegen()),
        budget: RunBudget::new(60, 512).expect("a budget"),
        network: NetworkAccess::closed(),
        source: CodeSource::Written,
    };
    image_sandbox()
        .save_version(&managing(&person("ann@corp.test")), draft)
        .expect("Ann saves a version")
}
