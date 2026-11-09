//! Tenants' logos: kept in the file store under a name the platform makes
//! from the tenant's id, and served from a host of their own that serves
//! no page of the platform's.
//!
//! The image reaching the store was checked as it became a `LogoImage`.
//! It is checked again, from its own bytes, each time it is served, so
//! the content type a browser is given always names what the bytes are,
//! and a file changed on disk is refused rather than served. Its address
//! carries a version made from its bytes, so a new logo is fetched afresh
//! and the same one uploaded twice keeps its address.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::branding::LogoStore;
use ianua_app::ports::files::PublicLogos;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::branding::logo::LogoImage;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{HttpsUrl, TenantId};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::files::store::{FileName, FileStore};

/// The most bytes a kept logo is read with: what the domain lets a logo
/// hold.
const MOST_BYTES: u64 = 512 * 1024;

/// How many bytes of the image's digest its version carries.
const VERSION_BYTES: usize = 8;

/// Tenants' logos in a file store, served under `served_from`.
pub struct FileLogoStore {
    store: Arc<dyn FileStore>,
    served_from: HttpsUrl,
}

impl FileLogoStore {
    /// Logos kept in `store`, served from `served_from`: the address of
    /// the logo route, on a host that serves no page of the platform's
    /// own.
    #[must_use]
    pub fn new(store: Arc<dyn FileStore>, served_from: HttpsUrl) -> Self {
        Self { store, served_from }
    }

    /// The logo the route serves under `key`, the last part of its
    /// address, or `None` when `key` names no tenant's logo.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the logo cannot be read,
    /// or the kept file is no longer a logo.
    pub async fn served(&self, key: &str) -> Result<Option<LogoImage>, DomainError> {
        let Some(tenant) = tenant_named(key) else {
            return Ok(None);
        };
        let Some(file) = self.store.open(&FileName::logo(&tenant)).await? else {
            return Ok(None);
        };
        let bytes = file.read_within(MOST_BYTES).await?;
        LogoImage::new(bytes)
            .map(Some)
            .map_err(|_| DomainError::corrupt_row("logo", "the kept file is not a logo"))
    }

    /// Where `tenant`'s logo `logo` is served.
    fn address_of(&self, tenant: &TenantId, logo: &LogoImage) -> Result<HttpsUrl, DomainError> {
        let digest = Sha256::digest(logo.bytes());
        let version: Vec<u8> = digest.iter().copied().take(VERSION_BYTES).collect();
        let address = format!(
            "{}/{}?v={}",
            self.served_from.as_str().trim_end_matches('/'),
            tenant.as_uuid().simple(),
            data_encoding::HEXLOWER.encode(&version)
        );
        HttpsUrl::new(address).map_err(DomainError::infra)
    }
}

/// The tenant `key` names, when it is a tenant's id written as the
/// address writes it: 32 hex characters and nothing else.
fn tenant_named(key: &str) -> Option<TenantId> {
    let id = Uuid::try_parse(key).ok()?;
    let canonical = id.simple().to_string() == key;
    canonical.then_some(TenantId::from_uuid(id))
}

impl TenantScoped for FileLogoStore {}

/// The tenants' logos the public logo route serves, read from where
/// [`FileLogoStore`] keeps them.
#[derive(Clone)]
pub struct FilePublicLogos(Arc<FileLogoStore>);

impl FilePublicLogos {
    /// The logos `store` keeps.
    #[must_use]
    pub fn new(store: Arc<FileLogoStore>) -> Self {
        Self(store)
    }
}

#[async_trait]
impl PublicLogos for FilePublicLogos {
    async fn logo_at(&self, key: &str) -> Result<Option<LogoImage>, DomainError> {
        self.0.served(key).await
    }
}

#[async_trait]
impl LogoStore for FileLogoStore {
    async fn put(
        &self,
        tenant_id: &ScopedTenant,
        logo: &LogoImage,
    ) -> Result<HttpsUrl, DomainError> {
        self.store
            .put(&FileName::logo(tenant_id), logo.bytes())
            .await?;
        self.address_of(tenant_id, logo)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::branding::logo::LogoFormat;

    use super::*;
    use crate::files::disk::DiskFileStore;

    /// The first bytes of a PNG `width` by `height` pixels: its signature
    /// and the header chunk that gives its size.
    fn png(width: u32, height: u32) -> Vec<u8> {
        let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        bytes.extend_from_slice(&[0, 0, 0, 13]);
        bytes.extend_from_slice(b"IHDR");
        bytes.extend_from_slice(&width.to_be_bytes());
        bytes.extend_from_slice(&height.to_be_bytes());
        bytes.extend_from_slice(&[8, 6, 0, 0, 0]);
        bytes
    }

    /// The first bytes of a JPEG `width` by `height` pixels, with the
    /// `APP0` segment cameras write before the frame header.
    fn jpeg(width: u16, height: u16) -> Vec<u8> {
        let mut bytes = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        bytes.extend_from_slice(b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0");
        bytes.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
        bytes.extend_from_slice(&height.to_be_bytes());
        bytes.extend_from_slice(&width.to_be_bytes());
        bytes.extend_from_slice(&[0x03; 10]);
        bytes
    }

    struct Fixture {
        dir: tempfile::TempDir,
        logos: FileLogoStore,
        tenant: ScopedTenant,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(DiskFileStore::new(dir.path()));
        let logos = FileLogoStore::new(
            store,
            HttpsUrl::new("https://assets.ianua.test/logos/").unwrap(),
        );
        Fixture {
            dir,
            logos,
            tenant: ScopedTenant::for_background(TenantId::new()),
        }
    }

    fn key_of(address: &HttpsUrl) -> &str {
        let path = address.as_str().split('?').next().unwrap();
        path.rsplit('/').next().unwrap()
    }

    /// Acme uploads a PNG. It is served back from its address as a PNG,
    /// byte for byte.
    #[tokio::test]
    async fn an_uploaded_logo_is_served_back_as_it_is() {
        let fixture = fixture();
        let logo = LogoImage::new(png(400, 120)).unwrap();

        let address = fixture.logos.put(&fixture.tenant, &logo).await.unwrap();
        let served = fixture
            .logos
            .served(key_of(&address))
            .await
            .unwrap()
            .unwrap();

        assert!(
            address
                .as_str()
                .starts_with("https://assets.ianua.test/logos/")
        );
        assert_eq!(served.format().content_type(), "image/png");
        assert_eq!(served.bytes(), logo.bytes());
    }

    /// Acme replaces its PNG with a JPEG. The address changes, so browsers
    /// fetch the new one, and the JPEG is what is served.
    #[tokio::test]
    async fn a_new_logo_replaces_the_old_under_a_new_address() {
        let fixture = fixture();
        let first = LogoImage::new(png(400, 120)).unwrap();
        let second = LogoImage::new(jpeg(640, 200)).unwrap();
        let old = fixture.logos.put(&fixture.tenant, &first).await.unwrap();

        let new = fixture.logos.put(&fixture.tenant, &second).await.unwrap();
        let served = fixture.logos.served(key_of(&new)).await.unwrap().unwrap();

        assert_ne!(old, new);
        assert_eq!(key_of(&old), key_of(&new));
        assert_eq!(served.format(), LogoFormat::Jpeg);
    }

    /// The same logo uploaded twice keeps its address, so a retry changes
    /// nothing.
    #[tokio::test]
    async fn the_same_logo_twice_keeps_its_address() {
        let fixture = fixture();
        let logo = LogoImage::new(png(400, 120)).unwrap();

        let first = fixture.logos.put(&fixture.tenant, &logo).await.unwrap();
        let again = fixture.logos.put(&fixture.tenant, &logo).await.unwrap();

        assert_eq!(first, again);
    }

    /// Traversal strings and noncanonical keys serve no logo; the uploaded logo
    /// remains available by its canonical key.
    #[tokio::test]
    async fn a_key_that_is_not_a_tenant_id_serves_nothing() {
        let fixture = fixture();
        let logo = LogoImage::new(png(400, 120)).unwrap();
        let address = fixture.logos.put(&fixture.tenant, &logo).await.unwrap();
        let hyphenated = fixture.tenant.as_uuid().hyphenated().to_string();

        for key in ["../../etc/passwd", "logo", hyphenated.as_str(), ""] {
            assert!(fixture.logos.served(key).await.unwrap().is_none(), "{key}");
        }
        assert!(
            fixture
                .logos
                .served(key_of(&address))
                .await
                .unwrap()
                .is_some()
        );
    }

    /// Replacing a stored logo with script-containing SVG makes serving it fail
    /// as corrupt storage.
    #[tokio::test]
    async fn a_kept_file_that_is_no_longer_a_logo_is_refused() {
        let fixture = fixture();
        let logo = LogoImage::new(png(400, 120)).unwrap();
        let address = fixture.logos.put(&fixture.tenant, &logo).await.unwrap();
        let name = FileName::logo(&fixture.tenant);
        let folder = name
            .folder()
            .into_iter()
            .fold(fixture.dir.path().to_path_buf(), |path, part| {
                path.join(part)
            });
        std::fs::write(
            folder.join(name.leaf()),
            b"<svg><script>steal()</script></svg>",
        )
        .unwrap();

        let served = fixture.logos.served(key_of(&address)).await;

        assert!(matches!(served, Err(DomainError::Infrastructure(_))));
    }

    /// A tenant that never uploaded a logo has none to serve.
    #[tokio::test]
    async fn a_tenant_without_a_logo_serves_nothing() {
        let fixture = fixture();
        let key = fixture.tenant.as_uuid().simple().to_string();

        assert!(fixture.logos.served(&key).await.unwrap().is_none());
    }
}
