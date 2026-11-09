//! How a device's user code is kept: whoever holds it while the request
//! waits can approve the device with their own account, so it is never
//! stored as typed. Its keyed hash finds a typed code, and the code sealed
//! is opened again for the page that shows it.

use std::sync::Arc;

use ianua_app::ports::authentication::{SealOwner, SealedField, SealedFor, SecretEncryptor};
use ianua_app::ports::oauth::CodeHasher;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{DeviceUserCode, SealedSecret, TenantId};

use crate::postgres::oauth::devices::record::{DEVICE, DeviceAuthRecord};

/// Where the user code of `tenant`'s request kept under the digest
/// `device_code_hash`, the row's key, is sealed for.
fn code_place(tenant: TenantId, device_code_hash: &str) -> SealedFor {
    SealedFor::new(
        SealOwner::Tenant(tenant),
        SealedField::DeviceUserCode,
        device_code_hash,
    )
}

/// The hasher and the sealer a user code is kept with.
pub(super) struct UserCodes {
    hasher: Arc<dyn CodeHasher>,
    encryptor: Arc<dyn SecretEncryptor>,
}

impl UserCodes {
    /// User codes hashed by `hasher` and sealed by `encryptor`.
    pub(super) fn new(hasher: Arc<dyn CodeHasher>, encryptor: Arc<dyn SecretEncryptor>) -> Self {
        Self { hasher, encryptor }
    }

    /// The keyed hash `code` is found by.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the hash cannot be made.
    pub(super) async fn hash_of(&self, code: &DeviceUserCode) -> Result<String, DomainError> {
        let hash = self.hasher.hash_code(&Secret::new(code.as_str())).await?;
        Ok(hash.as_str().to_owned())
    }

    /// `code` of `tenant`'s request kept under `device_code_hash`, sealed
    /// for storage.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be sealed.
    pub(super) async fn sealed(
        &self,
        tenant: TenantId,
        device_code_hash: &str,
        code: &DeviceUserCode,
    ) -> Result<String, DomainError> {
        let place = code_place(tenant, device_code_hash);
        let sealed = self
            .encryptor
            .encrypt(code.as_str().as_bytes(), &place)
            .await?;
        Ok(sealed.as_str().to_owned())
    }

    /// The code `record` holds, opened for the request it belongs to and
    /// read back through its rules.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it was not sealed by this
    /// sealer for this request, or what it holds is no user code.
    pub(super) async fn opened(
        &self,
        record: &DeviceAuthRecord,
    ) -> Result<DeviceUserCode, DomainError> {
        let sealed = DEVICE.value(
            "sealed user code",
            SealedSecret::new(record.user_code_sealed.as_str()),
        )?;
        let place = code_place(record.tenant(), &record.device_code_hash);
        let bytes = self.encryptor.decrypt(&sealed, &place).await?;
        let text = String::from_utf8(bytes)
            .map_err(|_| DomainError::corrupt_row(DEVICE.0, "a user code that is no text"))?;
        DEVICE.value("user code", DeviceUserCode::new(text))
    }
}
