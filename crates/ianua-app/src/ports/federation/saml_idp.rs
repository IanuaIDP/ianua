//! SAML as an identity provider: the tenant's SAML apps, the names people
//! are given to them, the assertions sealed for them, the certificate the
//! metadata publishes, the apps each session signed in to, and the sign-in
//! requests held from the moment they arrived until they are answered.

use async_trait::async_trait;
use ianua_domain::domains::federation::saml::name_id::SamlNameIdValue;
use ianua_domain::domains::federation::service_provider::SamlServiceProvider;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    CertificatePem, SamlArrivalId, SamlEntityId, SamlServiceProviderId, SessionId, SessionIndex,
    UserId,
};
use time::OffsetDateTime;

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys};
use crate::ports::TenantScoped;
use crate::ports::crypto::XmlSigningKey;
use crate::ports::federation::InboundSamlMessage;
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// The one order a tenant's SAML apps are listed in: newest first.
    pub enum SamlAppSortField {
        /// Order by creation time.
        CreatedAt => "created_at",
    }
    default = CreatedAt;
    default direction = Desc;
}

impl SortKeys<SamlAppSortField> for SamlServiceProvider<ResolvedTenant> {
    fn sort_key(&self, field: SamlAppSortField) -> SortKey {
        match field {
            SamlAppSortField::CreatedAt => self.created_at().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// Dyn-safe port for the tenant's SAML apps.
///
/// An app's entity id is unique within its tenant: two apps naming
/// themselves alike would leave a request to whichever is read first.
#[async_trait]
pub trait SamlServiceProviderStore: Send + Sync + TenantScoped {
    /// The app with `id`, if the tenant has it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &SamlServiceProviderId,
    ) -> Result<Option<SamlServiceProvider<ResolvedTenant>>, DomainError>;

    /// The app whose entity id is `entity_id`, if the tenant has it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_entity_id(
        &self,
        tenant_id: &ScopedTenant,
        entity_id: &SamlEntityId,
    ) -> Result<Option<SamlServiceProvider<ResolvedTenant>>, DomainError>;

    /// One page of the tenant's apps, newest first.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list(
        &self,
        tenant_id: &ScopedTenant,
        page: &PageRequest,
    ) -> Result<Page<SamlServiceProvider<ResolvedTenant>>, DomainError>;

    /// Saves a new or changed app.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` if another app of the tenant has the
    /// same entity id, or `DomainError::Infrastructure` on persistence
    /// failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        provider: &SamlServiceProvider<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Removes the app with `id`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &SamlServiceProviderId,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port making the `NameID` values that need a secret or a random
/// source, as the domain's `NameIdMint` asks.
///
/// # Implementors
///
/// - **Infrastructure:** a keyed hash of the app and the account under a
///   platform secret for the pairwise id, and random bytes for the
///   transient one.
/// - **Tests:** a fake returning fixed values.
pub trait SamlNameIds: Send + Sync {
    /// The pairwise id of `account` at `provider`: the same inputs give the
    /// same id every time, and nobody without the secret can link two apps'
    /// ids for one person.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the secret cannot be read.
    fn pairwise(
        &self,
        provider: &SamlServiceProviderId,
        account: &UserId,
    ) -> Result<SamlNameIdValue, DomainError>;

    /// A fresh random value, never given out before.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the random source fails.
    fn transient(&self) -> Result<SamlNameIdValue, DomainError>;
}

/// Dyn-safe port sealing a signed assertion for the app it is for.
#[async_trait]
pub trait AssertionEncrypter: Send + Sync {
    /// `signed_assertion` encrypted to the key in `recipient`, as a
    /// `<saml:EncryptedAssertion>` element, so the browser it passes
    /// through cannot read it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the certificate cannot be
    /// read or the encryption fails.
    async fn encrypt(
        &self,
        signed_assertion: &str,
        recipient: &CertificatePem,
    ) -> Result<String, DomainError>;
}

/// Dyn-safe port that issues the certificate an identity provider's
/// metadata carries for its signing key.
///
/// SAML names the key that signs assertions only through an X.509
/// certificate. The adapter wraps the key's public half in a certificate
/// signed with the key itself, its subject `issuer`. A service provider that
/// imports the metadata then checks each assertion against that public key.
/// The same key gives a certificate for the same public key every time, so
/// metadata fetched twice names one key.
#[async_trait]
pub trait SigningCertificateIssuer: Send + Sync {
    /// The certificate for `key`, issued in the name of `issuer`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the key cannot sign or the
    /// certificate cannot be written.
    async fn certificate_for(
        &self,
        key: &XmlSigningKey<'_>,
        issuer: &SamlEntityId,
    ) -> Result<CertificatePem, DomainError>;
}

/// A SAML app a session signed in to: the name the person went out as and
/// the session index the app keeps, so a logout reaches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlAppSession {
    /// The session here that signed in to the app.
    pub session_id: SessionId,
    /// The app.
    pub provider_id: SamlServiceProviderId,
    /// The `NameID` the person went out as.
    pub name_id: SamlNameIdValue,
    /// The session index the assertion carried.
    pub session_index: SessionIndex,
}

/// Dyn-safe port for the SAML apps each session signed in to.
#[async_trait]
pub trait SamlAppSessionStore: Send + Sync + TenantScoped {
    /// Remembers that a session signed in to an app.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        app_session: &SamlAppSession,
    ) -> Result<(), DomainError>;

    /// The apps `session_id` signed in to, each sign-in once.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_by_session(
        &self,
        tenant_id: &ScopedTenant,
        session_id: &SessionId,
    ) -> Result<Vec<SamlAppSession>, DomainError>;

    /// Forgets every app `session_id` signed in to, once logouts went out
    /// to them.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete_by_session(
        &self,
        tenant_id: &ScopedTenant,
        session_id: &SessionId,
    ) -> Result<(), DomainError>;
}

/// An app's sign-in request, held as it reached this platform until the
/// person it is for has signed in and it is answered.
///
/// The time it arrived is set here and never comes back from the browser:
/// an app that asks for a fresh sign-in is answered only for a sign-in made
/// after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldSamlSignIn {
    /// What the dashboard names the request by.
    pub id: SamlArrivalId,
    /// The request, as it arrived.
    pub message: InboundSamlMessage,
    /// What the app wants back with the answer, if it sent anything.
    pub relay_state: Option<String>,
    /// When the request reached this platform.
    pub arrived_at: OffsetDateTime,
}

/// Dyn-safe port for the sign-in requests held until they are answered.
///
/// A request is answered within ten minutes of arriving; storage may drop
/// one once that has passed.
#[async_trait]
pub trait HeldSamlSignInStore: Send + Sync + TenantScoped {
    /// Holds a request that just arrived.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn hold(
        &self,
        tenant_id: &ScopedTenant,
        request: &HeldSamlSignIn,
    ) -> Result<(), DomainError>;

    /// The request held as `id` in the tenant, if it still is.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        id: &SamlArrivalId,
    ) -> Result<Option<HeldSamlSignIn>, DomainError>;

    /// Lets go of the request held as `id` once it is answered, so it is
    /// answered once.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn release(
        &self,
        tenant_id: &ScopedTenant,
        id: &SamlArrivalId,
    ) -> Result<(), DomainError>;
}
