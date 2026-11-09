//! Fakes for what is kept against a session here for single logout: the
//! SAML apps it signed in to, and the provider session behind it. Both are
//! kept and forgotten by the session they belong to, so one store keeps
//! either.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{SessionId, TenantId};

use crate::ports::TenantScoped;
use crate::ports::federation::{
    ProviderSession, ProviderSessionStore, SamlAppSession, SamlAppSessionStore,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;

/// A record kept against the session here it belongs to.
pub trait KeptForSession: Clone + Send + Sync {
    /// The session it belongs to.
    fn session(&self) -> &SessionId;
}

impl KeptForSession for SamlAppSession {
    fn session(&self) -> &SessionId {
        &self.session_id
    }
}

impl KeptForSession for ProviderSession {
    fn session(&self) -> &SessionId {
        &self.session_id
    }
}

/// In-memory records kept against sessions, each under its tenant.
pub struct FakeSessionRecords<T> {
    records: Mutex<Vec<(TenantId, T)>>,
}

/// In-memory record of the SAML apps each session signed in to.
pub type FakeSamlAppSessions = FakeSessionRecords<SamlAppSession>;

/// In-memory record of the provider sessions behind sessions here.
pub type FakeProviderSessions = FakeSessionRecords<ProviderSession>;

impl<T> TenantScoped for FakeSessionRecords<T> {}

impl<T: KeptForSession> FakeSessionRecords<T> {
    /// A store holding no record.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            records: Mutex::new(Vec::new()),
        }
    }

    /// Every record kept, in every tenant.
    #[must_use]
    pub fn all(&self) -> Vec<T> {
        self.records
            .lock()
            .unwrap()
            .iter()
            .map(|(_, record)| record.clone())
            .collect()
    }

    /// Keeps `record` in `tenant`.
    fn keep(&self, tenant: &ScopedTenant, record: &T) {
        self.records
            .lock()
            .unwrap()
            .push((**tenant, record.clone()));
    }

    /// The records `tenant` keeps against `session`.
    fn of_session(&self, tenant: &ScopedTenant, session: &SessionId) -> Vec<T> {
        self.records
            .lock()
            .unwrap()
            .iter()
            .filter(|(kept_in, record)| kept_in == &**tenant && record.session() == session)
            .map(|(_, record)| record.clone())
            .collect()
    }

    /// Forgets every record `tenant` keeps against `session`.
    fn forget(&self, tenant: &ScopedTenant, session: &SessionId) {
        self.records
            .lock()
            .unwrap()
            .retain(|(kept_in, record)| !(kept_in == &**tenant && record.session() == session));
    }
}

#[async_trait]
impl SamlAppSessionStore for FakeSamlAppSessions {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        app_session: &SamlAppSession,
    ) -> Result<(), DomainError> {
        self.keep(tenant_id, app_session);
        Ok(())
    }

    async fn list_by_session(
        &self,
        tenant_id: &ScopedTenant,
        session_id: &SessionId,
    ) -> Result<Vec<SamlAppSession>, DomainError> {
        Ok(self.of_session(tenant_id, session_id))
    }

    async fn delete_by_session(
        &self,
        tenant_id: &ScopedTenant,
        session_id: &SessionId,
    ) -> Result<(), DomainError> {
        self.forget(tenant_id, session_id);
        Ok(())
    }
}

impl Fake for Arc<dyn SamlAppSessionStore> {
    fn fake() -> Self {
        Arc::new(FakeSamlAppSessions::empty())
    }
}

#[async_trait]
impl ProviderSessionStore for FakeProviderSessions {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        session: &ProviderSession,
    ) -> Result<(), DomainError> {
        self.keep(tenant_id, session);
        Ok(())
    }

    async fn find_by_session(
        &self,
        tenant_id: &ScopedTenant,
        session_id: &SessionId,
    ) -> Result<Option<ProviderSession>, DomainError> {
        Ok(self.of_session(tenant_id, session_id).into_iter().next())
    }

    async fn delete_by_session(
        &self,
        tenant_id: &ScopedTenant,
        session_id: &SessionId,
    ) -> Result<(), DomainError> {
        self.forget(tenant_id, session_id);
        Ok(())
    }
}

impl Fake for Arc<dyn ProviderSessionStore> {
    fn fake() -> Self {
        Arc::new(FakeProviderSessions::empty())
    }
}
