//! Fakes for connecting an account by signing in at a service: the service
//! and its app, the random values, and the connections kept.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::workflows::account::connection::{
    PendingConnection, PendingConnectionRow,
};
use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{PendingConnectionId, TenantId, TokenHash};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::ports::workflows::{
    ConnectionAt, ConnectionSecrets, ConnectionStates, Exchanging, PendingConnectionStore,
    PlaceAsked, ServiceSignIn, SignInAddress, SignInFailure, SignInRequest,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;

/// `connection` as it reads back from storage.
fn connection_copy(
    connection: &PendingConnection<ResolvedTenant>,
) -> PendingConnection<ResolvedTenant> {
    PendingConnection::reconstitute(PendingConnectionRow {
        id: *connection.id(),
        integration: connection.integration().clone(),
        name: connection.name().clone(),
        sharing: connection.sharing(),
        scope: connection.scope().clone(),
        place: connection.place().cloned(),
        started_by: connection.started_by().clone(),
        state: connection.state().clone(),
        verifier: connection.verifier().clone(),
        stage: connection.stage().clone(),
        expires_at: connection.expires_at(),
        created_at: Aggregate::created_at(connection),
        updated_at: Aggregate::updated_at(connection),
    })
    .expect("a kept connection reads back as itself")
}

/// In-memory connections, which also finds a connection by its state
/// across tenants.
#[derive(Default)]
pub struct FakePendingConnectionStore {
    kept: Mutex<Vec<(TenantId, PendingConnection<ResolvedTenant>)>>,
}

impl TenantScoped for FakePendingConnectionStore {}

impl FakePendingConnectionStore {
    /// A store holding no connection.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }
}

#[async_trait]
impl PendingConnectionStore for FakePendingConnectionStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &PendingConnectionId,
    ) -> Result<Option<PendingConnection<ResolvedTenant>>, DomainError> {
        Ok(self
            .kept
            .lock()
            .unwrap()
            .iter()
            .find(|(tenant, kept)| tenant == &**tenant_id && kept.id() == id)
            .map(|(_, kept)| connection_copy(kept)))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        connection: &PendingConnection<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut kept = self.kept.lock().unwrap();
        let same_state = kept
            .iter()
            .any(|(_, held)| held.id() != connection.id() && held.state() == connection.state());
        if same_state {
            return Err(DomainError::conflict(message!(
                "test-the-state-is-kept-already",
                "the state is kept already"
            )));
        }
        kept.retain(|(_, held)| held.id() != connection.id());
        kept.push((**tenant_id, connection_copy(connection)));
        Ok(())
    }
}

#[async_trait]
impl ConnectionStates for FakePendingConnectionStore {
    async fn find(&self, state: &TokenHash) -> Result<Option<ConnectionAt>, DomainError> {
        Ok(self
            .kept
            .lock()
            .unwrap()
            .iter()
            .find(|(_, kept)| kept.state() == state)
            .map(|(tenant, kept)| ConnectionAt {
                tenant_id: *tenant,
                connection_id: *kept.id(),
            }))
    }

    async fn remove_expired(&self, now: OffsetDateTime, limit: u32) -> Result<u64, DomainError> {
        let mut kept = self.kept.lock().unwrap();
        let before = kept.len();
        let mut left = u64::from(limit);
        kept.retain(|(_, held)| {
            let remove = left > 0 && held.expired_at(now);
            left -= u64::from(remove);
            !remove
        });
        Ok((before - kept.len()) as u64)
    }
}

impl Fake for Arc<dyn PendingConnectionStore> {
    fn fake() -> Self {
        Arc::new(FakePendingConnectionStore::empty())
    }
}

impl Fake for Arc<dyn ConnectionStates> {
    fn fake() -> Self {
        Arc::new(FakePendingConnectionStore::empty())
    }
}

/// A service offering sign-in for one integration, issuing `credential`
/// for the code `code`, and refusing any other.
pub struct FakeServiceSignIn {
    integration: IntegrationKey,
    code: String,
    credential: String,
    asks: PlaceAsked,
    asked: Mutex<Vec<(String, String)>>,
    places: Mutex<Vec<Option<String>>>,
}

impl FakeServiceSignIn {
    /// A service for `integration` swapping `code` for `credential`.
    #[must_use]
    pub fn issuing(integration: &str, code: &str, credential: &str) -> Self {
        Self {
            integration: IntegrationKey::new(integration).expect("a valid key"),
            code: code.to_owned(),
            credential: credential.to_owned(),
            asks: PlaceAsked::Nothing,
            asked: Mutex::new(Vec::new()),
            places: Mutex::new(Vec::new()),
        }
    }

    /// The service, its sign-in asking for the space named `word`, as
    /// Azure DevOps asks for an organization.
    #[must_use]
    pub fn asking_for(mut self, word: &'static str) -> Self {
        self.asks = PlaceAsked::Named(word);
        self
    }

    /// Each code it was asked to swap, with the verifier that came with it.
    #[must_use]
    pub fn swapped(&self) -> Vec<(String, String)> {
        self.asked.lock().unwrap().clone()
    }

    /// The place each swap was for.
    #[must_use]
    pub fn places(&self) -> Vec<Option<String>> {
        self.places.lock().unwrap().clone()
    }
}

#[async_trait]
impl ServiceSignIn for FakeServiceSignIn {
    fn offers(&self, integration: &IntegrationKey) -> bool {
        *integration == self.integration
    }

    fn asks_for(&self, integration: &IntegrationKey) -> PlaceAsked {
        match self.offers(integration) {
            true => self.asks,
            false => PlaceAsked::Nothing,
        }
    }

    fn authorize_address(
        &self,
        integration: &IntegrationKey,
        request: SignInRequest<'_>,
    ) -> Result<SignInAddress, DomainError> {
        if !self.offers(integration) {
            return Err(DomainError::invalid("no sign-in for this integration"));
        }
        Ok(SignInAddress::new(format!(
            "https://{integration}.test/authorize?state={}",
            request.state.expose()
        )))
    }

    async fn exchange(&self, exchanging: Exchanging<'_>) -> Result<Secret, SignInFailure> {
        self.asked.lock().unwrap().push((
            exchanging.code.expose().to_owned(),
            exchanging.verifier.expose().to_owned(),
        ));
        self.places
            .lock()
            .unwrap()
            .push(exchanging.place.map(|place| place.as_str().to_owned()));
        if exchanging.code.expose() != self.code {
            return Err(SignInFailure::Refused);
        }
        Ok(Secret::new(self.credential.clone()))
    }
}

impl Fake for Arc<dyn ServiceSignIn> {
    fn fake() -> Self {
        Arc::new(FakeServiceSignIn::issuing(
            "github",
            "no code",
            "no credential",
        ))
    }
}

/// Random values counting up, `value-1`, `value-2` and on, each digested
/// as `digest:` before it.
#[derive(Default)]
pub struct FakeConnectionSecrets {
    made: Mutex<u32>,
}

impl ConnectionSecrets for FakeConnectionSecrets {
    fn generate(&self) -> Result<(Secret, TokenHash), DomainError> {
        let mut made = self.made.lock().unwrap();
        *made += 1;
        let value = Secret::new(format!("value-{made}"));
        let digest = self.digest(&value);
        Ok((value, digest))
    }

    fn digest(&self, presented: &Secret) -> TokenHash {
        TokenHash::from_stored(format!("digest:{}", presented.expose()))
    }
}

impl Fake for Arc<dyn ConnectionSecrets> {
    fn fake() -> Self {
        Arc::new(FakeConnectionSecrets::default())
    }
}
