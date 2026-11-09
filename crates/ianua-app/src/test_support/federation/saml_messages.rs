//! Fakes for the SAML messages peers send, and the logout requests this
//! platform sent.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::federation::saml::authn_request::{
    InboundAuthnRequest, InboundAuthnRequestRow, NameIdAsked, Reauthentication, RequestSignature,
};
use ianua_domain::domains::federation::saml::logout::{
    SamlLogoutRequest, SamlLogoutResponse, SentLogoutRequest,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{HttpsUrl, SamlEntityId, SamlRequestId, TenantId};

use crate::ports::TenantScoped;
use crate::ports::federation::{
    InboundSamlMessage, SamlBinding, SamlLogoutLedger, SamlMessageReader, SentLogoutRequestStore,
    SignatureTrust,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::federation::TEST_APP_ENTITY_ID;

/// How the messages a [`FakeSamlMessageReader`] reads were signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeSignature {
    /// Not at all.
    Unsigned,
    /// By a key the reader is told to trust.
    ByTrustedKey,
    /// By some other key.
    Forged,
}

/// The sign-in request a [`FakeSamlMessageReader`] reads.
#[derive(Debug, Clone)]
struct AuthnShape {
    id: SamlRequestId,
    acs_url: Option<HttpsUrl>,
    force_authn: Reauthentication,
    name_id_policy: NameIdAsked,
}

/// Message reader that reads every message as coming from one issuer,
/// signed one way, and as the sign-in or logout message it was given. It
/// remembers the trust it was asked to check under.
pub struct FakeSamlMessageReader {
    issuer: SamlEntityId,
    signature: FakeSignature,
    authn: AuthnShape,
    logout_request: Option<SamlLogoutRequest>,
    logout_response: Option<SamlLogoutResponse>,
    trusts: Mutex<Vec<SignatureTrust>>,
}

impl FakeSamlMessageReader {
    /// The id of the sign-in request every message holds.
    pub const AUTHN_REQUEST_ID: &'static str = "_authn-1";

    /// A reader of unsigned messages from `issuer`, each a sign-in request
    /// naming no address and no format, and no logout message.
    ///
    /// # Panics
    ///
    /// If `issuer` is not an entity id. Tests pass literals that are.
    #[must_use]
    pub fn from_issuer(issuer: &str) -> Self {
        Self {
            issuer: SamlEntityId::new(issuer).expect("a valid entity id"),
            signature: FakeSignature::Unsigned,
            authn: AuthnShape {
                id: SamlRequestId::new(Self::AUTHN_REQUEST_ID).expect("a valid request id"),
                acs_url: None,
                force_authn: Reauthentication::NotForced,
                name_id_policy: NameIdAsked::AnyFormat,
            },
            logout_request: None,
            logout_response: None,
            trusts: Mutex::new(Vec::new()),
        }
    }

    /// The same reader, its messages signed as `signature` says.
    #[must_use]
    pub fn signed(self, signature: FakeSignature) -> Self {
        Self { signature, ..self }
    }

    /// The same reader, its sign-in request asking for the address `url`.
    ///
    /// # Panics
    ///
    /// If `url` is not HTTPS. Tests pass literals that are.
    #[must_use]
    pub fn asking_for(mut self, url: &str) -> Self {
        self.authn.acs_url = Some(HttpsUrl::new(url).expect("a valid url"));
        self
    }

    /// The same reader, its sign-in request asking for a fresh sign-in.
    #[must_use]
    pub fn forcing_sign_in(mut self) -> Self {
        self.authn.force_authn = Reauthentication::Forced;
        self
    }

    /// The same reader, its sign-in request asking for the `NameID` format
    /// `asked`.
    #[must_use]
    pub fn asking_format(mut self, asked: NameIdAsked) -> Self {
        self.authn.name_id_policy = asked;
        self
    }

    /// The same reader, reading `request` as every logout request.
    #[must_use]
    pub fn with_logout_request(self, request: SamlLogoutRequest) -> Self {
        Self {
            logout_request: Some(request),
            ..self
        }
    }

    /// The same reader, reading `response` as every logout answer.
    #[must_use]
    pub fn with_logout_response(self, response: SamlLogoutResponse) -> Self {
        Self {
            logout_response: Some(response),
            ..self
        }
    }

    /// The trusts messages were checked under, in order.
    #[must_use]
    pub fn trusts(&self) -> Vec<SignatureTrust> {
        self.trusts.lock().unwrap().clone()
    }

    /// What the signature counts as under `trust`, as the adapter reads a
    /// sign-in request.
    fn request_signature(&self, trust: &SignatureTrust) -> Result<RequestSignature, DomainError> {
        self.trusts.lock().unwrap().push(trust.clone());
        match (trust, self.signature) {
            (SignatureTrust::NotRequired, _)
            | (SignatureTrust::SignedBy(_), FakeSignature::Unsigned) => {
                Ok(RequestSignature::Absent)
            }
            (SignatureTrust::SignedBy(_), FakeSignature::ByTrustedKey) => {
                Ok(RequestSignature::Verified)
            }
            (SignatureTrust::SignedBy(_), FakeSignature::Forged) => {
                Err(DomainError::forbidden("the signature does not verify"))
            }
        }
    }

    /// Refuses a logout message `trust` wants signed that is not signed by
    /// a trusted key.
    fn ensure_logout_signed(&self, trust: &SignatureTrust) -> Result<(), DomainError> {
        match self.request_signature(trust)? {
            RequestSignature::Verified => Ok(()),
            RequestSignature::Absent if *trust == SignatureTrust::NotRequired => Ok(()),
            RequestSignature::Absent => Err(DomainError::forbidden("the message is unsigned")),
        }
    }
}

impl SamlMessageReader for FakeSamlMessageReader {
    fn issuer(&self, _message: &InboundSamlMessage) -> Result<SamlEntityId, DomainError> {
        Ok(self.issuer.clone())
    }

    fn authn_request(
        &self,
        _message: &InboundSamlMessage,
        trust: &SignatureTrust,
    ) -> Result<InboundAuthnRequest, DomainError> {
        let signature = self.request_signature(trust)?;
        let shape = self.authn.clone();
        InboundAuthnRequest::reconstitute(InboundAuthnRequestRow {
            id: shape.id,
            issuer: Some(self.issuer.clone()),
            acs_url: shape.acs_url,
            force_authn: shape.force_authn,
            name_id_policy: shape.name_id_policy,
            signature,
        })
    }

    fn logout_request(
        &self,
        _message: &InboundSamlMessage,
        trust: &SignatureTrust,
    ) -> Result<SamlLogoutRequest, DomainError> {
        self.ensure_logout_signed(trust)?;
        self.logout_request
            .clone()
            .ok_or_else(|| DomainError::invalid("this is not a logout request"))
    }

    fn logout_response(
        &self,
        _message: &InboundSamlMessage,
        trust: &SignatureTrust,
    ) -> Result<SamlLogoutResponse, DomainError> {
        self.ensure_logout_signed(trust)?;
        self.logout_response
            .clone()
            .ok_or_else(|| DomainError::invalid("this is not a logout answer"))
    }
}

impl Fake for Arc<dyn SamlMessageReader> {
    fn fake() -> Self {
        Arc::new(FakeSamlMessageReader::from_issuer(TEST_APP_ENTITY_ID))
    }
}

/// A message posted in a form, as every test sends one.
#[must_use]
pub fn posted_message() -> InboundSamlMessage {
    InboundSamlMessage {
        binding: SamlBinding::Post,
        message: "PHNhbWxwOk1lc3NhZ2UvPg==".to_owned(),
    }
}

/// In-memory store of sent logout requests, each handed out once.
#[derive(Default)]
pub struct FakeSentLogoutRequests {
    requests: Mutex<Vec<(TenantId, SentLogoutRequest)>>,
}

impl TenantScoped for FakeSentLogoutRequests {}

impl FakeSentLogoutRequests {
    /// A store holding no request.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Every request kept, in every tenant.
    #[must_use]
    pub fn all(&self) -> Vec<SentLogoutRequest> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|(_, request)| request.clone())
            .collect()
    }
}

#[async_trait]
impl SentLogoutRequestStore for FakeSentLogoutRequests {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        request: &SentLogoutRequest,
    ) -> Result<(), DomainError> {
        self.requests
            .lock()
            .unwrap()
            .push((**tenant_id, request.clone()));
        Ok(())
    }

    async fn take(
        &self,
        tenant_id: &ScopedTenant,
        id: &SamlRequestId,
    ) -> Result<Option<SentLogoutRequest>, DomainError> {
        let mut requests = self.requests.lock().unwrap();
        let position = requests
            .iter()
            .position(|(tenant, request)| tenant == &**tenant_id && request.id() == id);
        Ok(position.map(|at| requests.remove(at).1))
    }
}

impl Fake for Arc<dyn SentLogoutRequestStore> {
    fn fake() -> Self {
        Arc::new(FakeSentLogoutRequests::empty())
    }
}

/// Remembers the logout requests taken, per tenant, by issuer and id, like
/// the real ledger.
#[derive(Default)]
pub struct FakeSamlLogoutLedger {
    taken: Mutex<Vec<(TenantId, SamlEntityId, SamlRequestId)>>,
}

impl TenantScoped for FakeSamlLogoutLedger {}

impl FakeSamlLogoutLedger {
    /// A ledger that took nothing yet.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SamlLogoutLedger for FakeSamlLogoutLedger {
    async fn spend(
        &self,
        tenant_id: &ScopedTenant,
        request: &SamlLogoutRequest,
    ) -> Result<bool, DomainError> {
        let key = (**tenant_id, request.issuer().clone(), request.id().clone());
        let mut taken = self.taken.lock().unwrap();
        if taken.contains(&key) {
            return Ok(false);
        }
        taken.push(key);
        Ok(true)
    }
}

impl Fake for Arc<dyn SamlLogoutLedger> {
    fn fake() -> Self {
        Arc::new(FakeSamlLogoutLedger::empty())
    }
}
