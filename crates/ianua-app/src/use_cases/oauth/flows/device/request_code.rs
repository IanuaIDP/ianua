//! The start of the device flow: a device without a browser asks for a code
//! a person will approve on another screen (RFC 8628 3.1).
//!
//! The device's client proves itself the way it registered, as at the token
//! endpoint; a device app is usually public and proves nothing.

use std::sync::Arc;

use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClient};
use ianua_domain::domains::oauth::grants::device_authorization::{
    CreateDeviceAuthParams, DeviceAuthorization, PollInterval,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, DeviceUserCode, HttpsUrl, Issuer, Lifetime, Scope};

use crate::auditor::RequestAuditor;
use crate::error::OrInternal;
use crate::ports::oauth::{CodeHasher, DeviceAuthStore};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::oauth::token::client_auth::{
    Asking, ClientAuthPorts, ClientProof, authenticated_client,
};
use crate::use_cases::oauth::token::issuing::ensure_may_use;
use crate::use_cases::oauth::token::refusal::{OAuthErrorCode, TokenError};

/// What a device asks for.
pub struct RequestDeviceCodeRequest {
    /// How the device's client proves itself.
    pub client: ClientProof,
    /// The tenant's issuer.
    pub issuer: Issuer,
    /// The scopes it asks for.
    pub scopes: Vec<Scope>,
}

/// The codes a device is handed.
pub struct DeviceCodeResult {
    /// The raw device code the device polls with.
    pub device_code: Secret,
    /// The short code the person types on the other screen.
    pub user_code: DeviceUserCode,
    /// Where the person goes to type it.
    pub verification_uri: HttpsUrl,
    /// The shortest wait between polls.
    pub interval: PollInterval,
    /// How long the codes stay valid.
    pub expires_in: Lifetime,
}

/// How long device codes last and how often a device may poll.
#[derive(Debug, Clone, Copy)]
pub struct DeviceCodeTiming {
    /// How long the device and user codes stay valid.
    pub lifetime: Lifetime,
    /// The shortest wait between polls.
    pub poll_interval: PollInterval,
}

/// The ports [`RequestDeviceCodeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RequestDeviceCodePorts {
    /// How the device's client proves itself.
    pub client_auth: ClientAuthPorts,
    /// Where device requests are kept.
    pub device_auth_store: Arc<dyn DeviceAuthStore>,
    /// Makes the device code, its hash and the user code.
    pub code_hasher: Arc<dyn CodeHasher>,
}

/// Starts a device authorization.
pub struct RequestDeviceCodeUseCase {
    ports: RequestDeviceCodePorts,
    verification_uri: HttpsUrl,
    timing: DeviceCodeTiming,
}

impl RequestDeviceCodeUseCase {
    /// A use case working through `ports`, sending people to
    /// `verification_uri`, with codes timed by `timing`.
    #[must_use]
    pub fn new(
        ports: RequestDeviceCodePorts,
        verification_uri: HttpsUrl,
        timing: DeviceCodeTiming,
    ) -> Self {
        Self {
            ports,
            verification_uri,
            timing,
        }
    }

    /// A pending request `client` starts for `scopes`, with fresh codes and
    /// the raw device code.
    async fn pending_request(
        &self,
        client: &OAuthClient<ResolvedTenant>,
        scopes: Vec<Scope>,
    ) -> Result<(DeviceAuthorization<ResolvedTenant>, Secret), TokenError> {
        let hasher = self.ports.code_hasher.as_ref();
        let (device_code, device_code_hash) = hasher.generate_device_code().await.or_internal()?;
        let user_code = hasher.generate_user_code().await.or_internal()?;
        let params = CreateDeviceAuthParams {
            device_code_hash,
            user_code,
            scopes,
            interval: self.timing.poll_interval,
            lifetime: self.timing.lifetime,
        };
        let auth = DeviceAuthorization::create(client, params).map_err(|_| {
            TokenError::refused(
                OAuthErrorCode::InvalidScope,
                "a scope is not one this client was given",
            )
        })?;
        Ok((auth, device_code))
    }
}

impl Command for RequestDeviceCodeUseCase {
    type Caller = ScopedTenant;
    type Input = RequestDeviceCodeRequest;
    type Output = Result<DeviceCodeResult, TokenError>;

    /// Starts a device authorization in `tenant` for what `req` asks.
    /// Nobody is signed in on the device yet, so it records
    /// `oauth.device_authorization_requested` by the platform.
    ///
    /// # Errors
    ///
    /// - `invalid_client` when the client is unknown, revoked or does not
    ///   prove itself.
    /// - `unauthorized_client` when it was not given the device flow.
    /// - `invalid_scope` when it asks for a scope it was not given.
    /// - `TokenError::Failed` when the codes cannot be made, or the request
    ///   cannot be saved or audited.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        req: RequestDeviceCodeRequest,
    ) -> Result<DeviceCodeResult, TokenError> {
        let asking = Asking {
            tenant,
            issuer: &req.issuer,
        };
        let client = authenticated_client(&self.ports.client_auth, asking, &req.client).await?;
        ensure_may_use(&client, GrantType::DeviceCode)?;
        let (mut auth, device_code) = self.pending_request(&client, req.scopes).await?;
        self.ports
            .device_auth_store
            .save(tenant, &auth)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ActorRef::System, auth.take_events(tenant))
            .await
            .or_internal()?;
        Ok(DeviceCodeResult {
            device_code,
            user_code: auth.user_code().clone(),
            verification_uri: self.verification_uri.clone(),
            interval: auth.interval(),
            expires_in: self.timing.lifetime,
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::status::OAuthClientStatus;

    use super::*;
    use crate::test_support::oauth::{
        FakeDeviceAuthStore, FakeOAuthClientStore, client_with, public_client, stored_client,
        test_issuer,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A tenant holding one device client, and the requests started.
    struct Fixture {
        client: OAuthClient<ResolvedTenant>,
        clients: Arc<FakeOAuthClientStore>,
        requests: Arc<FakeDeviceAuthStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        /// The tenant holding `client`.
        fn holding(client: OAuthClient<ResolvedTenant>) -> Self {
            Self {
                clients: Arc::new(FakeOAuthClientStore::holding(
                    &test_ctx().tenant(),
                    client.clone(),
                )),
                client,
                requests: Arc::new(FakeDeviceAuthStore::empty()),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// The tenant holding a public TV app.
        fn tv() -> Self {
            Self::holding(public_client("TV", &[GrantType::DeviceCode]))
        }

        /// The client asking, proving nothing, for `scope`.
        fn asking(&self, scope: &str) -> RequestDeviceCodeRequest {
            RequestDeviceCodeRequest {
                client: ClientProof::Nothing {
                    client_id: self.client.client_id_value().clone(),
                },
                issuer: test_issuer(),
                scopes: vec![Scope::new(scope).unwrap()],
            }
        }

        /// What starting `req` answers.
        fn request(&self, req: RequestDeviceCodeRequest) -> Result<DeviceCodeResult, TokenError> {
            let use_case = RequestDeviceCodeUseCase::new(
                RequestDeviceCodePorts {
                    client_auth: ClientAuthPorts {
                        client_store: self.clients.clone(),
                        ..ClientAuthPorts::fakes()
                    },
                    device_auth_store: self.requests.clone(),
                    ..RequestDeviceCodePorts::fakes()
                },
                HttpsUrl::new("https://auth.acme.example/device").unwrap(),
                DeviceCodeTiming {
                    lifetime: Lifetime::seconds(600).unwrap(),
                    poll_interval: PollInterval::DEFAULT,
                },
            );
            let auditor = test_auditor(self.audit.clone());
            block_on(use_case.execute(&test_ctx().tenant(), &auditor, req))
        }

        /// The audit records written, by event name.
        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// The error code `result` was refused with, if it was.
    fn refused_with(result: &Result<DeviceCodeResult, TokenError>) -> Option<OAuthErrorCode> {
        result.as_ref().err().and_then(TokenError::code)
    }

    /// Ann's TV asks to read for her. It gets a device code to poll with, a
    /// short code to show her and where to type it; the request is kept
    /// pending and recorded.
    #[test]
    fn a_device_gets_codes_and_the_request_waits() {
        let fixture = Fixture::tv();

        let result = fixture.request(fixture.asking("read")).unwrap();

        assert!(!result.device_code.expose().is_empty());
        assert_eq!(result.interval, PollInterval::DEFAULT);
        let kept = block_on(
            fixture
                .requests
                .find_by_user_code(&test_ctx().tenant(), &result.user_code),
        )
        .unwrap()
        .unwrap();
        assert!(kept.is_pending());
        assert_eq!(fixture.recorded(), ["oauth.device_authorization_requested"]);
    }

    /// A device client requesting an ungranted scope receives invalid_scope,
    /// with no stored request or audit event.
    #[test]
    fn a_scope_the_client_was_not_given_is_refused() {
        let fixture = Fixture::tv();

        let result = fixture.request(fixture.asking("admin"));

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidScope));
        assert_eq!(fixture.requests.count(), 0);
        assert!(fixture.recorded().is_empty());
    }

    /// A client allowed only client credentials receives unauthorized_client
    /// when it requests the device flow.
    #[test]
    fn a_client_without_the_device_flow_is_refused() {
        let fixture = Fixture::holding(stored_client("Robot", &[GrantType::ClientCredentials]));

        let result = fixture.request(RequestDeviceCodeRequest {
            client: crate::test_support::oauth::basic_proof(&fixture.client),
            ..fixture.asking("read")
        });

        assert_eq!(
            refused_with(&result),
            Some(OAuthErrorCode::UnauthorizedClient)
        );
    }

    /// A revoked device client receives invalid_client when requesting codes.
    #[test]
    fn a_revoked_client_is_refused() {
        let fixture = Fixture::holding(client_with("TV", &[GrantType::DeviceCode], |row| {
            row.credential =
                ianua_domain::domains::oauth::clients::credential::ClientCredential::Public;
            row.status = OAuthClientStatus::Revoked;
        }));

        let result = fixture.request(fixture.asking("read"));

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidClient));
    }

    /// A device request naming an unknown client receives invalid_client.
    #[test]
    fn an_unknown_client_is_refused() {
        let fixture = Fixture::tv();

        let result = fixture.request(RequestDeviceCodeRequest {
            client: ClientProof::Nothing {
                client_id: ianua_domain::types::ClientId::new("client_unknown").unwrap(),
            },
            ..fixture.asking("read")
        });

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidClient));
    }
}
