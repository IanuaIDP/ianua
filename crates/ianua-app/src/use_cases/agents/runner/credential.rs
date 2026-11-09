//! Credential: what one request from the agent carries on its way out of
//! the sandbox.
//!
//! The runner sends the request where its path says: to the message relay
//! for a topic, to the gateway for everything else. It attaches the task
//! token that destination takes, and for the gateway a proof of possession
//! made with the agent's key for this request alone, so the token is
//! useless to whoever copies it. The agent holds neither the key nor the
//! token. Nothing is recorded here: the platform records the token
//! exchange, and the gateway each request it decides.

use std::sync::Arc;

use ianua_domain::domains::agents::runner::{GatewayAddress, RunnerDestination};
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::shared::clock;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::HttpMethod;

use crate::error::AppError;
use crate::ports::agents::{
    ProofRequest, RunnerKey, RunnerKeys, RunnerProofs, RunnerTokens, TaskToken,
};
use crate::use_case::Query;

/// One request from the agent, as far as its credential depends on it.
#[derive(Debug, Clone)]
pub struct CredentialRequest {
    /// The request's method.
    pub method: HttpMethod,
    /// Its path with the query, as the destination receives it.
    pub path_and_query: String,
}

impl CredentialRequest {
    /// The path alone, without the query or a fragment.
    fn path(&self) -> &str {
        self.path_and_query
            .split(['?', '#'])
            .next()
            .unwrap_or_default()
    }
}

/// Where a request goes and what it carries there.
pub enum Credential {
    /// To the gateway, with a token bound to the agent's key and the proof
    /// that the key's holder sends this request.
    Gateway {
        /// Delegated access bound to the signing key used by the proof.
        token: TaskToken,
        /// The proof, a `DPoP` header's value.
        proof: Secret,
    },
    /// To the message relay, for `topic`, with a bearer token.
    Relay {
        /// The relay destination this credential authorizes.
        topic: TopicName,
        /// The bearer value presented to the message relay.
        token: TaskToken,
    },
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gateway { .. } => f.write_str("Credential::Gateway(***)"),
            Self::Relay { topic, .. } => write!(f, "Credential::Relay({})", topic.as_str()),
        }
    }
}

/// The ports [`CredentialUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CredentialPorts {
    /// The key the runner signs with.
    pub keys: Arc<dyn RunnerKeys>,
    /// The task tokens it holds.
    pub tokens: Arc<dyn RunnerTokens>,
    /// Signs the proofs.
    pub proofs: Arc<dyn RunnerProofs>,
}

/// Works out what each of the agent's requests carries.
pub struct CredentialUseCase {
    ports: CredentialPorts,
    gateway: GatewayAddress,
}

impl CredentialUseCase {
    /// A use case working through `ports`, for an agent whose requests
    /// address the gateway as `gateway`.
    #[must_use]
    pub fn new(ports: CredentialPorts, gateway: GatewayAddress) -> Self {
        Self { ports, gateway }
    }

    /// The proof that `token`'s holder sends `req` to the gateway now.
    fn proof(
        &self,
        key: &RunnerKey,
        token: &TaskToken,
        req: &CredentialRequest,
    ) -> Result<Secret, AppError> {
        let target = self.gateway.proof_target(&req.path_and_query);
        self.ports
            .proofs
            .proof(
                key,
                &ProofRequest {
                    method: req.method,
                    target: &target,
                    token,
                    at: clock::now(),
                },
            )
            .map_err(AppError::from_domain)
    }
}

impl Query for CredentialUseCase {
    type Caller = ();
    type Input = CredentialRequest;
    type Output = Result<Credential, AppError>;

    /// What `req` carries: the destination its path names, the token that
    /// destination takes, and for the gateway the proof for this request.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the path names the relay but no topic.
    /// - `AppError::Forbidden` when the platform refused the attestation
    ///   or the token exchange.
    /// - `AppError::Internal` when no key or token can be had, or the key
    ///   cannot sign.
    async fn execute(&self, _caller: &(), req: CredentialRequest) -> Result<Credential, AppError> {
        let destination = RunnerDestination::of(req.path())?;
        let key = self
            .ports
            .keys
            .current()
            .await
            .map_err(AppError::from_domain)?;
        let token = self
            .ports
            .tokens
            .current(&key, destination.token_binding())
            .await
            .map_err(AppError::from_domain)?;
        match destination {
            RunnerDestination::Gateway => {
                let proof = self.proof(&key, &token, &req)?;
                Ok(Credential::Gateway { token, proof })
            }
            RunnerDestination::Relay(topic) => Ok(Credential::Relay { topic, token }),
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::TokenBinding;
    use ianua_domain::domains::agents::runner::GatewayTransport;
    use ianua_domain::types::DomainName;

    use super::*;
    use crate::test_support::agents::{FakeRunnerKeys, FakeRunnerProofs, FakeRunnerTokens};
    use crate::test_support::block_on;

    struct Bench {
        tokens: Arc<FakeRunnerTokens>,
        proofs: Arc<FakeRunnerProofs>,
    }

    impl Bench {
        fn new() -> Self {
            Self {
                tokens: Arc::new(FakeRunnerTokens::default()),
                proofs: Arc::new(FakeRunnerProofs::default()),
            }
        }

        fn credential_for(
            &self,
            method: HttpMethod,
            path_and_query: &str,
        ) -> Result<Credential, AppError> {
            self.credential_with(Arc::new(FakeRunnerKeys::holding()), method, path_and_query)
        }

        fn credential_with(
            &self,
            keys: Arc<FakeRunnerKeys>,
            method: HttpMethod,
            path_and_query: &str,
        ) -> Result<Credential, AppError> {
            let use_case = CredentialUseCase::new(
                CredentialPorts {
                    keys,
                    tokens: self.tokens.clone(),
                    proofs: self.proofs.clone(),
                },
                GatewayAddress::new(
                    DomainName::new("api.acme.test").unwrap(),
                    GatewayTransport::Tls,
                ),
            );
            block_on(use_case.execute(
                &(),
                CredentialRequest {
                    method,
                    path_and_query: path_and_query.to_owned(),
                },
            ))
        }
    }

    /// Ann's agent reads `/reports/5?month=1`. It goes to the gateway with
    /// a key-bound token and a proof naming the tenant's host and the path,
    /// without the query.
    #[test]
    fn a_request_to_the_gateway_carries_a_bound_token_and_its_proof() {
        let bench = Bench::new();

        let credential = bench
            .credential_for(HttpMethod::Get, "/reports/5?month=1")
            .unwrap();

        let Credential::Gateway { token, .. } = credential else {
            panic!("the request goes to the gateway");
        };
        assert_eq!(token.reveal(), "token-proof_of_possession");
        assert_eq!(bench.proofs.made(), ["GET https://api.acme.test/reports/5"]);
    }

    /// A message to `orders.created` goes to the relay with a bearer token,
    /// and no proof is made.
    #[test]
    fn a_message_goes_to_the_relay_with_a_bearer_token() {
        let bench = Bench::new();

        let credential = bench
            .credential_for(HttpMethod::Post, "/_ianua/messages/orders.created")
            .unwrap();

        let Credential::Relay { topic, token } = credential else {
            panic!("the message goes to the relay");
        };
        assert_eq!(topic.as_str(), "orders.created");
        assert_eq!(token.reveal(), "token-bearer");
        assert!(bench.proofs.made().is_empty());
        assert_eq!(bench.tokens.asked(), [TokenBinding::Bearer]);
    }

    /// A relay topic containing parent-directory traversal is rejected
    /// before the runner requests a token.
    #[test]
    fn a_topic_that_is_no_plain_name_is_refused_before_any_token() {
        let bench = Bench::new();

        let credential = bench.credential_for(HttpMethod::Post, "/_ianua/messages/../../signup");

        assert!(matches!(credential, Err(AppError::Domain(_))));
        assert!(bench.tokens.asked().is_empty());
    }

    /// A refused runner key prevents credential creation without requesting
    /// a task token.
    #[test]
    fn no_key_means_no_request() {
        let bench = Bench::new();

        let credential = bench.credential_with(
            Arc::new(FakeRunnerKeys::refusing()),
            HttpMethod::Get,
            "/reports",
        );

        assert!(matches!(credential, Err(AppError::Forbidden(_))));
        assert!(bench.tokens.asked().is_empty());
    }
}
