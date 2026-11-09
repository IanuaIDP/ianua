//! Certificates from an ACME authority, such as Let's Encrypt.
//!
//! One order per certificate: the account is read back or registered, the
//! order placed for the one name, each authorization proved the way the
//! provisioner was built to prove it, the order finalized with a key made
//! here, and the chain collected. Every proof published is withdrawn
//! whatever the order did. Each call to the authority is held to a time,
//! each poll to a time, and the whole order to a few minutes, so a stalled
//! authority never holds the certificate job for ever.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::domain::{AcmeChallengeStore, TlsProvisioner};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificatePem, DomainName, Email};
use instant_acme::{AuthorizationStatus, Identifier, NewOrder, Order, OrderStatus, RetryPolicy};

use crate::tls::accounts::AuthorityAccounts;
use crate::tls::proofs::{DnsProofs, Proof, ProofRoute};
use crate::tls::seams::{AcmeAccountStore, AcmeDirectory};

/// Which authority to ask, and how long each step may take.
#[derive(Debug, Clone)]
pub struct AcmeSettings {
    /// The authority's directory. Its staging directory issues untrusted
    /// certificates against generous limits, the right choice everywhere
    /// but production.
    pub directory: AcmeDirectory,
    /// Where the authority writes about expiry and revocation, if anyone.
    pub contact: Option<Email>,
    /// How long each call to the authority may take.
    pub call_timeout: Duration,
    /// How long the whole order may take, proofs and polls included.
    pub order_timeout: Duration,
    /// The first wait between two looks at an order, doubled after each.
    pub poll_every: Duration,
    /// How long an order is polled for one change of state.
    pub poll_for: Duration,
}

impl AcmeSettings {
    /// The authority at `directory`, with the times a production order
    /// keeps to: ten seconds a call, five minutes an order, polled from
    /// every second for up to ninety seconds.
    #[must_use]
    pub fn standard(directory: AcmeDirectory, contact: Option<Email>) -> Self {
        Self {
            directory,
            contact,
            call_timeout: Duration::from_secs(10),
            order_timeout: Duration::from_secs(300),
            poll_every: Duration::from_secs(1),
            poll_for: Duration::from_secs(90),
        }
    }
}

/// Issues certificates from an ACME authority, proving control over
/// HTTP-01 or DNS-01 as it was built to.
pub struct AcmeTlsProvisioner {
    accounts: AuthorityAccounts,
    proofs: ProofRoute,
    order_timeout: Duration,
    polls: RetryPolicy,
}

impl AcmeTlsProvisioner {
    /// A provisioner proving over HTTP-01: the challenge is published in
    /// `challenges`, where the proxy answers it on the customer's hostname.
    #[must_use]
    pub fn over_http(
        settings: AcmeSettings,
        accounts: Arc<dyn AcmeAccountStore>,
        challenges: Arc<dyn AcmeChallengeStore>,
    ) -> Self {
        Self::proving(settings, accounts, ProofRoute::Http(challenges))
    }

    /// A provisioner proving over DNS-01: the proof is written through
    /// the configured store into a zone we answer for, and the authority is
    /// asked to check only once the configured resolver sees it.
    #[must_use]
    pub fn over_dns(
        settings: AcmeSettings,
        accounts: Arc<dyn AcmeAccountStore>,
        proofs: DnsProofs,
    ) -> Self {
        Self::proving(settings, accounts, ProofRoute::Dns(proofs))
    }

    /// A provisioner for the authority `settings` name, keeping its account
    /// in `store` and proving control along `proofs`.
    fn proving(
        settings: AcmeSettings,
        store: Arc<dyn AcmeAccountStore>,
        proofs: ProofRoute,
    ) -> Self {
        Self {
            accounts: AuthorityAccounts {
                directory: settings.directory,
                contact: settings.contact,
                store,
                call_timeout: settings.call_timeout,
            },
            proofs,
            order_timeout: settings.order_timeout,
            polls: RetryPolicy::new()
                .initial_delay(settings.poll_every)
                .timeout(settings.poll_for),
        }
    }

    /// The certificate for `domain`, its proofs withdrawn however the
    /// order went.
    async fn issued(
        &self,
        domain: &DomainName,
        names: &[DomainName],
    ) -> Result<(CertificatePem, Secret), DomainError> {
        let account = self.accounts.account().await?;
        let identifiers: Vec<_> = names
            .iter()
            .map(|name| Identifier::Dns(name.as_str().to_owned()))
            .collect();
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(DomainError::infra)?;
        let mut published = Vec::new();
        let outcome = async {
            self.answer_challenges(&mut order, domain, &mut published)
                .await?;
            finished(&mut order, names, &self.polls).await
        }
        .await;
        self.proofs.withdraw_all(domain, &published).await;
        outcome
    }

    /// Publishes a proof for each authorization still pending, waits until
    /// it is visible, and only then tells the authority to check it.
    /// Each proof enters `published` before its write so cleanup also covers
    /// partially completed writes.
    async fn answer_challenges(
        &self,
        order: &mut Order,
        domain: &DomainName,
        published: &mut Vec<Proof>,
    ) -> Result<(), DomainError> {
        let mut authorizations = order.authorizations();
        while let Some(next) = authorizations.next().await {
            let mut authorization = next.map_err(DomainError::infra)?;
            if !still_to_prove(authorization.status, domain)? {
                continue;
            }
            let mut challenge = authorization
                .challenge(self.proofs.challenge_type())
                .ok_or_else(|| {
                    DomainError::infra_msg(format!(
                        "the authority offered no challenge this provisioner answers for {}",
                        domain.as_str()
                    ))
                })?;
            let proof = Proof::of(&challenge)?;
            published.push(proof.clone());
            self.proofs.publish(domain, &proof).await?;
            self.proofs.until_visible(domain, &proof).await?;
            challenge.set_ready().await.map_err(DomainError::infra)?;
        }
        Ok(())
    }
}

#[async_trait]
impl TlsProvisioner for AcmeTlsProvisioner {
    async fn provision(
        &self,
        domain: &DomainName,
    ) -> Result<(CertificatePem, Secret), DomainError> {
        self.proofs.ensure_provable(domain)?;
        let issued = tokio::time::timeout(
            self.order_timeout,
            self.issued(domain, std::slice::from_ref(domain)),
        )
        .await
        .map_err(|_| {
            DomainError::infra_msg(format!(
                "the certificate authority did not finish the order for {} in time",
                domain.as_str()
            ))
        })??;
        tracing::info!(domain = domain.as_str(), "issued an ACME certificate");
        Ok(issued)
    }

    async fn provision_pair(
        &self,
        root: &DomainName,
    ) -> Result<(CertificatePem, Secret), DomainError> {
        let wildcard =
            DomainName::new(format!("*.{}", root.as_str())).map_err(DomainError::infra)?;
        self.proofs.ensure_provable(&wildcard)?;
        let names = [root.clone(), wildcard];
        tokio::time::timeout(self.order_timeout, self.issued(root, &names))
            .await
            .map_err(|_| DomainError::infra_msg("the platform certificate order timed out"))?
    }
}

/// Whether an authorization in `status` still needs a proof: a valid one
/// was proved before, a pending one waits for one.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` for an authorization the authority
/// refused, revoked or let expire.
fn still_to_prove(status: AuthorizationStatus, domain: &DomainName) -> Result<bool, DomainError> {
    match status {
        AuthorizationStatus::Valid => Ok(false),
        AuthorizationStatus::Pending => Ok(true),
        AuthorizationStatus::Invalid
        | AuthorizationStatus::Revoked
        | AuthorizationStatus::Expired
        | AuthorizationStatus::Deactivated => Err(DomainError::infra_msg(format!(
            "the authority holds the authorization for {} as {status:?}",
            domain.as_str()
        ))),
    }
}

/// Waits for the authority to accept the proofs, finalizes the order with
/// a key made here, and collects the chain.
async fn finished(
    order: &mut Order,
    names: &[DomainName],
    polls: &RetryPolicy,
) -> Result<(CertificatePem, Secret), DomainError> {
    let status = order.poll_ready(polls).await.map_err(DomainError::infra)?;
    if status != OrderStatus::Ready {
        return Err(DomainError::infra_msg(format!(
            "the authority left the order {status:?} instead of accepting the proof"
        )));
    }
    let (request, key) = signing_request(names)?;
    order
        .finalize_csr(request.der())
        .await
        .map_err(DomainError::infra)?;
    let chain = order
        .poll_certificate(polls)
        .await
        .map_err(DomainError::infra)?;
    let chain = CertificatePem::new(chain).map_err(DomainError::infra)?;
    Ok((chain, key))
}

/// A fresh P-256 key and a signing request for `domain` made with it, the
/// key's PEM held as a secret.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the key or the request
/// cannot be made.
fn signing_request(
    names: &[DomainName],
) -> Result<(rcgen::CertificateSigningRequest, Secret), DomainError> {
    let key = rcgen::KeyPair::generate().map_err(DomainError::infra)?;
    let mut params = rcgen::CertificateParams::new(
        names
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect::<Vec<_>>(),
    )
    .map_err(DomainError::infra)?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let request = params.serialize_request(&key).map_err(DomainError::infra)?;
    Ok((request, Secret::new(key.serialize_pem())))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use ianua_app::test_support::domain::{AcceptingDnsResolver, RejectingDnsResolver};
    use ianua_domain::domains::tenant::custom_domains::acme_challenge::{
        AcmeChallenge, ChallengeToken,
    };
    use ianua_domain::domains::tenant::custom_domains::dns_zone::TxtValue;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::tls::{AcmeDnsChallengeStore, VisibilityWait};

    /// How the stand-in authority ends an order.
    #[derive(Clone, Copy)]
    enum Ending {
        Issues,
        Refuses,
    }

    /// Keeps one account's credentials in memory.
    #[derive(Default)]
    struct KeptAccounts(Mutex<Option<Secret>>);

    #[async_trait]
    impl AcmeAccountStore for KeptAccounts {
        async fn load(&self, _directory: &AcmeDirectory) -> Result<Option<Secret>, DomainError> {
            Ok(self.0.lock().unwrap().clone())
        }

        async fn save(
            &self,
            _directory: &AcmeDirectory,
            credentials: &Secret,
        ) -> Result<(), DomainError> {
            *self.0.lock().unwrap() = Some(credentials.clone());
            Ok(())
        }
    }

    /// Writes down every proof published and withdrawn, by token for
    /// HTTP-01 and by hostname for DNS-01.
    #[derive(Default)]
    struct Ledger {
        published: Mutex<Vec<String>>,
        withdrawn: Mutex<Vec<String>>,
    }

    impl Ledger {
        fn published(&self) -> Vec<String> {
            self.published.lock().unwrap().clone()
        }

        fn withdrawn(&self) -> Vec<String> {
            self.withdrawn.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl AcmeChallengeStore for Ledger {
        async fn publish(&self, challenge: &AcmeChallenge) -> Result<(), DomainError> {
            self.published
                .lock()
                .unwrap()
                .push(challenge.token().as_str().to_owned());
            Ok(())
        }

        async fn find(
            &self,
            _token: &ChallengeToken,
        ) -> Result<Option<AcmeChallenge>, DomainError> {
            Ok(None)
        }

        async fn withdraw(&self, token: &ChallengeToken) -> Result<(), DomainError> {
            self.withdrawn
                .lock()
                .unwrap()
                .push(token.as_str().to_owned());
            Ok(())
        }

        async fn purge_expired(&self) -> Result<u64, DomainError> {
            Ok(0)
        }
    }

    #[async_trait]
    impl AcmeDnsChallengeStore for Ledger {
        async fn publish(
            &self,
            hostname: &DomainName,
            _value: &TxtValue,
        ) -> Result<(), DomainError> {
            self.published
                .lock()
                .unwrap()
                .push(hostname.as_str().to_owned());
            Ok(())
        }

        async fn withdraw(
            &self,
            hostname: &DomainName,
            _value: &TxtValue,
        ) -> Result<(), DomainError> {
            self.withdrawn
                .lock()
                .unwrap()
                .push(hostname.as_str().to_owned());
            Ok(())
        }
    }

    fn name(text: &str) -> DomainName {
        DomainName::new(text).unwrap()
    }

    fn answer(status: u16, body: serde_json::Value) -> ResponseTemplate {
        ResponseTemplate::new(status)
            .insert_header("Replay-Nonce", "nonce")
            .set_body_json(body)
    }

    fn located(status: u16, location: String, body: serde_json::Value) -> ResponseTemplate {
        answer(status, body).insert_header("Location", location)
    }

    async fn mount(server: &MockServer, verb: &str, route: &str, response: ResponseTemplate) {
        Mock::given(method(verb))
            .and(path(route))
            .respond_with(response)
            .mount(server)
            .await;
    }

    fn order_state(base: &str, status: &str) -> serde_json::Value {
        json!({
            "status": status,
            "authorizations": [format!("{base}/authz/1")],
            "finalize": format!("{base}/finalize/1"),
            "certificate": format!("{base}/cert/1"),
        })
    }

    fn challenge(base: &str, kind: &str, number: u8) -> serde_json::Value {
        json!({
            "type": kind,
            "url": format!("{base}/chall/{number}"),
            "token": format!("tok_{number}"),
            "status": "pending",
        })
    }

    /// Mounts an authority on `server` that registers, takes one order for
    /// `auth.acme.test` and ends it as `ending` says.
    async fn authority(server: &MockServer, ending: Ending) {
        let base = server.uri();
        register_account(server, &base).await;
        pending_order(server, &base).await;
        challenge_responses(server, &base).await;
        certificate_response(server, &base).await;
        orders_end(server, &base, ending).await;
    }

    /// Serves directory discovery, nonces and registration for the test account.
    async fn register_account(server: &MockServer, base: &str) {
        mount(
            server,
            "GET",
            "/directory",
            answer(
                200,
                json!({
                    "newNonce": format!("{base}/nonce"),
                    "newAccount": format!("{base}/account"),
                    "newOrder": format!("{base}/order"),
                }),
            ),
        )
        .await;
        mount(server, "HEAD", "/nonce", answer(200, json!({}))).await;
        mount(
            server,
            "POST",
            "/account",
            located(201, format!("{base}/acct/1"), json!({"status": "valid"})),
        )
        .await;
    }

    /// Creates an order whose authorization offers both supported proof methods.
    async fn pending_order(server: &MockServer, base: &str) {
        mount(
            server,
            "POST",
            "/order",
            located(201, format!("{base}/order/1"), order_state(base, "pending")),
        )
        .await;
        mount(
            server,
            "POST",
            "/authz/1",
            answer(
                200,
                json!({
                    "status": "pending",
                    "identifier": {"type": "dns", "value": "auth.acme.test"},
                    "challenges": [challenge(base, "http-01", 1), challenge(base, "dns-01", 2)],
                }),
            ),
        )
        .await;
    }

    /// Accepts a readiness request for either challenge while keeping its token stable.
    async fn challenge_responses(server: &MockServer, base: &str) {
        for number in [1, 2] {
            let kind = if number == 1 { "http-01" } else { "dns-01" };
            mount(
                server,
                "POST",
                &format!("/chall/{number}"),
                answer(200, challenge(base, kind, number)),
            )
            .await;
        }
    }

    /// Accepts the signing request and returns a PEM chain for the requested hostname.
    async fn certificate_response(server: &MockServer, base: &str) {
        mount(
            server,
            "POST",
            "/finalize/1",
            answer(200, order_state(base, "processing")),
        )
        .await;
        let chain = rcgen::generate_simple_self_signed(vec!["auth.acme.test".to_owned()])
            .unwrap()
            .cert
            .pem();
        mount(
            server,
            "POST",
            "/cert/1",
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "nonce")
                .set_body_string(chain),
        )
        .await;
    }

    /// The order's own address: ready once, then valid, or refused.
    async fn orders_end(server: &MockServer, base: &str, ending: Ending) {
        match ending {
            Ending::Issues => {
                Mock::given(method("POST"))
                    .and(path("/order/1"))
                    .respond_with(answer(200, order_state(base, "ready")))
                    .up_to_n_times(1)
                    .with_priority(1)
                    .mount(server)
                    .await;
                mount(
                    server,
                    "POST",
                    "/order/1",
                    answer(200, order_state(base, "valid")),
                )
                .await;
            }
            Ending::Refuses => {
                let mut refused = order_state(base, "invalid");
                refused["error"] = json!({
                    "type": "urn:ietf:params:acme:error:unauthorized",
                    "detail": "the proof did not match",
                    "status": 403,
                });
                mount(server, "POST", "/order/1", answer(200, refused)).await;
            }
        }
    }

    fn settings(server: &MockServer) -> AcmeSettings {
        let directory = AcmeDirectory::parse(&format!("{}/directory", server.uri())).unwrap();
        AcmeSettings {
            call_timeout: Duration::from_secs(5),
            order_timeout: Duration::from_secs(20),
            poll_every: Duration::from_millis(10),
            poll_for: Duration::from_secs(5),
            ..AcmeSettings::standard(directory, None)
        }
    }

    const SHORT_WAIT: VisibilityWait = VisibilityWait {
        longest: Duration::from_millis(200),
        every: Duration::from_millis(10),
    };

    async fn requests_to(server: &MockServer, route: &str) -> usize {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.url.path() == route)
            .count()
    }

    /// A first issuance registers an account, keeps it, and answers with
    /// the chain and a private key.
    #[tokio::test]
    async fn a_first_issuance_registers_and_keeps_an_account() {
        let server = MockServer::start().await;
        authority(&server, Ending::Issues).await;
        let accounts = Arc::new(KeptAccounts::default());
        let provisioner = AcmeTlsProvisioner::over_http(
            settings(&server),
            accounts.clone(),
            Arc::new(Ledger::default()),
        );

        let (chain, key) = provisioner
            .provision(&name("auth.acme.test"))
            .await
            .unwrap();

        assert!(chain.as_str().contains("BEGIN CERTIFICATE"));
        assert!(key.expose().contains("PRIVATE KEY"));
        assert_eq!(requests_to(&server, "/account").await, 1);
        assert!(accounts.0.lock().unwrap().is_some());
    }

    /// A second successful issuance reuses the stored account without another registration request.
    #[tokio::test]
    async fn a_kept_account_is_used_again() {
        let server = MockServer::start().await;
        authority(&server, Ending::Issues).await;
        let accounts = Arc::new(KeptAccounts::default());
        let provisioner =
            AcmeTlsProvisioner::over_http(settings(&server), accounts, Arc::new(Ledger::default()));
        provisioner
            .provision(&name("auth.acme.test"))
            .await
            .unwrap();
        server.reset().await;
        authority(&server, Ending::Issues).await;

        provisioner
            .provision(&name("auth.acme.test"))
            .await
            .unwrap();

        assert_eq!(requests_to(&server, "/account").await, 0);
    }

    /// An HTTP-01 order publishes its challenge for the proxy, has it
    /// checked, and withdraws it once the certificate is issued.
    #[tokio::test]
    async fn an_http_challenge_is_published_checked_and_withdrawn() {
        let server = MockServer::start().await;
        authority(&server, Ending::Issues).await;
        let ledger = Arc::new(Ledger::default());
        let provisioner = AcmeTlsProvisioner::over_http(
            settings(&server),
            Arc::new(KeptAccounts::default()),
            ledger.clone(),
        );

        provisioner
            .provision(&name("auth.acme.test"))
            .await
            .unwrap();

        assert_eq!(ledger.published(), vec!["tok_1".to_owned()]);
        assert_eq!(ledger.withdrawn(), vec!["tok_1".to_owned()]);
        assert_eq!(requests_to(&server, "/chall/1").await, 1);
    }

    /// A refused order returns an infrastructure error and still withdraws its HTTP challenge.
    #[tokio::test]
    async fn a_refused_order_fails_and_still_withdraws_its_challenge() {
        let server = MockServer::start().await;
        authority(&server, Ending::Refuses).await;
        let ledger = Arc::new(Ledger::default());
        let provisioner = AcmeTlsProvisioner::over_http(
            settings(&server),
            Arc::new(KeptAccounts::default()),
            ledger.clone(),
        );

        let result = provisioner.provision(&name("auth.acme.test")).await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
        assert_eq!(ledger.withdrawn(), vec!["tok_1".to_owned()]);
    }

    /// A wildcard requested through HTTP-01 fails validation without contacting the authority.
    #[tokio::test]
    async fn a_wildcard_over_http_is_refused_before_any_call() {
        let server = MockServer::start().await;
        authority(&server, Ending::Issues).await;
        let provisioner = AcmeTlsProvisioner::over_http(
            settings(&server),
            Arc::new(KeptAccounts::default()),
            Arc::new(Ledger::default()),
        );

        let result = provisioner.provision(&name("*.acme.test")).await;

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// A DNS-01 proof is written into the zone, checked once the resolver
    /// sees it, and withdrawn after.
    #[tokio::test]
    async fn a_dns_proof_is_checked_once_seen_and_withdrawn() {
        let server = MockServer::start().await;
        authority(&server, Ending::Issues).await;
        let ledger = Arc::new(Ledger::default());
        let provisioner = AcmeTlsProvisioner::over_dns(
            settings(&server),
            Arc::new(KeptAccounts::default()),
            DnsProofs {
                store: ledger.clone(),
                resolver: Arc::new(AcceptingDnsResolver),
                wait: SHORT_WAIT,
            },
        );

        provisioner
            .provision(&name("auth.acme.test"))
            .await
            .unwrap();

        assert_eq!(ledger.published(), vec!["auth.acme.test".to_owned()]);
        assert_eq!(requests_to(&server, "/chall/2").await, 1);
        assert_eq!(ledger.withdrawn(), vec!["auth.acme.test".to_owned()]);
    }

    /// A DNS proof that remains invisible fails issuance without a challenge
    /// request, and the published proof is withdrawn.
    #[tokio::test]
    async fn a_dns_proof_never_seen_is_never_checked() {
        let server = MockServer::start().await;
        authority(&server, Ending::Issues).await;
        let ledger = Arc::new(Ledger::default());
        let provisioner = AcmeTlsProvisioner::over_dns(
            settings(&server),
            Arc::new(KeptAccounts::default()),
            DnsProofs {
                store: ledger.clone(),
                resolver: Arc::new(RejectingDnsResolver),
                wait: SHORT_WAIT,
            },
        );

        let result = provisioner.provision(&name("auth.acme.test")).await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
        assert_eq!(requests_to(&server, "/chall/2").await, 0);
        assert_eq!(ledger.withdrawn(), vec!["auth.acme.test".to_owned()]);
    }
}
