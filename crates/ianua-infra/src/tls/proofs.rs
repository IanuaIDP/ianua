//! The two ways control of a hostname is proved to an authority, and where
//! each proof is published.
//!
//! **HTTP-01** puts a token at a well-known URL on the hostname itself, so
//! only what already serves the hostname, the proxy, can answer. It reads
//! the challenge from the same store the provisioner writes, so it is
//! visible at once. It cannot prove a wildcard: no one URL stands for
//! every name beneath one.
//!
//! **DNS-01** puts a token in the hostname's DNS, which for a delegated
//! domain is ours. The record must reach the resolvers before the
//! authority looks, so the provisioner waits, bounded, until a resolver
//! sees it. Asking the authority to check a proof that is not there yet
//! spends one of a few validation attempts.

use std::sync::Arc;
use std::time::Duration;

use ianua_app::ports::domain::{AcmeChallengeStore, DnsResolver};
use ianua_domain::domains::tenant::custom_domains::acme_challenge::{
    AcmeChallenge, ChallengeToken, KeyAuthorization,
};
use ianua_domain::domains::tenant::custom_domains::dns_zone::{RecordName, TxtValue};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::DomainName;
use instant_acme::{ChallengeHandle, ChallengeType};

use crate::tls::seams::AcmeDnsChallengeStore;
use crate::tls::zones::{challenge_name, zone_of};

/// How long a published DNS-01 proof is looked for before the order is
/// given up, and how often.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisibilityWait {
    /// The longest wait, generous since records travel through the
    /// nameservers' refresh first.
    pub longest: Duration,
    /// The time between two looks.
    pub every: Duration,
}

/// One challenge's answer, in each form a route may publish.
#[derive(Debug, Clone)]
pub(crate) struct Proof {
    token: ChallengeToken,
    key_authorization: KeyAuthorization,
    dns_value: TxtValue,
}

impl Proof {
    /// The answer to `challenge`, under the account's key.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the authority's token is
    /// not one a challenge may carry.
    pub(crate) fn of(challenge: &ChallengeHandle<'_>) -> Result<Self, DomainError> {
        let answer = challenge.key_authorization();
        Ok(Self {
            token: ChallengeToken::new(challenge.token.as_str()).map_err(DomainError::infra)?,
            key_authorization: KeyAuthorization::new(answer.as_str())
                .map_err(DomainError::infra)?,
            dns_value: TxtValue::new(answer.dns_value()).map_err(DomainError::infra)?,
        })
    }
}

/// Where DNS-01 proofs go, and how their arrival is seen.
pub struct DnsProofs {
    /// Where the proof is written.
    pub store: Arc<dyn AcmeDnsChallengeStore>,
    /// What looks for it, as the authority would.
    pub resolver: Arc<dyn DnsResolver>,
    /// How long and how often it is looked for.
    pub wait: VisibilityWait,
}

/// How a provisioner proves control of a hostname.
pub(crate) enum ProofRoute {
    /// A token served on the hostname by the proxy.
    Http(Arc<dyn AcmeChallengeStore>),
    /// A token in the hostname's zone.
    Dns(DnsProofs),
}

impl ProofRoute {
    /// The challenge this route answers.
    pub(crate) fn challenge_type(&self) -> ChallengeType {
        match self {
            Self::Http(_) => ChallengeType::Http01,
            Self::Dns(_) => ChallengeType::Dns01,
        }
    }

    /// Refuses a hostname this route cannot prove: a wildcard over HTTP-01.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` for a wildcard over HTTP-01.
    pub(crate) fn ensure_provable(&self, domain: &DomainName) -> Result<(), DomainError> {
        match self {
            Self::Http(_) if domain.is_wildcard() => Err(DomainError::invalid(message!(
                "infra-a-wildcard-certificate-can-only-be",
                "a wildcard certificate can only be proved over DNS-01"
            ))),
            Self::Http(_) | Self::Dns(_) => Ok(()),
        }
    }

    /// Publishes `proof` for `domain`.
    ///
    /// # Errors
    ///
    /// Returns what the store reports when it cannot publish.
    pub(crate) async fn publish(
        &self,
        domain: &DomainName,
        proof: &Proof,
    ) -> Result<(), DomainError> {
        match self {
            Self::Http(challenges) => {
                challenges
                    .publish(&AcmeChallenge::open(
                        proof.token.clone(),
                        proof.key_authorization.clone(),
                        domain.clone(),
                    ))
                    .await
            }
            Self::Dns(dns) => dns.store.publish(domain, &proof.dns_value).await,
        }
    }

    /// Returns once `proof` can be seen where the authority will look.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a DNS-01 proof is not
    /// seen within the wait, or the resolver fails.
    pub(crate) async fn until_visible(
        &self,
        domain: &DomainName,
        proof: &Proof,
    ) -> Result<(), DomainError> {
        let Self::Dns(dns) = self else {
            return Ok(());
        };
        let name = challenge_name(&zone_of(domain))?;
        let mut last_error = None;
        tokio::time::timeout(
            dns.wait.longest,
            wait_for_record(dns, &name, &proof.dns_value, &mut last_error),
        )
        .await
        .map_err(|_| {
            last_error.unwrap_or_else(|| {
                DomainError::infra_msg(format!(
                    "the DNS-01 proof for {} was not seen in time",
                    domain.as_str()
                ))
            })
        })?
    }

    /// Withdraws every proof in `published`, whatever the order did. A
    /// failure is logged, never raised: the certificate was issued or
    /// refused already, and a tidy-up problem must not change that answer.
    pub(crate) async fn withdraw_all(&self, domain: &DomainName, published: &[Proof]) {
        for proof in published {
            if let Err(error) = self.withdraw(domain, proof).await {
                tracing::warn!(
                    domain = domain.as_str(),
                    %error,
                    "an ACME proof could not be withdrawn"
                );
            }
        }
    }

    /// Withdraws one proof.
    async fn withdraw(&self, domain: &DomainName, proof: &Proof) -> Result<(), DomainError> {
        match self {
            Self::Http(challenges) => challenges.withdraw(&proof.token).await,
            Self::Dns(dns) => dns.store.withdraw(domain, &proof.dns_value).await,
        }
    }
}

/// Returns once the resolver finds `value` at `name`, looking again after
/// each wait.
async fn wait_for_record(
    dns: &DnsProofs,
    name: &RecordName,
    value: &TxtValue,
    last_error: &mut Option<DomainError>,
) -> Result<(), DomainError> {
    loop {
        match dns.resolver.verify_txt_record(name, value).await {
            Ok(true) => return Ok(()),
            Ok(false) => *last_error = None,
            Err(error) => *last_error = Some(error),
        }
        tokio::time::sleep(dns.wait.every).await;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::*;

    /// Resolver answers in arrival order, then keeps reporting no proof.
    struct Resolver(Mutex<VecDeque<Result<bool, DomainError>>>);

    #[async_trait]
    impl DnsResolver for Resolver {
        /// Replays a temporary refusal followed by the nameserver's loaded proof.
        async fn verify_txt_record(
            &self,
            _name: &RecordName,
            _expected: &TxtValue,
        ) -> Result<bool, DomainError> {
            self.0.lock().unwrap().pop_front().unwrap_or(Ok(false))
        }

        /// No CNAME is part of DNS-01 validation.
        async fn verify_cname(
            &self,
            _domain: &DomainName,
            _expected: &DomainName,
        ) -> Result<bool, DomainError> {
            Ok(false)
        }

        /// No delegation is being established by this polling test.
        async fn verify_delegation(
            &self,
            _domain: &DomainName,
            _expected: &[DomainName],
        ) -> Result<bool, DomainError> {
            Ok(false)
        }
    }

    /// Refuses any unexpected write while checking an already-published proof.
    struct NoWrites;

    #[async_trait]
    impl AcmeDnsChallengeStore for NoWrites {
        /// Visibility polling must never publish another proof.
        async fn publish(&self, _host: &DomainName, _value: &TxtValue) -> Result<(), DomainError> {
            Err(DomainError::infra_msg("unexpected proof write"))
        }

        /// Visibility polling must never withdraw the proof it is checking.
        async fn withdraw(&self, _host: &DomainName, _value: &TxtValue) -> Result<(), DomainError> {
            Err(DomainError::infra_msg("unexpected proof withdrawal"))
        }
    }

    /// A temporary resolver error is retried, and the later matching TXT
    /// answer completes the proof's visibility wait.
    #[tokio::test]
    async fn a_nameserver_still_loading_its_zone_is_polled_again() {
        let route = ProofRoute::Dns(DnsProofs {
            store: Arc::new(NoWrites),
            resolver: Arc::new(Resolver(Mutex::new(VecDeque::from([
                Err(DomainError::infra_msg("zone not loaded yet")),
                Ok(true),
            ])))),
            wait: VisibilityWait {
                longest: Duration::from_secs(1),
                every: Duration::from_millis(1),
            },
        });
        let proof = Proof {
            token: ChallengeToken::new("token").unwrap(),
            key_authorization: KeyAuthorization::new("token.thumbprint").unwrap(),
            dns_value: TxtValue::new("matching-proof").unwrap(),
        };
        route
            .until_visible(&DomainName::new("label.apps.example.com").unwrap(), &proof)
            .await
            .unwrap();
    }
}
