//! The certificate served for each name a client asks for.
//!
//! The table holds the platform's own certificates, read once at start,
//! and every tenant's current certificates, which the caller reads from
//! [`CrossTenantServedCertificates`] and hands over whole whenever they
//! change. Each handover builds a new table and swaps it in, so a handshake
//! reads one consistent table and a removed domain stops being served from
//! the next handshake.
//!
//! There is no fallback certificate. A name with none of its own, and
//! none a wildcard covers, is refused at the handshake: answering it with
//! another name's certificate would show a client a name it did not ask
//! for, and tells a scanner which names share this gateway.
//!
//! [`CrossTenantServedCertificates`]: ianua_app::ports::proxy::CrossTenantServedCertificates

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use ianua_app::ports::proxy::ServedCertificate;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificatePem, DomainName};
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::sign::CertifiedKey;

/// Why a certificate cannot be served.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CertificateError {
    /// The chain or key does not read, the key does not match the chain,
    /// or the key's type is not one the gateway signs with.
    #[error("the certificate for {name} cannot be served")]
    Unusable {
        /// The name it was to be served for.
        name: String,
        /// What was wrong with it.
        #[source]
        cause: Box<dyn std::error::Error + Send + Sync>,
    },
}

/// A certificate of the platform's own, such as the wildcard over the
/// base domain tenants are served on.
pub(crate) struct PlatformCertificate {
    /// The names it is served for; a wildcard is written `*.base.com`.
    pub names: Vec<DomainName>,
    /// The certificate chain, leaf first.
    pub chain: CertificatePem,
    /// Its private key.
    pub key: Secret,
}

/// How a handover went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Loaded {
    /// How many names are served now, the platform's among them.
    pub names: usize,
    /// The names whose certificate could not be used, or that the
    /// platform or another tenant already serves. They are refused at the
    /// handshake until a usable certificate is handed over.
    pub refused: Vec<DomainName>,
}

/// The certificate for each name, swapped whole when it changes.
pub(crate) struct CertificateTable {
    provider: Arc<CryptoProvider>,
    platform: Vec<(DomainName, Arc<CertifiedKey>)>,
    served: ArcSwap<HashMap<String, Arc<CertifiedKey>>>,
}

impl CertificateTable {
    /// A table serving `platform`'s names, and no tenant's until
    /// [`replace`](Self::replace) is called.
    ///
    /// # Errors
    ///
    /// [`CertificateError`] when a platform certificate cannot be used: the
    /// gateway does not start without the certificates it was told to
    /// serve.
    pub(crate) fn new(
        provider: Arc<CryptoProvider>,
        platform: &[PlatformCertificate],
    ) -> Result<Self, CertificateError> {
        let platform = platform
            .iter()
            .map(|certificate| platform_names(certificate, &provider))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect();
        let table = Self {
            provider,
            platform,
            served: ArcSwap::from_pointee(HashMap::new()),
        };
        table.replace(&[]);
        Ok(table)
    }

    /// Serves `certificates` from the next handshake on, in place of every
    /// tenant certificate served before. A name the platform serves stays
    /// the platform's; of two tenants naming one domain, the first keeps it.
    pub(crate) fn replace(&self, certificates: &[ServedCertificate]) -> Loaded {
        let mut names: HashMap<String, Arc<CertifiedKey>> = self
            .platform
            .iter()
            .map(|(name, key)| (name.as_str().to_owned(), Arc::clone(key)))
            .collect();
        let mut refused = Vec::new();
        for certificate in certificates {
            match self.usable(&names, certificate) {
                Some(key) => {
                    names.insert(certificate.domain.as_str().to_owned(), key);
                }
                None => refused.push(certificate.domain.clone()),
            }
        }
        let loaded = Loaded {
            names: names.len(),
            refused,
        };
        self.served.store(Arc::new(names));
        loaded
    }

    /// `certificate`'s key, when its domain is free in `names` and the
    /// certificate can be served.
    fn usable(
        &self,
        names: &HashMap<String, Arc<CertifiedKey>>,
        certificate: &ServedCertificate,
    ) -> Option<Arc<CertifiedKey>> {
        let domain = &certificate.domain;
        let tenant = &certificate.tenant_id;
        if names.contains_key(domain.as_str()) {
            tracing::warn!(
                %domain,
                %tenant,
                "a tenant certificate names a domain already served; it is not served"
            );
            return None;
        }
        let bundle = &certificate.bundle;
        certified_key(
            bundle.certificate_pem(),
            bundle.private_key_pem(),
            &self.provider,
        )
        .inspect_err(|error| {
            tracing::warn!(
                %domain,
                %tenant,
                %error,
                "a tenant certificate cannot be used; its domain is refused"
            );
        })
        .ok()
    }

    /// The certificate for `server_name`: its own, else the wildcard one
    /// label up. `None` when neither is served.
    pub(crate) fn find(&self, server_name: &DomainName) -> Option<Arc<CertifiedKey>> {
        let served = self.served.load();
        let name = server_name.as_str();
        served
            .get(name)
            .or_else(|| wildcard_over(name).and_then(|wildcard| served.get(&wildcard)))
            .cloned()
    }
}

/// The wildcard that would cover `name`, one label up: `*.acme.com` for
/// `api.acme.com`. A single label has none, and a wildcard is not covered
/// by another.
fn wildcard_over(name: &str) -> Option<String> {
    let (label, parent) = name.split_once('.')?;
    if label == "*" || parent.is_empty() {
        return None;
    }
    Some(format!("*.{parent}"))
}

fn platform_names(
    certificate: &PlatformCertificate,
    provider: &CryptoProvider,
) -> Result<Vec<(DomainName, Arc<CertifiedKey>)>, CertificateError> {
    let key = certified_key(&certificate.chain, &certificate.key, provider).map_err(|cause| {
        CertificateError::Unusable {
            name: names_of(&certificate.names),
            cause,
        }
    })?;
    Ok(certificate
        .names
        .iter()
        .map(|name| (name.clone(), Arc::clone(&key)))
        .collect())
}

fn names_of(names: &[DomainName]) -> String {
    names
        .iter()
        .map(DomainName::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

type Cause = Box<dyn std::error::Error + Send + Sync>;

/// The chain and key, ready to sign handshakes with.
fn certified_key(
    chain: &CertificatePem,
    key: &Secret,
    provider: &CryptoProvider,
) -> Result<Arc<CertifiedKey>, Cause> {
    let chain = rustls_pemfile::certs(&mut chain.as_str().as_bytes())
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()?;
    if chain.is_empty() {
        return Err("the chain holds no certificate".into());
    }
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key.expose().as_bytes())?
        .ok_or("the key holds no private key")?;
    Ok(Arc::new(CertifiedKey::from_der(chain, key, provider)?))
}

#[cfg(test)]
pub(crate) mod fixtures {
    use ianua_app::ports::proxy::ServedCertificate;
    use ianua_domain::domains::tenant::custom_domains::certificate::{
        CertificateBundle, IssuedCertificate,
    };
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{CertificatePem, DomainId, DomainName, TenantId};

    /// A self-signed certificate for `names`: its chain and key, as PEM.
    pub(crate) fn self_signed(names: &[&str]) -> (String, String) {
        let names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
        let params = rcgen::CertificateParams::new(names).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        (certificate.pem(), key.serialize_pem())
    }

    /// `tenant`'s certificate for `domain`, read from `chain` and `key`.
    pub(crate) fn served(
        tenant: TenantId,
        domain: &str,
        chain: &str,
        key: &str,
    ) -> ServedCertificate {
        let now = ianua_domain::shared::clock::now();
        let bundle = CertificateBundle::new(IssuedCertificate {
            domain_id: DomainId::new(),
            certificate_pem: CertificatePem::new(chain).unwrap(),
            private_key_pem: Secret::new(key),
            issued_at: now,
            expires_at: now + time::Duration::days(90),
        })
        .unwrap();
        ServedCertificate {
            tenant_id: tenant,
            domain: DomainName::new(domain).unwrap(),
            bundle: bundle.into(),
        }
    }

    /// `tenant`'s self-signed certificate for `domain`.
    pub(crate) fn served_self_signed(tenant: TenantId, domain: &str) -> ServedCertificate {
        let (chain, key) = self_signed(&[domain]);
        served(tenant, domain, &chain, &key)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::TenantId;
    use tokio_rustls::rustls::crypto::ring;

    use super::fixtures::{self_signed, served, served_self_signed};
    use super::*;

    fn provider() -> Arc<CryptoProvider> {
        Arc::new(ring::default_provider())
    }

    fn name(text: &str) -> DomainName {
        DomainName::new(text).unwrap()
    }

    fn platform(names: &[&str]) -> PlatformCertificate {
        let (chain, key) = self_signed(names);
        PlatformCertificate {
            names: names.iter().map(|text| name(text)).collect(),
            chain: CertificatePem::new(chain).unwrap(),
            key: Secret::new(key),
        }
    }

    fn empty_table() -> CertificateTable {
        CertificateTable::new(provider(), &[]).unwrap()
    }

    /// A tenant's domain is served with its own certificate.
    #[test]
    fn a_domain_is_served_its_own_certificate() {
        let table = empty_table();

        let loaded = table.replace(&[served_self_signed(TenantId::new(), "app.acme.com")]);

        assert_eq!(loaded.names, 1);
        assert!(table.find(&name("app.acme.com")).is_some());
    }

    /// A wildcard covers one label beneath it, and no deeper.
    #[test]
    fn a_wildcard_covers_one_label() {
        let table = CertificateTable::new(provider(), &[platform(&["*.ianua.test"])]).unwrap();

        assert!(table.find(&name("acme-prod.ianua.test")).is_some());
        assert!(table.find(&name("a.b.ianua.test")).is_none());
        assert!(table.find(&name("ianua.test")).is_none());
    }

    /// A name nobody serves finds nothing: there is no fallback.
    #[test]
    fn a_name_without_a_certificate_finds_none() {
        let table = CertificateTable::new(provider(), &[platform(&["*.ianua.test"])]).unwrap();

        assert!(table.find(&name("bank.example.com")).is_none());
    }

    /// A domain left out of the next handover stops being served.
    #[test]
    fn a_removed_domain_stops_being_served() {
        let table = empty_table();
        table.replace(&[served_self_signed(TenantId::new(), "app.acme.com")]);

        table.replace(&[]);

        assert!(table.find(&name("app.acme.com")).is_none());
    }

    /// A tenant cannot take a name the platform serves.
    #[test]
    fn a_tenant_cannot_take_the_platforms_name() {
        let table = CertificateTable::new(provider(), &[platform(&["login.ianua.test"])]).unwrap();
        let platform_key = table.find(&name("login.ianua.test")).unwrap();

        let loaded = table.replace(&[served_self_signed(TenantId::new(), "login.ianua.test")]);

        assert_eq!(loaded.refused, vec![name("login.ianua.test")]);
        assert!(Arc::ptr_eq(
            &table.find(&name("login.ianua.test")).unwrap(),
            &platform_key
        ));
    }

    /// A certificate whose key belongs to another certificate is refused,
    /// and its domain with it.
    #[test]
    fn a_mismatched_key_is_refused() {
        let table = empty_table();
        let (chain, _) = self_signed(&["app.acme.com"]);
        let (_, other_key) = self_signed(&["app.acme.com"]);

        let loaded = table.replace(&[served(TenantId::new(), "app.acme.com", &chain, &other_key)]);

        assert_eq!(loaded.refused, vec![name("app.acme.com")]);
        assert!(table.find(&name("app.acme.com")).is_none());
    }

    /// The gateway does not start with a platform certificate it cannot use.
    #[test]
    fn an_unusable_platform_certificate_is_refused() {
        let mut certificate = platform(&["*.ianua.test"]);
        certificate.key = Secret::new("not a key");

        let table = CertificateTable::new(provider(), &[certificate]);

        assert!(matches!(table, Err(CertificateError::Unusable { .. })));
    }
}
