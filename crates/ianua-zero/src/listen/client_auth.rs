//! Each tenant's client-certificate verification (mutual TLS).
//!
//! A tenant that uses mutual TLS names the authorities its clients'
//! certificates must chain to. The handshake for one of its names verifies
//! against those authorities alone, never another tenant's and never a
//! platform-wide one. The table changes one tenant at a time from what
//! the caller reads about that tenant. Each handshake reads the table as
//! it is then, so an authority removed stops
//! verifying from the next handshake.
//!
//! A tenant whose authorities cannot be read is never treated as one that
//! asks for nothing. When it requires certificates its handshakes are
//! refused; when certificates are optional the handshake goes ahead
//! without one and the connection says so, and every route that needs a
//! client certificate refuses.
//!
//! A tenant that gives revocation lists has each client certificate checked
//! against them in the handshake, as the domain's mTLS setting says: a
//! revoked certificate, one whose issuer no list covers, and any once a
//! list is past its next update are refused. A list that cannot be read
//! makes the tenant's authorities unusable, refused as above. Revocation is
//! never asked of an OCSP responder while the client waits: the handshake's
//! check is synchronous, a responder on the network would hold every
//! handshake on it, and clients do not staple their own certificate's
//! status.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use ianua_domain::domains::tenant::access::network_security::{MtlsConfig, MtlsMode};
use ianua_domain::types::{CertificatePem, RevocationListPem, TenantId};
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::pki_types::{CertificateDer, CertificateRevocationListDer};
use tokio_rustls::rustls::server::danger::ClientCertVerifier;
use tokio_rustls::rustls::server::{ClientCertVerifierBuilder, WebPkiClientVerifier};

/// A tenant's mutual TLS settings, as the caller read them.
#[derive(Debug, Clone)]
pub(crate) struct TenantMtls {
    /// The ownership boundary whose client-certificate trust is being loaded.
    pub tenant_id: TenantId,
    /// Whether it asks for client certificates, and whose.
    pub config: MtlsConfig,
}

/// Why a tenant's client certificates cannot be verified.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ClientAuthError {
    /// An authority's PEM does not read.
    #[error("a client certificate authority does not read")]
    Unreadable(#[source] std::io::Error),
    /// An authority read but is not a certificate that can anchor trust.
    #[error("{0} client certificate authorities cannot anchor trust")]
    Unusable(usize),
    /// A revocation list's PEM holds no list.
    #[error("a client certificate revocation list holds no list")]
    NoRevocationList,
    /// The verifier could not be built from the authorities.
    #[error("the client certificate verifier cannot be built")]
    Verifier(#[source] tokio_rustls::rustls::server::VerifierBuilderError),
}

/// Whether a tenant's handshakes require a client certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Demand {
    /// One is asked for, and the handshake goes ahead without.
    Optional,
    /// The handshake fails without one.
    Required,
}

/// How a tenant's handshakes treat client certificates.
#[derive(Debug, Clone)]
pub(crate) enum ClientAuth {
    /// None is asked for.
    Off,
    /// Asked for, and verified by this verifier.
    Verify(Arc<dyn ClientCertVerifier>),
    /// Asked for, and none can be verified: the authorities cannot be used.
    Unbuildable(Demand),
}

/// Each tenant's client-certificate verification, changed one tenant at a time.
pub(crate) struct ClientAuthTable {
    provider: Arc<CryptoProvider>,
    tenants: ArcSwap<HashMap<TenantId, ClientAuth>>,
}

impl ClientAuthTable {
    /// A table in which no tenant asks for client certificates.
    #[must_use]
    pub(crate) fn new(provider: Arc<CryptoProvider>) -> Self {
        Self {
            provider,
            tenants: ArcSwap::from_pointee(HashMap::new()),
        }
    }

    /// Verifies as `tenant` says from the next handshake on.
    ///
    /// # Errors
    ///
    /// [`ClientAuthError`] when its authorities cannot be used. The tenant
    /// is held as one whose certificates cannot be verified, never as one
    /// that asks for none.
    pub(crate) fn set(&self, tenant: &TenantMtls) -> Result<(), ClientAuthError> {
        let (auth, outcome) = match client_auth(&tenant.config, &self.provider) {
            Ok(auth) => (auth, Ok(())),
            Err(refused) => (ClientAuth::Unbuildable(refused.demand), Err(refused.error)),
        };
        self.tenants.rcu(|current| {
            let mut next = HashMap::clone(current);
            next.insert(tenant.tenant_id, auth.clone());
            next
        });
        outcome
    }

    /// Stops asking `tenant_id`'s clients for certificates, as for a tenant
    /// no longer served.
    pub(crate) fn remove(&self, tenant_id: &TenantId) {
        self.tenants.rcu(|current| {
            let mut next = HashMap::clone(current);
            next.remove(tenant_id);
            next
        });
    }

    /// How a handshake for `tenant` treats client certificates. A name no
    /// tenant answers on asks for none.
    pub(crate) fn of(&self, tenant: Option<&TenantId>) -> ClientAuth {
        tenant
            .and_then(|tenant| self.tenants.load().get(tenant).cloned())
            .unwrap_or(ClientAuth::Off)
    }
}

/// A verifier that could not be built, and what the tenant asked for.
struct Refused {
    demand: Demand,
    error: ClientAuthError,
}

fn client_auth(config: &MtlsConfig, provider: &Arc<CryptoProvider>) -> Result<ClientAuth, Refused> {
    let demand = match config.mode() {
        MtlsMode::Disabled => return Ok(ClientAuth::Off),
        MtlsMode::Optional => Demand::Optional,
        MtlsMode::Required => Demand::Required,
    };
    verifier(config, demand, provider)
        .map(ClientAuth::Verify)
        .map_err(|error| Refused { demand, error })
}

fn verifier(
    config: &MtlsConfig,
    demand: Demand,
    provider: &Arc<CryptoProvider>,
) -> Result<Arc<dyn ClientCertVerifier>, ClientAuthError> {
    let roots = roots_of(config.trusted_ca_certs())?;
    let lists = revocation_lists_of(config.revocation_lists())?;
    let builder =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(provider));
    let builder = checking_revocation(builder, lists);
    let builder = match demand {
        Demand::Optional => builder.allow_unauthenticated(),
        Demand::Required => builder,
    };
    builder.build().map_err(ClientAuthError::Verifier)
}

/// The trust anchors `authorities` hold.
fn roots_of(authorities: &[CertificatePem]) -> Result<RootCertStore, ClientAuthError> {
    let certificates = authorities
        .iter()
        .map(certificates_in)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ClientAuthError::Unreadable)?;
    let mut roots = RootCertStore::empty();
    let (_, unusable) = roots.add_parsable_certificates(certificates.into_iter().flatten());
    if unusable > 0 {
        return Err(ClientAuthError::Unusable(unusable));
    }
    Ok(roots)
}

/// `builder`, checking each client certificate against `lists` when there
/// are any.
///
/// Closed on every doubt: a certificate whose issuer no list covers is
/// refused, as is any certificate once a list is past its next update. The
/// end entity is checked, the certificate the client is known by; the
/// tenant's authorities name the intermediates they trust by being them.
fn checking_revocation(
    builder: ClientCertVerifierBuilder,
    lists: Vec<CertificateRevocationListDer<'static>>,
) -> ClientCertVerifierBuilder {
    if lists.is_empty() {
        return builder;
    }
    builder
        .with_crls(lists)
        .only_check_end_entity_revocation()
        .enforce_revocation_expiration()
}

/// Every revocation list `pems` hold. A PEM holding none is an error,
/// never a list that revokes nothing.
fn revocation_lists_of(
    pems: &[RevocationListPem],
) -> Result<Vec<CertificateRevocationListDer<'static>>, ClientAuthError> {
    pems.iter()
        .map(|pem| {
            let lists = rustls_pemfile::crls(&mut pem.as_str().as_bytes())
                .collect::<std::io::Result<Vec<_>>>()
                .map_err(ClientAuthError::Unreadable)?;
            match lists.is_empty() {
                true => Err(ClientAuthError::NoRevocationList),
                false => Ok(lists),
            }
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|lists| lists.into_iter().flatten().collect())
}

fn certificates_in(pem: &CertificatePem) -> std::io::Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut pem.as_str().as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use tokio_rustls::rustls::crypto::ring;

    use super::*;
    use crate::listen::certificates::fixtures::self_signed;

    fn table() -> ClientAuthTable {
        ClientAuthTable::new(Arc::new(ring::default_provider()))
    }

    fn mtls(mode: MtlsMode, authorities: &[&str]) -> TenantMtls {
        let authorities = authorities
            .iter()
            .map(|pem| CertificatePem::new(*pem).unwrap())
            .collect();
        TenantMtls {
            tenant_id: TenantId::new(),
            config: MtlsConfig::new(mode, authorities).unwrap(),
        }
    }

    fn authority() -> String {
        self_signed(&["ca.acme.test"]).0
    }

    /// A tenant with mutual TLS off is asked for nothing.
    #[test]
    fn a_tenant_with_mtls_off_asks_for_nothing() {
        let table = table();
        let tenant = mtls(MtlsMode::Disabled, &[]);

        table.set(&tenant).unwrap();

        assert!(matches!(table.of(Some(&tenant.tenant_id)), ClientAuth::Off));
    }

    /// A tenant naming a usable authority is verified against it.
    #[test]
    fn a_usable_authority_verifies() {
        let table = table();
        let tenant = mtls(MtlsMode::Required, &[&authority()]);

        let installed = table.set(&tenant);

        assert!(installed.is_ok());
        assert!(matches!(
            table.of(Some(&tenant.tenant_id)),
            ClientAuth::Verify(_)
        ));
    }

    /// An authority that does not read leaves the tenant unverifiable,
    /// never asking for nothing, and the demand is kept.
    #[test]
    fn an_unreadable_authority_is_never_treated_as_none() {
        let table = table();
        let pem =
            "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----";
        let tenant = mtls(MtlsMode::Required, &[pem]);

        let refused = table.set(&tenant);

        assert!(refused.is_err());
        assert!(matches!(
            table.of(Some(&tenant.tenant_id)),
            ClientAuth::Unbuildable(Demand::Required)
        ));
    }

    /// A name no tenant answers on asks for nothing.
    #[test]
    fn no_tenant_asks_for_nothing() {
        let table = table();

        assert!(matches!(table.of(None), ClientAuth::Off));
    }

    /// A certificate authority for client certificates, a client
    /// certificate it issued with serial 7, and lists it signs.
    struct Pki {
        authority: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
        client: CertificateDer<'static>,
    }

    impl Pki {
        fn new() -> Self {
            use rcgen::{
                BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose,
                IsCa, KeyPair, KeyUsagePurpose,
            };
            let mut ca = CertificateParams::new(Vec::new()).unwrap();
            ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
                KeyUsagePurpose::DigitalSignature,
            ];
            let authority = CertifiedIssuer::self_signed(ca, KeyPair::generate().unwrap()).unwrap();
            let mut leaf = CertificateParams::new(vec!["client.acme.test".to_owned()]).unwrap();
            leaf.serial_number = Some(7u64.into());
            leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            let client = leaf
                .signed_by(&KeyPair::generate().unwrap(), &authority)
                .unwrap()
                .der()
                .clone();
            Self { authority, client }
        }

        fn authority_pem(&self) -> String {
            self.authority.pem()
        }

        /// A list revoking `serials`, its next update `next_update` away.
        fn list(&self, serials: &[u64], next_update: time::Duration) -> String {
            use rcgen::{CertificateRevocationListParams, KeyIdMethod, RevokedCertParams};
            let now = time::OffsetDateTime::now_utc();
            CertificateRevocationListParams {
                this_update: now - time::Duration::days(2),
                next_update: now + next_update,
                crl_number: 1u64.into(),
                issuing_distribution_point: None,
                revoked_certs: serials
                    .iter()
                    .map(|serial| RevokedCertParams {
                        serial_number: (*serial).into(),
                        revocation_time: now - time::Duration::hours(1),
                        reason_code: None,
                        invalidity_date: None,
                    })
                    .collect(),
                key_identifier_method: KeyIdMethod::Sha256,
            }
            .signed_by(&self.authority)
            .unwrap()
            .pem()
            .unwrap()
        }

        /// The verifier for a tenant requiring certificates from this
        /// authority, checked against `lists`.
        fn verifier(
            &self,
            lists: &[String],
        ) -> Result<Arc<dyn ClientCertVerifier>, ClientAuthError> {
            let config = MtlsConfig::new(
                MtlsMode::Required,
                vec![CertificatePem::new(self.authority_pem()).unwrap()],
            )
            .unwrap()
            .with_revocation_lists(
                lists
                    .iter()
                    .map(|pem| RevocationListPem::new(pem.as_str()).unwrap())
                    .collect(),
            )
            .unwrap();
            verifier(
                &config,
                Demand::Required,
                &Arc::new(ring::default_provider()),
            )
        }

        /// Whether the client's certificate passes `verifier`.
        fn passes(&self, verifier: &dyn ClientCertVerifier) -> bool {
            verifier
                .verify_client_cert(
                    &self.client,
                    &[],
                    tokio_rustls::rustls::pki_types::UnixTime::now(),
                )
                .is_ok()
        }
    }

    /// The tenant gives no revocation list: a certificate its authority
    /// issued passes.
    #[test]
    fn without_lists_an_issued_certificate_passes() {
        let pki = Pki::new();

        assert!(pki.passes(pki.verifier(&[]).unwrap().as_ref()));
    }

    /// Ann's laptop is stolen and her certificate, serial 7, revoked. The
    /// list naming it refuses it in the handshake; a list naming another
    /// lets it through.
    #[test]
    fn a_revoked_client_certificate_is_refused() {
        let pki = Pki::new();
        let day = time::Duration::days(1);

        let revoked = pki.verifier(&[pki.list(&[7], day)]).unwrap();
        let other = pki.verifier(&[pki.list(&[8], day)]).unwrap();

        assert!(!pki.passes(revoked.as_ref()));
        assert!(pki.passes(other.as_ref()));
    }

    /// A client certificate fails verification when its authority's empty
    /// revocation list is past its next-update time.
    #[test]
    fn a_list_past_its_next_update_refuses() {
        let pki = Pki::new();

        let stale = pki
            .verifier(&[pki.list(&[], -time::Duration::hours(1))])
            .unwrap();

        assert!(!pki.passes(stale.as_ref()));
    }

    /// A client certificate fails verification when the configured
    /// revocation list belongs to another authority.
    #[test]
    fn a_certificate_no_list_covers_is_refused() {
        let pki = Pki::new();
        let elsewhere = Pki::new();

        let verifier = pki
            .verifier(&[elsewhere.list(&[], time::Duration::days(1))])
            .unwrap();

        assert!(!pki.passes(verifier.as_ref()));
    }

    /// A list that does not read leaves the tenant's certificates
    /// unverifiable, held to its demand, never checked against nothing.
    #[test]
    fn an_unreadable_list_makes_the_authorities_unusable() {
        let table = table();
        let pki = Pki::new();
        let broken = "-----BEGIN X509 CRL-----\nbm90IGEgbGlzdA==\n-----END X509 CRL-----";
        let tenant = TenantMtls {
            tenant_id: TenantId::new(),
            config: MtlsConfig::new(
                MtlsMode::Required,
                vec![CertificatePem::new(pki.authority_pem()).unwrap()],
            )
            .unwrap()
            .with_revocation_lists(vec![RevocationListPem::new(broken).unwrap()])
            .unwrap(),
        };

        let refused = table.set(&tenant);

        assert!(refused.is_err());
        assert!(matches!(
            table.of(Some(&tenant.tenant_id)),
            ClientAuth::Unbuildable(Demand::Required)
        ));
    }

    /// A removed tenant is asked for nothing.
    #[test]
    fn a_removed_tenant_is_forgotten() {
        let table = table();
        let tenant = mtls(MtlsMode::Required, &[&authority()]);
        table.set(&tenant).unwrap();

        table.remove(&tenant.tenant_id);

        assert!(matches!(table.of(Some(&tenant.tenant_id)), ClientAuth::Off));
    }
}
