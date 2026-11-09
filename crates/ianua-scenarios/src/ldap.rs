//! An LDAP client as an application or a person's device speaks it: one
//! TLS connection to the stack's directory, trusting the stack's authority
//! alone and presenting a client certificate when it has one, a simple
//! bind, Who-am-I, and subtree searches, each answer read as the protocol
//! carries it.

use std::sync::Arc;

use futures_util::{SinkExt as _, StreamExt as _};
use ldap3_proto::LdapCodec;
use ldap3_proto::proto::{
    LdapAddRequest, LdapBindCred, LdapBindRequest, LdapDerefAliases, LdapExtendedRequest,
    LdapFilter, LdapModify, LdapModifyRequest, LdapModifyType, LdapMsg, LdapOp,
    LdapPartialAttribute, LdapResultCode, LdapSearchRequest, LdapSearchScope, OID_WHOAMI,
};
use rcgen::{CertificateParams, KeyPair};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::pem::PemObject as _;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_util::codec::Framed;

use crate::stack::Stack;

/// The root the directory's tree hangs from.
const ROOT: &str = "dc=ianua";

/// One connection to the directory.
pub struct LdapClient {
    framed: Framed<TlsStream<TcpStream>, LdapCodec>,
    next_id: i32,
}

/// A key made on a person's device for their LDAP client certificate,
/// which never leaves it. `Debug` shows no key.
pub struct DeviceKey {
    key: KeyPair,
}

/// A client certificate the tenant issued and the device's key for it.
/// `Debug` shows no key.
pub struct ClientCertificate {
    chain: Vec<CertificateDer<'static>>,
    key_pem: String,
}

impl std::fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceKey").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ClientCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCertificate")
            .field("certificates", &self.chain.len())
            .finish_non_exhaustive()
    }
}

impl DeviceKey {
    /// A fresh key.
    ///
    /// # Panics
    ///
    /// When the key cannot be made.
    /// The certificate scenario requires a device key before it can request issuance.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn new() -> Self {
        Self {
            key: KeyPair::generate().expect("a device key"),
        }
    }

    /// The signing request the tenant is asked to sign, PEM.
    ///
    /// # Panics
    ///
    /// When the request cannot be made.
    /// The generated device key and empty subject must produce the fixture's signing request.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn signing_request(&self) -> String {
        CertificateParams::new(Vec::<String>::new())
            .expect("request parameters")
            .serialize_request(&self.key)
            .expect("a signing request")
            .pem()
            .expect("the request as PEM")
    }

    /// The certificate `issued_pem` the tenant signed, with this key.
    ///
    /// # Panics
    ///
    /// When the PEM holds no certificate.
    /// This helper asserts that the tenant's successful issuance returned a usable certificate.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn certified(self, issued_pem: &str) -> ClientCertificate {
        let chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(issued_pem.as_bytes())
                .collect::<Result<_, _>>()
                .expect("the issued certificate reads as PEM");
        assert!(!chain.is_empty(), "the tenant issued a certificate");
        ClientCertificate {
            chain,
            key_pem: self.key.serialize_pem(),
        }
    }
}

impl Default for DeviceKey {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for LdapClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LdapClient")
            .field("next_id", &self.next_id)
            .finish_non_exhaustive()
    }
}

/// One entry a search found: its DN and its attributes, each with its
/// values as text.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Its distinguished name.
    pub dn: String,
    /// Its attributes, each with its values.
    pub attributes: Vec<(String, Vec<String>)>,
}

impl Entry {
    /// The values of the attribute `name`, whatever its letter case.
    #[must_use]
    pub fn values(&self, name: &str) -> Vec<String> {
        self.attributes
            .iter()
            .filter(|(attribute, _)| attribute.eq_ignore_ascii_case(name))
            .flat_map(|(_, values)| values.clone())
            .collect()
    }
}

impl LdapClient {
    /// A TLS connection to `stack`'s directory presenting no client
    /// certificate, as an application binding with a secret opens one.
    ///
    /// # Panics
    ///
    /// When the directory does not take the connection or its handshake.
    pub async fn connect(stack: &Stack) -> Self {
        Self::opened(stack, None).await
    }

    /// A TLS connection to `stack`'s directory presenting `certificate`, as
    /// a person's device opens one.
    ///
    /// # Panics
    ///
    /// When the directory does not take the connection or its handshake.
    pub async fn connect_presenting(stack: &Stack, certificate: &ClientCertificate) -> Self {
        Self::opened(stack, Some(certificate)).await
    }

    /// A connection trusting `stack`'s authority alone, presenting
    /// `certificate` when there is one.
    /// A connection or handshake failure aborts the scenario at its transport prerequisite.
    #[allow(clippy::expect_used)]
    async fn opened(stack: &Stack, certificate: Option<&ClientCertificate>) -> Self {
        let config = tls_config(stack, certificate);
        let stream = TcpStream::connect(stack.ldap())
            .await
            .expect("the directory takes the connection");
        let name = ServerName::try_from(stack.ldap_name()).expect("the directory's name");
        let tls = TlsConnector::from(Arc::new(config))
            .connect(name, stream)
            .await
            .expect("the directory's TLS handshake");
        Self {
            framed: Framed::new(tls, LdapCodec::default()),
            next_id: 1,
        }
    }

    /// The result of a simple bind as `dn` with `password`.
    pub async fn bind(&mut self, dn: &str, password: &str) -> LdapResultCode {
        let answer = self
            .ask(LdapOp::BindRequest(LdapBindRequest {
                dn: dn.to_owned(),
                cred: LdapBindCred::Simple(password.to_owned()),
            }))
            .await;
        match answer.op {
            LdapOp::BindResponse(response) => response.res.code,
            other => panic!("expected a bind answer, got {other:?}"),
        }
    }

    /// Who the connection is bound as, the DN without its `dn:`, or empty
    /// when it is bound as nobody.
    pub async fn who_am_i(&mut self) -> String {
        let answer = self
            .ask(LdapOp::ExtendedRequest(LdapExtendedRequest {
                name: OID_WHOAMI.to_owned(),
                value: None,
            }))
            .await;
        let LdapOp::ExtendedResponse(response) = answer.op else {
            panic!("expected a Who-am-I answer, got {:?}", answer.op);
        };
        let named = String::from_utf8(response.value.unwrap_or_default()).unwrap_or_default();
        named.trim_start_matches("dn:").to_owned()
    }

    /// The entries under `base` that `filter` matches, and how the search
    /// ended.
    pub async fn search(&mut self, base: &str, filter: LdapFilter) -> (Vec<Entry>, LdapResultCode) {
        let id = self
            .sent(LdapOp::SearchRequest(LdapSearchRequest {
                base: base.to_owned(),
                scope: LdapSearchScope::Subtree,
                aliases: LdapDerefAliases::Never,
                sizelimit: 0,
                timelimit: 0,
                typesonly: false,
                filter,
                attrs: vec![],
            }))
            .await;
        self.search_results(id).await
    }

    /// The result of adding the entry `dn` with `attributes`, each an
    /// attribute's name and its values.
    pub async fn add(&mut self, dn: &str, attributes: &[(&str, &[&str])]) -> LdapResultCode {
        let answer = self
            .ask(LdapOp::AddRequest(LdapAddRequest {
                dn: dn.to_owned(),
                attributes: attributes
                    .iter()
                    .map(|(name, values)| partial_attribute(name, values))
                    .collect(),
            }))
            .await;
        match answer.op {
            LdapOp::AddResponse(result) => result.code,
            other => panic!("expected an add answer, got {other:?}"),
        }
    }

    /// The result of adding `values` to `attribute` of the entry `dn`.
    pub async fn add_values(
        &mut self,
        dn: &str,
        attribute: &str,
        values: &[&str],
    ) -> LdapResultCode {
        self.changed(
            dn,
            LdapModifyType::Add,
            partial_attribute(attribute, values),
        )
        .await
    }

    /// The result of putting `values` in the place of `attribute` of the
    /// entry `dn`.
    pub async fn replace_values(
        &mut self,
        dn: &str,
        attribute: &str,
        values: &[&str],
    ) -> LdapResultCode {
        self.changed(
            dn,
            LdapModifyType::Replace,
            partial_attribute(attribute, values),
        )
        .await
    }

    /// The result of deleting `values` from `attribute` of the entry `dn`.
    pub async fn delete_values(
        &mut self,
        dn: &str,
        attribute: &str,
        values: &[&str],
    ) -> LdapResultCode {
        self.changed(
            dn,
            LdapModifyType::Delete,
            partial_attribute(attribute, values),
        )
        .await
    }

    /// The result of the one change `modification` to the entry `dn`.
    async fn changed(
        &mut self,
        dn: &str,
        operation: LdapModifyType,
        modification: LdapPartialAttribute,
    ) -> LdapResultCode {
        let answer = self
            .ask(LdapOp::ModifyRequest(LdapModifyRequest {
                dn: dn.to_owned(),
                changes: vec![LdapModify {
                    operation,
                    modification,
                }],
            }))
            .await;
        match answer.op {
            LdapOp::ModifyResponse(result) => result.code,
            other => panic!("expected a modify answer, got {other:?}"),
        }
    }

    /// The result of deleting the entry `dn`.
    pub async fn delete(&mut self, dn: &str) -> LdapResultCode {
        let answer = self.ask(LdapOp::DelRequest(dn.to_owned())).await;
        match answer.op {
            LdapOp::DelResponse(result) => result.code,
            other => panic!("expected a delete answer, got {other:?}"),
        }
    }

    /// Collects entries until the search's terminal result, checking each message id.
    async fn search_results(&mut self, id: i32) -> (Vec<Entry>, LdapResultCode) {
        let mut found = Vec::new();
        loop {
            let answer = self.received(id).await;
            match answer.op {
                LdapOp::SearchResultEntry(entry) => found.push(Entry {
                    dn: entry.dn,
                    attributes: entry
                        .attributes
                        .into_iter()
                        .map(|attribute| {
                            let values = attribute
                                .vals
                                .into_iter()
                                .map(|value| String::from_utf8_lossy(&value).into_owned())
                                .collect();
                            (attribute.atype, values)
                        })
                        .collect(),
                }),
                LdapOp::SearchResultDone(done) => return (found, done.code),
                LdapOp::SearchResultReference(_) => {}
                other => panic!("expected a search answer, got {other:?}"),
            }
        }
    }

    /// Sends `op` and reads the one answer it gets.
    async fn ask(&mut self, op: LdapOp) -> LdapMsg {
        let id = self.sent(op).await;
        self.received(id).await
    }

    /// Sends `op` under a fresh message id and answers the id.
    /// A broken scenario connection must fail at the request that could not be sent.
    #[allow(clippy::expect_used)]
    async fn sent(&mut self, op: LdapOp) -> i32 {
        let msgid = self.next_id;
        self.next_id += 1;
        self.framed
            .send(LdapMsg {
                msgid,
                op,
                ctrl: vec![],
            })
            .await
            .expect("the directory takes the request");
        msgid
    }

    /// The next answer to the message `id`.
    /// Missing or malformed LDAP responses fail the scenario's protocol assertion.
    #[allow(clippy::expect_used)]
    async fn received(&mut self, id: i32) -> LdapMsg {
        let answer = self
            .framed
            .next()
            .await
            .expect("the directory answers")
            .expect("the answer reads as LDAP");
        assert_eq!(answer.msgid, id, "the answer is to the request sent");
        answer
    }
}

/// Builds the fixture's trust store and optional client certificate configuration.
/// Malformed fixture certificates or a mismatched key must abort the scenario setup.
#[allow(clippy::expect_used)]
fn tls_config(stack: &Stack, certificate: Option<&ClientCertificate>) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    for root in CertificateDer::pem_slice_iter(stack.root_certificate_pem().as_bytes()) {
        roots
            .add(root.expect("the stack's authority reads as PEM"))
            .expect("the stack's authority is a certificate");
    }
    let trusting = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_root_certificates(roots);
    match certificate {
        None => trusting.with_no_client_auth(),
        Some(certificate) => trusting
            .with_client_auth_cert(
                certificate.chain.clone(),
                PrivateKeyDer::from_pem_slice(certificate.key_pem.as_bytes())
                    .expect("the device key reads as PEM"),
            )
            .expect("the client certificate fits its key"),
    }
}

/// The attribute `name` with `values`, as an add or a modify carries it.
fn partial_attribute(name: &str, values: &[&str]) -> LdapPartialAttribute {
    LdapPartialAttribute {
        atype: name.to_owned(),
        vals: values
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect(),
    }
}

/// The DN of `org`'s tenant `tenant`'s groups.
#[must_use]
pub fn groups_dn(org: &str, tenant: &str) -> String {
    format!("ou=groups,ou={tenant},o={org},{ROOT}")
}

/// The DN of the group `name` in `org`'s tenant `tenant`.
#[must_use]
pub fn group_dn(org: &str, tenant: &str, name: &str) -> String {
    format!("cn={name},{}", groups_dn(org, tenant))
}

/// The DN of `org`'s tenant `tenant`'s users.
#[must_use]
pub fn users_dn(org: &str, tenant: &str) -> String {
    format!("ou=users,ou={tenant},o={org},{ROOT}")
}

/// The DN of the person at `email` in `org`'s tenant `tenant`.
#[must_use]
pub fn person_dn(org: &str, tenant: &str, email: &str) -> String {
    format!("uid={email},{}", users_dn(org, tenant))
}

/// The DN of `org`'s tenant `tenant`'s service account `name`.
#[must_use]
pub fn service_dn(org: &str, tenant: &str, name: &str) -> String {
    format!("cn={name},ou=services,ou={tenant},o={org},{ROOT}")
}
