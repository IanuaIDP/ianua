//! Reading a name's records from the public DNS, through recursive
//! resolvers, for the checks that prove a tenant controls a domain.
//!
//! Each lookup is held to a whole bound, retries included, so a name
//! server that hangs answers as an error within seconds. Nothing is
//! cached: a tenant who just wrote the record presses verify again and is
//! asked afresh, and a record taken away stops proving anything at once.
//! A name with no such record is an answer, `false`; only a resolver that
//! could not be asked is an error.
//!
//! A delegation is read from the zone above the name, asked directly and
//! without recursion, never from a recursive answer: that would come from
//! the delegated zone itself, which for a name delegated to us is ours.
//! The recursive resolvers only find the zone above and its servers. It
//! counts only the `NS` records of the name itself. A name that is an alias
//! holds no `NS` records of its own, so the name servers of the alias's
//! target, which whoever owns that target writes, prove nothing about it.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::rdata::{CNAME, NS};
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use hickory_resolver::system_conf::read_system_conf;
use ianua_app::ports::domain::DnsResolver;
use ianua_domain::domains::tenant::custom_domains::dns_zone::{RecordName, TxtValue};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::DomainName;

use crate::dns::referral::{DNS_PORT, ReferralAsker};

/// How long a lookup may take: each try, and the whole of it.
#[derive(Debug, Clone, Copy)]
pub struct LookupBounds {
    /// How long one question to one resolver may wait for its answer.
    pub per_try: Duration,
    /// How many times a question is asked before it is given up.
    pub tries: usize,
    /// How long the whole lookup may take, every try included.
    pub whole: Duration,
}

impl Default for LookupBounds {
    /// Two seconds a try, two tries, five seconds in all.
    fn default() -> Self {
        Self {
            per_try: Duration::from_secs(2),
            tries: 2,
            whole: Duration::from_secs(5),
        }
    }
}

/// Reads records through recursive resolvers: the host's own, or the ones
/// the deployment names; and delegations from the servers of the zone
/// above, asked directly.
pub struct RecursiveDnsResolver {
    resolver: TokioResolver,
    referrals: ReferralAsker,
    whole: Duration,
}

impl RecursiveDnsResolver {
    /// A resolver asking the resolvers the host is configured with.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the host's resolver
    /// settings cannot be read.
    pub fn from_host(bounds: LookupBounds) -> Result<Self, DomainError> {
        let (config, options) = read_system_conf().map_err(DomainError::infra)?;
        Self::built(config, options, bounds)
    }

    /// A resolver asking only the resolvers at `nameservers`, over UDP and
    /// then TCP.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the resolver cannot be
    /// built.
    pub fn asking(nameservers: &[SocketAddr], bounds: LookupBounds) -> Result<Self, DomainError> {
        let servers = nameservers
            .iter()
            .map(|address| nameserver_at(*address))
            .collect();
        Self::built(
            ResolverConfig::from_name_servers(servers),
            ResolverOpts::default(),
            bounds,
        )
    }

    /// A resolver asking as `config` says, with `options` held to `bounds`
    /// and nothing cached.
    fn built(
        config: ResolverConfig,
        options: ResolverOpts,
        bounds: LookupBounds,
    ) -> Result<Self, DomainError> {
        let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(bounded(options, bounds))
            .build()
            .map_err(DomainError::infra)?;
        Ok(Self {
            resolver,
            referrals: ReferralAsker::new(DNS_PORT, bounds.per_try),
            whole: bounds.whole,
        })
    }

    /// This resolver asking the servers of the zone above a name on `port`
    /// rather than on 53, for a test whose name servers listen on a
    /// loopback port.
    #[cfg(test)]
    fn asking_above_on(self, port: u16, bounds: LookupBounds) -> Self {
        Self {
            referrals: ReferralAsker::new(port, bounds.per_try),
            ..self
        }
    }

    /// The `NS` records the zone above `owner` holds for it, read from
    /// that zone's own servers.
    async fn delegation_of(&self, owner: &Name) -> Result<Vec<Record>, DomainError> {
        let servers = self.servers_above(owner).await?;
        self.referrals.delegation(owner, &servers).await
    }

    /// The addresses of the servers of the closest zone above `owner`,
    /// IPv4 first.
    async fn servers_above(&self, owner: &Name) -> Result<Vec<IpAddr>, DomainError> {
        let mut zone = owner.base_name();
        while !zone.is_root() {
            let hosts = self.nameservers_of(&zone).await?;
            if !hosts.is_empty() {
                return self.addresses_of(hosts).await;
            }
            zone = zone.base_name();
        }
        Err(DomainError::infra_msg(
            "no zone above the name has name servers",
        ))
    }

    /// The name servers `zone` names for itself, none when it is no zone.
    async fn nameservers_of(&self, zone: &Name) -> Result<Vec<Name>, DomainError> {
        let records = self.answers(&zone.to_ascii(), RecordType::NS).await?;
        Ok(records
            .iter()
            .filter(|record| record.name == *zone)
            .filter_map(|record| nameserver_of(&record.data))
            .cloned()
            .collect())
    }

    /// Every address `hosts` resolve to, IPv4 first. A host with none is
    /// passed over.
    async fn addresses_of(&self, hosts: Vec<Name>) -> Result<Vec<IpAddr>, DomainError> {
        let mut addresses = Vec::new();
        for host in hosts {
            match self.resolver.lookup_ip(host).await {
                Ok(found) => addresses.extend(found.iter()),
                Err(error) => tracing::debug!(%error, "a server above the name has no address"),
            }
        }
        if addresses.is_empty() {
            return Err(DomainError::infra_msg(
                "no server of the zone above the name has an address",
            ));
        }
        addresses.sort_by_key(IpAddr::is_ipv6);
        Ok(addresses)
    }

    /// The records answering `kind` at `name`, aliases followed included,
    /// or none when the name holds none.
    async fn answers(&self, name: &str, kind: RecordType) -> Result<Vec<Record>, DomainError> {
        let query = absolute(name)?;
        let asked = tokio::time::timeout(self.whole, self.resolver.lookup(query, kind))
            .await
            .map_err(DomainError::infra)?;
        match asked {
            Ok(found) => Ok(found.answers().to_vec()),
            Err(missing) if missing.is_no_records_found() => Ok(Vec::new()),
            Err(failed) => Err(DomainError::infra(failed)),
        }
    }
}

/// `options` with each try held to `bounds` and no cache kept.
fn bounded(mut options: ResolverOpts, bounds: LookupBounds) -> ResolverOpts {
    options.timeout = bounds.per_try;
    options.attempts = bounds.tries;
    options.cache_size = 0;
    options
}

/// A resolver asking only the resolvers at `nameservers`, each question
/// held to `bounds` and nothing cached, for the addresses an outbound
/// client connects to.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the resolver cannot be
/// built.
pub(crate) fn address_resolver(
    nameservers: &[SocketAddr],
    bounds: LookupBounds,
) -> Result<TokioResolver, DomainError> {
    let servers = nameservers
        .iter()
        .map(|address| nameserver_at(*address))
        .collect();
    TokioResolver::builder_with_config(
        ResolverConfig::from_name_servers(servers),
        TokioRuntimeProvider::default(),
    )
    .with_options(bounded(ResolverOpts::default(), bounds))
    .build()
    .map_err(DomainError::infra)
}

/// A resolver at `address`, asked over UDP and then TCP on its own port.
fn nameserver_at(address: SocketAddr) -> NameServerConfig {
    let mut server = NameServerConfig::udp_and_tcp(address.ip());
    for connection in &mut server.connections {
        connection.port = address.port();
    }
    server
}

/// `name` as a fully qualified name, so no search domain of the host is
/// ever tried in its place.
fn absolute(name: &str) -> Result<Name, DomainError> {
    Name::from_ascii(format!("{}.", name.trim_end_matches('.'))).map_err(DomainError::infra)
}

/// The text a `TXT` record holds, its strings joined as one value.
fn text_of(data: &RData) -> Option<Vec<u8>> {
    let RData::TXT(text) = data else {
        return None;
    };
    Some(
        text.txt_data
            .iter()
            .flat_map(|part| part.iter().copied())
            .collect(),
    )
}

/// The name a `CNAME` record points at.
fn alias_of(data: &RData) -> Option<String> {
    let RData::CNAME(CNAME(target)) = data else {
        return None;
    };
    Some(target.to_ascii())
}

/// The name server an `NS` record names.
fn nameserver_of(data: &RData) -> Option<&Name> {
    let RData::NS(NS(server)) = data else {
        return None;
    };
    Some(server)
}

/// Whether `found` and `expected` name the same host, case and a final dot
/// set aside.
fn same_host(found: &str, expected: &str) -> bool {
    found
        .trim_end_matches('.')
        .eq_ignore_ascii_case(expected.trim_end_matches('.'))
}

/// Whether every one of `expected` is among `found`. Nothing expected
/// proves nothing.
fn holds_every(found: &[String], expected: &[DomainName]) -> bool {
    !expected.is_empty()
        && expected.iter().all(|wanted| {
            found
                .iter()
                .any(|server| same_host(server, wanted.as_str()))
        })
}

#[async_trait]
impl DnsResolver for RecursiveDnsResolver {
    async fn verify_txt_record(
        &self,
        name: &RecordName,
        expected: &TxtValue,
    ) -> Result<bool, DomainError> {
        let records = self.answers(name.as_str(), RecordType::TXT).await?;
        Ok(records
            .iter()
            .filter_map(|record| text_of(&record.data))
            .any(|text| text == expected.as_str().as_bytes()))
    }

    async fn verify_cname(
        &self,
        domain: &DomainName,
        expected_target: &DomainName,
    ) -> Result<bool, DomainError> {
        let records = self.answers(domain.as_str(), RecordType::CNAME).await?;
        Ok(records
            .iter()
            .filter_map(|record| alias_of(&record.data))
            .any(|target| same_host(&target, expected_target.as_str())))
    }

    async fn verify_delegation(
        &self,
        domain: &DomainName,
        expected_nameservers: &[DomainName],
    ) -> Result<bool, DomainError> {
        let owner = absolute(domain.as_str())?;
        let records = tokio::time::timeout(self.whole, self.delegation_of(&owner))
            .await
            .map_err(DomainError::infra)??;
        let found: Vec<String> = records
            .iter()
            .filter(|record| record.name == owner)
            .filter_map(|record| nameserver_of(&record.data))
            .map(Name::to_ascii)
            .collect();
        Ok(holds_every(&found, expected_nameservers))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use hickory_resolver::proto::op::{Message, ResponseCode};
    use hickory_resolver::proto::rr::rdata::{A, TXT};
    use tokio::net::UdpSocket;

    use super::*;

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }

    fn txt(at: &str, parts: &[&str]) -> Record {
        let strings = parts.iter().map(|part| (*part).to_owned()).collect();
        Record::from_rdata(name(at), 60, RData::TXT(TXT::new(strings)))
    }

    fn alias(at: &str, target: &str) -> Record {
        Record::from_rdata(name(at), 60, RData::CNAME(CNAME(name(target))))
    }

    fn delegation(at: &str, server: &str) -> Record {
        Record::from_rdata(name(at), 60, RData::NS(NS(name(server))))
    }

    fn domain(text: &str) -> DomainName {
        DomainName::new(text).unwrap()
    }

    /// The answer a name server holding `records` gives `request`: every
    /// record of the asked name and type, or no such name.
    fn reply_to(request: &Message, records: &[Record]) -> Message {
        let mut reply = Message::response(request.metadata.id, request.metadata.op_code);
        reply.metadata.recursion_desired = request.metadata.recursion_desired;
        reply.metadata.recursion_available = true;
        let Some(query) = request.queries.first() else {
            return reply;
        };
        reply.add_query(query.clone());
        let matching: Vec<Record> = records
            .iter()
            .filter(|record| {
                record.name == *query.name() && record.record_type() == query.query_type()
            })
            .cloned()
            .collect();
        if matching.is_empty() {
            reply.metadata.response_code = ResponseCode::NXDomain;
        }
        reply.insert_answers(matching);
        reply
    }

    /// The answer a name server following an alias gives `request`: every
    /// one of `records`, the alias and what its target holds, whatever was
    /// asked.
    fn every_record(request: &Message, records: &[Record]) -> Message {
        let mut reply = Message::response(request.metadata.id, request.metadata.op_code);
        reply.metadata.recursion_desired = request.metadata.recursion_desired;
        reply.metadata.recursion_available = true;
        let Some(query) = request.queries.first() else {
            return reply;
        };
        reply.add_query(query.clone());
        reply.insert_answers(records.to_vec());
        reply
    }

    /// A name server on a loopback port answering from `records` alone.
    async fn serving(records: Vec<Record>) -> SocketAddr {
        serving_with(records, reply_to).await
    }

    /// A name server on a loopback port answering from `records` as
    /// `answering` says.
    async fn serving_with(
        records: Vec<Record>,
        answering: fn(&Message, &[Record]) -> Message,
    ) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = vec![0_u8; 4096];
            while let Ok((read, from)) = socket.recv_from(&mut buffer).await {
                let Ok(request) = Message::from_vec(&buffer[..read]) else {
                    continue;
                };
                let reply = answering(&request, &records).to_vec().unwrap();
                socket.send_to(&reply, from).await.unwrap();
            }
        });
        address
    }

    fn quick() -> LookupBounds {
        LookupBounds {
            per_try: Duration::from_millis(200),
            tries: 1,
            whole: Duration::from_millis(800),
        }
    }

    async fn resolver_for(records: Vec<Record>) -> RecursiveDnsResolver {
        let address = serving(records).await;
        RecursiveDnsResolver::asking(&[address], quick()).unwrap()
    }

    fn record_name(text: &str) -> RecordName {
        RecordName::new(text).unwrap()
    }

    fn value(text: &str) -> TxtValue {
        TxtValue::new(text).unwrap()
    }

    /// Acme wrote the verification token at `_ianua-verify.acme.com`. The
    /// check finds it.
    #[tokio::test]
    async fn a_txt_record_holding_the_token_verifies() {
        let resolver =
            resolver_for(vec![txt("_ianua-verify.acme.com.", &["ianua-verify=abc"])]).await;

        let found = resolver
            .verify_txt_record(
                &record_name("_ianua-verify.acme.com"),
                &value("ianua-verify=abc"),
            )
            .await
            .unwrap();

        assert!(found);
    }

    /// A long value a name server split into several strings is read
    /// joined, as one value.
    #[tokio::test]
    async fn a_txt_value_split_into_strings_is_read_whole() {
        let resolver = resolver_for(vec![txt(
            "_proof.acme.com.",
            &["first-half", "-second-half"],
        )])
        .await;

        let found = resolver
            .verify_txt_record(
                &record_name("_proof.acme.com"),
                &value("first-half-second-half"),
            )
            .await
            .unwrap();

        assert!(found);
    }

    /// A TXT value with an extra character does not verify the expected token.
    #[tokio::test]
    async fn a_txt_record_holding_another_value_does_not_verify() {
        let resolver =
            resolver_for(vec![txt("_ianua-verify.acme.com.", &["ianua-verify=abcd"])]).await;

        let found = resolver
            .verify_txt_record(
                &record_name("_ianua-verify.acme.com"),
                &value("ianua-verify=abc"),
            )
            .await
            .unwrap();

        assert!(!found);
    }

    /// A name with no record at all answers no, not an error: the tenant
    /// has not written it yet.
    #[tokio::test]
    async fn a_name_without_the_record_answers_no() {
        let resolver = resolver_for(Vec::new()).await;

        let found = resolver
            .verify_txt_record(
                &record_name("_ianua-verify.acme.com"),
                &value("ianua-verify=abc"),
            )
            .await
            .unwrap();

        assert!(!found);
    }

    /// `auth.acme.com` points at the tenant's subdomain, written with a
    /// capital and a final dot. It verifies.
    #[tokio::test]
    async fn a_cname_to_the_expected_target_verifies() {
        let resolver = resolver_for(vec![alias("auth.acme.com.", "Acme.Ianua.Cloud.")]).await;

        let found = resolver
            .verify_cname(&domain("auth.acme.com"), &domain("acme.ianua.cloud"))
            .await
            .unwrap();

        assert!(found);
    }

    /// A CNAME pointing at another tenant's subdomain fails verification.
    #[tokio::test]
    async fn a_cname_to_another_target_does_not_verify() {
        let resolver = resolver_for(vec![alias("auth.acme.com.", "globex.ianua.cloud.")]).await;

        let found = resolver
            .verify_cname(&domain("auth.acme.com"), &domain("acme.ianua.cloud"))
            .await
            .unwrap();

        assert!(!found);
    }

    fn address(at: &str, ip: &str) -> Record {
        Record::from_rdata(name(at), 60, RData::A(A(ip.parse().unwrap())))
    }

    /// What the recursive resolvers know of the zone above `auth.acme.com`:
    /// `acme.com` is served by `ns.acme.com`, at the loopback address.
    fn zone_above() -> Vec<Record> {
        vec![
            delegation("acme.com.", "ns.acme.com."),
            address("ns.acme.com.", "127.0.0.1"),
        ]
    }

    /// One name server on a loopback port playing both parts: a recursive
    /// resolver answering from `recursive`, and the server of the zone
    /// above answering a direct question from `direct` as `answering` says.
    async fn serving_both(
        recursive: Vec<Record>,
        direct: Vec<Record>,
        answering: fn(&Message, &[Record]) -> Message,
    ) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = vec![0_u8; 4096];
            while let Ok((read, from)) = socket.recv_from(&mut buffer).await {
                let Ok(request) = Message::from_vec(&buffer[..read]) else {
                    continue;
                };
                let reply = match request.metadata.recursion_desired {
                    true => reply_to(&request, &recursive),
                    false => answering(&request, &direct),
                };
                socket
                    .send_to(&reply.to_vec().unwrap(), from)
                    .await
                    .unwrap();
            }
        });
        address
    }

    /// A resolver whose zone above `auth.acme.com` writes `direct` for it,
    /// and whose recursive resolvers answer from `recursive` beside what
    /// they know of that zone.
    async fn delegated_by(
        recursive: Vec<Record>,
        direct: Vec<Record>,
        answering: fn(&Message, &[Record]) -> Message,
    ) -> RecursiveDnsResolver {
        let recursive = zone_above().into_iter().chain(recursive).collect();
        let address = serving_both(recursive, direct, answering).await;
        RecursiveDnsResolver::asking(&[address], quick())
            .unwrap()
            .asking_above_on(address.port(), quick())
    }

    fn ours() -> [DomainName; 2] {
        [domain("ns1-x.ianua.cloud"), domain("ns2-x.ianua.cloud")]
    }

    /// The zone above delegates `auth.acme.com` to both expected name
    /// servers. It verifies.
    #[tokio::test]
    async fn a_whole_delegation_verifies() {
        let resolver = delegated_by(
            Vec::new(),
            vec![
                delegation("auth.acme.com.", "ns1-x.ianua.cloud."),
                delegation("auth.acme.com.", "ns2-x.ianua.cloud."),
            ],
            reply_to,
        )
        .await;

        let found = resolver
            .verify_delegation(&domain("auth.acme.com"), &ours())
            .await
            .unwrap();

        assert!(found);
    }

    /// Delegation to only one of two expected name servers fails verification.
    #[tokio::test]
    async fn a_partial_delegation_does_not_verify() {
        let resolver = delegated_by(
            Vec::new(),
            vec![delegation("auth.acme.com.", "ns1-x.ianua.cloud.")],
            reply_to,
        )
        .await;

        let found = resolver
            .verify_delegation(&domain("auth.acme.com"), &ours())
            .await
            .unwrap();

        assert!(!found);
    }

    /// Expected name servers in a recursive answer cannot verify a delegation
    /// when the parent zone names different servers.
    #[tokio::test]
    async fn the_delegated_zones_own_answer_does_not_verify() {
        let resolver = delegated_by(
            vec![
                delegation("auth.acme.com.", "ns1-x.ianua.cloud."),
                delegation("auth.acme.com.", "ns2-x.ianua.cloud."),
            ],
            vec![
                delegation("auth.acme.com.", "ns1-old.ianua.cloud."),
                delegation("auth.acme.com.", "ns2-old.ianua.cloud."),
            ],
            reply_to,
        )
        .await;

        let found = resolver
            .verify_delegation(&domain("auth.acme.com"), &ours())
            .await
            .unwrap();

        assert!(!found);
    }

    /// A name the zone above does not know is not delegated: an answer,
    /// not an error.
    #[tokio::test]
    async fn a_name_the_zone_above_does_not_know_does_not_verify() {
        let resolver = delegated_by(Vec::new(), Vec::new(), reply_to).await;

        let found = resolver
            .verify_delegation(&domain("auth.acme.com"), &ours())
            .await
            .unwrap();

        assert!(!found);
    }

    /// Expected name servers belonging to an alias target cannot verify the
    /// alias name's delegation.
    #[tokio::test]
    async fn name_servers_behind_an_alias_do_not_verify() {
        let resolver = delegated_by(
            Vec::new(),
            vec![
                alias("auth.acme.com.", "mallory.test."),
                delegation("mallory.test.", "ns1-x.ianua.cloud."),
                delegation("mallory.test.", "ns2-x.ianua.cloud."),
            ],
            every_record,
        )
        .await;

        let found = resolver
            .verify_delegation(&domain("auth.acme.com"), &ours())
            .await
            .unwrap();

        assert!(!found);
    }

    /// A delegation check with no expected name servers returns false.
    #[tokio::test]
    async fn a_delegation_to_no_one_does_not_verify() {
        let resolver = delegated_by(
            Vec::new(),
            vec![delegation("auth.acme.com.", "ns1-x.ianua.cloud.")],
            reply_to,
        )
        .await;

        let found = resolver
            .verify_delegation(&domain("auth.acme.com"), &[])
            .await
            .unwrap();

        assert!(!found);
    }

    /// A silent parent zone makes the delegation check fail with an
    /// infrastructure error within three seconds.
    #[tokio::test]
    async fn a_silent_zone_above_is_given_up_in_time() {
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let recursive = serving(zone_above()).await;
        let resolver = RecursiveDnsResolver::asking(&[recursive], quick())
            .unwrap()
            .asking_above_on(silent.local_addr().unwrap().port(), quick());
        let started = Instant::now();

        let result = resolver
            .verify_delegation(&domain("auth.acme.com"), &ours())
            .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    /// A silent resolver makes the TXT lookup fail with an infrastructure error
    /// within three seconds.
    #[tokio::test]
    async fn a_silent_name_server_is_given_up_in_time() {
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver =
            RecursiveDnsResolver::asking(&[silent.local_addr().unwrap()], quick()).unwrap();
        let started = Instant::now();

        let result = resolver
            .verify_txt_record(
                &record_name("_ianua-verify.acme.com"),
                &value("ianua-verify=abc"),
            )
            .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
