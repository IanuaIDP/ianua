//! The nameservers started as the binary starts them, against a real
//! database, signed in as their own role, answering real queries over UDP
//! and TCP on a loopback port.

#![cfg(test)]

mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::ResponseCode;
use ianua_app::ports::domain::{DnsZoneWriter, RegisteredDomainStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_boot::env::Env;
use ianua_boot::shutdown::Shutdown;
use ianua_domain::domains::tenant::custom_domains::dns_zone::{DelegationLabel, RecordKind};
use ianua_domain::domains::tenant::custom_domains::registered_domain::{
    RegisteredDomain, RegisteredDomainRow,
};
use ianua_infra::postgres::domain::{PgDnsZoneWriter, PgRegisteredDomainStore};
use ianua_infra::test_support::rows::domain::{
    delegated_domain_row, nameserver_bases, proved_domain_row, record_set, saved_tenant,
};
use ianua_infra::test_support::{NAMESERVER_ROLE, NAMESERVER_ROLE_PASSWORD, TestDb};

use crate::support::{addresses, answered_within, over_tcp, over_udp};

/// Acme's proved zone.
const PROVED: &str = "auth.acme.example";

/// Globex's zone, registered and never proved.
const UNPROVED: &str = "login.globex.example";

/// Registers `row` for `tenant`, opens its zone and writes one address
/// into it.
async fn delegated(db: &TestDb, tenant: &ScopedTenant, row: RegisteredDomainRow, address: &str) {
    let registered = RegisteredDomain::reconstitute(row).unwrap();
    PgRegisteredDomainStore::new(Arc::clone(&db.databases))
        .save(tenant, &registered)
        .await
        .unwrap();
    let zones = PgDnsZoneWriter::new(Arc::clone(&db.databases), nameserver_bases());
    let label = DelegationLabel::for_registration(registered.id());
    zones
        .create_zone(tenant, registered.domain(), &label)
        .await
        .unwrap();
    let host = registered.domain().as_str();
    zones
        .replace_record_set(
            tenant,
            registered.domain(),
            &record_set(&format!("api.{host}"), RecordKind::A, address),
        )
        .await
        .unwrap();
}

/// A database holding Acme's proved zone and Globex's unproved one.
async fn seeded() -> TestDb {
    let db = TestDb::fresh().await;
    let acme = saved_tenant(&db.databases).await;
    let globex = saved_tenant(&db.databases).await;
    delegated(&db, &acme, proved_domain_row(PROVED), "203.0.113.7").await;
    delegated(&db, &globex, delegated_domain_row(UNPROVED), "203.0.113.66").await;
    db
}

/// The nameservers `db` describes, serving under `shutdown` on any
/// loopback port.
async fn started(db: &TestDb, shutdown: &Shutdown) -> SocketAddr {
    let login = db.address(NAMESERVER_ROLE, NAMESERVER_ROLE_PASSWORD);
    let vars = Env::of([
        ("APP_ENV", "development"),
        ("NAMESERVER_DATABASE_URL", login.as_str()),
        ("DNS_BIND", "127.0.0.1:0"),
        ("DNS_HOSTMASTER", "hostmaster.ianua.example"),
    ]);
    ianua_dns::serving(&vars, shutdown).await.unwrap().address
}

/// A resolver asks for a name in Acme's proved zone over UDP and over TCP,
/// and is answered with authority and Acme's address both times.
#[tokio::test]
async fn a_proved_zone_is_answered_over_udp_and_tcp() {
    let db = seeded().await;
    let shutdown = Shutdown::new(Duration::from_secs(2));
    let address = started(&db, &shutdown).await;

    let udp = over_udp(address, &format!("api.{PROVED}")).await;
    let tcp = over_tcp(address, &format!("api.{PROVED}")).await;

    assert!(udp.metadata.authoritative);
    assert_eq!(addresses(&udp), ["203.0.113.7"]);
    assert!(tcp.metadata.authoritative);
    assert_eq!(addresses(&tcp), ["203.0.113.7"]);
    shutdown.stop();
    shutdown.join().await.unwrap();
}

/// Globex's unproved zone and an unrelated name both receive REFUSED;
/// the unproved zone returns no address records.
#[tokio::test]
async fn an_unproved_zone_and_a_stranger_are_refused() {
    let db = seeded().await;
    let shutdown = Shutdown::new(Duration::from_secs(2));
    let address = started(&db, &shutdown).await;

    let unproved = over_udp(address, &format!("api.{UNPROVED}")).await;
    let stranger = over_tcp(address, "www.example.com").await;

    assert_eq!(unproved.metadata.response_code, ResponseCode::Refused);
    assert!(addresses(&unproved).is_empty());
    assert_eq!(stranger.metadata.response_code, ResponseCode::Refused);
    shutdown.stop();
    shutdown.join().await.unwrap();
}

/// A nameserver starts with an unreachable database but supplies no
/// successful answer for Acme's name during the observation window.
#[tokio::test]
async fn a_database_it_cannot_reach_leaves_every_query_refused() {
    let shutdown = Shutdown::new(Duration::from_secs(2));
    let vars = Env::of([
        ("APP_ENV", "development"),
        (
            "NAMESERVER_DATABASE_URL",
            "postgres://ianua_nameserver:ns-pw@127.0.0.1:1/nothing",
        ),
        ("DATABASE_ACQUIRE_TIMEOUT_SECONDS", "1"),
        ("DNS_BIND", "127.0.0.1:0"),
        ("DNS_HOSTMASTER", "hostmaster.ianua.example"),
    ]);
    let address = ianua_dns::serving(&vars, &shutdown).await.unwrap().address;

    let answered = answered_within(address, &format!("api.{PROVED}"), Duration::from_secs(1)).await;

    assert!(answered.is_none(), "every query is refused");
    shutdown.stop();
    shutdown.join().await.unwrap();
}
