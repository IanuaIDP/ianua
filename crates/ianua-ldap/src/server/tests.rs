//! Conversations with the server over an in-memory stream, the use cases
//! behind it real and their stores the app's fakes.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use ianua_app::acting::directory::DirectoryActing;
use ianua_app::ports::authorization::GroupStore;
use ianua_app::ports::identity::UserStore;
use ianua_app::test_support::authentication::AllowingThrottle;
use ianua_app::test_support::directory::{BOUND_PASSWORD, BoundDirectory, laptop};
use ianua_app::test_support::directory_service::{
    FakeServiceAccountStore, JIRA_SECRET, service_bind_ports, service_secret_hash,
};
use ianua_app::test_support::organization::{org_store_with, test_org};
use ianua_app::test_support::tenant::tenant_store_in_status;
use ianua_app::test_support::{Fake, FakeEventDispatcher, test_ctx};
use ianua_app::use_cases::directory::listing::EntryPorts;
use ianua_app::use_cases::directory::{
    BindPorts, BindUseCase, SearchPorts, SearchUseCase, groups, service_accounts, users,
};
use ianua_domain::domains::authentication::directory_service::account::{
    DirectoryServiceAccount, DirectoryServiceAccountRow, ServiceAccountStatus,
};
use ianua_domain::domains::authentication::directory_service::scope::{
    BaseDn, DirectoryAccess, ServiceAccountName, ServiceAccountScope,
};
use ianua_domain::domains::tenant::status::TenantStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::types::{CertificateFingerprint, DirectoryServiceAccountId};
use ldap3_proto::proto::{
    LdapBindCred, LdapBindRequest, LdapDerefAliases, LdapExtendedRequest, LdapFilter, LdapOp,
    LdapResultCode, LdapSearchRequest, LdapSearchScope, OID_WHOAMI,
};
use tokio::io::{AsyncWriteExt, DuplexStream};

use super::*;
use crate::ports::{GroupWrites, Targets, UserWrites};

/// Ann's entry in the test tenant, `acme` of `acme-corp`.
const ANN_DN: &str = "uid=ann@acme.test,ou=users,ou=acme,o=acme-corp,dc=ianua";

/// Jira's service account in the test tenant.
const JIRA_DN: &str = "cn=jira,ou=services,ou=acme,o=acme-corp,dc=ianua";

/// The test tenant's users.
const USERS_DN: &str = "ou=users,ou=acme,o=acme-corp,dc=ianua";

/// The test tenant's groups.
const GROUPS_DN: &str = "ou=groups,ou=acme,o=acme-corp,dc=ianua";

/// The client's end of a conversation, framed as LDAP.
type Client = Framed<DuplexStream, LdapCodec>;

/// A conversation with a server asking `ports`, from a client whose
/// handshake presented `presented`.
fn connect(ports: LdapPorts, presented: Option<CertificateFingerprint>) -> Client {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let limits = LdapLimits {
        max_connections: 4,
        idle_timeout: Duration::from_secs(5),
        handshake_timeout: Duration::from_secs(5),
        binds_per_ip_per_minute: 30,
    };
    let shared = Connections {
        ports,
        throttle: IpBindThrottle::new(limits.binds_per_ip_per_minute),
        limits,
    };
    let session = Session::new(IpAddr::V4(Ipv4Addr::LOCALHOST), presented);
    tokio::spawn(async move {
        converse(&shared, server, session, &CancellationToken::new()).await;
    });
    Framed::new(client, LdapCodec::default())
}

/// Every use case over the app's neutral fakes, which grant and hold
/// nothing.
fn ports() -> LdapPorts {
    LdapPorts {
        bind: Arc::new(BindUseCase::new(BindPorts::fakes())),
        service_bind: Arc::new(service_accounts::BindUseCase::new(
            service_accounts::BindPorts::fakes(),
        )),
        search: Arc::new(SearchUseCase::new(SearchPorts::fakes())),
        service_search: Arc::new(service_accounts::SearchAsUseCase::new(
            service_accounts::SearchAsPorts::fakes(),
        )),
        users: user_writes(),
        groups: group_writes(),
        targets: Targets {
            users: <Arc<dyn UserStore> as Fake>::fake(),
            groups: <Arc<dyn GroupStore> as Fake>::fake(),
        },
        events: Arc::new(FakeEventDispatcher::new()),
    }
}

/// User mutation use cases with stores that grant and hold nothing.
fn user_writes() -> UserWrites {
    UserWrites {
        add: Arc::new(users::AddDirectoryUseCase::new(
            users::AddDirectoryPorts::fakes(),
        )),
        rename: Arc::new(users::RenameDirectoryUseCase::new(
            users::RenameDirectoryPorts::fakes(),
        )),
        change_email: Arc::new(users::ChangeDirectoryEmailUseCase::new(
            users::ChangeDirectoryEmailPorts::fakes(),
        )),
        remove: Arc::new(users::RemoveDirectoryUseCase::new(
            users::RemoveDirectoryPorts::fakes(),
        )),
        change_password: Arc::new(users::ChangeDirectoryPasswordUseCase::new(
            users::ChangeDirectoryPasswordPorts::fakes(),
        )),
    }
}

/// Group mutation use cases with stores that grant and hold nothing.
fn group_writes() -> GroupWrites {
    GroupWrites {
        add: Arc::new(groups::AddDirectoryUseCase::new(
            groups::AddDirectoryPorts::fakes(),
        )),
        rename: Arc::new(groups::RenameDirectoryUseCase::new(
            groups::RenameDirectoryPorts::fakes(),
        )),
        remove: Arc::new(groups::RemoveDirectoryUseCase::new(
            groups::RemoveDirectoryPorts::fakes(),
        )),
        add_member: Arc::new(groups::AddDirectoryMemberUseCase::new(
            groups::AddDirectoryMemberPorts::fakes(),
        )),
        remove_member: Arc::new(groups::RemoveDirectoryMemberUseCase::new(
            groups::RemoveDirectoryMemberPorts::fakes(),
        )),
    }
}

/// The person bind of the test tenant, where Ann's account and her
/// laptop's certificate are `directory`'s.
fn ann_binding(directory: &BoundDirectory) -> Arc<BindUseCase> {
    Arc::new(BindUseCase::new(BindPorts {
        organizations: org_store_with([test_org(test_ctx().organization_id(), "acme-corp")]),
        tenants: tenant_store_in_status(TenantStatus::Active),
        throttle: Arc::new(AllowingThrottle),
        certificates: directory.certificates.clone(),
        users: directory.users.clone(),
        credentials: directory.credentials.clone(),
        directory_authorities: Arc::new(DirectoryActing::new(directory.access.clone())),
        ..BindPorts::fakes()
    }))
}

/// Jira's account in the test tenant, in `status`, reading `ou=groups`
/// only.
fn jira(status: ServiceAccountStatus) -> DirectoryServiceAccount<ResolvedTenant> {
    let now = clock::now();
    DirectoryServiceAccount::reconstitute(DirectoryServiceAccountRow {
        id: DirectoryServiceAccountId::new(),
        name: ServiceAccountName::new("jira").unwrap(),
        secret_hash: service_secret_hash(JIRA_SECRET),
        scope: ServiceAccountScope::new(
            DirectoryAccess::ReadOnly,
            vec![BaseDn::new(GROUPS_DN).unwrap()],
        )
        .unwrap(),
        status,
        created_at: now,
        secret_changed_at: now,
    })
    .unwrap()
}

/// The ports of a test tenant holding Jira's account in `status`.
fn with_jira(status: ServiceAccountStatus) -> LdapPorts {
    let accounts = Arc::new(FakeServiceAccountStore::holding(
        &test_ctx().tenant(),
        [jira(status)],
    ));
    LdapPorts {
        service_bind: Arc::new(service_accounts::BindUseCase::new(service_bind_ports(
            accounts.clone(),
        ))),
        service_search: Arc::new(service_accounts::SearchAsUseCase::new(
            service_accounts::SearchAsPorts {
                accounts,
                entries: EntryPorts::fakes(),
            },
        )),
        ..ports()
    }
}

fn bind(dn: &str, password: &str) -> LdapMsg {
    LdapMsg {
        msgid: 1,
        op: LdapOp::BindRequest(LdapBindRequest {
            dn: dn.to_owned(),
            cred: LdapBindCred::Simple(password.to_owned()),
        }),
        ctrl: vec![],
    }
}

fn whoami() -> LdapMsg {
    LdapMsg {
        msgid: 2,
        op: LdapOp::ExtendedRequest(LdapExtendedRequest {
            name: OID_WHOAMI.to_owned(),
            value: None,
        }),
        ctrl: vec![],
    }
}

fn search(base: &str) -> LdapMsg {
    LdapMsg {
        msgid: 3,
        op: LdapOp::SearchRequest(LdapSearchRequest {
            base: base.to_owned(),
            scope: LdapSearchScope::Subtree,
            aliases: LdapDerefAliases::Never,
            sizelimit: 0,
            timelimit: 0,
            typesonly: false,
            filter: LdapFilter::Present("objectClass".to_owned()),
            attrs: vec![],
        }),
        ctrl: vec![],
    }
}

/// Sends `message` and reads the one answer it gets.
async fn ask(client: &mut Client, message: LdapMsg) -> LdapMsg {
    client.send(message).await.unwrap();
    client.next().await.unwrap().unwrap()
}

/// Sends a search and reads its entries' DNs and how it ended.
async fn searched(client: &mut Client, message: LdapMsg) -> (Vec<String>, LdapResultCode) {
    client.send(message).await.unwrap();
    let mut found = Vec::new();
    loop {
        let answer = client.next().await.unwrap().unwrap();
        match answer.op {
            LdapOp::SearchResultEntry(entry) => found.push(entry.dn),
            LdapOp::SearchResultDone(done) => return (found, done.code),
            other => panic!("expected a search answer, got {other:?}"),
        }
    }
}

/// The result code `answer` carries.
fn code(answer: &LdapMsg) -> LdapResultCode {
    match &answer.op {
        LdapOp::BindResponse(response) => response.res.code.clone(),
        LdapOp::ExtendedResponse(response) => response.res.code.clone(),
        LdapOp::SearchResultDone(done) => done.code.clone(),
        other => panic!("expected an answer with a result code, got {other:?}"),
    }
}

/// The DN a Who-am-I answer names, without its `dn:`.
async fn bound_as(client: &mut Client) -> String {
    let answer = ask(client, whoami()).await;
    let LdapOp::ExtendedResponse(response) = answer.op else {
        panic!("expected a Who-am-I answer, got {:?}", answer.op);
    };
    let authzid = String::from_utf8(response.value.unwrap_or_default()).unwrap();
    authzid.trim_start_matches("dn:").to_owned()
}

/// Ann binds from her laptop with her password, and the connection is
/// bound as her entry.
#[tokio::test]
async fn password_and_certificate_bind_the_person() {
    let directory = BoundDirectory::holding(&[]);
    let ports = LdapPorts {
        bind: ann_binding(&directory),
        ..ports()
    };
    let mut client = connect(ports, Some(laptop()));

    let answer = ask(&mut client, bind(ANN_DN, BOUND_PASSWORD)).await;

    assert_eq!(code(&answer), LdapResultCode::Success);
    assert_eq!(bound_as(&mut client).await, ANN_DN);
}

/// A wrong password from Ann's certified laptop is refused as invalid
/// credentials, leaving the connection unbound.
#[tokio::test]
async fn wrong_passwords_cannot_bind() {
    let directory = BoundDirectory::holding(&[]);
    let ports = LdapPorts {
        bind: ann_binding(&directory),
        ..ports()
    };
    let mut client = connect(ports, Some(laptop()));

    let answer = ask(&mut client, bind(ANN_DN, "guess")).await;

    assert_eq!(code(&answer), LdapResultCode::InvalidCredentials);
    assert_eq!(bound_as(&mut client).await, "");
}

/// Ann's correct password without her device certificate is refused as
/// invalid credentials.
#[tokio::test]
async fn passwords_without_certificates_are_refused() {
    let directory = BoundDirectory::holding(&[]);
    let ports = LdapPorts {
        bind: ann_binding(&directory),
        ..ports()
    };
    let mut client = connect(ports, None);

    let answer = ask(&mut client, bind(ANN_DN, BOUND_PASSWORD)).await;

    assert_eq!(code(&answer), LdapResultCode::InvalidCredentials);
}

/// Jira binds as its account with its secret, and the connection is bound
/// as the account.
#[tokio::test]
async fn service_accounts_bind_with_their_secret() {
    let mut client = connect(with_jira(ServiceAccountStatus::Active), None);

    let answer = ask(&mut client, bind(JIRA_DN, JIRA_SECRET)).await;

    assert_eq!(code(&answer), LdapResultCode::Success);
    assert_eq!(bound_as(&mut client).await, JIRA_DN);
}

/// A disabled Jira service account cannot bind with its correct secret,
/// and the connection remains unbound.
#[tokio::test]
async fn refuses_disabled_service_accounts() {
    let mut client = connect(with_jira(ServiceAccountStatus::Disabled), None);

    let answer = ask(&mut client, bind(JIRA_DN, JIRA_SECRET)).await;

    assert_eq!(code(&answer), LdapResultCode::InvalidCredentials);
    assert_eq!(bound_as(&mut client).await, "");
}

/// Jira reads the groups it was given.
#[tokio::test]
async fn searches_within_account_scope_are_answered() {
    let mut client = connect(with_jira(ServiceAccountStatus::Active), None);
    ask(&mut client, bind(JIRA_DN, JIRA_SECRET)).await;

    let (found, done) = searched(&mut client, search(GROUPS_DN)).await;

    assert_eq!(done, LdapResultCode::Success);
    assert_eq!(found, [GROUPS_DN]);
}

/// Jira's groups-only account cannot search users; the search reports
/// insufficient rights and returns no entries.
#[tokio::test]
async fn searches_outside_account_scope_are_refused() {
    let mut client = connect(with_jira(ServiceAccountStatus::Active), None);
    ask(&mut client, bind(JIRA_DN, JIRA_SECRET)).await;

    let (found, done) = searched(&mut client, search(USERS_DN)).await;

    assert_eq!(done, LdapResultCode::InsufficentAccessRights);
    assert!(found.is_empty());
}

/// An unbound client's user search reports insufficient rights and
/// returns no entries.
#[tokio::test]
async fn searches_before_binding_are_refused() {
    let mut client = connect(ports(), None);

    let (found, done) = searched(&mut client, search(USERS_DN)).await;

    assert_eq!(done, LdapResultCode::InsufficentAccessRights);
    assert!(found.is_empty());
}

/// A malformed LDAP message receives a protocol-error notice before the
/// server closes the connection.
#[tokio::test]
async fn closes_connections_after_malformed_messages() {
    let mut client = connect(ports(), None);

    client
        .get_mut()
        .write_all(&[0x30, 0x03, 0x02, 0x01, 0x01])
        .await
        .unwrap();

    let notice = client.next().await.unwrap().unwrap();
    assert_eq!(code(&notice), LdapResultCode::ProtocolError);
    assert!(client.next().await.is_none());
}
