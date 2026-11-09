//! Handing a message to an SMTP server, over TLS, within a time limit.
//!
//! A tenant's server is a name the tenant chose. It is resolved again on
//! every delivery and only an address the deployment may reach is dialled,
//! so a name that pointed outside when it was saved cannot be turned
//! inward later. The certificate is still checked against the name.

use std::net::SocketAddr;
use std::time::Duration;

use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::transport::smtp::extension::ClientId;
use lettre::{AsyncSmtpTransport, AsyncTransport as _, Message, Tokio1Executor};

use crate::mail::sending::accounts::{SmtpAccount, SmtpTls};
use crate::mail::sending::delivery::MailFailure;

/// Which addresses a server may be dialled at.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Reach<'a> {
    /// As configured: the platform chose the server.
    AsConfigured,
    /// Only an address `networks` permits: a tenant chose the server.
    Screened(&'a UpstreamNetworks),
}

/// One message on its way to an SMTP server.
pub(crate) struct SmtpSend<'a> {
    /// The server and how to sign in.
    pub(crate) account: &'a SmtpAccount,
    /// Which addresses it may be dialled at.
    pub(crate) reach: Reach<'a>,
    /// The name the platform greets the server with.
    pub(crate) hello: &'a str,
    /// How long the whole exchange may take.
    pub(crate) timeout: Duration,
}

/// Hands `message` to the server `send` names, the whole exchange held to
/// the send's timeout: resolving the server's name as much as talking to
/// it, since a tenant's name may be served by a resolver that never
/// answers.
///
/// # Errors
///
/// - `DomainError::Validation` when a tenant's server resolves to no
///   address the deployment may reach.
/// - `DomainError::Infrastructure` when the server cannot be reached in
///   time, will not secure the connection, or refuses the mail.
pub(crate) async fn deliver(send: &SmtpSend<'_>, message: Message) -> Result<(), DomainError> {
    let Ok(delivered) = tokio::time::timeout(send.timeout, exchange(send, message)).await else {
        return Err(DomainError::infra(MailFailure::TimedOut {
            provider: "smtp",
        }));
    };
    delivered
}

/// Resolves the server `send` names and hands it `message`.
async fn exchange(send: &SmtpSend<'_>, message: Message) -> Result<(), DomainError> {
    let server = dialled(send.account, send.reach).await?;
    let transport = transport_for(send, server)?;
    transport
        .send(message)
        .await
        .map(|_| ())
        .map_err(|error| DomainError::infra(refusal(&error)))
}

/// The address to dial: the configured host, or the first address the
/// tenant's host resolves to that `reach` permits.
async fn dialled(account: &SmtpAccount, reach: Reach<'_>) -> Result<String, DomainError> {
    let Reach::Screened(networks) = reach else {
        return Ok(account.host.clone());
    };
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host((account.host.as_str(), account.port))
        .await
        .map_err(|cause| DomainError::infra(MailFailure::Unresolved { cause }))?
        .collect();
    permitted(&resolved, networks)
        .map(|address| address.ip().to_string())
        .ok_or_else(|| {
            DomainError::invalid(message!(
                "mail-the-mail-server-no-longer-resolves",
                "the mail server no longer resolves to an address this deployment may reach"
            ))
        })
}

/// The first of `resolved` that `networks` permits.
fn permitted(resolved: &[SocketAddr], networks: &UpstreamNetworks) -> Option<SocketAddr> {
    resolved
        .iter()
        .find(|address| networks.permits(address.ip()))
        .copied()
}

/// A transport to `server`, checking the certificate against the
/// account's host, signing in as it says, each command and the whole
/// exchange held to the send's timeout.
fn transport_for(
    send: &SmtpSend<'_>,
    server: String,
) -> Result<AsyncSmtpTransport<Tokio1Executor>, DomainError> {
    let account = send.account;
    let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(server)
        .port(account.port)
        .tls(tls_of(account)?)
        .hello_name(ClientId::Domain(send.hello.to_owned()))
        .timeout(Some(send.timeout));
    if let Some(login) = &account.login {
        builder = builder.credentials(Credentials::new(
            login.username.clone(),
            login.password.expose().to_owned(),
        ));
    }
    Ok(builder.build())
}

/// The TLS the account asks for, checked against its host.
fn tls_of(account: &SmtpAccount) -> Result<Tls, DomainError> {
    let parameters = || {
        TlsParameters::new(account.host.clone())
            .map_err(|cause| DomainError::infra(MailFailure::SmtpTls { cause }))
    };
    match account.tls {
        SmtpTls::StartTls => Ok(Tls::Required(parameters()?)),
        SmtpTls::Implicit => Ok(Tls::Wrapper(parameters()?)),
        SmtpTls::Unencrypted => Ok(Tls::None),
    }
}

/// What a failed exchange says, by kind and reply code only: the server's
/// own words are never kept, as they may repeat the mail or the login.
fn refusal(error: &lettre::transport::smtp::Error) -> MailFailure {
    if error.is_timeout() {
        return MailFailure::TimedOut { provider: "smtp" };
    }
    let Some(code) = error.status() else {
        return MailFailure::SmtpUnreachable;
    };
    MailFailure::SmtpRefused {
        code: code.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use ianua_domain::types::CidrRange;

    use super::*;

    fn at(ip: [u8; 4]) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), 587)
    }

    /// With public-only networks, address selection skips a private result and
    /// chooses the permitted address that follows it.
    #[test]
    fn only_an_address_the_deployment_may_reach_is_dialled() {
        let resolved = [at([10, 0, 0, 5]), at([203, 0, 113, 7])];

        let chosen = permitted(&resolved, &UpstreamNetworks::public_only());

        assert_eq!(chosen, Some(at([203, 0, 113, 7])));
    }

    /// A list containing only loopback and link-local addresses yields no
    /// permitted SMTP destination under public-only networks.
    #[test]
    fn a_name_resolving_only_inside_is_not_dialled() {
        let resolved = [at([127, 0, 0, 1]), at([169, 254, 169, 254])];

        assert_eq!(permitted(&resolved, &UpstreamNetworks::public_only()), None);
    }

    /// A self-hosted deployment lists its own network, and a mail server
    /// there is dialled.
    #[test]
    fn a_listed_network_is_dialled() {
        let networks = UpstreamNetworks::new(vec![CidrRange::new("10.0.0.0/8").unwrap()]);

        assert_eq!(
            permitted(&[at([10, 0, 0, 5])], &networks),
            Some(at([10, 0, 0, 5]))
        );
    }

    /// A server that accepts the connection but sends no greeting causes
    /// delivery to fail before the five-second test bound.
    #[tokio::test]
    async fn a_server_that_never_answers_is_given_up_on() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let networks = UpstreamNetworks::new(vec![CidrRange::new("127.0.0.0/8").unwrap()]);
        let account = SmtpAccount {
            host: "127.0.0.1".to_owned(),
            port,
            tls: SmtpTls::Unencrypted,
            login: None,
        };
        let send = SmtpSend {
            account: &account,
            reach: Reach::Screened(&networks),
            hello: "acme.test",
            timeout: Duration::from_millis(300),
        };
        let message = Message::builder()
            .from("hello@acme.test".parse().unwrap())
            .to("ann@acme.test".parse().unwrap())
            .subject("Hi")
            .body("Hello".to_owned())
            .unwrap();

        let sent = tokio::time::timeout(Duration::from_secs(5), deliver(&send, message)).await;

        assert!(matches!(sent, Ok(Err(DomainError::Infrastructure(_)))));
    }

    /// STARTTLS configuration requires a TLS upgrade, while implicit TLS wraps
    /// the connection from its start.
    #[test]
    fn a_tenant_server_is_never_reached_in_the_clear() {
        let account = |tls| SmtpAccount {
            host: "smtp.acme.com".to_owned(),
            port: 587,
            tls,
            login: None,
        };

        assert!(matches!(
            tls_of(&account(SmtpTls::StartTls)),
            Ok(Tls::Required(_))
        ));
        assert!(matches!(
            tls_of(&account(SmtpTls::Implicit)),
            Ok(Tls::Wrapper(_))
        ));
    }
}
