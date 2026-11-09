//! Binding: a person by their password over the client certificate their
//! TLS handshake presented, or an application as its service account by
//! its secret. Both are simple binds; the bind DN says which.
//!
//! Every attempt with a credential is counted against its source address
//! before it reaches a use case, so guessing at organization and tenant
//! slugs is held back too: the use cases' own rate counts only once a
//! tenant is found. Every refusal waits the same and reads the same.

use ianua_app::error::AppError;
use ianua_app::use_case::Command as _;
use ianua_app::use_cases::directory::{BindRequest, service_accounts};
use ianua_domain::domains::authentication::directory_service::scope::ServiceAccountName;
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::Email;
use ldap3_proto::proto::{LdapMsg, LdapResultCode};
use ldap3_proto::simple::SimpleBindRequest;

use crate::dit::dn::{self, BindDn, TenantPath};
use crate::ip_throttle::IpBindThrottle;
use crate::ops::responses::sasl_bind_response;
use crate::ops::{connection_auditor, naming};
use crate::ports::LdapPorts;
use crate::server::FAILED_BIND_DELAY;
use crate::session::{Bound, PersonBind, ServiceBind, Session};

/// Answers a simple bind.
///
/// Any bind first drops the one before. An anonymous bind (no DN, no
/// password) succeeds and binds nobody. A DN with no password, LDAP's
/// unauthenticated bind, is refused.
pub(super) async fn handle(
    ports: &LdapPorts,
    throttle: &IpBindThrottle,
    session: &mut Session,
    mut req: SimpleBindRequest,
) -> LdapMsg {
    session.sign_out();
    if req.dn.is_empty() && req.pw.is_empty() {
        return req.gen_success();
    }
    if !throttle.check_and_record(session.peer) {
        return req.gen_error(
            LdapResultCode::Busy,
            "too many bind attempts from this address".to_owned(),
        );
    }
    let password = Secret::new(std::mem::take(&mut req.pw));
    match bound(ports, session, &req.dn, password).await {
        Ok(bound) => {
            session.bound = bound;
            req.gen_success()
        }
        Err(refused) => refusal(&req, refused).await,
    }
}

/// Answers a SASL bind: none is served. Binding takes a password over a
/// client certificate, or a service account's secret, both simple binds; a
/// certificate alone binds nothing.
pub(super) fn refuse_sasl(session: &mut Session, msgid: i32) -> LdapMsg {
    session.sign_out();
    sasl_bind_response(
        msgid,
        LdapResultCode::AuthMethodNotSupported,
        "SASL is not served; use a simple bind".to_owned(),
    )
}

/// Who `dn` binds as with `password`, as the bind use cases decide.
async fn bound(
    ports: &LdapPorts,
    session: &Session,
    dn: &str,
    password: Secret,
) -> Result<Bound, AppError> {
    if password.expose().is_empty() {
        return Err(invalid_credentials());
    }
    match dn::parse_bind_dn(dn).ok_or_else(invalid_credentials)? {
        BindDn::Person { tenant, email } => {
            let claim = Claim {
                tenant: &tenant,
                named: &email,
                secret: password,
            };
            person(ports, session, claim).await
        }
        BindDn::Service { tenant, name } => {
            let claim = Claim {
                tenant: &tenant,
                named: &name,
                secret: password,
            };
            service(ports, session, claim).await
        }
    }
}

/// Who a bind names and what it proves them with. It holds the password,
/// so it has no `Debug`.
struct Claim<'a> {
    /// The tenant the bind DN lies in.
    tenant: &'a TenantPath,
    /// The address or account name the bind DN names.
    named: &'a str,
    /// The password or secret presented.
    secret: Secret,
}

/// A person binding as the address `claim` names, over the certificate the
/// connection presented.
async fn person(ports: &LdapPorts, session: &Session, claim: Claim<'_>) -> Result<Bound, AppError> {
    let base = naming::base_of(claim.tenant).ok_or_else(invalid_credentials)?;
    let email = Email::new(claim.named).map_err(|_| invalid_credentials())?;
    let request = BindRequest {
        base,
        email,
        password: claim.secret,
        presented: session.presented,
        ip_address: session.ip.clone(),
    };
    let principal = ports
        .bind
        .execute(&(), &connection_auditor(ports, session), request)
        .await?;
    Ok(Bound::Person(Box::new(PersonBind {
        principal,
        dn: claim.tenant.user_dn(claim.named),
    })))
}

/// An application binding as the service account `claim` names.
async fn service(
    ports: &LdapPorts,
    session: &Session,
    claim: Claim<'_>,
) -> Result<Bound, AppError> {
    let base = naming::base_of(claim.tenant).ok_or_else(invalid_credentials)?;
    let name = ServiceAccountName::new(claim.named).map_err(|_| invalid_credentials())?;
    let request = service_accounts::BindRequest {
        base,
        name,
        secret: claim.secret,
        ip_address: session.ip.clone(),
    };
    let principal = ports
        .service_bind
        .execute(&(), &connection_auditor(ports, session), request)
        .await?;
    Ok(Bound::Service(Box::new(ServiceBind {
        principal,
        dn: claim.tenant.service_dn(claim.named),
    })))
}

/// The answer to a refused bind. A refusal of the credential, or of
/// anything about the bind other than its rate, reads as bad credentials,
/// after the same wait.
async fn refusal(req: &SimpleBindRequest, refused: AppError) -> LdapMsg {
    match refused {
        AppError::TooManyRequests(_) | AppError::Busy => req.gen_error(
            LdapResultCode::Busy,
            "too many binds, try again shortly".to_owned(),
        ),
        AppError::TenantUnavailable(_) => {
            tokio::time::sleep(FAILED_BIND_DELAY).await;
            req.gen_error(
                LdapResultCode::Unavailable,
                "this directory is unavailable".to_owned(),
            )
        }
        error @ (AppError::Internal(_) | AppError::Upstream(_)) => {
            tracing::warn!(%error, "ldap: a bind could not be checked");
            tokio::time::sleep(FAILED_BIND_DELAY).await;
            req.gen_error(
                LdapResultCode::OperationsError,
                "the bind could not be checked".to_owned(),
            )
        }
        _ => {
            tokio::time::sleep(FAILED_BIND_DELAY).await;
            req.gen_invalid_cred()
        }
    }
}

/// The one refusal every bad bind gets, whichever part was wrong.
fn invalid_credentials() -> AppError {
    AppError::NotFound(message!(
        "authentication-invalid-credentials",
        "invalid credentials"
    ))
}
