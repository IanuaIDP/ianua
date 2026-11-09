//! A company's own cloud accounts: beginning a connection, handing over
//! the credential, proving it, reading the networks it reaches, and
//! disconnecting; and the role template its AWS customers read.

use super::{OrgPath, Request, Text};
use crate::net::Call;
use crate::wire::cloud::{CloudAccount, CloudGrant, CloudNetwork, ConnectionInstructions};

/// `GET …/cloud-accounts`.
#[must_use]
pub fn list(org: &OrgPath) -> Request<Vec<CloudAccount>> {
    Request::of(Call::get(org.at("/cloud-accounts")))
}

/// `POST …/cloud-accounts/{provider}`: begins connecting `provider`.
#[must_use]
pub fn begin(org: &OrgPath, provider: &str) -> Request<ConnectionInstructions> {
    Request::of(Call::post(org.at(&format!("/cloud-accounts/{provider}"))))
}

/// `PUT …/cloud-accounts/{provider}/credential`: hands over `grant`, then
/// proves it once.
#[must_use]
pub fn submit(org: &OrgPath, provider: &str, grant: &CloudGrant) -> Request<CloudAccount> {
    Request::of(Call::put(org.at(&format!("/cloud-accounts/{provider}/credential"))).json(grant))
}

/// `POST …/cloud-accounts/{provider}/verify`: proves the stored credential
/// again.
#[must_use]
pub fn verify(org: &OrgPath, provider: &str) -> Request<CloudAccount> {
    Request::of(Call::post(
        org.at(&format!("/cloud-accounts/{provider}/verify")),
    ))
}

/// `GET …/cloud-accounts/{provider}/networks`, in `region` when one is
/// named.
#[must_use]
pub fn networks(org: &OrgPath, provider: &str, region: Option<&str>) -> Request<Vec<CloudNetwork>> {
    let mut path = org.at(&format!("/cloud-accounts/{provider}/networks"));
    if let Some(region) = region {
        path = format!("{path}?region={region}");
    }
    Request::of(Call::get(path))
}

/// `DELETE …/cloud-accounts/{provider}`: forgets the credential.
#[must_use]
pub fn disconnect(org: &OrgPath, provider: &str) -> Request<()> {
    Request::of(Call::delete(org.at(&format!("/cloud-accounts/{provider}"))))
}

/// `GET /.well-known/ianua/aws-connect.yaml`: the role template, as text.
#[must_use]
pub fn aws_template() -> Request<Text> {
    Request::text(Call::get("/.well-known/ianua/aws-connect.yaml"))
}
