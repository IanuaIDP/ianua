//! A domain a tenant brings, as a customer brings one: registered through
//! the API, proved by the `TXT` record written at their DNS provider (the
//! stack's name server), and served with the certificate their authority
//! issued (the stack's), uploaded through the API.

use std::time::Duration;

use crate::api::{TenantPath, domains};
use crate::expect::{Waiting, eventually_paced};
use crate::net::Client;
use crate::stack::Stack;
use crate::wire::domains::{NewDomain, UploadCertificate};

/// The status of a domain whose proof was found.
const VERIFIED: &str = "Verified";

/// Brings `name`, a name under the stack's customer domain, into `tenant`
/// as `admin`: registers it, writes its proof, verifies it, and uploads a
/// certificate for it. Answers the name.
///
/// # Panics
///
/// When any step is refused, or the proof is not found within
/// twenty seconds.
pub async fn brought(stack: &Stack, admin: &Client, tenant: &TenantPath, name: &str) -> String {
    let added = domains::add(
        tenant,
        &NewDomain {
            domain: name.to_owned(),
        },
    )
    .send(admin)
    .await
    .ok();
    let (Some(record), Some(value)) = (added.dns_record_name, added.dns_record_value) else {
        panic!("{name} was registered without a record to prove it with");
    };
    stack.name_server().write_txt(&record, &value);
    verify(admin, tenant, &added.id, name).await;
    let issued = stack.certificate_for(&[name.to_owned()]);
    let certificate = UploadCertificate {
        certificate_pem: issued.chain_pem().to_owned(),
        private_key_pem: issued.key_pem().to_owned(),
    };
    domains::upload_certificate(tenant, &added.id, &certificate)
        .send(admin)
        .await
        .ok();
    name.to_owned()
}

/// Waits until the tenant's domain proof is visible through its normal verification API.
async fn verify(admin: &Client, tenant: &TenantPath, domain_id: &str, name: &str) {
    let waiting = Waiting {
        patience: Duration::from_secs(20),
        every: Duration::from_secs(1),
    };
    eventually_paced(&format!("{name} to be verified"), waiting, || async {
        let found = domains::verify(tenant, domain_id).send(admin).await.ok();
        (found.status == VERIFIED).then_some(())
    })
    .await;
}
