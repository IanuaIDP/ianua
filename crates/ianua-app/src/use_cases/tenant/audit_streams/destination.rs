//! Where a stream sends records, as the caller typed it, and the same
//! destination with every credential sealed before the stream keeps it.
//!
//! A collector token or an API key lets whoever reads it write into the
//! tenant's SIEM. So it is sealed through the crypto port as soon as it
//! arrives, and only its sealed form reaches the domain and storage.

use ianua_domain::domains::audit::streaming::{
    DatadogSite, DatadogTarget, HttpAuthorization, HttpTarget, SplunkIndex, SplunkTarget,
    StreamDestination, StreamHeaderName, SyslogTarget,
};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{AuditStreamId, PublicHttpsUrl};

use crate::error::AppError;
use crate::ports::authentication::{SealOwner, SealedField, SealedFor, SecretEncryptor};
use crate::services::sealing::sealed_text;
use crate::tenancy::ScopedTenant;

/// Where a stream sends records, with its credentials as typed. Holds
/// credentials, so it has no `Debug`.
pub enum StreamTarget {
    /// A Splunk HTTP Event Collector.
    Splunk {
        /// Where the collector listens.
        endpoint: PublicHttpsUrl,
        /// The collector token.
        token: Secret,
        /// Which index records go to.
        index: SplunkIndex,
    },
    /// A Datadog account's log intake.
    Datadog {
        /// The site the account lives on.
        site: DatadogSite,
        /// The credential authorizing writes to Datadog's log intake.
        api_key: Secret,
    },
    /// A syslog collector over TLS. It takes no credential.
    Syslog(SyslogTarget),
    /// Any HTTPS endpoint.
    Http {
        /// Where records are sent.
        endpoint: PublicHttpsUrl,
        /// What each request carries to show where it came from.
        authorization: TypedAuthorization,
    },
}

/// How an HTTPS endpoint knows the records come from the platform, with
/// the header's value as typed.
pub enum TypedAuthorization {
    /// The endpoint asks for nothing.
    Unauthenticated,
    /// Each request carries this header.
    Header {
        /// The header, such as `authorization`.
        name: StreamHeaderName,
        /// The secret sent in this header on each delivery.
        value: Secret,
    },
}

/// Where `tenant`'s stream `stream` keeps the credentials of its
/// destination.
pub(crate) fn credentials_place(tenant: &ScopedTenant, stream: &AuditStreamId) -> SealedFor {
    SealedFor::new(
        SealOwner::from(tenant),
        SealedField::AuditStreamCredential,
        stream,
    )
}

/// `target`, with every credential sealed through `encryptor` for
/// `place`.
///
/// # Errors
///
/// `AppError::Internal` when a credential cannot be sealed.
pub(super) async fn sealed_destination(
    encryptor: &dyn SecretEncryptor,
    target: StreamTarget,
    place: &SealedFor,
) -> Result<StreamDestination, AppError> {
    let destination = match target {
        StreamTarget::Splunk {
            endpoint,
            token,
            index,
        } => StreamDestination::Splunk(SplunkTarget::new(
            endpoint,
            sealed_text(encryptor, token.expose(), place).await?,
            index,
        )),
        StreamTarget::Datadog { site, api_key } => StreamDestination::Datadog(DatadogTarget::new(
            site,
            sealed_text(encryptor, api_key.expose(), place).await?,
        )),
        StreamTarget::Syslog(target) => StreamDestination::Syslog(target),
        StreamTarget::Http {
            endpoint,
            authorization,
        } => StreamDestination::Http(HttpTarget::new(
            endpoint,
            sealed_authorization(encryptor, authorization, place).await?,
        )),
    };
    Ok(destination)
}

/// `authorization`, with the header's value sealed for `place`.
///
/// # Errors
///
/// `AppError::Internal` when the value cannot be sealed.
async fn sealed_authorization(
    encryptor: &dyn SecretEncryptor,
    authorization: TypedAuthorization,
    place: &SealedFor,
) -> Result<HttpAuthorization, AppError> {
    match authorization {
        TypedAuthorization::Unauthenticated => Ok(HttpAuthorization::Unauthenticated),
        TypedAuthorization::Header { name, value } => Ok(HttpAuthorization::Header {
            name,
            value: sealed_text(encryptor, value.expose(), place).await?,
        }),
    }
}
