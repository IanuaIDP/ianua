//! What an object store is reached with, checked once when the store is
//! made, and the address of each object in it.
//!
//! Every value here is the platform's own configuration, never a tenant's,
//! so the store is called through the fixed client. The endpoint is HTTPS;
//! plain HTTP is taken only for a store on this machine's own loopback,
//! such as a local MinIO in development.

use std::fmt;
use std::net::IpAddr;

use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;

use crate::crypto::sigv4::escaped;

/// The longest region name any store uses.
const LONGEST_REGION: usize = 32;

/// The longest access key id any store hands out.
const LONGEST_KEY_ID: usize = 128;

/// How the bucket is named in a request's address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BucketAddressing {
    /// In the path, `https://<endpoint>/<bucket>/<key>`: what MinIO and a
    /// store on a single host take.
    Path,
    /// In the host, `https://<bucket>.<endpoint>/<key>`: what AWS asks for
    /// and DigitalOcean Spaces, Wasabi, Backblaze B2, Cloudflare R2 and
    /// Google Cloud Storage take.
    VirtualHost,
}

/// Where the platform's object store is and the key it is reached with.
#[derive(Clone)]
pub struct ObjectStoreSettings {
    /// The store's endpoint, such as `https://s3.eu-central-1.amazonaws.com`,
    /// `https://<account>.r2.cloudflarestorage.com` or
    /// `https://storage.googleapis.com`, with no path.
    pub endpoint: url::Url,
    /// The region requests are signed for, such as `eu-central-1`, or
    /// `auto` for Cloudflare R2 and Google Cloud Storage.
    pub region: String,
    /// The bucket every file is kept in.
    pub bucket: String,
    /// The access key's id, or an HMAC key's id for Google Cloud Storage.
    pub access_key_id: String,
    /// The access key's secret.
    pub secret_access_key: Secret,
    /// How the bucket is named in each address.
    pub addressing: BucketAddressing,
}

/// Shows where the store is, never the secret.
impl fmt::Debug for ObjectStoreSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectStoreSettings")
            .field("endpoint", &self.endpoint.as_str())
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field("addressing", &self.addressing)
            .finish()
    }
}

impl ObjectStoreSettings {
    /// The settings, once each value is one a store takes.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` naming the value that is wrong,
    /// never the secret.
    pub(super) fn checked(self) -> Result<Self, DomainError> {
        ensure_endpoint(&self.endpoint)?;
        ensure_region(&self.region)?;
        ensure_bucket(&self.bucket, self.addressing)?;
        ensure_named_host(&self.endpoint, self.addressing)?;
        ensure_key(&self.access_key_id, &self.secret_access_key)?;
        Ok(self)
    }

    /// The address of the object `key`, or of the bucket itself when `key`
    /// is empty, with `query` in it: each name and value escaped as the
    /// signature escapes them, a name with no value written alone.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the address cannot be
    /// made, which checked settings never cause.
    pub(super) fn url_of(
        &self,
        key: &str,
        query: &[(&str, &str)],
    ) -> Result<url::Url, DomainError> {
        let mut url = self.bucket_root()?;
        url.set_path(&self.path_of(key));
        url.set_query(written_query(query).as_deref());
        Ok(url)
    }

    /// The path of the object `key`, each of its segments escaped, under
    /// the bucket when the bucket is named in the path.
    fn path_of(&self, key: &str) -> String {
        let bucket = match self.addressing {
            BucketAddressing::Path => Some(self.bucket.as_str()),
            BucketAddressing::VirtualHost => None,
        };
        let segments: Vec<String> = bucket
            .into_iter()
            .chain(key.split('/').filter(|part| !part.is_empty()))
            .map(escaped)
            .collect();
        let closing = match (key.is_empty(), bucket) {
            (true, Some(_)) => "/",
            (true, None) | (false, _) => "",
        };
        format!("/{}{closing}", segments.join("/"))
    }

    /// The endpoint with the bucket in its host when it is named there.
    fn bucket_root(&self) -> Result<url::Url, DomainError> {
        let mut url = self.endpoint.clone();
        if self.addressing == BucketAddressing::Path {
            return Ok(url);
        }
        let host = self.endpoint.host_str().unwrap_or_default();
        url.set_host(Some(&format!("{}.{host}", self.bucket)))
            .map_err(DomainError::infra)?;
        Ok(url)
    }
}

/// `query` as a URL writes it, or `None` when it is empty.
fn written_query(query: &[(&str, &str)]) -> Option<String> {
    if query.is_empty() {
        return None;
    }
    let written = query
        .iter()
        .map(|(name, value)| written_pair(name, value))
        .collect::<Vec<_>>()
        .join("&");
    Some(written)
}

/// One name and value of a query, the name alone when the value is empty.
fn written_pair(name: &str, value: &str) -> String {
    if value.is_empty() {
        return escaped(name);
    }
    format!("{}={}", escaped(name), escaped(value))
}

/// Refuses an endpoint that is not HTTPS, outside loopback, or that holds
/// anything but a scheme, a host and a port.
fn ensure_endpoint(endpoint: &url::Url) -> Result<(), DomainError> {
    let secure = endpoint.scheme() == "https";
    let local = endpoint.scheme() == "http" && on_loopback(endpoint);
    if !(secure || local) {
        return Err(DomainError::invalid(message!(
            "infra-the-object-store-s-endpoint-must",
            "the object store's endpoint must be https, or http on this machine's loopback"
        )));
    }
    let bare = endpoint.host_str().is_some_and(|host| !host.is_empty())
        && endpoint.username().is_empty()
        && endpoint.password().is_none()
        && endpoint.path() == "/"
        && endpoint.query().is_none()
        && endpoint.fragment().is_none();
    if !bare {
        return Err(DomainError::invalid(message!(
            "infra-the-object-store-s-endpoint-is",
            "the object store's endpoint is a scheme, a host and a port, with no path"
        )));
    }
    Ok(())
}

/// Whether `endpoint` names this machine's loopback.
fn on_loopback(endpoint: &url::Url) -> bool {
    match endpoint.host() {
        Some(url::Host::Domain(name)) => name == "localhost",
        Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
        Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
        None => false,
    }
}

/// Refuses a region no store names: empty, too long, or with anything but
/// lowercase letters, digits and hyphens.
fn ensure_region(region: &str) -> Result<(), DomainError> {
    let plain = !region.is_empty()
        && region.len() <= LONGEST_REGION
        && region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !plain {
        return Err(DomainError::invalid(message!(
            "infra-the-object-store-s-region-is",
            "the object store's region is lowercase letters, digits and hyphens, such as \
             eu-central-1 or auto"
        )));
    }
    Ok(())
}

/// Refuses a bucket name the stores refuse, and a dotted one named in the
/// host, whose name no store's certificate covers.
fn ensure_bucket(bucket: &str, addressing: BucketAddressing) -> Result<(), DomainError> {
    let bytes = bucket.as_bytes();
    let edges = |byte: Option<&u8>| byte.is_some_and(u8::is_ascii_alphanumeric);
    let named = (3..=63).contains(&bytes.len())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-' || *byte == b'.'
        })
        && edges(bytes.first())
        && edges(bytes.last());
    if !named {
        return Err(DomainError::invalid(message!(
            "infra-the-object-store-s-bucket-is",
            "the object store's bucket is 3 to 63 lowercase letters, digits, dots and hyphens"
        )));
    }
    if addressing == BucketAddressing::VirtualHost && bucket.contains('.') {
        return Err(DomainError::invalid(message!(
            "infra-a-bucket-with-a-dot-in",
            "a bucket with a dot in its name is named in the path, not the host"
        )));
    }
    Ok(())
}

/// Refuses a bucket named in the host of an endpoint that is an address,
/// which has no names beneath it.
fn ensure_named_host(endpoint: &url::Url, addressing: BucketAddressing) -> Result<(), DomainError> {
    let named = matches!(endpoint.host(), Some(url::Host::Domain(_)));
    if addressing == BucketAddressing::VirtualHost && !named {
        return Err(DomainError::invalid(message!(
            "infra-a-bucket-named-in-the-host",
            "a bucket named in the host needs an endpoint named by a domain, not an address"
        )));
    }
    Ok(())
}

/// Refuses a key with no id or no secret, or an id no store hands out.
fn ensure_key(id: &str, secret: &Secret) -> Result<(), DomainError> {
    let plain_id = !id.is_empty()
        && id.len() <= LONGEST_KEY_ID
        && id.bytes().all(|byte| byte.is_ascii_graphic());
    if !plain_id || secret.expose().is_empty() {
        return Err(DomainError::invalid(message!(
            "infra-the-object-store-s-key-is",
            "the object store's key is an id of visible characters and a secret"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(endpoint: &str, addressing: BucketAddressing) -> ObjectStoreSettings {
        ObjectStoreSettings {
            endpoint: url::Url::parse(endpoint).unwrap(),
            region: "eu-central-1".to_owned(),
            bucket: "acme-files".to_owned(),
            access_key_id: "AKIDEXAMPLE".to_owned(),
            secret_access_key: Secret::new("top-secret"),
            addressing,
        }
    }

    /// An object is addressed under the bucket in the path, its key's
    /// slashes kept, and a query name with no value written alone.
    #[test]
    fn a_path_style_address_names_the_bucket_in_the_path() {
        let store = settings("https://s3.example.com", BucketAddressing::Path);

        let url = store
            .url_of("logos/abc/logo", &[("uploads", ""), ("prefix", "a/b")])
            .unwrap();

        assert_eq!(
            url.as_str(),
            "https://s3.example.com/acme-files/logos/abc/logo?uploads&prefix=a%2Fb"
        );
    }

    /// An object is addressed under the bucket in the host, and the bucket
    /// itself at the root.
    #[test]
    fn a_virtual_host_address_names_the_bucket_in_the_host() {
        let store = settings(
            "https://s3.eu-central-1.amazonaws.com",
            BucketAddressing::VirtualHost,
        );

        let object = store.url_of("logos/abc/logo", &[]).unwrap();
        let bucket = store.url_of("", &[("list-type", "2")]).unwrap();

        assert_eq!(
            object.as_str(),
            "https://acme-files.s3.eu-central-1.amazonaws.com/logos/abc/logo"
        );
        assert_eq!(
            bucket.as_str(),
            "https://acme-files.s3.eu-central-1.amazonaws.com/?list-type=2"
        );
    }

    /// The bucket itself, named in the path, is addressed with a closing
    /// slash, as the stores expect.
    #[test]
    fn the_bucket_in_the_path_is_addressed_with_a_closing_slash() {
        let store = settings("http://127.0.0.1:9000", BucketAddressing::Path);

        let bucket = store.url_of("", &[("delete", "")]).unwrap();

        assert_eq!(bucket.as_str(), "http://127.0.0.1:9000/acme-files/?delete");
    }

    /// A remote object store cannot use plain HTTP; a loopback store can.
    #[test]
    fn plain_http_is_taken_only_on_loopback() {
        let remote = settings("http://minio.internal:9000", BucketAddressing::Path);
        let local = settings("http://127.0.0.1:9000", BucketAddressing::Path);

        assert!(matches!(remote.checked(), Err(DomainError::Validation(_))));
        assert!(local.checked().is_ok());
    }

    /// Object-store endpoints containing a path, query or user credentials are
    /// rejected during configuration.
    #[test]
    fn an_endpoint_with_more_than_a_host_is_refused() {
        for endpoint in [
            "https://s3.example.com/base",
            "https://s3.example.com/?x=1",
            "https://user:pass@s3.example.com",
        ] {
            assert!(
                settings(endpoint, BucketAddressing::Path)
                    .checked()
                    .is_err(),
                "{endpoint}"
            );
        }
    }

    /// A bucket the stores refuse is refused here, and a dotted one is
    /// refused in the host, whose certificate would not cover it.
    #[test]
    fn a_bucket_is_named_as_the_stores_take_it() {
        let mut dotted = settings("https://s3.example.com", BucketAddressing::VirtualHost);
        dotted.bucket = "acme.files".to_owned();
        let mut upper = settings("https://s3.example.com", BucketAddressing::Path);
        upper.bucket = "Acme".to_owned();
        let mut edged = settings("https://s3.example.com", BucketAddressing::Path);
        edged.bucket = "-acme".to_owned();

        assert!(dotted.checked().is_err());
        assert!(upper.checked().is_err());
        assert!(edged.checked().is_err());
    }

    /// A region such as `auto` or `us-west-004` is taken; a blank one or
    /// one with a slash, which would change the signature's scope, is
    /// refused.
    #[test]
    fn a_region_is_a_plain_name() {
        let mut store = settings("https://s3.example.com", BucketAddressing::Path);
        for (region, taken) in [
            ("auto", true),
            ("us-west-004", true),
            ("", false),
            ("eu/central", false),
        ] {
            store.region = region.to_owned();
            assert_eq!(store.clone().checked().is_ok(), taken, "{region}");
        }
    }

    /// Debug output retains the access key's ID while omitting its secret.
    #[test]
    fn the_settings_never_show_the_secret() {
        let store = settings("https://s3.example.com", BucketAddressing::Path);

        let shown = format!("{store:?}");

        assert!(shown.contains("AKIDEXAMPLE"));
        assert!(!shown.contains("top-secret"));
    }
}
