//! The object store the object file store's tests run against, started
//! once for the run by the `objects` setup script: a VersityGW container
//! reached on loopback, with a fresh bucket for each test.

use std::time::Duration;

use ianua_domain::shared::security::secret::Secret;
use reqwest::Method;

use crate::crypto::sigv4::{AccessKey, Payload, Request, Scope, Signing};
use crate::files::{BucketAddressing, ObjectStoreSettings};
use crate::http::client::fixed;

/// The test store's access key id, which the setup script starts it with.
pub const ACCESS_KEY_ID: &str = "ianua-test";

/// The test store's secret, which the setup script starts it with.
pub const SECRET: &str = "ianua-test-secret";

/// The region the test store signs for.
const REGION: &str = "us-east-1";

/// Settings for a bucket of its own on the test store, made empty for
/// this test.
///
/// # Panics
///
/// When the setup script did not run or the store does not make the
/// bucket: no object store test can go on without it.
pub async fn fresh_settings() -> ObjectStoreSettings {
    let port = std::env::var("IANUA_TEST_OBJECTS_PORT")
        .expect("the objects setup script names the test object store's port");
    let settings = ObjectStoreSettings {
        endpoint: url::Url::parse(&format!("http://127.0.0.1:{port}"))
            .expect("the test store's address reads"),
        region: REGION.to_owned(),
        bucket: format!("ianua-test-{}", uuid::Uuid::now_v7().simple()),
        access_key_id: ACCESS_KEY_ID.to_owned(),
        secret_access_key: Secret::new(SECRET),
        addressing: BucketAddressing::Path,
    };
    let made = signed(&settings, Method::PUT, bucket_url(&settings, "")).await;
    assert!(
        made.status().is_success(),
        "the test bucket is made: {}",
        made.status()
    );
    settings
}

/// How many multipart uploads of the object `key` are unfinished in the
/// bucket `settings` names, listed by the object's own key, the one
/// listing every S3-compatible store answers as AWS does.
///
/// # Panics
///
/// When the store does not list them.
pub async fn pending_uploads(settings: &ObjectStoreSettings, key: &str) -> usize {
    let mut url = bucket_url(settings, "uploads");
    url.query_pairs_mut().append_pair("prefix", key);
    let listed = signed(settings, Method::GET, url).await;
    assert!(listed.status().is_success(), "{}", listed.status());
    let text = listed.text().await.expect("the listing is read");
    let document = roxmltree::Document::parse(&text).expect("the listing is XML");
    document
        .root_element()
        .children()
        .filter(|node| node.has_tag_name("Upload"))
        .count()
}

/// The address of the bucket `settings` names, with `query`.
fn bucket_url(settings: &ObjectStoreSettings, query: &str) -> url::Url {
    let mut url = settings.endpoint.clone();
    url.set_path(&format!("/{}/", settings.bucket));
    url.set_query(Some(query).filter(|query| !query.is_empty()));
    url
}

/// The test store's answer to `method` on `url`, signed with the test
/// key.
async fn signed(
    settings: &ObjectStoreSettings,
    method: Method,
    url: url::Url,
) -> reqwest::Response {
    let key = AccessKey {
        id: &settings.access_key_id,
        secret: settings.secret_access_key.expose(),
        token: None,
    };
    let signing = Signing {
        key: &key,
        scope: Scope {
            region: &settings.region,
            service: "s3",
        },
        at: time::OffsetDateTime::now_utc(),
    };
    let headers = signing
        .headers(&Request {
            method: method.as_str(),
            url: &url,
            headers: &[],
            payload: Payload::Bytes(b""),
        })
        .expect("the request is signed");
    fixed(Duration::from_secs(10))
        .expect("a client is built")
        .request(method, url)
        .headers(headers)
        .send()
        .await
        .expect("the test object store answers")
}
