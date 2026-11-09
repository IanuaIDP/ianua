//! What a company's named image points to now, asked of its registry over
//! the registry's HTTP API: the digest of its manifest, and how large its
//! layers are.
//!
//! Only manifests are read, each bounded in size and time, through a client
//! that screens every address the registry's name resolves to, so a tenant
//! cannot point the platform at its own network. A registry that asks for a
//! token is answered as the registry's token service says, with the login
//! the tenant keeps sealed, when that service is an address the deployment
//! may reach; nothing else is sent anywhere. For an image
//! built for several platforms, its size is that of its largest Linux
//! build, so a pull of any of them stays within the bound checked.

use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use ianua_app::ports::workflows::{ImageResolver, PullLogin, Resolving};
use ianua_domain::domains::workflows::sandbox::image::{ImageDigest, ImageName, ImageReference};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::types::UntrustedText;
use reqwest::header::{ACCEPT, AUTHORIZATION, WWW_AUTHENTICATE};
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::http::client::{ensure_reachable, screened};

/// How long one call to a registry may take.
const CALL_WITHIN: Duration = Duration::from_secs(20);

/// The most bytes of a manifest or a token answer that are read.
const MOST_READ: usize = 4 * 1024 * 1024;

/// The most platform builds of one image whose manifests are read.
const MOST_PLATFORMS: usize = 8;

/// The manifest kinds asked for: an image's, or its list of platform
/// builds, in OCI's and Docker's words.
const MANIFESTS: &str = "application/vnd.oci.image.index.v1+json, \
    application/vnd.docker.distribution.manifest.list.v2+json, \
    application/vnd.oci.image.manifest.v1+json, \
    application/vnd.docker.distribution.manifest.v2+json";

/// Whether registries are reached over TLS, which they always are but in
/// this module's tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Https,
    #[cfg(test)]
    Http,
}

impl Scheme {
    fn as_str(self) -> &'static str {
        match self {
            Self::Https => "https",
            #[cfg(test)]
            Self::Http => "http",
        }
    }
}

/// Asks registries over their HTTP API.
pub struct RegistryImageResolver {
    client: Client,
    scheme: Scheme,
    networks: UpstreamNetworks,
}

/// A manifest as a registry served it: its digest and its body.
struct Manifest {
    digest: ImageDigest,
    body: Value,
}

/// Why a registry gave no manifest.
enum Unread {
    /// It refused: no such image, or the login does not open it.
    Refused(String),
    /// It could not be reached or failed.
    Unavailable(String),
}

impl RegistryImageResolver {
    /// A resolver reaching registries over TLS through a client that
    /// screens their addresses against `networks`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be
    /// built.
    pub fn new(networks: UpstreamNetworks) -> Result<Self, DomainError> {
        Ok(Self {
            client: screened(CALL_WITHIN, networks.clone())?,
            scheme: Scheme::Https,
            networks,
        })
    }

    /// The manifest `reference` names in `name`'s repository.
    async fn manifest(
        &self,
        name: &ImageName,
        reference: &str,
        login: &PullLogin,
    ) -> Result<Manifest, Unread> {
        let url = format!(
            "{}://{}/v2/{}/manifests/{reference}",
            self.scheme.as_str(),
            name.registry().as_str(),
            name.repository().as_str()
        );
        let first = self
            .sent(self.client.get(&url).header(ACCEPT, MANIFESTS))
            .await?;
        let answered = match first.status() {
            StatusCode::UNAUTHORIZED => {
                let authorization = self.authorization(&first, name, login).await?;
                self.sent(
                    self.client
                        .get(&url)
                        .header(ACCEPT, MANIFESTS)
                        .header(AUTHORIZATION, authorization),
                )
                .await?
            }
            _ => first,
        };
        manifest_of(answered).await
    }

    /// The `Authorization` a registry's challenge in `refused` asks for,
    /// with `login`.
    async fn authorization(
        &self,
        refused: &Response,
        name: &ImageName,
        login: &PullLogin,
    ) -> Result<String, Unread> {
        let challenge = refused
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        match challenge.split_once(' ') {
            Some((scheme, _)) if scheme.eq_ignore_ascii_case("basic") => basic_of(login),
            Some((scheme, parameters)) if scheme.eq_ignore_ascii_case("bearer") => {
                self.bearer(parameters, name, login).await
            }
            _ => Err(Unread::Refused(
                "the registry asked for no login it names".to_owned(),
            )),
        }
    }

    /// A token from the service a bearer challenge's `parameters` name,
    /// asked with `login`.
    async fn bearer(
        &self,
        parameters: &str,
        name: &ImageName,
        login: &PullLogin,
    ) -> Result<String, Unread> {
        let realm = parameter(parameters, "realm")
            .ok_or_else(|| Unread::Refused("the registry's challenge names no realm".to_owned()))?;
        let reachable = url::Url::parse(realm)
            .ok()
            .filter(|url| ensure_reachable(url, &self.networks).is_ok());
        if reachable.is_none() {
            return Err(Unread::Refused(
                "the registry's token service is no address this deployment may reach".to_owned(),
            ));
        }
        let scope = format!("repository:{}:pull", name.repository().as_str());
        let mut query = vec![("scope", scope.as_str())];
        if let Some(service) = parameter(parameters, "service") {
            query.push(("service", service));
        }
        let asked = with_login(self.client.get(realm).query(&query), login);
        let answer = self.sent(asked).await?;
        if !answer.status().is_success() {
            return Err(refused_or_down(answer.status(), "the token service"));
        }
        let token = bounded_json(answer).await?;
        token
            .get("token")
            .or_else(|| token.get("access_token"))
            .and_then(Value::as_str)
            .map(|token| format!("Bearer {token}"))
            .ok_or_else(|| Unread::Refused("the token service gave no token".to_owned()))
    }

    /// `request`, sent; a call that does not go through is unavailable.
    async fn sent(&self, request: RequestBuilder) -> Result<Response, Unread> {
        request
            .send()
            .await
            .map_err(|error| Unread::Unavailable(format!("the registry was not reached: {error}")))
    }

    /// The size of the image `manifest` describes: its layers and config,
    /// or for a list of platform builds, its largest Linux build's.
    async fn size_of(
        &self,
        name: &ImageName,
        manifest: &Manifest,
        login: &PullLogin,
    ) -> Result<u64, Unread> {
        let Some(builds) = manifest.body.get("manifests").and_then(Value::as_array) else {
            return image_size(&manifest.body);
        };
        let mut largest = 0;
        for digest in linux_builds(builds) {
            let build = self.manifest(name, &digest, login).await?;
            largest = largest.max(image_size(&build.body)?);
        }
        match largest {
            0 => Err(Unread::Refused("the image has no Linux build".to_owned())),
            bytes => Ok(bytes),
        }
    }
}

#[async_trait]
impl ImageResolver for RegistryImageResolver {
    async fn resolve(&self, name: &ImageName, login: &PullLogin) -> Resolving {
        let reference = match name.reference() {
            ImageReference::Tag(tag) => tag.as_str(),
            ImageReference::Digest(digest) => digest.as_str(),
        };
        let resolved = async {
            let manifest = self.manifest(name, reference, login).await?;
            ensure_named(name.reference(), &manifest.digest)?;
            let bytes = self.size_of(name, &manifest, login).await?;
            Ok::<_, Unread>((manifest.digest, bytes))
        };
        match resolved.await {
            Ok((digest, bytes)) => Resolving::Resolved { digest, bytes },
            Err(Unread::Refused(why)) => Resolving::Refused(UntrustedText::record(&why)),
            Err(Unread::Unavailable(why)) => Resolving::Unavailable(UntrustedText::record(&why)),
        }
    }
}

/// The manifest `answered` holds, named by the SHA-256 of what was served,
/// whatever the registry says it is.
async fn manifest_of(answered: Response) -> Result<Manifest, Unread> {
    if !answered.status().is_success() {
        return Err(refused_or_down(answered.status(), "the registry"));
    }
    let body = bounded(answered).await?;
    let digest = ImageDigest::new(format!("sha256:{}", hex_of(&Sha256::digest(&body))))
        .map_err(|_| Unread::Unavailable("the manifest's digest is not one".to_owned()))?;
    let body = serde_json::from_slice(&body)
        .map_err(|_| Unread::Refused("the manifest is not JSON".to_owned()))?;
    Ok(Manifest { digest, body })
}

/// Refuses a manifest whose digest is not the one `reference` pinned.
fn ensure_named(reference: &ImageReference, digest: &ImageDigest) -> Result<(), Unread> {
    match reference {
        ImageReference::Digest(pinned) if pinned != digest => Err(Unread::Refused(
            "the registry served another manifest than the digest named".to_owned(),
        )),
        ImageReference::Digest(_) | ImageReference::Tag(_) => Ok(()),
    }
}

/// The digests of `builds`' Linux builds, at most `MOST_PLATFORMS`.
fn linux_builds(builds: &[Value]) -> Vec<String> {
    builds
        .iter()
        .filter(|build| {
            build
                .get("platform")
                .and_then(|platform| platform.get("os"))
                .and_then(Value::as_str)
                == Some("linux")
        })
        .filter_map(|build| build.get("digest").and_then(Value::as_str))
        .filter(|digest| ImageDigest::new(*digest).is_ok())
        .take(MOST_PLATFORMS)
        .map(str::to_owned)
        .collect()
}

/// The bytes an image manifest's config and layers add up to.
fn image_size(manifest: &Value) -> Result<u64, Unread> {
    let layers = manifest
        .get("layers")
        .and_then(Value::as_array)
        .ok_or_else(|| Unread::Refused("the manifest lists no layers".to_owned()))?;
    let config = manifest.get("config").into_iter();
    config
        .chain(layers)
        .map(|part| part.get("size").and_then(Value::as_u64))
        .try_fold(0_u64, |total, size| {
            size.map(|size| total.saturating_add(size))
                .ok_or_else(|| Unread::Refused("a layer of the manifest has no size".to_owned()))
        })
}

/// The value of `name` in a challenge's comma-separated `key="value"`
/// parameters.
fn parameter<'p>(parameters: &'p str, name: &str) -> Option<&'p str> {
    parameters.split(',').find_map(|pair| {
        let (key, value) = pair.trim().split_once('=')?;
        (key == name).then(|| value.trim_matches('"'))
    })
}

/// `request` with `login` as basic credentials, or as it is.
fn with_login(request: RequestBuilder, login: &PullLogin) -> RequestBuilder {
    match login {
        PullLogin::Anonymous => request,
        PullLogin::Password { username, password } => {
            request.basic_auth(username.as_str(), Some(password.expose()))
        }
    }
}

/// The basic `Authorization` of `login`; a registry asking for it from no
/// login refuses.
fn basic_of(login: &PullLogin) -> Result<String, Unread> {
    match login {
        PullLogin::Anonymous => Err(Unread::Refused("the registry asks for a login".to_owned())),
        PullLogin::Password { username, password } => {
            let pair = format!("{}:{}", username.as_str(), password.expose());
            Ok(format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(pair)
            ))
        }
    }
}

/// A refusal for a status in the 400s, else the registry is down.
fn refused_or_down(status: StatusCode, who: &str) -> Unread {
    match status.is_client_error() {
        true => Unread::Refused(format!("{who} answered {status}")),
        false => Unread::Unavailable(format!("{who} answered {status}")),
    }
}

/// `response`'s body, at most `MOST_READ` bytes.
async fn bounded(mut response: Response) -> Result<Vec<u8>, Unread> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| Unread::Unavailable(format!("the answer was not read: {error}")))?
    {
        if body.len().saturating_add(chunk.len()) > MOST_READ {
            return Err(Unread::Refused(
                "the answer is larger than a manifest may be".to_owned(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// `response`'s body as JSON, at most `MOST_READ` bytes.
async fn bounded_json(response: Response) -> Result<Value, Unread> {
    let body = bounded(response).await?;
    serde_json::from_slice(&body).map_err(|_| Unread::Refused("the answer is not JSON".to_owned()))
}

/// `bytes` as lowercase hex.
fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::sandbox::registry::RegistryUsername;
    use ianua_domain::shared::security::secret::Secret;
    use serde_json::json;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const HOST: &str = "registry.acme.test";

    /// A resolver reaching `server` over plain HTTP under `HOST`.
    fn resolver(server: &MockServer) -> RegistryImageResolver {
        let client = Client::builder()
            .resolve(HOST, *server.address())
            .build()
            .unwrap();
        RegistryImageResolver {
            client,
            scheme: Scheme::Http,
            networks: UpstreamNetworks::public_only(),
        }
    }

    fn name(server: &MockServer, reference: &str) -> ImageName {
        let port = server.address().port();
        ImageName::parse(&format!("{HOST}:{port}/tools/codegen{reference}")).unwrap()
    }

    fn image_manifest() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "config": {"size": 1000, "digest": format!("sha256:{}", "c".repeat(64))},
            "layers": [{"size": 30000}, {"size": 70000}],
        }))
        .unwrap()
    }

    fn robot() -> PullLogin {
        PullLogin::Password {
            username: RegistryUsername::new("robot").unwrap(),
            password: Secret::new("s3cret token"),
        }
    }

    /// `server` as a registry asking for a token, its token service giving
    /// one to Acme's robot login, and the tag's manifest read with it.
    async fn serve_behind_a_token(server: &MockServer) {
        let realm = format!("http://{HOST}:{}/token", server.address().port());
        Mock::given(method("GET"))
            .and(path("/v2/tools/codegen/manifests/1.4"))
            .and(header("authorization", "Bearer t0k3n"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(image_manifest()))
            .mount(server)
            .await;
        Mock::given(path("/v2/tools/codegen/manifests/1.4"))
            .respond_with(ResponseTemplate::new(401).insert_header(
                "www-authenticate",
                format!(r#"Bearer realm="{realm}",service="acme""#).as_str(),
            ))
            .mount(server)
            .await;
        Mock::given(path("/token"))
            .and(query_param("scope", "repository:tools/codegen:pull"))
            .and(header("authorization", "Basic cm9ib3Q6czNjcmV0IHRva2Vu"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"token": "t0k3n"})))
            .mount(server)
            .await;
    }

    /// The registry asks for a token; the token service, asked with Acme's
    /// robot login, gives one, and the tag's manifest is read with it. The
    /// image is pinned to the SHA-256 of what was served, its size its
    /// config and layers.
    #[tokio::test]
    async fn a_tag_is_resolved_through_a_token() {
        let server = MockServer::start().await;
        serve_behind_a_token(&server).await;

        let resolved = resolver(&server)
            .resolve(&name(&server, ":1.4"), &robot())
            .await;

        let digest = format!("sha256:{}", hex_of(&Sha256::digest(image_manifest())));
        assert_eq!(
            resolved,
            Resolving::Resolved {
                digest: ImageDigest::new(digest).unwrap(),
                bytes: 101_000,
            }
        );
    }

    /// A manifest served for a digest that is not its own is refused, and
    /// an image the registry does not have is refused.
    #[tokio::test]
    async fn a_manifest_that_is_not_the_one_named_is_refused() {
        let server = MockServer::start().await;
        let other = format!("sha256:{}", "a".repeat(64));
        Mock::given(path(format!("/v2/tools/codegen/manifests/{other}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(image_manifest()))
            .mount(&server)
            .await;

        let swapped = resolver(&server)
            .resolve(&name(&server, &format!("@{other}")), &PullLogin::Anonymous)
            .await;
        let missing = resolver(&server)
            .resolve(&name(&server, ":2.0"), &PullLogin::Anonymous)
            .await;

        assert!(matches!(swapped, Resolving::Refused(_)));
        assert!(matches!(missing, Resolving::Refused(_)));
    }

    /// For a list of platform builds, the size is the largest Linux
    /// build's; a build for another system is not read.
    #[test]
    fn only_linux_builds_are_sized() {
        let builds = json!([
            {"digest": format!("sha256:{}", "1".repeat(64)), "platform": {"os": "linux"}},
            {"digest": format!("sha256:{}", "2".repeat(64)), "platform": {"os": "windows"}},
        ]);

        let read = linux_builds(builds.as_array().unwrap());

        assert_eq!(read, [format!("sha256:{}", "1".repeat(64))]);
    }

    /// A challenge's parameters are read by name.
    #[test]
    fn a_challenge_is_read_by_name() {
        let parameters = r#"realm="https://auth.example/token",service="registry.example""#;

        assert_eq!(parameter(parameters, "service"), Some("registry.example"));
        assert_eq!(parameter(parameters, "scope"), None);
    }
}
