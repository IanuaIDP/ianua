//! Turning an OpenAPI 3 document into a gateway configuration.
//!
//! A converter, not an importer: it answers with a configuration document and
//! writes nothing. The team then reads it, edits the parts a spec cannot know
//! about (which pipeline runs, who may call it) and posts it to the import
//! endpoint like any other document. One apply path, and the generated
//! configuration gets reviewed before it is real, which is the whole reason
//! for having a declarative format at all.
//!
//! The spec arrives as arbitrary JSON rather than through an OpenAPI crate.
//! Four fields are read: the version, the server URL, the paths, and the
//! method keys under each path. A parser for the rest of OpenAPI would be a
//! large dependency in exchange for validating fields nothing here consults.

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
use ianua_domain::domains::routing::backend::upstream::{HostHeader, Upstream, UpstreamTimeout};
use ianua_domain::domains::routing::matching::parameter::RouteReach;
use ianua_domain::domains::routing::matching::request_match::RouteConditions;
use ianua_domain::domains::routing::policy::RoutePolicy;
use ianua_domain::domains::routing::route_status::RouteStatus;
use ianua_domain::message;
use ianua_domain::types::{Audience, HttpMethod, HttpUrl, UrlPath};
use serde::Deserialize;
use serde_json::Value;

use crate::dto::gateway::{
    GatewayConfigBody, PipelineConfigBody, RouteConfigBody, ServiceConfigBody,
};
use crate::dto::routing::routes::PathRewriteBody;
use crate::error::ApiError;

/// The methods a path item may declare, in the order they are emitted.
const OPERATIONS: [(&str, HttpMethod); 7] = [
    ("get", HttpMethod::Get),
    ("post", HttpMethod::Post),
    ("put", HttpMethod::Put),
    ("patch", HttpMethod::Patch),
    ("delete", HttpMethod::Delete),
    ("head", HttpMethod::Head),
    ("options", HttpMethod::Options),
];

/// The priority every generated route gets.
const GENERATED_PRIORITY: u16 = 100;

/// A spec plus the things a spec cannot say.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OpenApiImportBody {
    /// The OpenAPI 3 document, as JSON.
    #[schema(value_type = Object)]
    pub spec: Value,
    /// The pipeline the generated routes run.
    ///
    /// Required, and not defaulted: which security pipeline a route runs is
    /// the one decision a spec has no opinion about, and picking one on the
    /// caller's behalf would decide it silently.
    pub pipeline: String,
    /// What to call the generated service. Defaults to the spec's title.
    #[serde(default)]
    pub service: Option<String>,
    /// The upstream URL, when the spec names no server or names the wrong
    /// one.
    #[serde(default)]
    pub upstream_url: Option<String>,
    /// The audience the upstream pins. Required for any policy other than
    /// `Public`; see `policy`.
    #[serde(default)]
    pub expected_audience: Option<String>,
    /// Who may call the generated routes. Defaults to `Public`, which is the
    /// only policy a spec supports on its own: anything stricter needs an
    /// `expected_audience` the spec does not carry.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub policy: Option<RoutePolicy>,
    /// Prepended to every generated route name, so two specs imported into
    /// one tenant do not collide.
    #[serde(default)]
    pub name_prefix: Option<String>,
}

impl OpenApiImportBody {
    /// Converts the spec into a configuration document.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::validation`] if the document is not OpenAPI 3,
    /// declares no paths, names no usable server and none was supplied, or
    /// carries a path that is not a valid URL path.
    pub(crate) fn convert(&self) -> Result<GatewayConfigBody, ApiError> {
        require_openapi_3(&self.spec)?;
        let upstream = self.upstream()?;
        let service = self.service_name()?;
        let routes = self.routes(&service)?;
        if routes.is_empty() {
            return Err(ApiError::validation(message!(
                "api-the-document-declares-no-paths-with",
                "the document declares no paths with operations, so there is nothing to import"
            )));
        }
        Ok(GatewayConfigBody {
            services: vec![generated_service(service, upstream)],
            pipelines: vec![PipelineConfigBody {
                name: self.pipeline.clone(),
                stages: Vec::new(),
                status: PipelineStatus::Draft,
            }],
            routes,
            stream_routes: Vec::new(),
            egress_policies: Vec::new(),
            consumers: Vec::new(),
        })
    }

    /// Where the generated service points.
    ///
    /// The supplied URL wins over the spec's: a spec's `servers` entry is
    /// routinely the public address of the very gateway being configured, and
    /// pointing the gateway at itself is a loop the operator would have to
    /// find at runtime.
    fn upstream(&self) -> Result<Upstream, ApiError> {
        let raw = self
            .upstream_url
            .clone()
            .or_else(|| first_server_url(&self.spec))
            .ok_or_else(|| {
                ApiError::validation(message!(
                    "api-the-document-names-no-server-supply",
                    "the document names no server; supply upstream_url alongside the spec"
                ))
            })?;
        let url = HttpUrl::new(raw).map_err(ApiError::validation)?;
        let upstream = Upstream::new(url, UpstreamTimeout::DEFAULT, HostHeader::Rewrite);
        let Some(audience) = &self.expected_audience else {
            return Ok(upstream);
        };
        let audience = Audience::new(audience.as_str()).map_err(ApiError::validation)?;
        Ok(upstream.with_audience(audience))
    }

    /// What the generated service is called.
    fn service_name(&self) -> Result<String, ApiError> {
        if let Some(name) = &self.service {
            return Ok(name.clone());
        }
        self.spec
            .get("info")
            .and_then(|info| info.get("title"))
            .and_then(Value::as_str)
            .map(slug)
            .filter(|slug| !slug.is_empty())
            .ok_or_else(|| {
                ApiError::validation(message!(
                    "api-the-document-has-no-info-title",
                    "the document has no info.title to name the service after; supply service"
                ))
            })
    }

    /// One route per declared path, carrying the methods that path declares.
    fn routes(&self, service: &str) -> Result<Vec<RouteConfigBody>, ApiError> {
        let Some(paths) = self.spec.get("paths").and_then(Value::as_object) else {
            return Err(ApiError::validation(message!(
                "api-the-document-declares-no-paths",
                "the document declares no paths"
            )));
        };
        let policy = self.policy.clone().unwrap_or(RoutePolicy::Public);
        let target = RouteTarget {
            service,
            policy: &policy,
        };
        let mut routes = paths
            .iter()
            .map(|(path, item)| (path, methods_of(item)))
            .filter(|(_, methods)| !methods.is_empty())
            .map(|(path, methods)| self.route(&target, path, methods))
            .collect::<Result<Vec<_>, _>>()?;
        routes.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(routes)
    }

    /// The route serving `path` with `methods`.
    fn route(
        &self,
        target: &RouteTarget<'_>,
        path: &str,
        methods: Vec<HttpMethod>,
    ) -> Result<RouteConfigBody, ApiError> {
        UrlPath::new(path).map_err(ApiError::validation)?;
        Ok(RouteConfigBody {
            name: self.route_name(path),
            path_pattern: path.to_owned(),
            methods,
            service: target.service.to_owned(),
            pipeline: self.pipeline.clone(),
            policy: target.policy.clone(),
            path_rewrite: PathRewriteBody::Keep,
            priority: GENERATED_PRIORITY,
            hosts: Vec::new(),
            conditions: RouteConditions::default(),
            data_class: DataClassLevel::Internal,
            action_class: None,
            reach: RouteReach::Fixed,
            parameter_rules: Vec::new(),
            status: RouteStatus::Active,
        })
    }

    /// A route name derived from the path it serves.
    ///
    /// Derived rather than taken from `operationId`: a route covers a whole
    /// path item, and the operations under it carry different ids, so any one
    /// of them would name the route after a fraction of what it does.
    fn route_name(&self, path: &str) -> String {
        let body = path_slug(path);
        let Some(prefix) = &self.name_prefix else {
            return body;
        };
        format!("{}-{body}", slug(prefix))
    }
}

/// The destination and access policy shared by every path in an imported document.
struct RouteTarget<'a> {
    service: &'a str,
    policy: &'a RoutePolicy,
}

/// A generated service with only the upstream supplied by the import.
fn generated_service(name: String, upstream: Upstream) -> ServiceConfigBody {
    ServiceConfigBody {
        name,
        upstream,
        client_certificate: None,
        connector: None,
        health_check: None,
        app_sign_in: None,
        accepts_app_sign_in_of: None,
        sign_in_delivery: None,
        status: RouteStatus::Active,
    }
}

/// Refuses anything that is not an OpenAPI 3 document.
///
/// Swagger 2 uses a different shape for servers and for path parameters, so
/// reading it with these rules would produce a plausible configuration that
/// points somewhere else.
fn require_openapi_3(spec: &Value) -> Result<(), ApiError> {
    let version = spec.get("openapi").and_then(Value::as_str).ok_or_else(|| {
        ApiError::validation(message!(
            "api-not-an-openapi-document-no-openapi",
            "not an OpenAPI document: no 'openapi' version"
        ))
    })?;
    if !version.starts_with("3.") {
        return Err(ApiError::validation(message!(
            "api-openapi-is-not-supported-this-reads",
            format!("OpenAPI {version} is not supported; this reads OpenAPI 3 documents")
        )));
    }
    Ok(())
}

/// The first `servers` entry's URL, if the document has one.
fn first_server_url(spec: &Value) -> Option<String> {
    spec.get("servers")?
        .as_array()?
        .iter()
        .find_map(|server| server.get("url")?.as_str().map(str::to_owned))
}

/// The methods a path item declares, ignoring everything else under it.
fn methods_of(item: &Value) -> Vec<HttpMethod> {
    OPERATIONS
        .iter()
        .filter(|(key, _)| item.get(*key).is_some())
        .map(|(_, method)| *method)
        .collect()
}

/// The slug of a path, or `root` for one that has nothing to slug.
fn path_slug(path: &str) -> String {
    let body = slug(path);
    if body.is_empty() {
        return "root".to_owned();
    }
    body
}

/// A name a route or service can carry, from arbitrary text: lowercase
/// letters and digits, with each run of anything else turned into one dash.
fn slug(value: &str) -> String {
    value
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// `ApiError` deliberately has no `Debug` (it wraps values that must not
    /// be printed), so tests unwrap through this instead.
    fn converted(request: &OpenApiImportBody) -> GatewayConfigBody {
        match request.convert() {
            Ok(config) => config,
            Err(_) => panic!("conversion failed"),
        }
    }

    /// An import of `spec` into the `edge` pipeline, with nothing else set.
    fn body(spec: Value) -> OpenApiImportBody {
        OpenApiImportBody {
            spec,
            pipeline: "edge".to_owned(),
            service: None,
            upstream_url: None,
            expected_audience: None,
            policy: None,
            name_prefix: None,
        }
    }

    /// A small pet store spec: one server and two paths with two methods
    /// each.
    fn petstore() -> Value {
        json!({
            "openapi": "3.0.3",
            "info": { "title": "Pet Store", "version": "1.0.0" },
            "servers": [{ "url": "https://petstore.internal:8443/v1" }],
            "paths": {
                "/pets": {
                    "get": { "operationId": "listPets" },
                    "post": { "operationId": "createPet" }
                },
                "/pets/{petId}": {
                    "get": { "operationId": "getPet" },
                    "delete": { "operationId": "deletePet" },
                    "parameters": []
                }
            }
        })
    }

    /// The pet store spec becomes one service at its server, one route per
    /// path, and the pipeline it was imported into.
    #[test]
    fn a_spec_becomes_one_service_and_one_route_per_path() {
        let config = converted(&body(petstore()));

        assert_eq!(config.services.len(), 1);
        assert_eq!(config.services[0].name, "pet-store");
        assert_eq!(
            config.services[0].upstream.url().as_str(),
            "https://petstore.internal:8443/v1"
        );
        assert_eq!(config.routes.len(), 2);
        assert_eq!(config.pipelines.len(), 1);
        assert_eq!(config.pipelines[0].name, "edge");
    }

    /// Each route lets through only the methods its path declares.
    #[test]
    fn a_route_carries_the_methods_its_path_declares() {
        let config = converted(&body(petstore()));

        let pets = config.routes.iter().find(|r| r.name == "pets").unwrap();
        assert_eq!(pets.methods, vec![HttpMethod::Get, HttpMethod::Post]);

        let one = config.routes.iter().find(|r| r.name != "pets").unwrap();
        assert_eq!(one.methods, vec![HttpMethod::Get, HttpMethod::Delete]);
        assert_eq!(one.path_pattern, "/pets/{petId}");
    }

    /// `parameters` is not an operation, and a path item that declares only
    /// non-operation keys claims no methods.
    #[test]
    fn a_path_item_with_no_operations_is_skipped() {
        let spec = json!({
            "openapi": "3.0.0",
            "info": { "title": "Empty" },
            "servers": [{ "url": "https://x.internal:8443" }],
            "paths": {
                "/nothing": { "parameters": [] },
                "/something": { "get": {} }
            }
        });

        let config = converted(&body(spec));

        assert_eq!(config.routes.len(), 1);
        assert_eq!(config.routes[0].path_pattern, "/something");
    }

    /// A spec's `servers` entry is routinely the public address of the very
    /// gateway being configured.
    #[test]
    fn a_supplied_upstream_wins_over_the_specs_server() {
        let mut request = body(petstore());
        request.upstream_url = Some("https://real-backend.internal:9443".to_owned());

        let config = converted(&request);

        assert_eq!(
            config.services[0].upstream.url().as_str(),
            "https://real-backend.internal:9443"
        );
    }

    /// A spec that names no server, imported without an upstream, has
    /// nowhere to send traffic and is refused.
    #[test]
    fn a_spec_with_no_server_and_no_supplied_url_is_refused() {
        let spec = json!({
            "openapi": "3.0.0",
            "info": { "title": "Serverless" },
            "paths": { "/x": { "get": {} } }
        });

        assert!(body(spec).convert().is_err());
    }

    /// An older Swagger 2.0 spec is refused.
    #[test]
    fn swagger_2_is_refused() {
        let spec = json!({
            "swagger": "2.0",
            "info": { "title": "Old" },
            "paths": { "/x": { "get": {} } }
        });

        assert!(body(spec).convert().is_err());
    }

    /// A spec with no paths would make no routes, so it is refused.
    #[test]
    fn a_spec_with_no_paths_is_refused() {
        let spec = json!({
            "openapi": "3.1.0",
            "info": { "title": "Nothing" },
            "servers": [{ "url": "https://x.internal:8443" }],
            "paths": {}
        });

        assert!(body(spec).convert().is_err());
    }

    /// Two specs imported into one tenant would otherwise collide on `/pets`.
    #[test]
    fn a_name_prefix_keeps_two_imports_apart() {
        let mut request = body(petstore());
        request.name_prefix = Some("Store V2".to_owned());

        let config = converted(&request);

        assert!(
            config
                .routes
                .iter()
                .all(|r| r.name.starts_with("store-v2-")),
            "{:?}",
            config.routes.iter().map(|r| &r.name).collect::<Vec<_>>()
        );
    }

    /// The one thing a spec cannot say, so the caller says it and the
    /// generated document carries it into the audience-pinning check.
    #[test]
    fn an_audience_reaches_the_generated_upstream() {
        let mut request = body(petstore());
        request.expected_audience = Some("petstore".to_owned());
        request.policy = Some(RoutePolicy::Authenticated);

        let config = converted(&request);

        assert_eq!(
            config.services[0]
                .upstream
                .expected_audience()
                .map(Audience::as_str),
            Some("petstore")
        );
        assert!(matches!(
            config.routes[0].policy,
            RoutePolicy::Authenticated
        ));
    }

    /// Names and paths become lower-case slugs with each run of punctuation
    /// turned into one dash, and the bare root path is named `root`.
    #[test]
    fn slugs_collapse_runs_of_punctuation() {
        assert_eq!(slug("/v1/users/{id}"), "v1-users-id");
        assert_eq!(slug("Pet Store!"), "pet-store");
        assert_eq!(slug("///"), "");
        assert_eq!(path_slug("/"), "root");
    }
}
