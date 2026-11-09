//! API key bodies: making, listing and changing a tenant's API keys.

use ianua_app::use_cases::oauth::api_keys::{CreateRequest, CreateResult, UpdateRequest};
use ianua_domain::domains::oauth::clients::api_key::{ApiKey, KeyStanding};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{ApiKeyId, Expiry, Label, Scope, TenantSlug};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::ApiError;

/// Request body for making an API key.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateApiKeyBody {
    /// The name people see.
    pub name: String,
    /// What the key may reach. A key reaches only what its scopes name,
    /// however much its maker holds.
    #[serde(default)]
    #[schema(value_type = Vec<String>)]
    pub scopes: Vec<Scope>,
    /// When the key stops working (RFC 3339), which must be ahead of now.
    /// Left out, it never does.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
}

impl CreateApiKeyBody {
    /// The key this body asks for, in the tenant `tenant_slug` names.
    ///
    /// # Errors
    ///
    /// - [`ApiError::validation`] when the name is not a valid label.
    pub(crate) fn request_in(self, tenant_slug: TenantSlug) -> Result<CreateRequest, ApiError> {
        Ok(CreateRequest {
            name: Label::new("name", self.name).map_err(ApiError::validation)?,
            scopes: self.scopes,
            expires_at: self.expires_at.map_or(Expiry::Never, Expiry::At),
            tenant_slug,
        })
    }
}

/// Request body for changing an API key. A field left out keeps its value.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateApiKeyBody {
    /// A new name.
    pub name: Option<String>,
    /// New scopes.
    #[schema(value_type = Option<Vec<String>>)]
    pub scopes: Option<Vec<Scope>>,
}

impl UpdateApiKeyBody {
    /// The change to `key_id` this body asks for.
    ///
    /// # Errors
    ///
    /// - [`ApiError::validation`] when the name is not a valid label.
    pub(crate) fn change_of(self, key_id: ApiKeyId) -> Result<UpdateRequest, ApiError> {
        Ok(UpdateRequest {
            key_id,
            name: self
                .name
                .map(|name| Label::new("name", name))
                .transpose()
                .map_err(ApiError::validation)?,
            scopes: self.scopes,
        })
    }
}

/// An API key, without the key itself.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ApiKeyResponse {
    /// The key's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: ApiKeyId,
    /// The name people see.
    pub name: String,
    /// When it was made.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it was last used, or `null` when it never was.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_used_at: Option<OffsetDateTime>,
    /// The address it was last used from, or `null` when it never was.
    pub last_used_ip: Option<String>,
    /// What the key may reach, as `idp:<domain>:<action>` scopes. It
    /// reaches only these, however much its maker holds.
    pub scopes: Vec<String>,
    /// When it was paused, or `null` while it works. A paused key signs in
    /// nothing until it is resumed.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub paused_at: Option<OffsetDateTime>,
    /// When it stops working. Left out for a key that never does.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub expires_at: Option<OffsetDateTime>,
}

impl From<ApiKey<ResolvedTenant>> for ApiKeyResponse {
    fn from(key: ApiKey<ResolvedTenant>) -> Self {
        let paused_at = match key.standing() {
            KeyStanding::Working => None,
            KeyStanding::Paused(at) => Some(at),
        };
        Self {
            paused_at,
            expires_at: key.expires_at().instant(),
            id: *key.id(),
            name: key.name().as_str().to_owned(),
            created_at: key.created_at(),
            last_used_at: key.last_used_at(),
            last_used_ip: key.last_used_ip().map(|ip| ip.as_str().to_owned()),
            scopes: key
                .scopes()
                .iter()
                .map(|scope| scope.as_str().to_owned())
                .collect(),
        }
    }
}

/// An API key just made, with the key shown this once.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CreateApiKeyResponse {
    /// The key's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: ApiKeyId,
    /// The raw key, shown once and never stored.
    pub raw_key: String,
}

impl From<CreateResult> for CreateApiKeyResponse {
    fn from(result: CreateResult) -> Self {
        Self {
            id: result.key_id,
            raw_key: result.raw_key.expose().to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::test_support::oauth::{api_key_row, stored_api_key};
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::{ActorRef, Fact, IpAddress, UserId};
    use serde_json::{Value, json};
    use time::format_description::well_known::Rfc3339;

    use super::*;

    /// The moment `written` names, in RFC 3339.
    fn instant(written: &str) -> OffsetDateTime {
        OffsetDateTime::parse(written, &Rfc3339).unwrap()
    }

    /// The request `body` reads as, in the tenant `acme`.
    fn body(body: Value) -> CreateRequest {
        let slug = TenantSlug::new("acme", &DomainLimits::default().slug).unwrap();
        serde_json::from_value::<CreateApiKeyBody>(body)
            .unwrap()
            .request_in(slug)
            .map_err(|_| "a valid name")
            .unwrap()
    }

    /// Bob's deploy key last signed in from `203.0.113.9`. The key as
    /// listed says when, and from which address.
    #[test]
    fn a_used_key_shows_when_and_where_it_was_last_used() {
        let mut key = stored_api_key("deploys", ActorRef::User(UserId::new()));
        key.record_usage(&Fact::Known(IpAddress::new("203.0.113.9").unwrap()));

        let response = ApiKeyResponse::from(key);

        assert!(response.last_used_at.is_some());
        assert_eq!(response.last_used_ip.as_deref(), Some("203.0.113.9"));
    }

    /// A body with no `expires_at` asks for a key that never ends, as every
    /// body before the field did.
    #[test]
    fn a_body_with_no_end_asks_for_a_key_that_never_ends() {
        let request = body(json!({"name": "deploys", "scopes": ["idp:routing:view"]}));

        assert_eq!(request.expires_at, Expiry::Never);
    }

    /// Tess gives the contractor's key an end. The body says it in RFC 3339
    /// and the request carries that instant.
    #[test]
    fn a_body_naming_an_end_asks_for_a_key_with_that_end() {
        let request = body(json!({
            "name": "contractor",
            "scopes": ["idp:routing:view"],
            "expires_at": "2030-06-01T12:00:00Z",
        }));

        assert_eq!(
            request.expires_at,
            Expiry::At(instant("2030-06-01T12:00:00Z"))
        );
    }

    /// A key with no end shows no `expires_at` at all, so its JSON is what
    /// it was before keys could end; one with an end shows it.
    #[test]
    fn only_a_key_with_an_end_shows_it() {
        let never = stored_api_key("deploys", ActorRef::User(UserId::new()));
        let mut row = api_key_row("contractor", ActorRef::User(UserId::new()));
        row.expires_at = Expiry::At(instant("2100-06-01T12:00:00Z"));
        let ending = ApiKey::reconstitute(row).unwrap();

        let without = serde_json::to_value(ApiKeyResponse::from(never)).unwrap();
        let with = serde_json::to_value(ApiKeyResponse::from(ending)).unwrap();

        assert!(without.get("expires_at").is_none());
        assert_eq!(with["expires_at"], "2100-06-01T12:00:00Z");
    }

    /// Bob's deploy key may only read routes. The key as listed says so, in
    /// the spelling it was made with.
    #[test]
    fn a_key_shows_the_scopes_it_reaches() {
        let key = stored_api_key("deploys", ActorRef::User(UserId::new()));

        let response = ApiKeyResponse::from(key);

        assert_eq!(response.scopes, ["idp:routing:view"]);
    }
}
