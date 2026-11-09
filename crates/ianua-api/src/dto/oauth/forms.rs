//! The forms clients send the OAuth protocol endpoints, as the OpenAPI
//! document describes them. The requests are read by the extractors in
//! `extractors/oauth`, parameter by parameter, so a parameter sent twice
//! or empty is handled as the standards ask; these shapes only name what
//! each endpoint reads.

use utoipa::openapi::RefOr;
use utoipa::openapi::schema::{AllOfBuilder, ObjectBuilder, RefBuilder, Schema, SchemaType, Type};
use utoipa::{PartialSchema, ToSchema};

use crate::extractors::oauth::authorization::AuthorizationParams;

/// How a client proves itself in a form, unless it sends its secret in an
/// `Authorization: Basic` header (RFC 6749 2.3.1, RFC 7523 2.2).
pub(crate) struct ClientProofForm;

impl ToSchema for ClientProofForm {}

impl PartialSchema for ClientProofForm {
    /// Documents the optional credentials accepted by the client-proof extractor.
    fn schema() -> RefOr<Schema> {
        optional_text_fields(&[
            ("client_id", "The client, by the `client_id` it was issued."),
            ("client_secret", "Its secret, for `client_secret_post`."),
            ("client_assertion_type", "`urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, for\n`private_key_jwt`."),
            ("client_assertion", "The JWT it signed, for `private_key_jwt`."),
        ])
        .description(Some("How a client proves itself in a form, unless it sends its secret in an\n`Authorization: Basic` header (RFC 6749 2.3.1, RFC 7523 2.2)."))
        .into()
    }
}

/// A token request (RFC 6749 4.1.3, 4.4.2, 6; RFC 8628 3.4; RFC 8693 2.1;
/// RFC 8707 2.2).
pub(crate) struct TokenForm;

impl ToSchema for TokenForm {
    /// Includes the credential schema referenced by this form.
    fn schemas(schemas: &mut Vec<(String, RefOr<Schema>)>) {
        client_schemas(schemas);
    }
}

impl PartialSchema for TokenForm {
    /// Documents grant-specific parameters alongside the shared client credentials.
    fn schema() -> RefOr<Schema> {
        AllOfBuilder::new().item(client_reference()).item(token_fields())
            .description(Some("A token request (RFC 6749 4.1.3, 4.4.2, 6; RFC 8628 3.4; RFC 8693 2.1;\nRFC 8707 2.2)."))
            .into()
    }
}

/// A token a client holds, sent to introspection or revocation (RFC 7662
/// 2.1, RFC 7009 2.1).
pub(crate) struct TokenAboutForm;

impl ToSchema for TokenAboutForm {
    /// Includes the credential schema referenced by this form.
    fn schemas(schemas: &mut Vec<(String, RefOr<Schema>)>) {
        client_schemas(schemas);
    }
}

impl PartialSchema for TokenAboutForm {
    /// Requires the token and permits a token-kind hint with client credentials.
    fn schema() -> RefOr<Schema> {
        let fields = optional_text_fields(&[(
            "token_type_hint",
            "`access_token` or `refresh_token`, where to look first.",
        )])
        .property(
            "token",
            text_field("The credential whose status is queried or whose authority is withdrawn."),
        )
        .required("token");
        AllOfBuilder::new().item(client_reference()).item(fields)
            .description(Some("A token a client holds, sent to introspection or revocation (RFC 7662\n2.1, RFC 7009 2.1)."))
            .into()
    }
}

/// A device asking for its codes (RFC 8628 3.1).
pub(crate) struct DeviceCodeForm;

impl ToSchema for DeviceCodeForm {
    /// Includes the credential schema referenced by this form.
    fn schemas(schemas: &mut Vec<(String, RefOr<Schema>)>) {
        client_schemas(schemas);
    }
}

impl PartialSchema for DeviceCodeForm {
    /// Documents the optional scopes and the client's credential parameters.
    fn schema() -> RefOr<Schema> {
        AllOfBuilder::new()
            .item(client_reference())
            .item(optional_text_fields(&[(
                "scope",
                "The scopes asked for, separated by spaces.",
            )]))
            .description(Some("A device asking for its codes (RFC 8628 3.1)."))
            .into()
    }
}

/// An authorization request a client pushes (RFC 9126 2.1).
pub(crate) struct PushedRequestForm;

impl ToSchema for PushedRequestForm {
    /// Includes both referenced forms and their nested schemas.
    fn schemas(schemas: &mut Vec<(String, RefOr<Schema>)>) {
        schemas.push((
            AuthorizationParams::name().into(),
            AuthorizationParams::schema(),
        ));
        AuthorizationParams::schemas(schemas);
        client_schemas(schemas);
    }
}

impl PartialSchema for PushedRequestForm {
    /// Combines authorization parameters and client proof without wrapper fields.
    fn schema() -> RefOr<Schema> {
        AllOfBuilder::new()
            .item(
                RefBuilder::new()
                    .ref_location_from_schema_name(AuthorizationParams::name())
                    .description(Some(
                        "The authorization request's parameters, but `request_uri`.",
                    )),
            )
            .item(client_reference())
            .description(Some(
                "An authorization request a client pushes (RFC 9126 2.1).",
            ))
            .into()
    }
}

/// An access token sent in a form body rather than the header (RFC 6750
/// 2.2).
pub(crate) struct AccessTokenForm;

impl ToSchema for AccessTokenForm {}

impl PartialSchema for AccessTokenForm {
    /// Requires the bearer credential used by the form-body authentication extractor.
    fn schema() -> RefOr<Schema> {
        ObjectBuilder::new()
            .property(
                "access_token",
                text_field("The bearer credential presented to authorize this request."),
            )
            .required("access_token")
            .description(Some(
                "An access token sent in a form body rather than the header (RFC 6750\n2.2).",
            ))
            .into()
    }
}

/// Optional parameters shared by the supported token grants.
const TOKEN_FIELDS: &[(&str, &str)] = &[
    ("code", "The authorization code, for `authorization_code`."),
    (
        "redirect_uri",
        "The redirect URI the code was sent to, for `authorization_code`.",
    ),
    (
        "code_verifier",
        "The PKCE verifier, for `authorization_code`.",
    ),
    (
        "refresh_token",
        "The credential exchanged for new access tokens under the refresh grant.",
    ),
    ("device_code", "The device code, for the device grant."),
    ("subject_token", "The token exchanged, for token exchange."),
    (
        "subject_token_type",
        "`urn:ietf:params:oauth:token-type:access_token`, for token exchange.",
    ),
    (
        "actor_token",
        "The token of whoever acts for the subject, for token exchange.",
    ),
    (
        "actor_token_type",
        "`urn:ietf:params:oauth:token-type:access_token`, with an actor token.",
    ),
    (
        "audience",
        "The `client_id` of the client the exchanged token is for.",
    ),
    ("scope", "The scopes asked for, separated by spaces."),
    (
        "resource",
        "For `authorization_code`, `refresh_token` and the device grant, a\nresource indicator (RFC 8707): `urn:ianua:stream-route:` and a\nstream route's id asks for a token meant for that route's signed-in\ntunnel alone. The route must be an active tunnel of the tenant, and\nthe client must take JWT access tokens; otherwise `invalid_target`.",
    ),
];

/// The grant selector and optional fields read by the token extractor.
fn token_fields() -> ObjectBuilder {
    optional_text_fields(TOKEN_FIELDS)
    .property("grant_type", text_field("`authorization_code`, `refresh_token`, `client_credentials`,\n`urn:ietf:params:oauth:grant-type:device_code` or\n`urn:ietf:params:oauth:grant-type:token-exchange`."))
    .required("grant_type")
}

/// Adds the reusable credential schema when a form references it.
fn client_schemas(schemas: &mut Vec<(String, RefOr<Schema>)>) {
    schemas.push((ClientProofForm::name().into(), ClientProofForm::schema()));
}

/// Keeps the common credential reference and its field-level description.
fn client_reference() -> RefBuilder {
    RefBuilder::new()
        .ref_location_from_schema_name(ClientProofForm::name())
        .description(Some("How the client proves itself."))
}

/// Documents string parameters that may be absent or explicitly null.
fn optional_text_fields(fields: &[(&str, &str)]) -> ObjectBuilder {
    fields
        .iter()
        .fold(ObjectBuilder::new(), |schema, (name, description)| {
            schema.property(
                *name,
                text_field(description)
                    .schema_type(SchemaType::Array(vec![Type::String, Type::Null])),
            )
        })
}

/// Describes a required textual parameter without changing its wire name.
fn text_field(description: &str) -> ObjectBuilder {
    ObjectBuilder::new()
        .schema_type(Type::String)
        .description(Some(description))
}
