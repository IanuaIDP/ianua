//! SAML metadata documents, served as XML of their kind.

use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};

/// A SAML metadata document, served as XML of its kind.
pub(crate) struct SamlMetadata {
    content_type: &'static str,
    xml: String,
}

impl SamlMetadata {
    /// This platform's service provider metadata for one connection.
    #[must_use]
    pub(crate) fn service_provider(xml: String) -> Self {
        Self {
            content_type: "application/samlmetadata+xml",
            xml,
        }
    }

    /// A tenant's identity provider metadata.
    #[must_use]
    pub(crate) fn identity_provider(xml: String) -> Self {
        Self {
            content_type: "application/xml",
            xml,
        }
    }
}

impl IntoResponse for SamlMetadata {
    fn into_response(self) -> Response {
        ([(CONTENT_TYPE, self.content_type)], self.xml).into_response()
    }
}
