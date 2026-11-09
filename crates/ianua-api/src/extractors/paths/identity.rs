//! The tenant, organization, user, erasure request and attribute an
//! identity request names.

use ianua_app::context::{CallerContext, CallerIdentity};
use ianua_app::email::LinkScope;
use ianua_app::use_cases::identity::whose::Whose;
use ianua_domain::domains::identity::attribute::{AttributeKey, AttributeNamespace};
use ianua_domain::message;
use ianua_domain::types::{
    DataExportId, ErasureRequestId, SessionId, SupportImpersonationId, TenantSlug, UserId,
    UserImportId,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::ApiError;

/// `/api/v1/organizations/{org_slug}/...`: the organization an emailed link
/// must lead back to.
#[derive(Deserialize)]
pub(crate) struct OrgPath {
    org_slug: TenantSlug,
}

impl OrgPath {
    /// The organization named.
    #[must_use]
    pub(crate) fn organization(&self) -> &TenantSlug {
        &self.org_slug
    }

    /// Where a link mailed from this request lands: the organization's own
    /// pages.
    #[must_use]
    pub(crate) fn link_scope(&self) -> LinkScope {
        LinkScope::organization(self.org_slug.clone())
    }
}

/// `/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/...`: the tenant
/// an emailed link must lead back to.
#[derive(Deserialize)]
pub(crate) struct TenantPath {
    org_slug: TenantSlug,
    tenant_slug: TenantSlug,
}

impl TenantPath {
    /// The organization named.
    #[must_use]
    pub(crate) fn organization(&self) -> &TenantSlug {
        &self.org_slug
    }

    /// The tenant named.
    #[must_use]
    pub(crate) fn tenant(&self) -> &TenantSlug {
        &self.tenant_slug
    }

    /// Where a link mailed from this request lands: the tenant's own pages,
    /// so it opens cold from a mail client.
    #[must_use]
    pub(crate) fn link_scope(&self) -> LinkScope {
        LinkScope::tenant(self.org_slug.clone(), self.tenant_slug.clone())
    }
}

/// `.../users/{id}/...`: one user of the tenant the path names.
#[derive(Deserialize)]
pub(crate) struct UserPath {
    org_slug: TenantSlug,
    tenant_slug: TenantSlug,
    id: Uuid,
}

impl UserPath {
    /// The user named.
    #[must_use]
    pub(crate) fn user(&self) -> UserId {
        UserId::from_uuid(self.id)
    }

    /// Whose account the request is about: the caller's own when the path
    /// names the user they are signed in as, someone else's otherwise.
    ///
    /// This says only who the request concerns. Whether the caller may act
    /// on it, for themselves or for another, is the app's question.
    #[must_use]
    pub(crate) fn whose(&self, caller: &CallerContext) -> Whose {
        whose_account(self.user(), caller)
    }

    /// Where a link mailed from this request lands: the tenant's own pages.
    #[must_use]
    pub(crate) fn link_scope(&self) -> LinkScope {
        LinkScope::tenant(self.org_slug.clone(), self.tenant_slug.clone())
    }
}

/// `.../users/{id}/sessions/{session_id}`: one session of one user.
#[derive(Deserialize)]
pub(crate) struct UserSessionPath {
    id: Uuid,
    session_id: Uuid,
}

impl UserSessionPath {
    /// Whose session it is, as [`UserPath::whose`] reads it.
    #[must_use]
    pub(crate) fn whose(&self, caller: &CallerContext) -> Whose {
        whose_account(UserId::from_uuid(self.id), caller)
    }

    /// The session named.
    #[must_use]
    pub(crate) fn session(&self) -> SessionId {
        SessionId::from_uuid(self.session_id)
    }
}

/// `.../me/sessions/{session_id}`: one of the caller's own sessions.
#[derive(Deserialize)]
pub(crate) struct MySessionPath {
    session_id: Uuid,
}

impl MySessionPath {
    /// The session named.
    #[must_use]
    pub(crate) fn session(&self) -> SessionId {
        SessionId::from_uuid(self.session_id)
    }
}

/// `.../users/exports/{id}/...`: one data export.
#[derive(Deserialize)]
pub(crate) struct ExportPath {
    id: Uuid,
}

impl ExportPath {
    /// The export named.
    #[must_use]
    pub(crate) fn export(&self) -> DataExportId {
        DataExportId::from_uuid(self.id)
    }
}

/// `.../users/imports/{id}`: one import of accounts.
#[derive(Deserialize)]
pub(crate) struct ImportPath {
    id: Uuid,
}

impl ImportPath {
    /// The import named.
    #[must_use]
    pub(crate) fn import(&self) -> UserImportId {
        UserImportId::from_uuid(self.id)
    }
}

/// `.../impersonations/{id}/...`: one support impersonation.
#[derive(Deserialize)]
pub(crate) struct ImpersonationPath {
    id: Uuid,
}

impl ImpersonationPath {
    /// The impersonation named.
    #[must_use]
    pub(crate) fn impersonation(&self) -> SupportImpersonationId {
        SupportImpersonationId::from_uuid(self.id)
    }
}

/// `.../users/erasure/{id}/...`: one erasure request.
#[derive(Deserialize)]
pub(crate) struct ErasurePath {
    id: Uuid,
}

impl ErasurePath {
    /// The erasure request named.
    #[must_use]
    pub(crate) fn request(&self) -> ErasureRequestId {
        ErasureRequestId::from_uuid(self.id)
    }
}

/// `.../user-attributes/{namespace}/{key}/...`: one declared attribute, as
/// written.
#[derive(Deserialize)]
pub(crate) struct AttributePath {
    namespace: String,
    key: String,
}

impl AttributePath {
    /// The namespace and key as the domain names them.
    ///
    /// # Errors
    ///
    /// [`ApiError::validation`] when the namespace is not `user` or `app`,
    /// or the key could not name an attribute.
    pub(crate) fn attribute(&self) -> Result<(AttributeNamespace, AttributeKey), ApiError> {
        attribute_named(&self.namespace, &self.key)
    }
}

/// `.../users/{id}/attributes/{namespace}/{key}`: one user's value for one
/// declared attribute.
#[derive(Deserialize)]
pub(crate) struct AttributeValuePath {
    id: Uuid,
    namespace: String,
    key: String,
}

impl AttributeValuePath {
    /// Whose value it is, as [`UserPath::whose`] reads it.
    #[must_use]
    pub(crate) fn whose(&self, caller: &CallerContext) -> Whose {
        whose_account(UserId::from_uuid(self.id), caller)
    }

    /// The namespace and key as the domain names them.
    ///
    /// # Errors
    ///
    /// [`ApiError::validation`] when the namespace is not `user` or `app`,
    /// or the key could not name an attribute.
    pub(crate) fn attribute(&self) -> Result<(AttributeNamespace, AttributeKey), ApiError> {
        attribute_named(&self.namespace, &self.key)
    }
}

/// The caller's own account when `user` is the one they are signed in as,
/// someone else's otherwise.
fn whose_account(user: UserId, caller: &CallerContext) -> Whose {
    match caller.identity() {
        CallerIdentity::TenantUser(own) if *own == user => Whose::Own,
        _ => Whose::OnBehalfOf(user),
    }
}

/// The namespace and key a URL names. A malformed key is refused here
/// rather than looked up, so nothing that could not name an attribute
/// reaches the schema.
fn attribute_named(
    namespace: &str,
    key: &str,
) -> Result<(AttributeNamespace, AttributeKey), ApiError> {
    let namespace = AttributeNamespace::parse(namespace).ok_or_else(|| {
        ApiError::validation(message!(
            "api-namespace-must-be-user-or-app",
            "namespace must be 'user' or 'app'"
        ))
    })?;
    let key = AttributeKey::new(key).map_err(ApiError::validation)?;
    Ok((namespace, key))
}
