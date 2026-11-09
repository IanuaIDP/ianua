//! Opening a stream route to workflows: the login of the system behind it
//! that Protected data steps sign in with, and how their connection to it
//! is protected.

use ianua_app::use_cases::routing::stream_routes::{
    SetStreamWorkflowUseRequest, StreamWorkflowChange, TlsRequest,
};
use ianua_domain::domains::routing::stream::{CertificateName, LoginUser, TlsAuthority};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificatePem, HostName, StreamRouteId};
use serde::Deserialize;

use crate::error::ApiError;

/// Whether a Protected data step's connection to the system is held to TLS.
#[derive(Debug, Clone, Copy, Default, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LoginTlsBody {
    /// TLS from the worker to the system itself, its certificate checked.
    #[default]
    Required,
    /// None, for a system that serves no TLS.
    Off,
}

/// Request body for opening a stream route to workflows: the login of the
/// system behind it that Protected data steps sign in with.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OpenStreamRouteToWorkflowsBody {
    /// The user name, such as a database user made for workflows.
    pub login_user: String,
    /// Its password. Kept sealed, and never shown again.
    #[schema(format = Password)]
    pub login_password: String,
    /// Whether the connection to the system is held to TLS: `required`
    /// unless `off` is chosen.
    #[serde(default)]
    pub tls: LoginTlsBody,
    /// The PEM of the authority the system's certificate chains to, when
    /// not a public one.
    #[serde(default)]
    pub tls_authority: Option<String>,
    /// The name the system's certificate is for, when not the host every
    /// backend shares.
    #[serde(default)]
    pub tls_server_name: Option<String>,
}

impl OpenStreamRouteToWorkflowsBody {
    /// The opening this body asks of `route`.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::validation`] for an invalid user name, an empty
    /// password, an authority or name that does not read, or either of
    /// them beside `tls: off`.
    pub(crate) fn into_request(
        self,
        route: StreamRouteId,
    ) -> Result<SetStreamWorkflowUseRequest, ApiError> {
        let user = LoginUser::new(self.login_user).map_err(ApiError::validation)?;
        if self.login_password.is_empty() {
            return Err(ApiError::validation(DomainError::invalid(message!(
                "routing-a-workflow-login-needs-a-password",
                "a workflow login needs a password"
            ))));
        }
        let tls = tls_request(self.tls, self.tls_authority, self.tls_server_name)?;
        Ok(SetStreamWorkflowUseRequest {
            stream_route_id: route,
            change: StreamWorkflowChange::Open {
                user,
                password: Secret::new(self.login_password),
                tls,
            },
        })
    }
}

/// The protection asked for: `mode`, with the certificate's `authority` and
/// `server_name` when TLS is required.
fn tls_request(
    mode: LoginTlsBody,
    authority: Option<String>,
    server_name: Option<String>,
) -> Result<TlsRequest, ApiError> {
    match mode {
        LoginTlsBody::Required => Ok(TlsRequest::Required {
            authority: authority
                .map(CertificatePem::new)
                .transpose()
                .map_err(ApiError::validation)?
                .map_or(TlsAuthority::PublicRoots, TlsAuthority::Own),
            name: server_name
                .map(HostName::new)
                .transpose()
                .map_err(ApiError::validation)?
                .map_or(CertificateName::SharedBackendHost, CertificateName::Given),
        }),
        LoginTlsBody::Off => ensure_no_certificate_check(authority.as_ref(), server_name.as_ref())
            .map(|()| TlsRequest::Off),
    }
}

/// Refuses an authority or a name beside `tls: off`, which would check
/// nothing while reading as if it did.
fn ensure_no_certificate_check(
    authority: Option<&String>,
    server_name: Option<&String>,
) -> Result<(), ApiError> {
    if authority.is_none() && server_name.is_none() {
        return Ok(());
    }
    Err(ApiError::validation(DomainError::invalid(message!(
        "routing-a-login-without-tls-checks-no-certificate",
        "a login without TLS checks no certificate, so name no authority or server name for it"
    ))))
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    /// The opening `body` asks of a stream route.
    fn opened(body: &str) -> Result<SetStreamWorkflowUseRequest, ApiError> {
        let body: OpenStreamRouteToWorkflowsBody = serde_json::from_str(body).unwrap();
        body.into_request(StreamRouteId::from_uuid(Uuid::nil()))
    }

    /// A login sent without saying is held to TLS, checked against the
    /// public roots and the backends' host.
    #[test]
    fn tls_is_required_unless_turned_off() {
        let request = opened(r#"{"login_user":"workflows_reader","login_password":"pw"}"#)
            .ok()
            .expect("the opening reads");

        assert!(matches!(
            request.change,
            StreamWorkflowChange::Open {
                tls: TlsRequest::Required {
                    authority: TlsAuthority::PublicRoots,
                    name: CertificateName::SharedBackendHost
                },
                ..
            }
        ));
    }

    /// Ann's database serves no TLS and she says so by name.
    #[test]
    fn tls_is_off_when_chosen() {
        let request =
            opened(r#"{"login_user":"workflows_reader","login_password":"pw","tls":"off"}"#)
                .ok()
                .expect("the opening reads");

        assert!(matches!(
            request.change,
            StreamWorkflowChange::Open {
                tls: TlsRequest::Off,
                ..
            }
        ));
    }

    /// A server name beside `off` is refused rather than checking nothing.
    #[test]
    fn a_name_beside_tls_off_is_refused() {
        let request = opened(
            r#"{"login_user":"workflows_reader","login_password":"pw","tls":"off","tls_server_name":"db.internal"}"#,
        );

        assert!(request.is_err());
    }

    /// An authority that is not a certificate is refused.
    #[test]
    fn an_authority_that_is_no_certificate_is_refused() {
        let request = opened(
            r#"{"login_user":"workflows_reader","login_password":"pw","tls_authority":"not a certificate"}"#,
        );

        assert!(request.is_err());
    }
}
