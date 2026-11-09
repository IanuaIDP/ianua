//! Answer connection: an integration's service sends the browser back to
//! the platform's one callback address with its code, and the code is
//! swapped for a credential at once, kept sealed until the person who began
//! the connection finishes it.
//!
//! Nobody signs in here; the `state` the browser brings back finds the
//! connection, by its digest. The browser is handed only a one-time code of
//! the platform's own, never the credential.

use std::sync::Arc;

use ianua_domain::domains::workflows::account::connection::PendingConnection;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{PendingConnectionId, SealedSecret};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::workflows::{
    ConnectionSecrets, ConnectionStates, Exchanging, PendingConnectionStore, ServiceSignIn,
    SignInFailure,
};
use crate::services::sealing::{opened_text, sealed_text};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::workflows::accounts::connections::lookup::{
    existing_connection, issued_credential_place, verifier_place,
};

/// What the service sent the browser back with. Holds both in the clear,
/// so it has no `Debug`.
pub struct AnswerRequest {
    /// The `state` the browser carried to the service and back.
    pub state: Secret,
    /// The service's code.
    pub code: Secret,
}

/// The connection answered, and the one-time code the browser carries to
/// the dashboard, which finishes it with the person's session. Holds the
/// code, so it has no `Debug`.
pub struct Answered {
    /// The pending exchange whose provider answer has been accepted.
    pub connection_id: PendingConnectionId,
    /// The one-time code that finishes it.
    pub code: Secret,
}

/// The ports [`AnswerUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AnswerPorts {
    /// Finds the connection a `state` names, across tenants.
    pub states: Arc<dyn ConnectionStates>,
    /// Keeps the connections.
    pub connections: Arc<dyn PendingConnectionStore>,
    /// Swaps the service's code for a credential.
    pub sign_in: Arc<dyn ServiceSignIn>,
    /// Digests the `state` and makes the one-time code.
    pub secrets: Arc<dyn ConnectionSecrets>,
    /// Opens the verifier and seals the credential.
    pub encryptor: Arc<dyn SecretEncryptor>,
}

/// Takes services' answers to connections.
pub struct AnswerUseCase {
    ports: AnswerPorts,
}

impl AnswerUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AnswerPorts) -> Self {
        Self { ports }
    }

    /// The credential the service issues for `code` on `connection`, at
    /// `at`, sealed for the connection.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the service refused the code.
    /// - `AppError::Upstream` when the service could not be reached.
    /// - `AppError::Internal` when the verifier does not open, or the
    ///   credential cannot be sealed.
    async fn issued(
        &self,
        tenant: &ScopedTenant,
        connection: &PendingConnection<ResolvedTenant>,
        code: &Secret,
    ) -> Result<SealedSecret, AppError> {
        let id = connection.id();
        let encryptor = self.ports.encryptor.as_ref();
        let verifier = opened_text(
            encryptor,
            connection.verifier(),
            &verifier_place(tenant, id),
        )
        .await
        .or_internal()?;
        let credential = self
            .ports
            .sign_in
            .exchange(Exchanging {
                integration: connection.integration(),
                code,
                verifier: &verifier,
                place: connection.place(),
            })
            .await
            .map_err(exchange_failed)?;
        sealed_text(
            encryptor,
            credential.expose(),
            &issued_credential_place(tenant, id),
        )
        .await
    }
}

impl Command for AnswerUseCase {
    type Caller = ();
    type Input = AnswerRequest;
    type Output = Result<Answered, AppError>;

    /// Swaps the service's code for a credential on the connection the
    /// `state` names, and hands back the one-time code that finishes it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when no connection has the `state`.
    /// - `AppError::Conflict` when it expired or was already answered.
    /// - `AppError::Domain` when the service refused the code.
    /// - `AppError::Upstream` when the service could not be reached.
    /// - `AppError::Internal` on sealing or storage failure.
    async fn execute(
        &self,
        _caller: &(),
        _auditor: &RequestAuditor,
        request: AnswerRequest,
    ) -> Result<Answered, AppError> {
        let state = self.ports.secrets.digest(&request.state);
        let found = self.ports.states.find(&state).await.or_internal()?;
        let at = found.ok_or(AppError::Unauthenticated)?;
        let tenant = ScopedTenant::from_connection_state(at.tenant_id);
        let mut connection =
            existing_connection(self.ports.connections.as_ref(), &tenant, &at.connection_id)
                .await?;
        let sealed = self.issued(&tenant, &connection, &request.code).await?;
        let (code, code_digest) = self.ports.secrets.generate().or_internal()?;
        connection
            .answer(&state, sealed, code_digest)
            .map_err(AppError::from_domain)?;
        self.ports
            .connections
            .save(&tenant, &connection)
            .await
            .or_internal()?;
        Ok(Answered {
            connection_id: at.connection_id,
            code,
        })
    }
}

/// The error a person sees when the service would not swap its code.
fn exchange_failed(failure: SignInFailure) -> AppError {
    match failure {
        SignInFailure::Refused => AppError::Domain(DomainError::invalid(message!(
            "workflows-the-service-refused-the-sign-in",
            "the service refused the sign-in; begin connecting again"
        ))),
        SignInFailure::Unreachable => AppError::Upstream(Box::new(DomainError::infra_msg(
            "the service could not be reached to finish the sign-in",
        ))),
    }
}
