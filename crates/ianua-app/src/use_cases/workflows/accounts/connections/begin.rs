//! Begin connection: a person asks to connect an account by signing in at
//! the integration's service, and is handed the address to send their
//! browser to.

use std::sync::Arc;

use ianua_domain::domains::workflows::account::connection::{
    ConnectionRequest, PendingConnection, StartConnectionParams,
};
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{PendingConnectionId, SealedSecret, TokenHash};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::workflows::{
    ConnectionSecrets, PendingConnectionStore, PlaceAsked, ServiceSignIn, SignInAddress,
    SignInRequest,
};
use crate::services::sealing::sealed_text;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::workflows::accounts::connections::lookup::verifier_place;

/// A connection begun: the address to send the browser to.
#[derive(Debug)]
pub struct Begun {
    /// The connection, which finishing it names.
    pub connection_id: PendingConnectionId,
    /// Where to send the browser to sign in at the service.
    pub address: SignInAddress,
}

/// The ports [`BeginUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct BeginPorts {
    /// Keeps the connections.
    pub connections: Arc<dyn PendingConnectionStore>,
    /// The services a person may sign in at, and their addresses.
    pub sign_in: Arc<dyn ServiceSignIn>,
    /// Makes the `state` and the verifier.
    pub secrets: Arc<dyn ConnectionSecrets>,
    /// Seals the verifier.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Begins account connections.
pub struct BeginUseCase {
    ports: BeginPorts,
}

impl BeginUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: BeginPorts) -> Self {
        Self { ports }
    }

    /// Where the browser is sent to sign in at `integration`'s service for
    /// the connection `id`, with the digest of its `state` and its verifier
    /// sealed for the connection.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the integration offers no sign-in here.
    /// - `AppError::Internal` when no randomness is to be had, or the
    ///   verifier cannot be sealed.
    async fn ticket(
        &self,
        tenant: &ScopedTenant,
        id: &PendingConnectionId,
        integration: &IntegrationKey,
    ) -> Result<Ticket, AppError> {
        let (state, state_digest) = self.ports.secrets.generate().or_internal()?;
        let (verifier, _) = self.ports.secrets.generate().or_internal()?;
        let sealed = sealed_text(
            self.ports.encryptor.as_ref(),
            verifier.expose(),
            &verifier_place(tenant, id),
        )
        .await?;
        let address = self.ports.sign_in.authorize_address(
            integration,
            SignInRequest {
                state: &state,
                verifier: &verifier,
            },
        )?;
        Ok(Ticket {
            address,
            state: state_digest,
            verifier: sealed,
        })
    }
}

/// What a connection begins with: where the browser goes, and what is kept
/// to tie the service's answer to it.
struct Ticket {
    address: SignInAddress,
    state: TokenHash,
    verifier: SealedSecret,
}

impl Command for BeginUseCase {
    type Caller = CallerContext;
    type Input = ConnectionRequest;
    type Output = Result<Begun, AppError>;

    /// Begins connecting the account `request` describes, for the person
    /// `ctx` names, and records `workflows.account_connection_started`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not connect accounts.
    /// - `AppError::Domain` when the integration cannot be connected by
    ///   signing in here.
    /// - `AppError::Internal` on sealing, storage or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ConnectionRequest,
    ) -> Result<Begun, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        ensure_offered(self.ports.sign_in.as_ref(), &request)?;
        ensure_place_fits(self.ports.sign_in.as_ref(), &request)?;
        let tenant = ctx.tenant();
        let id = PendingConnectionId::new();
        let ticket = self.ticket(&tenant, &id, &request.integration).await?;
        let params = StartConnectionParams {
            id,
            request,
            state: ticket.state,
            verifier: ticket.verifier,
        };
        let mut connection = PendingConnection::start(params, &WorkflowControl::new(&authority))
            .map_err(AppError::from_domain)?;
        self.ports
            .connections
            .save(&tenant, &connection)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), connection.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(Begun {
            connection_id: id,
            address: ticket.address,
        })
    }
}

/// Refuses an integration that cannot be connected by signing in here:
/// its service offers no sign-in, or the deployment registered no app.
fn ensure_offered(
    sign_in: &dyn ServiceSignIn,
    request: &ConnectionRequest,
) -> Result<(), AppError> {
    if sign_in.offers(&request.integration) {
        return Ok(());
    }
    Err(AppError::Domain(DomainError::invalid(message!(
        "workflows-the-integration-offers-no-sign-in",
        format!(
            "{} cannot be connected by signing in here; connect it with a credential instead",
            request.integration
        )
    ))))
}

/// Refuses a request naming a place the sign-in does not ask for, or
/// leaving out one it does: Bob connecting Azure DevOps names the
/// organization the account works in, and nobody names one for GitHub.
fn ensure_place_fits(
    sign_in: &dyn ServiceSignIn,
    request: &ConnectionRequest,
) -> Result<(), AppError> {
    match (sign_in.asks_for(&request.integration), &request.place) {
        (PlaceAsked::Nothing, None) | (PlaceAsked::Named(_), Some(_)) => Ok(()),
        (PlaceAsked::Named(word), None) => Err(AppError::Domain(DomainError::invalid(message!(
            "workflows-the-sign-in-needs-a-place",
            format!(
                "connecting {} by signing in needs the {word} the account works in",
                request.integration
            )
        )))),
        (PlaceAsked::Nothing, Some(_)) => Err(AppError::Domain(DomainError::invalid(message!(
            "workflows-the-sign-in-takes-no-place",
            format!(
                "connecting {} by signing in takes no place; leave it out",
                request.integration
            )
        )))),
    }
}
