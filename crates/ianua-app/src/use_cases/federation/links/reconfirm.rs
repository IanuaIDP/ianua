//! Reconfirm link: the holder of an account confirms its link to a
//! connection's provider again, after the provider's signing key changed.
//!
//! Whoever holds a new signing key could sign in as anyone linked through
//! the connection, so an account holding built-in permissions stops
//! signing in through it until its holder confirms the link. They do it
//! from a sign-in of their own, proving who they are again just now.

use std::sync::Arc;

use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ConnectionId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::federation::{ConnectionStore, FederatedLinkStore};
use crate::services::authentication::fresh_proof::{FreshProofs, ReenteredProof, proved_person};
use crate::use_case::Command;
use crate::use_cases::federation::lookup::{existing_connection, existing_link};

/// Which link to confirm, and the holder's proof that it is them.
pub struct ReconfirmRequest {
    /// The connection whose provider the account is linked to.
    pub connection_id: ConnectionId,
    /// What the holder typed again just now to prove who they are.
    pub proof: ReenteredProof,
}

/// The ports [`ReconfirmUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ReconfirmPorts {
    /// The links between accounts and providers.
    pub links: Arc<dyn FederatedLinkStore>,
    /// The tenant's connections, for the provider's name on the record.
    pub connections: Arc<dyn ConnectionStore>,
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Turns what the holder typed again into a fresh proof of them.
    pub fresh_proofs: Arc<dyn FreshProofs>,
}

/// Confirms the caller's own link to a connection's provider again.
pub struct ReconfirmUseCase {
    ports: ReconfirmPorts,
}

impl ReconfirmUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ReconfirmPorts) -> Self {
        Self { ports }
    }
}

impl Command for ReconfirmUseCase {
    type Caller = CallerContext;
    type Input = ReconfirmRequest;
    type Output = Result<(), AppError>;

    /// Confirms the caller's link through `request.connection_id` again,
    /// so the provider signs their account in once more, and records
    /// `federation.link_reconfirmed`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller came with no tenant
    ///   session, or it no longer counts.
    /// - `AppError::Forbidden` when what they typed again does not prove
    ///   who they are, and the other cases [`FreshProofs::prove`] lists.
    /// - `AppError::NotFound` when their account is not linked through the
    ///   connection.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ReconfirmRequest,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let (person, fresh) = proved_person(
            self.ports.tenant_authorities.as_ref(),
            self.ports.fresh_proofs.as_ref(),
            ctx,
            request.proof,
        )
        .await?;
        let links = self.ports.links.as_ref();
        let account_id = person.account.id();
        let mut link = existing_link(links, &tenant, &request.connection_id, account_id).await?;
        let connections = self.ports.connections.as_ref();
        let connection = existing_connection(connections, &tenant, &request.connection_id).await?;
        link.reconfirm(&person.account, &fresh, &connection)
            .map_err(AppError::from_domain)?;

        links.update(&tenant, &link).await.or_internal()?;
        auditor
            .dispatch(&link.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::events::data::FieldValue;
    use ianua_domain::types::UserId;
    use time::Duration;

    use super::*;
    use crate::context::CallerIdentity;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{right_password, wrong_password};
    use crate::test_support::federation::{
        FakeConnectionStore, FakeFederatedLinkStore, test_connection, test_link,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The caller, Ann.
    fn ann() -> UserId {
        match test_ctx().identity() {
            CallerIdentity::TenantUser(id) => *id,
            _ => unreachable!("the test caller is a tenant user"),
        }
    }

    /// Ann's link to the Okta connection, made and confirmed a week ago.
    struct Linked {
        connection_id: ConnectionId,
        links: Arc<FakeFederatedLinkStore>,
        connections: Arc<FakeConnectionStore>,
    }

    impl Linked {
        fn last_week() -> Self {
            let connection_id = ConnectionId::new();
            let links = Arc::new(FakeFederatedLinkStore::empty());
            let link = test_link(connection_id, ann(), clock::now() - Duration::weeks(1));
            block_on(links.save(&test_ctx().tenant(), &link)).unwrap();
            let connection = test_connection(connection_id, ConnectionStatus::Active);
            Self {
                connection_id,
                links,
                connections: Arc::new(FakeConnectionStore::holding(
                    &test_ctx().tenant(),
                    [connection],
                )),
            }
        }

        fn ports(&self) -> ReconfirmPorts {
            ReconfirmPorts {
                links: self.links.clone(),
                connections: self.connections.clone(),
                ..ReconfirmPorts::fakes()
            }
        }

        fn request(&self, proof: ReenteredProof) -> ReconfirmRequest {
            ReconfirmRequest {
                connection_id: self.connection_id,
                proof,
            }
        }

        fn confirmed_today(&self) -> bool {
            let (tenant, ann) = (test_ctx().tenant(), ann());
            let found = self.links.find_by_user(&tenant, &self.connection_id, &ann);
            let link = block_on(found).unwrap().unwrap();
            link.confirmed_at() > clock::now() - Duration::days(1)
        }
    }

    fn reconfirm(ports: ReconfirmPorts, request: ReconfirmRequest) -> Result<(), AppError> {
        reconfirm_recorded(ports, request, &Arc::new(FakeEventDispatcher::new()))
    }

    fn reconfirm_recorded(
        ports: ReconfirmPorts,
        request: ReconfirmRequest,
        events: &Arc<FakeEventDispatcher>,
    ) -> Result<(), AppError> {
        block_on(ReconfirmUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(events.clone()),
            request,
        ))
    }

    /// Okta's signing key changed, and Ann, who types her password again,
    /// confirms her Okta link. It is saved as confirmed now.
    #[test]
    fn the_holder_confirms_her_link_again() {
        let linked = Linked::last_week();

        reconfirm(linked.ports(), linked.request(right_password())).unwrap();

        assert!(linked.confirmed_today());
    }

    /// Ann confirms her Okta link again. The audit trail records it, naming
    /// her account.
    #[test]
    fn confirming_a_link_again_is_recorded() {
        let linked = Linked::last_week();
        let events = Arc::new(FakeEventDispatcher::new());

        reconfirm_recorded(linked.ports(), linked.request(right_password()), &events).unwrap();

        let payload = events.payload_of("federation.link_reconfirmed");
        let Some(FieldValue::Reference(user)) = payload.value("user") else {
            panic!("the account is not referenced");
        };
        assert_eq!(user.id(), ann().to_string());
    }

    /// Ann confirms a link through a connection she is not linked to. It
    /// is not found.
    #[test]
    fn a_link_that_is_not_there_is_not_found() {
        let linked = Linked::last_week();
        let request = ReconfirmRequest {
            connection_id: ConnectionId::new(),
            proof: right_password(),
        };

        let result = reconfirm(linked.ports(), request);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A wrong password prevents reconfirming Ann's link through her
    /// session; its confirmation remains older than today.
    #[test]
    fn a_wrong_password_is_refused() {
        let linked = Linked::last_week();

        let result = reconfirm(linked.ports(), linked.request(wrong_password()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(!linked.confirmed_today());
    }

    /// A signed-out session cannot reconfirm the link even with the correct
    /// password; its confirmation remains older than today.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let linked = Linked::last_week();
        let ports = ReconfirmPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..linked.ports()
        };

        let result = reconfirm(ports, linked.request(right_password()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(!linked.confirmed_today());
    }
}
