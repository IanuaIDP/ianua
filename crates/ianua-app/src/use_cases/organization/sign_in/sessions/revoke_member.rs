//! Ending another member's session: a member who may update members, or
//! the platform through an operator, signs it out.

use std::sync::Arc;

use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{OrganizationId, SessionId};

use crate::acting::{OperatorAuthorities, OrgActors};
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgSessionStore, OrganizationStore};
use crate::use_case::Command;
use crate::use_cases::organization::lookup::existing_org_session;
use crate::use_cases::organization::steward::{OrganizationSteward, StewardSources, Stewarding};

/// The session to end, and the organization it is in.
pub struct RevokeMemberSessionRequest {
    /// The organization the session belongs to.
    pub organization_id: OrganizationId,
    /// The session to end.
    pub session_id: SessionId,
}

/// The ports [`RevokeMemberSessionUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokeMemberSessionPorts {
    /// Members' sessions.
    pub sessions: Arc<dyn OrgSessionStore>,
    /// Organizations, for the one an operator names.
    pub organizations: Arc<dyn OrganizationStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// What an operator may do on the platform.
    pub operators: Arc<dyn OperatorAuthorities>,
}

/// Ends a member's session on behalf of the organization or the platform.
pub struct RevokeMemberSessionUseCase {
    ports: RevokeMemberSessionPorts,
}

impl RevokeMemberSessionUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RevokeMemberSessionPorts) -> Self {
        Self { ports }
    }
}

impl Command for RevokeMemberSessionUseCase {
    type Caller = OrganizationSteward;
    type Input = RevokeMemberSessionRequest;
    type Output = Result<(), AppError>;

    /// Ends the session `request` names and records
    /// `organization.org_session_revoked`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when a member may not update members, or the
    ///   operator is disabled or not theirs.
    /// - `AppError::NotFound` when the organization or the session is
    ///   unknown, or a member names another organization.
    /// - `AppError::Domain` when the session was already ended.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &OrganizationSteward,
        auditor: &RequestAuditor,
        request: RevokeMemberSessionRequest,
    ) -> Result<(), AppError> {
        let sources = StewardSources {
            org_actors: self.ports.org_actors.as_ref(),
            operators: self.ports.operators.as_ref(),
            organizations: self.ports.organizations.as_ref(),
        };
        let stewarding = Stewarding::resolve(sources, caller, &request.organization_id).await?;
        let store = self.ports.sessions.as_ref();
        let mut session =
            existing_org_session(store, &request.organization_id, &request.session_id).await?;
        stewarding.decide(|by| session.revoke(by))?;
        store.save(&session).await.or_internal()?;
        auditor
            .dispatch_by(&stewarding.audit_actor(), session.take_events())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::{OperatorId, OrgUserId, OrganizationId, TenantId};

    use super::*;
    use crate::test_support::acting::{FakeOperatorAuthorities, FakeOrgActors, Refusal};
    use crate::test_support::notifications::operator_caller;
    use crate::test_support::organization::{
        RecordingOrgSessionStore, org_session_for, org_store_with, password_only, test_org,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: RevokeMemberSessionUseCase,
        sessions: Arc<RecordingOrgSessionStore>,
        audit: Arc<FakeEventDispatcher>,
        session_id: SessionId,
    }

    impl Setup {
        /// Sam's session in the test caller's organization, Acme.
        fn new(ports: RevokeMemberSessionPorts) -> Self {
            let organization_id = test_org_caller().organization_id();
            let session = org_session_for(
                OrgUserId::new(),
                organization_id,
                TenantId::new(),
                password_only(),
            );
            let session_id = *session.id();
            let sessions = Arc::new(RecordingOrgSessionStore::holding([session]));
            Self {
                uc: RevokeMemberSessionUseCase::new(RevokeMemberSessionPorts {
                    sessions: sessions.clone(),
                    organizations: org_store_with([test_org(organization_id, "acme")]),
                    ..ports
                }),
                sessions,
                audit: Arc::new(FakeEventDispatcher::new()),
                session_id,
            }
        }

        fn with_actors(actors: FakeOrgActors) -> Self {
            Self::new(RevokeMemberSessionPorts {
                org_actors: Arc::new(actors),
                ..RevokeMemberSessionPorts::fakes()
            })
        }

        fn revoke_as(&self, caller: &OrganizationSteward) -> Result<(), AppError> {
            let request = RevokeMemberSessionRequest {
                organization_id: test_org_caller().organization_id(),
                session_id: self.session_id,
            };
            block_on(
                self.uc
                    .execute(caller, &test_auditor(self.audit.clone()), request),
            )
        }

        fn revoke(&self) -> Result<(), AppError> {
            self.revoke_as(&OrganizationSteward::Member(test_org_caller()))
        }

        fn ended(&self) -> bool {
            self.sessions
                .saved()
                .iter()
                .any(|session| *session.id() == self.session_id && !session.is_valid())
        }
    }

    fn platform() -> OrganizationSteward {
        OrganizationSteward::Platform(operator_caller(OperatorId::new()))
    }

    /// Olivia, an owner of Acme, signs Sam out. His session ends, stops
    /// answering at once, and the sign-out is recorded.
    #[test]
    fn an_owner_ends_a_members_session() {
        let setup = Setup::with_actors(FakeOrgActors::in_role(OrgRole::Owner));

        setup.revoke().unwrap();

        assert!(setup.ended());
        assert_eq!(
            *setup.audit.records.lock().unwrap(),
            ["organization.org_session_revoked"]
        );
    }

    /// The platform signs Sam out, as after a security incident. His
    /// session ends.
    #[test]
    fn the_platform_ends_a_members_session() {
        let setup = Setup::with_actors(FakeOrgActors::refusing(Refusal::Forbidden));

        setup.revoke_as(&platform()).unwrap();

        assert!(setup.ended());
    }

    /// A plain member cannot revoke another member's session, which remains valid.
    #[test]
    fn a_plain_member_may_not_end_another_members_session() {
        let setup = Setup::with_actors(FakeOrgActors::in_role(OrgRole::Member));

        let result = setup.revoke();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(!setup.ended());
    }

    /// A signed-out caller cannot revoke another member's session.
    #[test]
    fn a_signed_out_member_is_refused() {
        let setup = Setup::with_actors(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = setup.revoke();

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(!setup.ended());
    }

    /// Gina's session in Globex, kept beside Acme, where Olivia is an owner.
    struct Globex {
        id: OrganizationId,
        ginas_session: SessionId,
        sessions: Arc<RecordingOrgSessionStore>,
        uc: RevokeMemberSessionUseCase,
    }

    impl Globex {
        fn new() -> Self {
            let id = OrganizationId::new();
            let ginas = org_session_for(OrgUserId::new(), id, TenantId::new(), password_only());
            let ginas_session = *ginas.id();
            let sessions = Arc::new(RecordingOrgSessionStore::holding([ginas]));
            let uc = RevokeMemberSessionUseCase::new(RevokeMemberSessionPorts {
                org_actors: Arc::new(FakeOrgActors::in_role(OrgRole::Owner)),
                sessions: sessions.clone(),
                organizations: org_store_with([
                    test_org(test_org_caller().organization_id(), "acme"),
                    test_org(id, "globex"),
                ]),
                ..RevokeMemberSessionPorts::fakes()
            });
            Self {
                id,
                ginas_session,
                sessions,
                uc,
            }
        }

        /// Olivia asks to end Gina's session, naming it as one of
        /// `organization_id`'s.
        fn olivia_ends_ginas_session_in(
            &self,
            organization_id: OrganizationId,
        ) -> Result<(), AppError> {
            let request = RevokeMemberSessionRequest {
                organization_id,
                session_id: self.ginas_session,
            };
            let caller = OrganizationSteward::Member(test_org_caller());
            let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
            block_on(self.uc.execute(&caller, &auditor, request))
        }

        fn ginas_session_ended(&self) -> bool {
            self.sessions
                .saved()
                .iter()
                .any(|session| *session.id() == self.ginas_session && !session.is_valid())
        }
    }

    /// A foreign session named under the caller's organization is not found
    /// and is not revoked.
    #[test]
    fn another_organizations_session_is_not_found_under_ones_own() {
        let globex = Globex::new();

        let result = globex.olivia_ends_ginas_session_in(test_org_caller().organization_id());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(!globex.ginas_session_ended());
    }

    /// An owner cannot revoke a session by naming another organization;
    /// the foreign session remains valid.
    #[test]
    fn an_owner_of_one_organization_ends_no_session_in_another() {
        let globex = Globex::new();

        let result = globex.olivia_ends_ginas_session_in(globex.id);

        assert!(result.is_err());
        assert!(!globex.ginas_session_ended());
    }

    /// An operator refused by the authority port cannot revoke the member's session.
    #[test]
    fn a_refused_operator_ends_nothing() {
        let setup = Setup::new(RevokeMemberSessionPorts {
            operators: Arc::new(FakeOperatorAuthorities::refusing(Refusal::Forbidden)),
            ..RevokeMemberSessionPorts::fakes()
        });

        let result = setup.revoke_as(&platform());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(!setup.ended());
    }
}
