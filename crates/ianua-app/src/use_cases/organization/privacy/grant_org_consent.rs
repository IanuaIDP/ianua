//! A member agrees to terms, such as a privacy policy or marketing mail,
//! from their own signed-in session.

use std::sync::Arc;

use ianua_domain::domains::identity::privacy::consent::{ConsentDecision, ConsentTerms};
use ianua_domain::domains::organization::members::privacy::consent::OrgConsentRecord;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::ActorRef;

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrgConsentStore;
use crate::use_case::Command;

/// The ports [`GrantOrgConsentUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GrantOrgConsentPorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// Members' consent records.
    pub consents: Arc<dyn OrgConsentStore>,
}

/// Records a member's consent.
pub struct GrantOrgConsentUseCase {
    ports: GrantOrgConsentPorts,
}

impl GrantOrgConsentUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: GrantOrgConsentPorts) -> Self {
        Self { ports }
    }
}

impl Command for GrantOrgConsentUseCase {
    type Caller = OrgCaller;
    type Input = ConsentTerms;
    type Output = Result<(), AppError>;

    /// Records that the member signed in to the caller's session agrees to
    /// `terms`, from the address their request came from, and records
    /// `organization.org_user_consent_granted`. Agreeing again records
    /// again: a new version, or a confirmation.
    ///
    /// Consent is the member's own word, so nobody gives it for them, and
    /// a key they minted does not give it either.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller acts through a key.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        terms: ConsentTerms,
    ) -> Result<(), AppError> {
        let (_, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        let mut record = OrgConsentRecord::record(
            actor.member(),
            terms,
            ConsentDecision::Granted,
            caller.audit_context().ip_address().clone(),
            &control,
        )
        .map_err(AppError::from_domain)?;
        self.ports.consents.save(&record).await.or_internal()?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*caller.member()), record.take_events())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::privacy::consent::ConsentType;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::{Label, Scope};

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::FakeOrgConsentStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: GrantOrgConsentUseCase,
        consents: Arc<FakeOrgConsentStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    fn as_caller(actors: FakeOrgActors) -> Setup {
        let consents = Arc::new(FakeOrgConsentStore::empty());
        Setup {
            uc: GrantOrgConsentUseCase::new(GrantOrgConsentPorts {
                org_actors: Arc::new(actors),
                consents: consents.clone(),
            }),
            consents,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn agree(setup: &Setup) -> Result<(), AppError> {
        let terms = ConsentTerms {
            consent_type: ConsentType::Marketing,
            version: Label::new("version", "v2").unwrap(),
        };
        block_on(setup.uc.execute(
            &test_org_caller(),
            &test_auditor(setup.audit.clone()),
            terms,
        ))
    }

    /// Sam agrees to marketing mail. His consent is kept and recorded.
    #[test]
    fn a_member_agrees_for_themselves() {
        let setup = as_caller(FakeOrgActors::in_role(OrgRole::Member));

        agree(&setup).unwrap();

        assert_eq!(setup.consents.count(), 1);
        assert_eq!(
            *setup.audit.records.lock().unwrap(),
            ["organization.org_user_consent_granted"]
        );
    }

    /// An API key cannot grant consent for its member, so no consent or
    /// audit event is recorded.
    #[test]
    fn a_key_gives_no_consent() {
        let scope = Scope::new("org:members:update").unwrap();
        let setup = as_caller(FakeOrgActors::through_key(OrgRole::Owner, vec![scope]));

        let result = agree(&setup);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.consents.count(), 0);
        assert!(setup.audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot grant consent, and no consent is saved.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = as_caller(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = agree(&setup);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(setup.consents.count(), 0);
    }
}
