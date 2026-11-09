//! Grant consent: the signed-in person agrees to a version of the terms, a
//! policy or a use of their data.
//!
//! Consent is append-only: each decision is a new record, so the history of
//! what was agreed and when stays, as GDPR Article 7 asks.

use std::sync::Arc;

use ianua_domain::domains::identity::privacy::consent::{
    ConsentDecision, ConsentRecord, ConsentTerms,
};
use ianua_domain::shared::events::raised::Raises as _;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::ConsentStore;
use crate::use_case::Command;

/// The ports [`GrantConsentUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GrantConsentPorts {
    /// Keeps consent records.
    pub consent_store: Arc<dyn ConsentStore>,
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Records the signed-in person's consent.
pub struct GrantConsentUseCase {
    ports: GrantConsentPorts,
}

impl GrantConsentUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: GrantConsentPorts) -> Self {
        Self { ports }
    }
}

impl Command for GrantConsentUseCase {
    type Caller = CallerContext;
    type Input = ConsentTerms;
    type Output = Result<(), AppError>;

    /// Records that the person signed in to the caller's session agrees to
    /// `terms`, from the address their request came from. Agreeing again
    /// records again: a new version, or a confirmation.
    ///
    /// Consent is the person's own word, so nobody gives it for them.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller came with no tenant
    ///   session, or it no longer counts.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        terms: ConsentTerms,
    ) -> Result<(), AppError> {
        let person = self.ports.tenant_authorities.signed_in(ctx).await?;
        let mut record = ConsentRecord::record(
            *person.account.id(),
            terms,
            ConsentDecision::Granted,
            ctx.audit_context().ip_address().clone(),
            &person.signed_in,
        )
        .map_err(AppError::from_domain)?;
        record
            .name_person(&person.account)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        self.ports
            .consent_store
            .save(&tenant, &record)
            .await
            .or_internal()?;
        auditor
            .dispatch(&record.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::privacy::consent::ConsentType;
    use ianua_domain::types::Label;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::FakeConsentStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn marketing() -> ConsentTerms {
        ConsentTerms {
            consent_type: ConsentType::Marketing,
            version: Label::new("version", "mkt-2026").unwrap(),
        }
    }

    fn grant(ports: GrantConsentPorts) -> Result<(), AppError> {
        grant_recorded(ports, &Arc::new(FakeEventDispatcher::new()))
    }

    fn grant_recorded(
        ports: GrantConsentPorts,
        events: &Arc<FakeEventDispatcher>,
    ) -> Result<(), AppError> {
        block_on(GrantConsentUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(events.clone()),
            marketing(),
        ))
    }

    /// Ann agrees to marketing mail. Her consent is recorded.
    #[test]
    fn the_person_records_their_consent() {
        let consents = Arc::new(FakeConsentStore::empty());

        grant(GrantConsentPorts {
            consent_store: consents.clone(),
            ..GrantConsentPorts::fakes()
        })
        .unwrap();

        assert_eq!(consents.count(), 1);
    }

    /// Ann agrees to marketing mail. The audit trail records the kind of
    /// consent and the version she agreed to.
    #[test]
    fn a_consent_is_recorded_with_its_kind_and_version() {
        let events = Arc::new(FakeEventDispatcher::new());

        grant_recorded(GrantConsentPorts::fakes(), &events).unwrap();

        let payload = events.payload_of("identity.consent_granted");
        assert_eq!(payload.get("consent_type"), Some("marketing"));
        assert_eq!(payload.get("version"), Some("mkt-2026"));
    }

    /// Ann agrees again, to a newer version. Both decisions are kept.
    #[test]
    fn agreeing_again_records_again() {
        let consents = Arc::new(FakeConsentStore::empty());
        let ports = || GrantConsentPorts {
            consent_store: consents.clone(),
            ..GrantConsentPorts::fakes()
        };
        grant(ports()).unwrap();

        grant(ports()).unwrap();

        assert_eq!(consents.count(), 2);
    }

    /// A signed-out person cannot grant marketing consent, and no consent
    /// record is saved.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let consents = Arc::new(FakeConsentStore::empty());

        let result = grant(GrantConsentPorts {
            consent_store: consents.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
        });

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(consents.count(), 0);
    }
}
