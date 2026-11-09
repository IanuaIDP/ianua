//! Revoke consent: a person withdraws consent they gave, themselves or
//! through someone who may record it for them.

use std::sync::Arc;

use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::domains::identity::privacy::consent::{
    ConsentDecision, ConsentRecord, ConsentTerms, ConsentType,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::UserId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::AccessRecordStore;
use crate::ports::identity::{ConsentStore, UserStore};
use crate::services::lookup::existing_user;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::account_control::account_control;
use crate::use_cases::identity::whose::Whose;

/// The ports [`RevokeConsentUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokeConsentPorts {
    /// Keeps consent records.
    pub consent_store: Arc<dyn ConsentStore>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// The tenant's accounts, to name the person on the record.
    pub users: Arc<dyn UserStore>,
    /// Who the caller is and what they hold in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Whose consent to withdraw, and on which terms.
pub struct RevokeConsentRequest {
    /// Whose consent it is.
    pub whose: Whose,
    /// The kind and version of consent withdrawn.
    pub terms: ConsentTerms,
}

/// Records a withdrawal of consent.
pub struct RevokeConsentUseCase {
    ports: RevokeConsentPorts,
}

impl RevokeConsentUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RevokeConsentPorts) -> Self {
        Self { ports }
    }

    /// The withdrawal `whose` asks for, made by the person themselves or
    /// for them, naming the person on the record.
    async fn withdrawal(
        &self,
        ctx: &CallerContext,
        whose: Whose,
        terms: ConsentTerms,
    ) -> Result<ConsentRecord<ResolvedTenant>, AppError> {
        match whose {
            Whose::Own => self.own_withdrawal(ctx, terms).await,
            Whose::OnBehalfOf(user_id) => self.withdrawal_for(ctx, user_id, terms).await,
        }
    }

    /// The signed-in person withdrawing their own consent.
    async fn own_withdrawal(
        &self,
        ctx: &CallerContext,
        terms: ConsentTerms,
    ) -> Result<ConsentRecord<ResolvedTenant>, AppError> {
        let person = self.ports.tenant_authorities.signed_in(ctx).await?;
        let user_id = *person.account.id();
        self.ensure_granted(ctx, user_id, terms.consent_type)
            .await?;
        let ip_address = ctx.audit_context().ip_address().clone();
        let mut record = ConsentRecord::record(
            user_id,
            terms,
            ConsentDecision::Withdrawn,
            ip_address,
            &person.signed_in,
        )
        .map_err(AppError::from_domain)?;
        record
            .name_person(&person.account)
            .map_err(AppError::from_domain)?;
        Ok(record)
    }

    /// Staff recording a withdrawal for `user_id`. The consent given and the
    /// account are read only once the domain allowed it, so a refused caller
    /// learns nothing about which accounts exist or what they agreed to.
    async fn withdrawal_for(
        &self,
        ctx: &CallerContext,
        user_id: UserId,
        terms: ConsentTerms,
    ) -> Result<ConsentRecord<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let records = self.ports.access_records.as_ref();
        let tenant = ctx.tenant();
        let recording = AccountAction::RecordForThem;
        let control = account_control(records, &tenant, &authority, &user_id, recording).await?;
        let consent_type = terms.consent_type;
        let ip_address = ctx.audit_context().ip_address().clone();
        let mut record = ConsentRecord::withdraw_for(user_id, terms, ip_address, &control)
            .map_err(AppError::from_domain)?;
        self.ensure_granted(ctx, user_id, consent_type).await?;
        let account = existing_user(self.ports.users.as_ref(), &ctx.tenant(), &user_id).await?;
        record
            .name_person(&account)
            .map_err(AppError::from_domain)?;
        Ok(record)
    }

    async fn ensure_granted(
        &self,
        ctx: &CallerContext,
        user_id: UserId,
        consent_type: ConsentType,
    ) -> Result<(), AppError> {
        ensure_latest_granted(
            self.ports.consent_store.as_ref(),
            &ctx.tenant(),
            user_id,
            consent_type,
        )
        .await
    }
}

impl Command for RevokeConsentUseCase {
    type Caller = CallerContext;
    type Input = RevokeConsentRequest;
    type Output = Result<(), AppError>;

    /// Records that consent on `request.terms` is withdrawn, as a new record
    /// marked withdrawn. Withdrawing is as easy as giving: the person does it
    /// from their own session, or someone who may record it for them does,
    /// since withdrawing only lowers what is done with their data.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not record it for that
    ///   person, or the person holds more than the caller.
    /// - `AppError::NotFound` if no consent was given before.
    /// - `AppError::Conflict` if it is already withdrawn.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: RevokeConsentRequest,
    ) -> Result<(), AppError> {
        let RevokeConsentRequest { whose, terms } = request;
        let mut record = self.withdrawal(ctx, whose, terms).await?;
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

/// Refuses unless `user_id`'s latest decision on `consent_type` gave it.
async fn ensure_latest_granted(
    store: &dyn ConsentStore,
    tenant: &ScopedTenant,
    user_id: UserId,
    consent_type: ConsentType,
) -> Result<(), AppError> {
    let latest = store
        .find_latest(tenant, &user_id, consent_type)
        .await
        .or_internal()?;
    let Some(latest) = latest else {
        return Err(AppError::NotFound(message!(
            "identity-no-consent-record-found",
            "no consent record found"
        )));
    };
    if !latest.granted() {
        return Err(AppError::Conflict(message!(
            "identity-consent-already-revoked",
            "consent already revoked"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::types::Label;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::{
        FakeConsentStore, FakeUserStore, access_where_holds, stored_consent,
    };
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_ctx_with,
    };

    fn marketing() -> ConsentTerms {
        ConsentTerms {
            consent_type: ConsentType::Marketing,
            version: Label::new("version", "v1").unwrap(),
        }
    }

    /// Ann, who agreed to marketing mail, signed in, and the consents kept.
    struct Agreed {
        ann: UserId,
        consents: Arc<FakeConsentStore>,
    }

    impl Agreed {
        fn with(decision: Option<ConsentDecision>) -> Self {
            let ann = UserId::new();
            let consents = Arc::new(FakeConsentStore::empty());
            if let Some(decision) = decision {
                let record = stored_consent(ann, ConsentType::Marketing, decision);
                block_on(consents.save(&test_ctx().tenant(), &record)).unwrap();
            }
            Self { ann, consents }
        }

        fn granted() -> Self {
            Self::with(Some(ConsentDecision::Granted))
        }

        fn ports(&self) -> RevokeConsentPorts {
            RevokeConsentPorts {
                consent_store: self.consents.clone(),
                users: Arc::new(FakeUserStore::with_user(self.ann, "ann@acme.test")),
                ..RevokeConsentPorts::fakes()
            }
        }

        fn revoke(&self, ports: RevokeConsentPorts, whose: Whose) -> Result<(), AppError> {
            self.revoke_recorded(ports, whose, &Arc::new(FakeEventDispatcher::new()))
        }

        fn revoke_recorded(
            &self,
            ports: RevokeConsentPorts,
            whose: Whose,
            events: &Arc<FakeEventDispatcher>,
        ) -> Result<(), AppError> {
            let seeded = test_ctx();
            let as_ann = test_ctx_with(seeded.organization_id(), seeded.tenant_id(), self.ann);
            block_on(RevokeConsentUseCase::new(ports).execute(
                &as_ann,
                &test_auditor(events.clone()),
                RevokeConsentRequest {
                    whose,
                    terms: marketing(),
                },
            ))
        }
    }

    /// Support withdraws Ann's marketing consent for her. The audit trail
    /// names Ann, the kind of consent and the version it was given for.
    #[test]
    fn a_withdrawal_for_the_person_is_recorded_naming_them() {
        let agreed = Agreed::granted();
        let events = Arc::new(FakeEventDispatcher::new());

        agreed
            .revoke_recorded(agreed.ports(), Whose::OnBehalfOf(agreed.ann), &events)
            .unwrap();

        let payload = events.payload_of("identity.consent_revoked");
        assert_eq!(payload.get("consent_type"), Some("marketing"));
        assert_eq!(payload.get("version"), Some("v1"));
        assert_eq!(
            events
                .label_of("identity.consent_revoked", "user")
                .as_deref(),
            Some("ann@acme.test")
        );
    }

    /// Ann withdraws her consent. A withdrawal is recorded beside it.
    #[test]
    fn the_person_withdraws_their_consent() {
        let agreed = Agreed::granted();

        agreed.revoke(agreed.ports(), Whose::Own).unwrap();

        assert_eq!(agreed.consents.count(), 2);
    }

    /// Ann never agreed. There is nothing to withdraw.
    #[test]
    fn nothing_given_is_not_found() {
        let agreed = Agreed::with(None);

        let result = agreed.revoke(agreed.ports(), Whose::Own);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann already withdrew. Withdrawing again is a conflict.
    #[test]
    fn a_withdrawn_consent_is_a_conflict() {
        let agreed = Agreed::with(Some(ConsentDecision::Withdrawn));

        let result = agreed.revoke(agreed.ports(), Whose::Own);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(agreed.consents.count(), 1);
    }

    /// Ann phones support to stop the marketing mail. Support records the
    /// withdrawal for her.
    #[test]
    fn support_records_a_withdrawal_for_the_person() {
        let agreed = Agreed::granted();

        agreed
            .revoke(agreed.ports(), Whose::OnBehalfOf(agreed.ann))
            .unwrap();

        assert_eq!(agreed.consents.count(), 2);
    }

    /// User-viewing rights do not permit recording a consent withdrawal on
    /// behalf of a user. The existing consent is the only stored record.
    #[test]
    fn a_caller_who_may_not_record_for_others_is_refused() {
        let agreed = Agreed::granted();
        let ports = RevokeConsentPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::View),
            ])),
            ..agreed.ports()
        };

        let result = agreed.revoke(ports, Whose::OnBehalfOf(agreed.ann));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(agreed.consents.count(), 1);
    }

    /// An unauthorized withdrawal on behalf of a user returns forbidden
    /// instead of revealing that no consent exists.
    #[test]
    fn a_caller_who_may_not_record_for_others_learns_nothing_of_a_missing_consent() {
        let agreed = Agreed::with(None);
        let ports = RevokeConsentPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..agreed.ports()
        };

        let result = agreed.revoke(ports, Whose::OnBehalfOf(UserId::new()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// User-update rights cannot authorize a consent withdrawal on behalf
    /// of an account holding broader user-management rights.
    #[test]
    fn a_person_holding_more_than_the_caller_is_refused() {
        let agreed = Agreed::granted();
        let ports = RevokeConsentPorts {
            access_records: access_where_holds(agreed.ann, &[SystemPermission::ManageUsers]),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Update),
            ])),
            ..agreed.ports()
        };

        let result = agreed.revoke(ports, Whose::OnBehalfOf(agreed.ann));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out person cannot withdraw their own consent.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let agreed = Agreed::granted();
        let ports = RevokeConsentPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..agreed.ports()
        };

        let result = agreed.revoke(ports, Whose::Own);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
