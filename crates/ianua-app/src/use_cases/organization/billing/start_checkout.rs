//! Starting a checkout: a member with the billing right is sent to the
//! payment provider's page to add the card or mandate the organization is
//! charged through.
//!
//! Nothing changes here but the record of who opened the page. The
//! provider reports the method once the member finished, through the notice
//! [`receive_payment_notice`] reads.
//!
//! [`receive_payment_notice`]: crate::use_cases::organization::billing::receive_payment_notice

use std::sync::Arc;

use ianua_domain::domains::organization::events::billing::OrgCheckoutStarted;
use ianua_domain::domains::organization::members::permission::{OrgBillingAction, OrgPermission};
use ianua_domain::types::{ActorRef, HttpsUrl};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{CheckoutRequest, PaymentProvider};
use crate::use_case::Command;

/// The ports [`StartCheckoutUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct StartCheckoutPorts {
    /// The payment provider that holds payment methods.
    pub payment_provider: Arc<dyn PaymentProvider>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Opens a checkout at the payment provider for the caller's organization.
pub struct StartCheckoutUseCase {
    ports: StartCheckoutPorts,
}

impl StartCheckoutUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: StartCheckoutPorts) -> Self {
        Self { ports }
    }
}

impl Command for StartCheckoutUseCase {
    type Caller = OrgCaller;
    type Input = ();
    type Output = Result<HttpsUrl, AppError>;

    /// Opens a checkout for the organization, with receipts going to the
    /// member who opened it, records `organization.checkout_started` by
    /// them, and returns the provider's page to send them to. The payment
    /// method is recorded when the provider reports it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the member may not change what the
    ///   organization pays.
    /// - `AppError::Conflict` when the deployment has no payment provider.
    /// - `AppError::Internal` when the provider cannot be reached or does
    ///   not answer in time, or on audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<HttpsUrl, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        actor
            .control()?
            .ensure_may(
                organization.id(),
                OrgPermission::Billing(OrgBillingAction::Update),
            )
            .map_err(AppError::from_domain)?;
        let request = CheckoutRequest {
            organization_id: *organization.id(),
            billing_email: actor.member().email().clone(),
        };
        let page = self
            .ports
            .payment_provider
            .start_checkout(&request)
            .await
            .map_err(AppError::from_domain)?;
        let by = ActorRef::OrgUser(*actor.member().id());
        auditor
            .dispatch_by(&by, vec![OrgCheckoutStarted::observed(&organization)])
            .await
            .or_internal()?;
        Ok(page)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::errors::DomainError;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{FakePaymentProvider, TEST_CHECKOUT_URL};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    fn start_recorded(
        actors: FakeOrgActors,
        provider: &Arc<FakePaymentProvider>,
        audit: &Arc<FakeEventDispatcher>,
    ) -> Result<HttpsUrl, AppError> {
        let uc = StartCheckoutUseCase::new(StartCheckoutPorts {
            payment_provider: provider.clone(),
            org_actors: Arc::new(actors),
        });
        block_on(uc.execute(&test_org_caller(), &test_auditor(audit.clone()), ()))
    }

    fn start(
        actors: FakeOrgActors,
        provider: &Arc<FakePaymentProvider>,
    ) -> Result<HttpsUrl, AppError> {
        start_recorded(actors, provider, &Arc::new(FakeEventDispatcher::new()))
    }

    /// Bob, Acme's billing contact, adds a card. He is sent to the
    /// provider's page, opened for Acme with his address for receipts, and
    /// the opening is recorded as his.
    #[test]
    fn the_billing_contact_is_sent_to_the_checkout() {
        let provider = Arc::new(FakePaymentProvider::refusing_signatures());
        let audit = Arc::new(FakeEventDispatcher::new());

        let url =
            start_recorded(FakeOrgActors::in_role(OrgRole::Billing), &provider, &audit).unwrap();

        assert_eq!(url.as_str(), TEST_CHECKOUT_URL);
        let opened = provider.checkouts();
        assert_eq!(opened.len(), 1);
        assert_eq!(
            opened[0].organization_id,
            test_org_caller().organization_id()
        );
        assert_eq!(
            *audit.records.lock().unwrap(),
            ["organization.checkout_started"]
        );
    }

    /// A viewer is refused permission to add a payment method, before the
    /// provider opens a checkout.
    #[test]
    fn a_viewer_is_refused() {
        let provider = Arc::new(FakePaymentProvider::refusing_signatures());

        let result = start(FakeOrgActors::in_role(OrgRole::Viewer), &provider);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(provider.checkouts().is_empty());
    }

    /// A signed-out caller must authenticate, and no checkout opens.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let provider = Arc::new(FakePaymentProvider::refusing_signatures());

        let result = start(FakeOrgActors::refusing(Refusal::SignedOut), &provider);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(provider.checkouts().is_empty());
    }

    /// A deployment that bills nobody: it opens no checkout and reads no
    /// notice.
    struct NoProvider;

    #[async_trait::async_trait]
    impl PaymentProvider for NoProvider {
        async fn start_checkout(
            &self,
            _request: &CheckoutRequest,
        ) -> Result<HttpsUrl, DomainError> {
            Err(DomainError::conflict("no payment provider is set up"))
        }

        fn read_notice(
            &self,
            _webhook: &crate::ports::organization::PaymentWebhook,
        ) -> Result<crate::ports::organization::ReceivedNotice, DomainError> {
            Err(DomainError::unauthorized("no payment provider is set up"))
        }
    }

    /// Ann asks to add a card where nobody is billed. She is told plainly
    /// that no checkout can be opened, and nothing is recorded as opened.
    #[test]
    fn a_deployment_with_no_provider_refuses_the_checkout_plainly() {
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = StartCheckoutUseCase::new(StartCheckoutPorts {
            payment_provider: Arc::new(NoProvider),
            org_actors: Arc::new(FakeOrgActors::in_role(OrgRole::Billing)),
        });

        let result =
            block_on(use_case.execute(&test_org_caller(), &test_auditor(audit.clone()), ()));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(audit.records.lock().unwrap().is_empty());
    }
}
