//! The payment provider of a deployment that set none up, such as one
//! organization's own installation: nothing is billed, so every checkout
//! is refused and no notice is ever read, since no signing secret exists
//! to check one against.

use async_trait::async_trait;
use ianua_app::ports::organization::{
    CheckoutRequest, PaymentProvider, PaymentWebhook, ReceivedNotice,
};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::HttpsUrl;

/// No payment provider: every checkout refused, every notice unread.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPaymentProvider;

#[async_trait]
impl PaymentProvider for NoPaymentProvider {
    async fn start_checkout(&self, _request: &CheckoutRequest) -> Result<HttpsUrl, DomainError> {
        Err(DomainError::conflict(message!(
            "infra-no-payment-provider-opens-a-checkout",
            "no payment provider is set up on this deployment, so no checkout can be opened"
        )))
    }

    fn read_notice(&self, _webhook: &PaymentWebhook) -> Result<ReceivedNotice, DomainError> {
        Err(DomainError::unauthorized(message!(
            "infra-no-payment-provider-is-set-up",
            "no payment provider is set up, so no notice is signed by one"
        )))
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::organization::PaymentSignature;
    use ianua_domain::types::{Email, OrganizationId};

    use super::*;

    /// Olivia asks to add a card on a deployment that bills nobody. The
    /// checkout is refused rather than sent anywhere.
    #[tokio::test]
    async fn a_checkout_is_refused() {
        let request = CheckoutRequest {
            organization_id: OrganizationId::new(),
            billing_email: Email::new("olivia@acme.com").unwrap(),
        };

        let opened = NoPaymentProvider.start_checkout(&request).await;

        assert!(matches!(opened, Err(DomainError::Conflict(_))));
    }

    /// Without a configured provider, an invoice-paid notice is unauthorized.
    #[test]
    fn a_notice_is_refused_unread() {
        let webhook = PaymentWebhook {
            payload: br#"{"type":"invoice.paid"}"#.to_vec(),
            signature: PaymentSignature::new("t=1,v1=00"),
        };

        let read = NoPaymentProvider.read_notice(&webhook);

        assert!(matches!(read, Err(DomainError::Unauthorized(_))));
    }
}
