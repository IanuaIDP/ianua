//! Asking for a passkey challenge at an app's address.

use std::sync::Arc;

use ianua_domain::types::Email;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::authentication::app_sign_in::relay::common::AppSignInCommon;
use crate::use_cases::authentication::app_sign_in::{AppSignInContext, AppSignInOutcome};
use crate::use_cases::authentication::passkeys::{DiscoverableBeginUseCase, LoginBeginUseCase};

/// The dashboard's own ways of opening a passkey sign-in.
pub struct AppPasskeyBeginFlows {
    /// For someone who typed their address.
    pub for_address: Arc<LoginBeginUseCase>,
    /// For a browser offering whichever passkey it holds.
    pub discoverable: Arc<DiscoverableBeginUseCase>,
}

/// Opens a passkey sign-in at an app's address.
pub struct AppPasskeyBeginUseCase {
    common: Arc<AppSignInCommon>,
    flows: AppPasskeyBeginFlows,
}

impl AppPasskeyBeginUseCase {
    /// A use case opening ceremonies through the dashboard's own `flows`.
    pub(in crate::use_cases::authentication::app_sign_in) fn new(
        common: Arc<AppSignInCommon>,
        flows: AppPasskeyBeginFlows,
    ) -> Self {
        Self { common, flows }
    }
}

impl Command for AppPasskeyBeginUseCase {
    type Caller = AppSignInContext;
    type Input = Option<Email>;
    type Output = Result<AppSignInOutcome, AppError>;

    /// Opens a ceremony over the passkeys of the account `email` names, or
    /// for whichever passkey the browser offers when no address was typed,
    /// and hands back the browser's challenge. The ceremony's state stays on
    /// the server.
    ///
    /// An unknown address, or an account without passkeys, gets a decoy of
    /// the same shape, so the answer does not tell which accounts exist.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the app has no sign-in here.
    /// - `AppError::Internal` when the challenge cannot be made or the
    ///   ceremony cannot be stored or recorded.
    async fn execute(
        &self,
        ctx: &AppSignInContext,
        auditor: &RequestAuditor,
        email: Option<Email>,
    ) -> Result<AppSignInOutcome, AppError> {
        let (_, auditor) = self.common.resolved(ctx, auditor).await?;
        let flows = &self.flows;
        let tenant = &ctx.tenant;
        let started = match email {
            Some(email) => flows.for_address.execute(tenant, &auditor, email).await?,
            None => flows.discoverable.execute(tenant, &auditor, ()).await?,
        };
        Ok(AppSignInOutcome::PasskeyChallenge(started))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{HttpsUrl, ServiceId};

    use super::*;
    use crate::test_support::authentication::{
        FakePasskeyCeremonyStore, SHOP_HOST, app_sign_in_lifetimes, app_sign_in_services,
        app_sign_in_target_ports, ceremony_lifetime, cross_host_ctx, shop_with_app_sign_in,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::authentication::app_sign_in::SignInPorts;
    use crate::use_cases::authentication::passkeys::{DiscoverableBeginPorts, LoginBeginPorts};

    /// The shop, and the ceremonies kept.
    struct Fixture {
        use_case: AppPasskeyBeginUseCase,
        shop: ServiceId,
        ceremonies: Arc<FakePasskeyCeremonyStore>,
    }

    /// The shop signing people in on [`SHOP_HOST`], in a workspace where
    /// nobody has an account.
    fn fixture() -> Fixture {
        let shop = shop_with_app_sign_in();
        let shop_id = *shop.id();
        let ceremonies = Arc::new(FakePasskeyCeremonyStore::new());
        let flows = AppPasskeyBeginFlows {
            for_address: Arc::new(LoginBeginUseCase::new(
                ceremony_lifetime(),
                LoginBeginPorts {
                    ceremony_store: ceremonies.clone(),
                    ..LoginBeginPorts::fakes()
                },
            )),
            discoverable: Arc::new(DiscoverableBeginUseCase::new(
                ceremony_lifetime(),
                DiscoverableBeginPorts {
                    ceremony_store: ceremonies.clone(),
                    ..DiscoverableBeginPorts::fakes()
                },
            )),
        };
        let ports = SignInPorts {
            target: app_sign_in_target_ports(app_sign_in_services([shop])),
            ..SignInPorts::fakes()
        };
        let base = HttpsUrl::new("https://ianua.example.com").unwrap();
        let common = AppSignInCommon::new(ports, base, app_sign_in_lifetimes());
        Fixture {
            use_case: AppPasskeyBeginUseCase::new(Arc::new(common), flows),
            shop: shop_id,
            ceremonies,
        }
    }

    /// A passkey challenge asked of `service`'s sign-in on the shop's host,
    /// for `email` if any.
    fn begin(
        f: &Fixture,
        service: ServiceId,
        email: Option<&str>,
    ) -> Result<AppSignInOutcome, AppError> {
        block_on(f.use_case.execute(
            &cross_host_ctx(service, SHOP_HOST),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            email.map(|email| Email::new(email).unwrap()),
        ))
    }

    /// Ann's browser offers a passkey from the shop's empty login field. She
    /// gets a challenge, and its ceremony is kept on the server.
    #[test]
    fn a_browser_offering_a_passkey_gets_a_challenge() {
        let f = fixture();

        let outcome = begin(&f, f.shop, None).unwrap();

        assert!(matches!(outcome, AppSignInOutcome::PasskeyChallenge(_)));
        assert_eq!(f.ceremonies.len(), 1);
    }

    /// An unknown address receives a passkey challenge without storing a
    /// ceremony for it.
    #[test]
    fn an_unknown_address_gets_a_decoy() {
        let f = fixture();

        let outcome = begin(&f, f.shop, Some("nobody@acme.test")).unwrap();

        assert!(matches!(outcome, AppSignInOutcome::PasskeyChallenge(_)));
        assert!(f.ceremonies.is_empty());
    }

    /// A challenge request for an unknown service returns not found and
    /// stores no ceremony.
    #[test]
    fn a_service_without_app_sign_in_here_is_not_found() {
        let f = fixture();

        let outcome = begin(&f, ServiceId::new(), None);

        assert!(matches!(outcome, Err(AppError::NotFound(_))));
        assert!(f.ceremonies.is_empty());
    }
}
