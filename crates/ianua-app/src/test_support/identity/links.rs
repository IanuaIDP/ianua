//! Verification links made over the stores a test watches.

use std::sync::Arc;

use ianua_domain::test_support::fakes::FakeRefreshTokenGenerator;
use ianua_domain::types::{HttpsUrl, Lifetime};

use crate::email::InvitationPolicy;
use crate::ports::shared::MailSetup;
use crate::services::identity::link_scopes::TenantLinkScopes;
use crate::test_support::identity::FakeTokenStore;
use crate::test_support::organization::{org_store_with, test_org};
use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
use crate::test_support::{Fake, FakeMailer, resend_cooldown};
use crate::use_cases::identity::email::changes::links::EmailChangePolicy;
use crate::use_cases::identity::email::{
    VerificationLinkStores, VerificationLinks, VerificationPolicy,
};

/// The policy verification links are made under in tests: a day's
/// lifetime, the test cooldown.
///
/// # Panics
///
/// Never: the lifetime and address are constants that are valid.
#[must_use]
pub fn verification_policy() -> VerificationPolicy {
    VerificationPolicy {
        lifetime: Lifetime::seconds(86_400).expect("a day is a valid lifetime"),
        base_url: HttpsUrl::new("https://app.test").expect("a valid address"),
        resend_cooldown: resend_cooldown(),
    }
}

/// The policy email change links are made under in tests: a day's
/// lifetime, the test cooldown.
#[must_use]
pub fn email_change_policy() -> EmailChangePolicy {
    let VerificationPolicy {
        lifetime,
        base_url,
        resend_cooldown,
    } = verification_policy();
    EmailChangePolicy {
        lifetime,
        base_url,
        resend_cooldown,
    }
}

/// The policy invitations are sent under in tests: a day's lifetime, the
/// test cooldown.
#[must_use]
pub fn invitation_policy() -> InvitationPolicy {
    let VerificationPolicy {
        lifetime,
        base_url,
        resend_cooldown,
    } = verification_policy();
    InvitationPolicy {
        lifetime,
        base_url,
        resend_cooldown,
    }
}

impl Fake for EmailChangePolicy {
    fn fake() -> Self {
        email_change_policy()
    }
}

impl Fake for InvitationPolicy {
    fn fake() -> Self {
        invitation_policy()
    }
}

/// Links whose tokens land in `tokens` and whose mail goes to `mailer`.
#[must_use]
pub fn verification_links_over(
    tokens: &Arc<FakeTokenStore>,
    mailer: &Arc<FakeMailer>,
) -> Arc<VerificationLinks> {
    verification_links_reaching(tokens, mailer, Fake::fake())
}

/// As [`verification_links_over`], on a deployment whose mail is set up as
/// `mail` says.
#[must_use]
pub fn verification_links_reaching(
    tokens: &Arc<FakeTokenStore>,
    mailer: &Arc<FakeMailer>,
    mail: Arc<dyn MailSetup>,
) -> Arc<VerificationLinks> {
    Arc::new(VerificationLinks::new(
        Arc::new(FakeRefreshTokenGenerator::new()),
        verification_policy(),
        VerificationLinkStores {
            tokens: tokens.clone(),
            mailer: mailer.clone(),
            mail,
        },
    ))
}

/// The link scope of the tenant every test caller acts in: tenant `acme` of
/// the organization `acme`.
impl Fake for TenantLinkScopes {
    fn fake() -> Self {
        let tenant = test_tenant_for_ctx();
        let organization = test_org(*tenant.organization_id(), "acme");
        Self {
            tenants: Arc::new(FakeTenantStore::holding(tenant)),
            organizations: org_store_with([organization]),
        }
    }
}

impl Fake for Arc<VerificationLinks> {
    fn fake() -> Self {
        verification_links_over(
            &Arc::new(FakeTokenStore::empty()),
            &Arc::new(FakeMailer::new()),
        )
    }
}
