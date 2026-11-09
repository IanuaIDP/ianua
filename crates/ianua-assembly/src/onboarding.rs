//! The onboarding use cases the API serves: whether strangers may sign up,
//! asking for an organization, founding it once the link comes back, and a
//! member founding another organization.

use std::sync::Arc;

use ianua_app::use_cases::onboarding;
use ianua_app::use_cases::onboarding::founding::{Founder, FoundingPorts};

use crate::authentication::password_hashing;
use crate::deps::{Adapters, Settings};

/// The onboarding use cases.
#[derive(Clone)]
pub struct OnboardingState {
    pub signup_open: Arc<onboarding::SignupOpenUseCase>,
    pub signup: Arc<onboarding::SignupUseCase>,
    pub confirm_signup: Arc<onboarding::ConfirmSignupUseCase>,
    pub another_organization: Arc<onboarding::FoundAnotherOrganizationUseCase>,
}

/// Builds the onboarding use cases over `a`, tuned by `s`.
pub fn build(a: &Adapters, s: &Settings) -> OnboardingState {
    OnboardingState {
        signup_open: Arc::new(onboarding::SignupOpenUseCase::new(s.enrollment)),
        signup: Arc::new(signup(a, s)),
        confirm_signup: Arc::new(onboarding::ConfirmSignupUseCase::new(
            founder(a, s),
            onboarding::ConfirmSignupPorts {
                pending_signups: a.pending_signup_store.clone(),
                token_generator: a.refresh_token_generator.clone(),
            },
        )),
        another_organization: Arc::new(onboarding::FoundAnotherOrganizationUseCase::new(
            self_service(a, s),
            onboarding::AnotherOrganizationPorts {
                org_actors: a.org_actors.clone(),
            },
        )),
    }
}

/// Starts self-service founding with a throttled mailbox proof.
fn signup(a: &Adapters, s: &Settings) -> onboarding::SignupUseCase {
    onboarding::SignupUseCase::new(
        self_service(a, s),
        onboarding::SignupPorts {
            pending_signups: a.pending_signup_store.clone(),
            org_users: a.org_user_store.clone(),
            mailer: a.mailer.clone(),
            mail_throttle: a.mail_throttle.clone(),
            token_generator: a.refresh_token_generator.clone(),
            links: onboarding::SignupLinks {
                lifetime: s.tunables.org_verification_lifetime,
                base_url: s.app_base_url.clone(),
            },
            mail: a.mail_setup.clone(),
        },
    )
}

/// What founds organizations people ask for themselves, while this
/// deployment takes them.
fn self_service(a: &Adapters, s: &Settings) -> onboarding::SelfServiceFounding {
    onboarding::SelfServiceFounding {
        founder: founder(a, s),
        enrollment: s.enrollment,
    }
}

/// What founds an organization, its first tenant and its owner.
fn founder(a: &Adapters, s: &Settings) -> Founder {
    Founder::new(
        password_hashing(a),
        s.domain_limits.clone(),
        s.compliance_limits.clone(),
        FoundingPorts {
            random: a.secure_random.clone(),
            org_store: a.organization_store.clone(),
            subscriptions: a.org_subscription_store.clone(),
            tenant_store: a.tenant_store.clone(),
            org_user_store: a.org_user_store.clone(),
            setup_token_store: a.org_token_store_installation_setup.clone(),
            token_generator: a.refresh_token_generator.clone(),
            breach_checker: a.credential_breach_checker.clone(),
        },
    )
    .with_platform_hosts(s.platform_hosts.clone())
}
