//! What second factors a person may set up, and which one they hold: for a
//! sign-in that waits for a factor, to show what to answer with or what to
//! set up, and for a person signed in, on their security page.
//!
//! Only kinds the tenant offers, that reach its baseline, and whose codes
//! this deployment can deliver are listed: a factor listed but refused at
//! setup would leave the person stuck.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::enrollment::{MfaEnrollment, MfaMethod};
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{MfaEnrollmentStore, TextMessaging};
use crate::ports::identity::UserStore;
use crate::ports::shared::{MailSetup, SessionStore};
use crate::ports::tenant::TenantStore;
use crate::services::authentication::channels::Channels;
use crate::services::lookup::{existing_tenant, owned_session};
use crate::use_case::Query;
use crate::use_cases::authentication::mfa::enrollment::setup_proof::{
    FactorSetter, SetterAccounts,
};

/// The factor a person holds, as far as it went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeldFactor {
    /// None, or only one given up or turned off.
    None,
    /// One set up and still to be confirmed.
    Pending(MfaMethod),
    /// One confirmed and in force.
    InForce(MfaMethod),
}

impl HeldFactor {
    /// What `enrollment` amounts to.
    fn of(enrollment: Option<&MfaEnrollment<ResolvedTenant>>) -> Self {
        match enrollment {
            Some(factor) if factor.is_active() => Self::InForce(factor.method()),
            Some(factor) if factor.is_pending() => Self::Pending(factor.method()),
            _ => Self::None,
        }
    }
}

/// What a person may set up, what they hold, and what their sign-in owes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactorOptions {
    /// The kinds of factor the tenant offers them, in the order it lists
    /// them. Empty when second factors are off.
    pub offered: Vec<MfaMethod>,
    /// The factor they hold.
    pub held: HeldFactor,
    /// What the waiting sign-in still owes; nothing for a person signed in.
    pub owed: SecondFactor,
}

/// The ports [`FactorOptionsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct FactorOptionsPorts {
    /// The person's factor.
    pub enrollment_store: Arc<dyn MfaEnrollmentStore>,
    /// The tenant, for the factors it offers.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Whether codes can be texted here at all.
    pub text_messaging: Arc<dyn TextMessaging>,
    /// Whether anything can be mailed here at all.
    pub mail: Arc<dyn MailSetup>,
    /// The account of a waiting sign-in.
    pub user_store: Arc<dyn UserStore>,
    /// The session of a waiting sign-in.
    pub session_store: Arc<dyn SessionStore>,
    /// Who is signed in to a caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Tells a person which second factors they may set up and which they
/// hold.
pub struct FactorOptionsUseCase {
    ports: FactorOptionsPorts,
}

impl FactorOptionsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: FactorOptionsPorts) -> Self {
        Self { ports }
    }

    /// The ways this deployment delivers codes.
    fn channels(&self) -> Channels<'_> {
        Channels {
            texts: self.ports.text_messaging.as_ref(),
            mail: self.ports.mail.as_ref(),
        }
    }

    /// What `setter`'s sign-in owes: what its session owes for one waiting,
    /// nothing for a person signed in.
    async fn owed(&self, setter: &FactorSetter) -> Result<SecondFactor, AppError> {
        let FactorSetter::SigningIn(pending) = setter else {
            return Ok(SecondFactor::NotOwed);
        };
        let session = owned_session(
            self.ports.session_store.as_ref(),
            &pending.tenant,
            &pending.session_id,
            &pending.user_id,
        )
        .await?;
        Ok(session.owed())
    }
}

impl Query for FactorOptionsUseCase {
    type Caller = FactorSetter;
    type Input = ();
    type Output = Result<FactorOptions, AppError>;

    /// The second factors `setter`'s tenant offers them, the one they hold,
    /// and what their sign-in owes.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when a signed-in setter's session no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant, the account or a waiting
    ///   sign-in's session is gone.
    /// - `AppError::Internal` on storage failure.
    async fn execute(&self, setter: &FactorSetter, (): ()) -> Result<FactorOptions, AppError> {
        let accounts = SetterAccounts {
            authorities: self.ports.tenant_authorities.as_ref(),
            users: self.ports.user_store.as_ref(),
        };
        let (tenant, account) = accounts.account(setter).await?;
        let owed = self.owed(setter).await?;
        let workspace = existing_tenant(self.ports.tenant_store.as_ref(), &tenant).await?;
        let enrollment = self
            .ports
            .enrollment_store
            .find_by_user(&tenant, account.id())
            .await
            .or_internal()?;
        Ok(FactorOptions {
            offered: offered_kinds(&workspace, self.channels()),
            held: HeldFactor::of(enrollment.as_ref()),
            owed,
        })
    }
}

/// Every kind of factor `workspace` offers now whose codes can be
/// delivered here: texted codes are left out where nothing texts them, and
/// mailed codes where nothing is mailed.
fn offered_kinds(workspace: &Tenant, channels: Channels<'_>) -> Vec<MfaMethod> {
    MfaMethod::ALL
        .into_iter()
        .filter(|method| workspace.auth_config().offer_factor(*method).is_ok())
        .filter(|method| channels.deliverable(*method))
        .collect()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::methods::{AuthMethod, MfaPolicy};
    use ianua_domain::domains::authentication::risk_engine::step_up::StepUpPolicy;
    use ianua_domain::domains::authentication::sessions::mfa_factor::FactorProved;
    use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
    use ianua_domain::domains::tenant::access::auth_config::TenantAuthSettings;
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{
        FakeMfaEnrollmentStore, FakeSessionStore, FakeTextMessaging, session_signed_in,
        test_caller_id,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::tenant::tenant_store_signing_in_with;
    use crate::test_support::{FakeMailSetup, block_on, test_ctx};
    use crate::use_cases::authentication::mfa::sessions::sign_in_parties::PendingSignIn;

    fn listing(settings: TenantAuthSettings) -> FactorOptionsPorts {
        FactorOptionsPorts {
            tenant_store: tenant_store_signing_in_with(settings),
            ..FactorOptionsPorts::fakes()
        }
    }

    fn every_kind(policy: MfaPolicy) -> TenantAuthSettings {
        TenantAuthSettings {
            mfa_policy: policy,
            second_factors: MfaMethod::ALL.to_vec(),
            ..TenantAuthSettings::default()
        }
    }

    fn options(
        ports: FactorOptionsPorts,
        setter: &FactorSetter,
    ) -> Result<FactorOptions, AppError> {
        block_on(FactorOptionsUseCase::new(ports).execute(setter, ()))
    }

    fn signed_in() -> FactorSetter {
        FactorSetter::SignedIn(Box::new(test_ctx()))
    }

    /// Acme lists every kind. Ann, signed in with no factor yet, is offered
    /// all three and owes nothing.
    #[test]
    fn every_listed_kind_is_offered() {
        let result = options(listing(every_kind(MfaPolicy::Optional)), &signed_in()).unwrap();

        assert_eq!(result.offered, MfaMethod::ALL.to_vec());
        assert_eq!(result.held, HeldFactor::None);
        assert_eq!(result.owed, SecondFactor::NotOwed);
    }

    /// Missing SMS setup removes texted codes from the options while
    /// retaining authenticator apps and mailed codes.
    #[test]
    fn texted_codes_are_not_offered_where_nothing_texts() {
        let ports = FactorOptionsPorts {
            text_messaging: FakeTextMessaging::not_set_up(),
            ..listing(every_kind(MfaPolicy::Optional))
        };

        let result = options(ports, &signed_in()).unwrap();

        assert_eq!(result.offered, [MfaMethod::Totp, MfaMethod::EmailCode]);
    }

    /// Missing mail setup removes mailed codes from the options while
    /// retaining authenticator apps and texted codes.
    #[test]
    fn mailed_codes_are_not_offered_where_nothing_is_mailed() {
        let ports = FactorOptionsPorts {
            mail: FakeMailSetup::not_set_up(),
            ..listing(every_kind(MfaPolicy::Optional))
        };

        let result = options(ports, &signed_in()).unwrap();

        assert_eq!(result.offered, [MfaMethod::Totp, MfaMethod::SmsCode]);
    }

    /// Acme asks for AAL2. Mailed and texted codes never reach it, so they
    /// are not offered: a person who set one up would be refused at every
    /// sign-in. An authenticator app is.
    #[test]
    fn a_kind_below_the_baseline_is_not_offered() {
        let settings = TenantAuthSettings {
            step_up_policy: StepUpPolicy::strict(),
            ..every_kind(MfaPolicy::Required)
        };

        let result = options(listing(settings), &signed_in()).unwrap();

        assert!(!result.offered.contains(&MfaMethod::EmailCode));
        assert!(!result.offered.contains(&MfaMethod::SmsCode));
        assert!(result.offered.contains(&MfaMethod::Totp));
    }

    /// Acme switched second factors off. Nothing is offered.
    #[test]
    fn nothing_is_offered_while_factors_are_off() {
        let result = options(listing(every_kind(MfaPolicy::Disabled)), &signed_in()).unwrap();

        assert!(result.offered.is_empty());
    }

    /// Ann's sign-in waits for her authenticator. She is told she holds one
    /// in force and that her sign-in owes it.
    #[test]
    fn a_waiting_sign_in_is_told_what_it_owes() {
        let ann = UserId::new();
        let session = session_signed_in(
            ann,
            SignInProgressRow {
                method: AuthMethod::Password,
                factor: FactorProved::NoneYet,
                owed: SecondFactor::Verify,
            },
        );
        let pending = PendingSignIn {
            tenant: test_ctx().tenant(),
            session_id: *session.id(),
            user_id: ann,
        };
        let ports = FactorOptionsPorts {
            enrollment_store: Arc::new(FakeMfaEnrollmentStore::active_for(ann)),
            session_store: Arc::new(FakeSessionStore::with_session(session)),
            user_store: Arc::new(FakeUserStore::with_user(ann, "ann@acme.test")),
            ..listing(every_kind(MfaPolicy::Optional))
        };

        let result = options(ports, &FactorSetter::SigningIn(pending)).unwrap();

        assert_eq!(result.held, HeldFactor::InForce(MfaMethod::Totp));
        assert_eq!(result.owed, SecondFactor::Verify);
    }

    /// Ann started setting up her authenticator and did not confirm it yet.
    /// She is told it is still pending.
    #[test]
    fn a_setup_still_to_confirm_is_pending() {
        let ports = FactorOptionsPorts {
            enrollment_store: Arc::new(FakeMfaEnrollmentStore::pending_for(test_caller_id())),
            ..listing(every_kind(MfaPolicy::Optional))
        };

        let result = options(ports, &signed_in()).unwrap();

        assert_eq!(result.held, HeldFactor::Pending(MfaMethod::Totp));
    }

    /// A signed-out caller is unauthenticated when reading factor options.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let ports = FactorOptionsPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..listing(every_kind(MfaPolicy::Optional))
        };

        let result = options(ports, &signed_in());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
