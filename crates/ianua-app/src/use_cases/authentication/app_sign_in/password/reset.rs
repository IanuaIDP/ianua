//! Setting a new password at an app's address from the mailed link.

use std::sync::Arc;

use ianua_domain::shared::security::secret::Secret;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::authentication::app_sign_in::relay::common::AppSignInCommon;
use crate::use_cases::authentication::app_sign_in::{AppSignInContext, AppSignInOutcome};
use crate::use_cases::authentication::password::{ResetConfirmRequest, ResetConfirmUseCase};

/// A new password set from a mailed link. Holds the link's token, the
/// password and a factor code, so it has no `Debug`.
pub struct AppResetPasswordRequest {
    /// The token from the mailed link.
    pub token: Secret,
    /// The password chosen.
    pub new_password: Secret,
    /// A code from the account's second factor, when it has one.
    pub mfa_code: Option<String>,
}

/// Sets a new password at an app's address through the dashboard's own
/// reset.
pub struct AppResetPasswordUseCase {
    common: Arc<AppSignInCommon>,
    reset_confirm: Arc<ResetConfirmUseCase>,
}

impl AppResetPasswordUseCase {
    /// A use case setting passwords through the dashboard's own
    /// `reset_confirm`.
    pub(in crate::use_cases::authentication::app_sign_in) fn new(
        common: Arc<AppSignInCommon>,
        reset_confirm: Arc<ResetConfirmUseCase>,
    ) -> Self {
        Self {
            common,
            reset_confirm,
        }
    }
}

impl Command for AppResetPasswordUseCase {
    type Caller = AppSignInContext;
    type Input = AppResetPasswordRequest;
    type Output = Result<AppSignInOutcome, AppError>;

    /// Sets the new password on the account the link was mailed for, through
    /// the dashboard's own reset: the tenant's password rules, the account's
    /// second factor and the single use of the link all apply, and every
    /// session the account held ends. Answers `Accepted`; the person signs
    /// in again with the new password.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` for an app without sign-in or an unknown, expired, spent or superseded link.
    /// - `AppError::Domain` for a malformed token or a password outside tenant rules.
    /// - `AppError::StepUpRequired` for a missing factor code; `AccountLocked` after too many wrong codes.
    /// - `AppError::Forbidden` for a wrong code or disabled passwords; `Internal` on storage or hashing failure.
    async fn execute(
        &self,
        ctx: &AppSignInContext,
        auditor: &RequestAuditor,
        request: AppResetPasswordRequest,
    ) -> Result<AppSignInOutcome, AppError> {
        let (_, auditor) = self.common.resolved(ctx, auditor).await?;
        let AppResetPasswordRequest {
            token,
            new_password,
            mfa_code,
        } = request;
        let confirm = ResetConfirmRequest {
            raw_token: token.expose().to_owned(),
            new_password,
            mfa_code,
        };
        self.reset_confirm
            .execute(&ctx.tenant, &auditor, confirm)
            .await?;
        Ok(AppSignInOutcome::Accepted)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::credentials::password::PasswordHasher;
    use ianua_domain::domains::authentication::recovery::reset::{
        CreateResetParams, PasswordResetRequest, ResetInitiator,
    };
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::test_support::fakes::FakeHasher;
    use ianua_domain::types::{HttpsUrl, Lifetime, PasswordPolicy, ServiceId, UserId};

    use super::*;
    use crate::test_support::authentication::{
        FakeResetRequestStore, SHOP_HOST, app_sign_in_lifetimes, app_sign_in_services,
        app_sign_in_target_ports, cross_host_ctx, lockout, shop_with_app_sign_in,
    };
    use crate::test_support::identity::{
        FakeUserStore, RecordingCredentialStore, hash_of_link, stored_user,
    };
    use crate::test_support::tenant::tenant_store_with_password_policy;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::authentication::app_sign_in::SignInPorts;
    use crate::use_cases::authentication::password::{ReplacementPorts, ResetConfirmPorts};

    const BOB: &str = "bob@acme.test";
    const LINK: &str = "fake_refresh_0";

    /// The shop, Bob with a pending reset link, and his stored password.
    struct Fixture {
        use_case: AppResetPasswordUseCase,
        shop: ServiceId,
        bob: UserId,
        creds: Arc<RecordingCredentialStore>,
    }

    /// Bob's pending reset link, mailed to his verified address.
    fn pending_for(bob: UserId) -> PasswordResetRequest {
        PasswordResetRequest::create(
            &stored_user(bob, BOB, UserStatus::Active),
            CreateResetParams {
                initiator: ResetInitiator::User,
                token_hash: hash_of_link(LINK),
                lifetime: Lifetime::seconds(3600).unwrap(),
            },
        )
        .unwrap()
    }

    /// The shop signing people in on [`SHOP_HOST`], over a workspace where
    /// Bob asked for a reset link.
    fn fixture() -> Fixture {
        let shop = shop_with_app_sign_in();
        let shop_id = *shop.id();
        let bob = UserId::new();
        let creds = Arc::new(RecordingCredentialStore::holding(
            bob,
            &FakeHasher.hash("old").unwrap(),
        ));
        let reset_confirm = reset_confirm(bob, &creds);
        let ports = SignInPorts {
            target: app_sign_in_target_ports(app_sign_in_services([shop])),
            ..SignInPorts::fakes()
        };
        let base = HttpsUrl::new("https://ianua.example.com").unwrap();
        let common = AppSignInCommon::new(ports, base, app_sign_in_lifetimes());
        Fixture {
            use_case: AppResetPasswordUseCase::new(Arc::new(common), Arc::new(reset_confirm)),
            shop: shop_id,
            bob,
            creds,
        }
    }

    /// Bob's pending link replaces credentials through the fixture's recording store.
    fn reset_confirm(bob: UserId, creds: &Arc<RecordingCredentialStore>) -> ResetConfirmUseCase {
        ResetConfirmUseCase::new(
            lockout(),
            ResetConfirmPorts {
                reset_store: Arc::new(FakeResetRequestStore::with_request(&pending_for(bob))),
                replacement: ReplacementPorts {
                    user_store: Arc::new(FakeUserStore::with_user(bob, BOB)),
                    credential_store: creds.clone(),
                    tenant_store: tenant_store_with_password_policy(PasswordPolicy::relaxed()),
                    ..ReplacementPorts::fakes()
                },
                ..ResetConfirmPorts::fakes()
            },
        )
    }

    /// `token` sets a new password at `service`'s sign-in on the shop's host.
    fn reset(f: &Fixture, service: ServiceId, token: &str) -> Result<AppSignInOutcome, AppError> {
        let request = AppResetPasswordRequest {
            token: Secret::new(token),
            new_password: Secret::new("new_pass"),
            mfa_code: None,
        };
        block_on(f.use_case.execute(
            &cross_host_ctx(service, SHOP_HOST),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            request,
        ))
    }

    /// The hash of Bob's stored password.
    fn stored_hash(f: &Fixture) -> String {
        f.creds.hash_of(&f.bob).unwrap().as_str().to_owned()
    }

    /// Bob follows his reset link to the shop and sets a new password. It
    /// replaces the old one.
    #[test]
    fn the_mailed_link_sets_a_new_password() {
        let f = fixture();
        let before = stored_hash(&f);

        let outcome = reset(&f, f.shop, LINK).unwrap();

        assert!(matches!(outcome, AppSignInOutcome::Accepted));
        assert_ne!(stored_hash(&f), before);
    }

    /// A forged reset link returns not found and leaves Bob's password
    /// unchanged.
    #[test]
    fn a_forged_link_is_refused() {
        let f = fixture();
        let before = stored_hash(&f);

        let outcome = reset(&f, f.shop, "guessed-token");

        assert!(matches!(outcome, Err(AppError::NotFound(_))));
        assert_eq!(stored_hash(&f), before);
    }

    /// A reset link that successfully changed Bob's password returns not
    /// found when used again.
    #[test]
    fn a_used_link_is_refused() {
        let f = fixture();
        reset(&f, f.shop, LINK).unwrap();

        let outcome = reset(&f, f.shop, LINK);

        assert!(matches!(outcome, Err(AppError::NotFound(_))));
    }

    /// A reset request for an unknown service returns not found and leaves
    /// Bob's password unchanged.
    #[test]
    fn a_service_without_app_sign_in_here_is_not_found() {
        let f = fixture();
        let before = stored_hash(&f);

        let outcome = reset(&f, ServiceId::new(), LINK);

        assert!(matches!(outcome, Err(AppError::NotFound(_))));
        assert_eq!(stored_hash(&f), before);
    }
}
