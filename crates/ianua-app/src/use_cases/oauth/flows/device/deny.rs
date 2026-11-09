//! A person refusing, from their own sign-in, the device whose code they
//! typed. The device gets nothing.

use std::sync::Arc;

use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::DeviceUserCode;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::oauth::DeviceAuthStore;
use crate::ports::shared::AuditLabelResolver;
use crate::use_case::Command;
use crate::use_cases::oauth::flows::device::answer::{client_label, refused_answer};
use crate::use_cases::oauth::lookup::existing_device_authorization_for_user_code;

/// The ports [`DenyDeviceUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DenyDevicePorts {
    /// Where device requests are kept.
    pub device_auth_store: Arc<dyn DeviceAuthStore>,
    /// Names the client in the audit record.
    pub audit_label_resolver: Arc<dyn AuditLabelResolver>,
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Denies a device request for the person signed in.
///
/// A person who did not start the sign-in on the device, or no longer wants
/// it, says no here. The device's next poll is told it was denied.
pub struct DenyDeviceUseCase {
    ports: DenyDevicePorts,
}

impl DenyDeviceUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DenyDevicePorts) -> Self {
        Self { ports }
    }
}

impl Command for DenyDeviceUseCase {
    type Caller = CallerContext;
    type Input = DeviceUserCode;
    type Output = Result<(), AppError>;

    /// Denies the device request showing `user_code`, for the person signed
    /// in to `caller`'s session. Records `DeviceAuthorizationDenied`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller is not a person signed
    ///   in to a session of the tenant, or the session no longer counts.
    /// - `AppError::NotFound` when no request shows that code.
    /// - `AppError::Domain` when the request was already answered or ran
    ///   out.
    /// - `AppError::Internal` when the request cannot be read, saved or
    ///   audited.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        user_code: DeviceUserCode,
    ) -> Result<(), AppError> {
        let person = self.ports.tenant_authorities.signed_in(caller).await?;
        let store = self.ports.device_auth_store.as_ref();
        let tenant = caller.tenant();
        let mut auth =
            existing_device_authorization_for_user_code(store, &tenant, &user_code).await?;
        let resolver = self.ports.audit_label_resolver.as_ref();
        let label = client_label(resolver, caller, &auth).await;
        auth.deny(*person.account.id(), &person.signed_in, label)
            .map_err(refused_answer)?;
        store.save(&tenant, &auth).await.or_internal()?;
        auditor
            .dispatch_by(&caller.actor(), auth.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::client::GrantType;
    use ianua_domain::domains::oauth::grants::device_auth_status::DeviceAuthStatus;
    use ianua_domain::domains::oauth::grants::device_authorization::{
        DeviceAuthState, DeviceAuthorization,
    };
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::oauth::{
        FakeDeviceAuthStore, TEST_USER_CODE, device_row, stored_client,
    };
    use crate::test_support::{
        FakeAuditLabelResolver, FakeEventDispatcher, block_on, test_auditor, test_ctx,
    };

    struct Fixture {
        requests: Arc<FakeDeviceAuthStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn in_state(state: DeviceAuthState) -> Self {
            let tv = stored_client("TV", &[GrantType::DeviceCode]);
            let requests = Arc::new(FakeDeviceAuthStore::empty());
            let auth = DeviceAuthorization::reconstitute(device_row(&tv, state)).unwrap();
            block_on(requests.save(&test_ctx().tenant(), &auth)).unwrap();
            Self {
                requests,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn deny(&self, code: &str) -> Result<(), AppError> {
            self.deny_as(FakeTenantAuthorities::holding(&[]), code)
        }

        fn deny_as(&self, authorities: FakeTenantAuthorities, code: &str) -> Result<(), AppError> {
            let use_case = DenyDeviceUseCase::new(DenyDevicePorts {
                device_auth_store: self.requests.clone(),
                audit_label_resolver: Arc::new(FakeAuditLabelResolver::new()),
                tenant_authorities: Arc::new(authorities),
            });
            let auditor = test_auditor(self.audit.clone());
            block_on(use_case.execute(&test_ctx(), &auditor, DeviceUserCode::new(code).unwrap()))
        }

        fn status(&self) -> DeviceAuthStatus {
            let code = DeviceUserCode::new(TEST_USER_CODE).unwrap();
            block_on(self.requests.find_by_user_code(&test_ctx().tenant(), &code))
                .unwrap()
                .unwrap()
                .status()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann sees a code on a TV she never touched and refuses it. The
    /// request is denied and the refusal recorded.
    #[test]
    fn the_signed_in_person_denies_the_device() {
        let fixture = Fixture::in_state(DeviceAuthState::Pending);

        fixture.deny(TEST_USER_CODE).unwrap();

        assert_eq!(fixture.status(), DeviceAuthStatus::Denied);
        assert_eq!(fixture.recorded(), ["oauth.device_authorization_denied"]);
    }

    /// Denying an unknown device code returns not found and records no event.
    #[test]
    fn an_unknown_code_is_not_found() {
        let fixture = Fixture::in_state(DeviceAuthState::Pending);

        let result = fixture.deny("WXYZ-9999");

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(fixture.recorded().is_empty());
    }

    /// Denying an already approved device request is refused and preserves
    /// its approved status.
    #[test]
    fn an_answered_request_is_not_denied() {
        let fixture = Fixture::in_state(DeviceAuthState::Approved { by: UserId::new() });

        let result = fixture.deny(TEST_USER_CODE);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(fixture.status(), DeviceAuthStatus::Approved);
    }

    /// A signed-out caller cannot deny a device request, which stays pending.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::in_state(DeviceAuthState::Pending);

        let result = fixture.deny_as(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            TEST_USER_CODE,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.status(), DeviceAuthStatus::Pending);
    }
}
