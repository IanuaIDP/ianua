//! A person approving, from their own sign-in, the device whose code they
//! typed. The device gets tokens for them.

use std::sync::Arc;

use ianua_domain::shared::clock;
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

/// The ports [`ApproveDeviceUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ApproveDevicePorts {
    /// Where device requests are kept.
    pub device_auth_store: Arc<dyn DeviceAuthStore>,
    /// Names the client in the audit record.
    pub audit_label_resolver: Arc<dyn AuditLabelResolver>,
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Approves a device request for the person signed in.
pub struct ApproveDeviceUseCase {
    ports: ApproveDevicePorts,
}

impl ApproveDeviceUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ApproveDevicePorts) -> Self {
        Self { ports }
    }
}

impl Command for ApproveDeviceUseCase {
    type Caller = CallerContext;
    type Input = DeviceUserCode;
    type Output = Result<(), AppError>;

    /// Approves the device request showing `user_code`, for the person
    /// signed in to `caller`'s session. Records
    /// `DeviceAuthorizationApproved`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller is not a person signed
    ///   in to a session of the tenant, or the session no longer counts.
    /// - `AppError::NotFound` when no request shows that code.
    /// - `AppError::Domain` when the request has expired or was already
    ///   answered.
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
        auth.approve(*person.account.id(), &person.signed_in, label, clock::now())
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
        DeviceAuthRow, DeviceAuthState, DeviceAuthorization,
    };
    use time::Duration;

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
        fn with(edit: impl FnOnce(&mut DeviceAuthRow)) -> Self {
            let tv = stored_client("TV", &[GrantType::DeviceCode]);
            let mut row = device_row(&tv, DeviceAuthState::Pending);
            edit(&mut row);
            let requests = Arc::new(FakeDeviceAuthStore::empty());
            block_on(requests.save(
                &test_ctx().tenant(),
                &DeviceAuthorization::reconstitute(row).unwrap(),
            ))
            .unwrap();
            Self {
                requests,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn pending() -> Self {
            Self::with(|_| {})
        }

        fn approve(&self, code: &str) -> Result<(), AppError> {
            self.approve_through(
                FakeTenantAuthorities::holding(&[]),
                FakeAuditLabelResolver::new(),
                code,
            )
        }

        fn approve_through(
            &self,
            authorities: FakeTenantAuthorities,
            labels: FakeAuditLabelResolver,
            code: &str,
        ) -> Result<(), AppError> {
            let use_case = ApproveDeviceUseCase::new(ApproveDevicePorts {
                device_auth_store: self.requests.clone(),
                audit_label_resolver: Arc::new(labels),
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

    /// Ann types the code her TV shows and approves it. The request is
    /// approved for her and the approval recorded.
    #[test]
    fn the_signed_in_person_approves_the_device() {
        let fixture = Fixture::pending();

        fixture.approve(TEST_USER_CODE).unwrap();

        assert_eq!(fixture.status(), DeviceAuthStatus::Approved);
        assert_eq!(fixture.recorded(), ["oauth.device_authorization_approved"]);
    }

    /// Ann approves, though the client's name cannot be looked up. The
    /// approval stands and the record names the client by its id.
    #[test]
    fn an_unnamed_client_does_not_stop_the_approval() {
        let fixture = Fixture::pending();

        fixture
            .approve_through(
                FakeTenantAuthorities::holding(&[]),
                FakeAuditLabelResolver::missing(),
                TEST_USER_CODE,
            )
            .unwrap();

        assert_eq!(fixture.status(), DeviceAuthStatus::Approved);
        assert_eq!(fixture.recorded().len(), 1);
    }

    /// Approving an unknown device code returns not found and records no event.
    #[test]
    fn an_unknown_code_is_not_found() {
        let fixture = Fixture::pending();

        let result = fixture.approve("WXYZ-9999");

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(fixture.recorded().is_empty());
    }

    /// A repeated device approval is refused and leaves the audit trail at
    /// the single successful approval.
    #[test]
    fn a_request_is_answered_once() {
        let fixture = Fixture::pending();
        fixture.approve(TEST_USER_CODE).unwrap();

        let again = fixture.approve(TEST_USER_CODE);

        assert!(matches!(again, Err(AppError::Domain(_))));
        assert_eq!(fixture.recorded().len(), 1);
    }

    /// Approving a device request ten minutes past its expiry is refused
    /// and leaves its stored status pending.
    #[test]
    fn an_expired_request_is_refused() {
        let fixture = Fixture::with(|row| {
            row.created_at = clock::now() - Duration::minutes(20);
            row.expires_at = clock::now() - Duration::minutes(10);
        });

        let result = fixture.approve(TEST_USER_CODE);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(fixture.status(), DeviceAuthStatus::Pending);
    }

    /// A signed-out caller cannot approve a device request, which stays pending.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::pending();

        let result = fixture.approve_through(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            FakeAuditLabelResolver::new(),
            TEST_USER_CODE,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.status(), DeviceAuthStatus::Pending);
    }
}
