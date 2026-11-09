//! Request export: a person asks for a copy of the data kept about them, or
//! staff who may view them ask on their behalf. The file is gathered in the
//! background and goes to the person alone.

use std::sync::Arc;

use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::domains::identity::privacy::export::{DataExportRequest, ExportScope};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, DataExportId, UserId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::AccessRecordStore;
use crate::ports::identity::{DataExportStore, UserStore};
use crate::services::lookup::existing_user;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::account_control::account_control;
use crate::use_cases::identity::whose::Whose;

/// Whose data to copy, and what the copy holds.
pub struct RequestExportRequest {
    /// The signed-in person's own, or another user's.
    pub whose: Whose,
    /// Everything kept, or what the person gave, to take elsewhere.
    pub scope: ExportScope,
}

/// The ports [`RequestExportUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RequestExportPorts {
    /// Keeps the requests.
    pub export_store: Arc<dyn DataExportStore>,
    /// Loads the account the copy is of.
    pub user_store: Arc<dyn UserStore>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// Who the caller is and what they hold in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Asks for a copy of a person's data.
pub struct RequestExportUseCase {
    ports: RequestExportPorts,
}

impl RequestExportUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RequestExportPorts) -> Self {
        Self { ports }
    }

    /// The request for `whose`, made by the person or for them, and who
    /// made it.
    async fn requested(
        &self,
        ctx: &CallerContext,
        whose: Whose,
        scope: ExportScope,
    ) -> Result<(DataExportRequest<ResolvedTenant>, ActorRef), AppError> {
        match whose {
            Whose::Own => {
                let person = self.ports.tenant_authorities.signed_in(ctx).await?;
                let request = DataExportRequest::request(&person.account, scope, &person.signed_in)
                    .map_err(AppError::from_domain)?;
                Ok((request, ActorRef::User(*person.account.id())))
            }
            Whose::OnBehalfOf(user_id) => {
                let request = self.asked_for(ctx, &user_id, scope).await?;
                Ok((request, ctx.actor()))
            }
        }
    }

    /// The request staff who may view `user_id` make for them.
    async fn asked_for(
        &self,
        ctx: &CallerContext,
        user_id: &UserId,
        scope: ExportScope,
    ) -> Result<DataExportRequest<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let records = self.ports.access_records.as_ref();
        let export = AccountAction::Export;
        let control = account_control(records, &tenant, &authority, user_id, export).await?;
        let account = existing_user(self.ports.user_store.as_ref(), &tenant, user_id).await?;
        DataExportRequest::request_for(&account, scope, &control).map_err(AppError::from_domain)
    }
}

impl Command for RequestExportUseCase {
    type Caller = CallerContext;
    type Input = RequestExportRequest;
    type Output = Result<DataExportId, AppError>;

    /// Asks for a copy of `request.whose`'s data and records
    /// `identity.data_export_requested`. A person has one request open at a
    /// time: a second waits on the first.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts, or a person asking for their own came with no
    ///   session.
    /// - `AppError::Forbidden` when the caller may not view the user, or the
    ///   user holds more than the caller.
    /// - `AppError::NotFound` if the user doesn't exist.
    /// - `AppError::Conflict` when the person has a request still asked for
    ///   or ready to download.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: RequestExportRequest,
    ) -> Result<DataExportId, AppError> {
        let RequestExportRequest { whose, scope } = request;
        let tenant = ctx.tenant();
        let (mut export, actor) = self.requested(ctx, whose, scope).await?;
        ensure_none_open(self.ports.export_store.as_ref(), &tenant, export.user_id()).await?;

        self.ports
            .export_store
            .save(&tenant, &export)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&actor, export.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(*export.id())
    }
}

/// Refuses a request for a person who has one open.
///
/// # Errors
///
/// - `AppError::Conflict` when one is still asked for or ready.
/// - `AppError::Internal` on storage failure.
async fn ensure_none_open(
    store: &dyn DataExportStore,
    tenant: &ScopedTenant,
    user_id: &UserId,
) -> Result<(), AppError> {
    let open = store.open_for_user(tenant, user_id).await.or_internal()?;
    if open.is_some() {
        return Err(AppError::Conflict(message!(
            "identity-a-copy-of-this-person-s",
            "a copy of this person's data is already on its way"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::test_caller_id;
    use crate::test_support::identity::{FakeDataExportStore, FakeUserStore, access_where_holds};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        exports: Arc<FakeDataExportStore>,
        audit: Arc<FakeEventDispatcher>,
        ports: RequestExportPorts,
    }

    impl Fixture {
        fn with_bob(bob: UserId) -> Self {
            let exports = Arc::new(FakeDataExportStore::empty());
            Self {
                ports: RequestExportPorts {
                    export_store: exports.clone(),
                    user_store: Arc::new(FakeUserStore::with_user(bob, "bob@acme.test")),
                    ..RequestExportPorts::fakes()
                },
                exports,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ask(&self, whose: Whose) -> Result<DataExportId, AppError> {
            let use_case = RequestExportUseCase::new(RequestExportPorts {
                export_store: self.ports.export_store.clone(),
                user_store: self.ports.user_store.clone(),
                access_records: self.ports.access_records.clone(),
                tenant_authorities: self.ports.tenant_authorities.clone(),
            });
            let request = RequestExportRequest {
                whose,
                scope: ExportScope::Access,
            };
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.audit.clone()), request))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann asks what is kept about her. A request for her is kept and
    /// recorded.
    #[test]
    fn a_person_asks_for_their_own_data() {
        let fixture = Fixture::with_bob(UserId::new());

        let id = fixture.ask(Whose::Own).unwrap();

        let kept = fixture.exports.stored(&id).unwrap();
        assert_eq!(kept.user_id(), &test_caller_id());
        assert_eq!(fixture.recorded(), ["identity.data_export_requested"]);
    }

    /// Bob wrote to support. Ann, who may view users, asks on his behalf;
    /// the request is his.
    #[test]
    fn staff_ask_on_someones_behalf() {
        let bob = UserId::new();
        let fixture = Fixture::with_bob(bob);

        let id = fixture.ask(Whose::OnBehalfOf(bob)).unwrap();

        assert_eq!(fixture.exports.stored(&id).unwrap().user_id(), &bob);
    }

    /// Ann asks twice. The second waits on the first and nothing more is
    /// kept.
    #[test]
    fn a_second_request_waits_on_the_first() {
        let fixture = Fixture::with_bob(UserId::new());
        fixture.ask(Whose::Own).unwrap();

        let again = fixture.ask(Whose::Own);

        assert!(matches!(again, Err(AppError::Conflict(_))));
        assert_eq!(fixture.exports.count(), 1);
    }

    /// Without user-viewing rights, a caller cannot request Bob's data.
    /// No export request or audit event is saved.
    #[test]
    fn a_caller_who_may_not_view_users_is_refused() {
        let bob = UserId::new();
        let mut fixture = Fixture::with_bob(bob);
        fixture.ports.tenant_authorities = Arc::new(FakeTenantAuthorities::holding(&[]));

        let result = fixture.ask(Whose::OnBehalfOf(bob));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.exports.count(), 0);
        assert!(fixture.recorded().is_empty());
    }

    /// User-viewing rights do not permit requesting Bob's data while he
    /// holds broader user-management rights.
    #[test]
    fn a_user_holding_more_than_the_caller_is_refused() {
        let bob = UserId::new();
        let mut fixture = Fixture::with_bob(bob);
        fixture.ports.access_records = access_where_holds(bob, &[SystemPermission::ManageUsers]);
        fixture.ports.tenant_authorities =
            Arc::new(FakeTenantAuthorities::holding(&[SystemPermission::Users(
                UserAction::View,
            )]));

        let result = fixture.ask(Whose::OnBehalfOf(bob));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann asks for someone the tenant does not have. It is not found.
    #[test]
    fn an_unknown_user_is_not_found() {
        let fixture = Fixture::with_bob(UserId::new());

        let result = fixture.ask(Whose::OnBehalfOf(UserId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out person cannot request an export of their own data.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let mut fixture = Fixture::with_bob(UserId::new());
        fixture.ports.tenant_authorities =
            Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = fixture.ask(Whose::Own);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
