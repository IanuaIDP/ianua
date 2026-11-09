//! Create SCIM user: the directory opens an account for someone it added,
//! with the tenant's starting roles and the role the endpoint gives new
//! accounts.
//!
//! The directory's word never proves an address. A link to confirm it is
//! always mailed to the person, whether or not the endpoint lets them sign
//! in at once.

use std::sync::Arc;

use ianua_domain::domains::authorization::role_assignment::RoleAssignment;
use ianua_domain::domains::federation::scim::{DirectoryControl, ScimActivation, ScimEndpoint};
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::identity::account::user_profile::{DirectoryRecords, PersonalDetails};
use ianua_domain::domains::identity::account::user_status::UserStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{DisplayName, Email, UserId};

use crate::acting::ScimAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::ScimCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{
    AccessRecordStore, RoleAssignmentStore, RoleStore, SeparationRuleStore,
};
use crate::ports::federation::ScimStore;
use crate::ports::identity::UserStore;
use crate::ports::limits::{LimitEnforcer, PlanLimitsSource, ResourceKind};
use crate::services::authorization::duties::DutySources;
use crate::services::authorization::provider_grants::{self, ProviderRoleStores};
use crate::services::identity::address_free::ensure_email_free;
use crate::services::identity::link_scopes::TenantLinkScopes;
use crate::services::limits::room::{PlanSources, ensure_room_for_tenant};
use crate::services::lookup::existing_role;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::email::VerificationLinks;
use crate::use_cases::scim::sync::record_synced;
use crate::use_cases::scim::users::directory_account::{
    ConfirmationMail, confirmation_mailed, directory_reach,
};
use crate::use_cases::scim::users::fields::{AccountSwitch, ScimName, ScimUserFields};
use crate::use_cases::scim::users::update::ensure_manager_known;

/// The ports [`CreateScimUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreateScimPorts {
    /// Signs the directory in with its token.
    pub scim_authorities: Arc<dyn ScimAuthorities>,
    /// Records when the directory last synced.
    pub scim_store: Arc<dyn ScimStore>,
    /// Mails the new address the link that confirms it.
    pub verification_links: Arc<VerificationLinks>,
    /// Where the tenant's links point, from its records.
    pub link_scopes: TenantLinkScopes,
    /// Saves users and finds addresses already taken.
    pub user_store: Arc<dyn UserStore>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// The tenant's separation rules, which the endpoint's role is held to.
    pub separation_rules: Arc<dyn SeparationRuleStore>,
    /// Reads the tenant's default roles and the endpoint's role.
    pub role_store: Arc<dyn RoleStore>,
    /// Records the roles the new user starts with.
    pub assignment_store: Arc<dyn RoleAssignmentStore>,
    /// Reads the tenant's plan.
    pub plan_limits: Arc<dyn PlanLimitsSource>,
    /// Holds the tenant to its plan's user limit.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
}

impl PlanSources for CreateScimPorts {
    fn plan_limits(&self) -> &dyn PlanLimitsSource {
        self.plan_limits.as_ref()
    }

    fn limit_enforcer(&self) -> &dyn LimitEnforcer {
        self.limit_enforcer.as_ref()
    }
}

/// Opens accounts in a tenant for its directory.
pub struct CreateScimUseCase {
    ports: CreateScimPorts,
}

/// What the directory's record says about the person beyond their address
/// and display name.
struct SentProfile {
    name: ScimName,
    records: DirectoryRecords,
    active: AccountSwitch,
}

impl CreateScimUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CreateScimPorts) -> Self {
        Self { ports }
    }

    /// Refuses another user when the tenant's plan has no room for one.
    async fn ensure_room_for_one_more(&self, tenant: &ScopedTenant) -> Result<(), AppError> {
        ensure_room_for_tenant(self.ports.plan_room(), tenant, ResourceKind::Users).await
    }

    /// Lets the new account in as the endpoint and the directory's record
    /// say: at once when the endpoint says so, and kept out when the record
    /// switches it off. The address stays unverified either way. The
    /// record's name parts and the directory's records go onto the account.
    async fn admit(
        &self,
        tenant: &ScopedTenant,
        endpoint: &ScimEndpoint<ResolvedTenant>,
        user: &mut User<ResolvedTenant>,
        sent: SentProfile,
    ) -> Result<(), AppError> {
        let records = self.ports.access_records.as_ref();
        let reach = directory_reach(records, tenant, endpoint, user.id()).await?;
        open(user, endpoint.auto_activate(), sent.active, &reach.control)
            .map_err(AppError::from_domain)?;
        ensure_manager_known(
            self.ports.user_store.as_ref(),
            tenant,
            &sent.records.manager,
        )
        .await?;
        let details = PersonalDetails {
            given_name: sent.name.given_name,
            family_name: sent.name.family_name,
            ..PersonalDetails::default()
        };
        user.update_details(details, endpoint)
            .map_err(AppError::from_domain)?;
        user.update_records(sent.records, &reach.control)
            .map_err(AppError::from_domain)
    }

    /// The role the endpoint gives every account it opens, when it names
    /// one.
    async fn directory_role(
        &self,
        tenant: &ScopedTenant,
        endpoint: &ScimEndpoint<ResolvedTenant>,
        user: &User<ResolvedTenant>,
    ) -> Result<Vec<RoleAssignment<ResolvedTenant>>, AppError> {
        let Some(role_id) = endpoint.default_role_id() else {
            return Ok(Vec::new());
        };
        let role = existing_role(self.ports.role_store.as_ref(), tenant, role_id).await?;
        let given = endpoint
            .default_assignment(*user.id(), &role)
            .map_err(AppError::from_domain)?;
        Ok(vec![given])
    }

    /// Saves the new user and the roles they start with: the tenant's
    /// defaults, and the endpoint's role where the tenant's separation of
    /// duties allows it alongside them.
    async fn store(
        &self,
        tenant: &ScopedTenant,
        user: &User<ResolvedTenant>,
        extra: Vec<RoleAssignment<ResolvedTenant>>,
    ) -> Result<(), AppError> {
        self.ports
            .user_store
            .save(tenant, user)
            .await
            .or_internal()?;
        let stores = ProviderRoleStores {
            role_store: self.ports.role_store.as_ref(),
            assignment_store: self.ports.assignment_store.as_ref(),
            duties: DutySources::of(
                self.ports.access_records.as_ref(),
                self.ports.separation_rules.as_ref(),
            ),
        };
        provider_grants::grant_starting_roles(stores, tenant, *user.id(), extra).await
    }
}

impl Command for CreateScimUseCase {
    type Caller = ScimCaller;
    type Input = ScimUserFields;
    type Output = Result<User<ResolvedTenant>, AppError>;

    /// Opens an account for the person `fields` describes, mails a link
    /// to confirm the address when the account may be let in, records `identity.user_registered` by the system,
    /// `identity.verification_email_sent` once the mailer took the link,
    /// and the sync.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the directory's token is missing,
    ///   not the tenant's current one, or SCIM is switched off.
    /// - `AppError::Forbidden` at the plan's user limit, or when the
    ///   endpoint's role for new accounts may not be given that way.
    /// - `AppError::Conflict` if the address already has an account.
    /// - `AppError::NotFound` if the endpoint's role for new accounts is
    ///   gone, the manager the record names is not an account of the
    ///   tenant, or the tenant or its organization is not on record.
    /// - `AppError::Internal` on persistence or audit failure, or when the
    ///   confirmation link cannot be made or stored.
    async fn execute(
        &self,
        caller: &ScimCaller,
        auditor: &RequestAuditor,
        fields: ScimUserFields,
    ) -> Result<User<ResolvedTenant>, AppError> {
        let (user_name, display_name, sent) = split(fields);
        let tenant = caller.tenant();
        let endpoint = self.ports.scim_authorities.endpoint(caller).await?;
        self.ensure_room_for_one_more(tenant).await?;
        ensure_email_free(self.ports.user_store.as_ref(), tenant, &user_name).await?;
        let registered = User::register(UserId::new(), user_name, display_name, &endpoint);
        let mut user = registered.map_err(AppError::from_domain)?;
        self.admit(tenant, &endpoint, &mut user, sent).await?;
        let extra = self.directory_role(tenant, &endpoint, &user).await?;

        self.store(tenant, &user, extra).await?;
        let mail = ConfirmationMail {
            links: &self.ports.verification_links,
            scopes: &self.ports.link_scopes,
        };
        confirmation_mailed(mail, tenant, &mut user).await?;
        record_synced(
            self.ports.scim_store.as_ref(),
            tenant,
            endpoint,
            auditor,
            user.take_events(tenant),
        )
        .await?;
        Ok(user)
    }
}

/// `fields` as the account opens with them: the address and the name it
/// is registered under, and the rest, which goes on once it is open.
fn split(fields: ScimUserFields) -> (Email, DisplayName, SentProfile) {
    let ScimUserFields {
        user_name,
        display_name,
        name,
        records,
        active,
    } = fields;
    let sent = SentProfile {
        name,
        records,
        active,
    };
    (user_name, display_name, sent)
}

/// Lets `user`, a new account, in at once when `activation` says so and the
/// record keeps it on. A record that switches it off switches the account
/// off, so following the link later does not let it in.
fn open(
    user: &mut User<ResolvedTenant>,
    activation: ScimActivation,
    switch: AccountSwitch,
    control: &DirectoryControl,
) -> Result<(), DomainError> {
    match (switch, activation, user.status()) {
        (AccountSwitch::On, ScimActivation::Immediate, UserStatus::PendingVerification) => {
            user.activate(control).map(drop)
        }
        (AccountSwitch::On, _, _) => Ok(()),
        (AccountSwitch::Off, _, _) => user.deactivate(control).map(drop),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::federation::scim::ScimEndpointRow;
    use ianua_domain::domains::identity::account::profile_values::{ExternalId, GivenName};
    use ianua_domain::shared::config::DisplayNameLimits;
    use ianua_domain::types::{DisplayName, Email, PrincipalRef, Setting};

    use super::*;
    use crate::test_support::authorization::{FakeRoleAssignmentStore, FakeRoleStore, stored_role};
    use crate::test_support::federation::FakeScimStore;
    use crate::test_support::identity::{FakeTokenStore, FakeUserStore, verification_links_over};
    use crate::test_support::scim::{
        SignInRefusal, directory_row, refused_sign_in, scim_caller, scim_sign_in_with, sign_in_over,
    };
    use crate::test_support::{
        FakeEventDispatcher, FakeMailer, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };

    fn fields(email: &str, active: AccountSwitch) -> ScimUserFields {
        ScimUserFields {
            user_name: Email::new(email).unwrap(),
            display_name: DisplayName::new("Ada Lovelace", &DisplayNameLimits::default()).unwrap(),
            name: ScimName {
                given_name: Setting::Set(GivenName::new("Ada").unwrap()),
                family_name: Setting::Unset,
            },
            records: DirectoryRecords {
                external_id: Setting::Set(ExternalId::new("00u-ada").unwrap()),
                ..DirectoryRecords::default()
            },
            active,
        }
    }

    /// Entra adds Ada with its id for her and her given name. Her new
    /// account holds both.
    #[test]
    fn a_new_account_holds_the_directory_id_and_the_name() {
        let ada = create(ports_with(directory_row()), AccountSwitch::On);

        let profile = ada.profile();
        assert_eq!(profile.details.given_name.value().unwrap().as_str(), "Ada");
        assert_eq!(
            profile.records.external_id.value().unwrap().as_str(),
            "00u-ada"
        );
    }

    /// Entra adds Ada naming a manager Acme has no account for. The account
    /// is not opened.
    #[test]
    fn a_new_account_with_an_unknown_manager_is_not_opened() {
        let users = Arc::new(FakeUserStore::empty());
        let ports = CreateScimPorts {
            user_store: users.clone(),
            ..ports_with(directory_row())
        };
        let mut sent = fields("ada@acme.com", AccountSwitch::On);
        sent.records.manager = Setting::Set(UserId::new());

        let result = create_with(ports, &scim_caller(), sent);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        let ada = Email::new("ada@acme.com").unwrap();
        assert!(
            block_on(users.find_by_email(&test_ctx().tenant(), &ada))
                .unwrap()
                .is_none()
        );
    }

    fn create_with(
        ports: CreateScimPorts,
        caller: &ScimCaller,
        fields: ScimUserFields,
    ) -> Result<User<ResolvedTenant>, AppError> {
        let use_case = CreateScimUseCase::new(ports);
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        block_on(use_case.execute(caller, &auditor, fields))
    }

    fn create(ports: CreateScimPorts, active: AccountSwitch) -> User<ResolvedTenant> {
        create_with(ports, &scim_caller(), fields("ada@acme.com", active)).unwrap()
    }

    fn ports_with(row: ScimEndpointRow) -> CreateScimPorts {
        CreateScimPorts {
            scim_authorities: scim_sign_in_with(row),
            ..CreateScimPorts::fakes()
        }
    }

    /// Okta adds Ada, and Acme lets new accounts in at once. She can sign
    /// in, and her address waits for her to confirm it.
    #[test]
    fn a_new_user_signs_in_at_once_with_an_unconfirmed_address() {
        let user = create(ports_with(directory_row()), AccountSwitch::On);

        assert!(user.can_authenticate());
        assert!(!user.email_verified());
    }

    /// Acme asks new accounts to confirm their address first. Ada waits
    /// until she follows the link.
    #[test]
    fn without_activation_a_new_user_waits_to_confirm_their_address() {
        let row = ScimEndpointRow {
            auto_activate: ScimActivation::AfterConfirmation,
            ..directory_row()
        };

        let user = create(ports_with(row), AccountSwitch::On);

        assert_eq!(user.status(), UserStatus::PendingVerification);
    }

    /// Okta sends Ada already switched off. Her account is opened switched
    /// off, so following her confirmation link later does not let her in.
    #[test]
    fn a_user_sent_switched_off_is_not_let_in() {
        let user = create(ports_with(directory_row()), AccountSwitch::Off);

        assert_eq!(user.status(), UserStatus::Deactivated);
    }

    /// Acme gives every account its directory opens the Engineer role. Ada
    /// holds it from the start.
    #[test]
    fn a_new_user_holds_the_endpoints_role() {
        let engineer = stored_role("Engineer", Vec::new(), Vec::new());
        let role_id = *engineer.id();
        let assignments = Arc::new(FakeRoleAssignmentStore::empty());
        let ports = CreateScimPorts {
            role_store: Arc::new(FakeRoleStore::holding(test_ctx().tenant_id(), [engineer])),
            assignment_store: assignments.clone(),
            ..ports_with(ScimEndpointRow {
                default_role_id: Setting::Set(role_id),
                ..directory_row()
            })
        };

        let user = create(ports, AccountSwitch::On);

        assert_eq!(
            assignments.holders_of(test_ctx().tenant_id(), &role_id),
            [PrincipalRef::User(*user.id())]
        );
    }

    /// An endpoint granting an owner role cannot create a user through SCIM;
    /// the request is forbidden and no account is saved.
    #[test]
    fn a_role_with_built_in_permissions_is_never_given_by_the_directory() {
        let owner = stored_role("Owner", SystemPermission::all().to_vec(), Vec::new());
        let role_id = *owner.id();
        let users = Arc::new(FakeUserStore::empty());
        let ports = CreateScimPorts {
            user_store: users.clone(),
            role_store: Arc::new(FakeRoleStore::holding(test_ctx().tenant_id(), [owner])),
            ..ports_with(ScimEndpointRow {
                default_role_id: Setting::Set(role_id),
                ..directory_row()
            })
        };

        let result = create_with(
            ports,
            &scim_caller(),
            fields("mallory@acme.com", AccountSwitch::On),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(users.count(), 0);
    }

    /// Okta adds Ada a second time. The address already has an account, and
    /// nothing new is opened.
    #[test]
    fn a_second_user_with_the_same_user_name_is_a_conflict() {
        let users = Arc::new(FakeUserStore::empty());
        users.add_active_user(UserId::new(), "ada@acme.com");
        let ports = CreateScimPorts {
            user_store: users.clone(),
            ..ports_with(directory_row())
        };

        let result = create_with(
            ports,
            &scim_caller(),
            fields("ada@acme.com", AccountSwitch::On),
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(users.count(), 1);
    }

    /// Creating a user at the tenant's plan limit is forbidden and leaves
    /// the user store empty.
    #[test]
    fn a_user_is_refused_at_the_tenants_user_limit() {
        let users = Arc::new(FakeUserStore::empty());
        let ports = CreateScimPorts {
            user_store: users.clone(),
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..ports_with(directory_row())
        };

        let result = create_with(
            ports,
            &scim_caller(),
            fields("ada@acme.com", AccountSwitch::On),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(users.count(), 0);
    }

    /// Okta's call went through. Acme sees that its directory synced.
    #[test]
    fn a_created_user_records_the_sync() {
        let store = Arc::new(FakeScimStore::holding(
            &test_ctx().tenant(),
            ScimEndpoint::reconstitute(directory_row()).unwrap(),
        ));
        let ports = CreateScimPorts {
            scim_authorities: sign_in_over(&store),
            scim_store: store.clone(),
            ..CreateScimPorts::fakes()
        };

        create(ports, AccountSwitch::On);

        let stored = block_on(store.find(&test_ctx().tenant())).unwrap().unwrap();
        assert!(stored.last_sync_at().is_some());
    }

    /// `ports`, mailing through `mailer`.
    fn mailing_to(mailer: &Arc<FakeMailer>, ports: CreateScimPorts) -> CreateScimPorts {
        CreateScimPorts {
            verification_links: verification_links_over(&Arc::new(FakeTokenStore::empty()), mailer),
            ..ports
        }
    }

    /// Okta adds Ada. A link to confirm her address goes to her, and the
    /// mail is recorded after her account and the name and records Okta
    /// sent.
    #[test]
    fn an_unproven_address_is_mailed_a_confirmation_link() {
        let mailer = Arc::new(FakeMailer::new());
        let sink = Arc::new(FakeEventDispatcher::new());
        let use_case = CreateScimUseCase::new(mailing_to(&mailer, ports_with(directory_row())));

        block_on(use_case.execute(
            &scim_caller(),
            &test_auditor(sink.clone()),
            fields("ada@acme.com", AccountSwitch::On),
        ))
        .unwrap();

        assert_eq!(mailer.recipients(), ["ada@acme.com"]);
        assert_eq!(
            sink.records.lock().unwrap().clone(),
            [
                "identity.user_registered",
                "identity.user_profile_updated",
                "identity.user_profile_updated",
                "identity.verification_email_sent"
            ]
        );
    }

    /// An address supplied by the directory remains unverified, and its
    /// confirmation link is mailed to that address.
    #[test]
    fn an_address_from_the_directory_is_never_verified() {
        let mailer = Arc::new(FakeMailer::new());

        let user = create(
            mailing_to(&mailer, ports_with(directory_row())),
            AccountSwitch::On,
        );

        assert!(!user.email_verified());
        assert_eq!(mailer.recipients(), ["ada@acme.com"]);
    }

    /// Okta sends Ada already switched off. She is not let in, so no link
    /// is mailed to her until Okta switches her on.
    #[test]
    fn a_user_sent_switched_off_is_mailed_nothing() {
        let mailer = Arc::new(FakeMailer::new());

        create(
            mailing_to(&mailer, ports_with(directory_row())),
            AccountSwitch::Off,
        );

        assert_eq!(mailer.count(), 0);
    }

    /// Missing, invalid or rotated tokens and disabled SCIM each return an
    /// unauthenticated error without creating a user.
    #[test]
    fn a_directory_that_is_not_signed_in_is_refused() {
        for refusal in SignInRefusal::ALL {
            let (scim_authorities, caller) = refused_sign_in(refusal);
            let users = Arc::new(FakeUserStore::empty());
            let ports = CreateScimPorts {
                scim_authorities,
                user_store: users.clone(),
                ..CreateScimPorts::fakes()
            };

            let result = create_with(
                ports,
                &caller,
                fields("mallory@acme.com", AccountSwitch::On),
            );

            assert!(
                matches!(result, Err(AppError::Unauthenticated)),
                "{refusal:?}"
            );
            assert_eq!(users.count(), 0);
        }
    }
}
