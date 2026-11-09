//! Gathering a person's data export into one JSON file: an object with
//! the export's own details and one member per section the request names,
//! in the domain's order.
//!
//! The sections read whole are written as they are read. The audit
//! trail's records, the person's activity and their sign-ins, and the
//! notices sent to them, are written a keyset page at a time, so a long
//! history never sits in memory. Their sign-ins are read as the
//! person-facing list reads them: the ones they made, the lockouts of
//! their account, and the failed attempts at each address while they held
//! it, which the trail files under the platform, not under them. The
//! file appears in the store only once its last section is written; the
//! whole build is held to a bound, and a build cut short leaves nothing a
//! link could open and is written again from the start on the next run.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::listing::{Limit, Listing, PageRequest, SortOrder};
use ianua_app::ports::audit::AuditLogFilter;
use ianua_app::ports::identity::DataExportBuilder;
use ianua_app::ports::notifications::{ReadFilter, TenantNotificationFilter};
use ianua_app::services::identity::sign_ins::sign_ins_of;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::identity::privacy::export::{DataExportRequest, ExportSection};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ActorRef, UserId};
use serde_json::{Value, json};

use crate::files::records::{json_items, moment};
use crate::files::sections::{Person, PersonalDataSources, notice_item};
use crate::files::store::{FileName, FileStore, FileUpload};

/// How long gathering one export may take before it is given up on.
const BUILD_TIMEOUT: Duration = Duration::from_secs(120);

/// How many audit records, or notices, one page reads.
const LOG_PAGE: u32 = 500;

/// Everything the person did, as a filter of the audit log.
fn activity_of(user: &UserId) -> AuditLogFilter {
    AuditLogFilter {
        actor: Some(ActorRef::User(*user)),
        ..AuditLogFilter::default()
    }
}

/// Everything staff or an operator did while acting as the person.
fn acted_as(user: &UserId) -> AuditLogFilter {
    AuditLogFilter {
        acting_as: Some(*user),
        ..AuditLogFilter::default()
    }
}

/// Gathers people's data exports into files in a file store.
pub struct FileDataExportBuilder {
    store: Arc<dyn FileStore>,
    sources: PersonalDataSources,
}

impl FileDataExportBuilder {
    /// A builder reading through `sources` and keeping each file in
    /// `store`.
    #[must_use]
    pub fn new(store: Arc<dyn FileStore>, sources: PersonalDataSources) -> Self {
        Self { store, sources }
    }

    /// Writes `request`'s file whole.
    async fn write_export(
        &self,
        tenant: &ScopedTenant,
        request: &DataExportRequest<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let person = Person {
            tenant,
            user: request.user_id(),
        };
        let mut file = self
            .store
            .create(&FileName::data_export(tenant, request.id()))
            .await?;
        file.write(heading(request)?.as_bytes()).await?;
        for section in request.sections() {
            file.write(member_name(*section)?.as_bytes()).await?;
            self.write_section(file.as_mut(), person, *section).await?;
        }
        file.write(b"\n}\n").await?;
        file.finish().await
    }

    /// Writes `section` of `person`'s data.
    /// The exhaustive dispatch keeps every export section tied to its own reader and writer.
    #[allow(clippy::too_many_lines)]
    async fn write_section(
        &self,
        file: &mut dyn FileUpload,
        person: Person<'_>,
        section: ExportSection,
    ) -> Result<(), DomainError> {
        let sources = &self.sources;
        match section {
            ExportSection::Activity => {
                self.write_log(file, person, &activity_of(person.user))
                    .await
            }
            ExportSection::ActedAsThem => {
                self.write_log(file, person, &acted_as(person.user)).await
            }
            ExportSection::SignInHistory => {
                let filter = self.sign_ins_filter(person).await?;
                self.write_log(file, person, &filter).await
            }
            ExportSection::Notifications => self.write_notifications(file, person).await,
            ExportSection::FailedSignInCount => {
                write_whole(file, sources.failed_sign_in_count(person).await?).await
            }
            ExportSection::PasswordResets => {
                write_whole(file, sources.password_resets(person).await?).await
            }
            ExportSection::Invitations => {
                write_whole(file, sources.invitations(person).await?).await
            }
            ExportSection::BreakGlassGrants => {
                write_whole(file, sources.break_glass_grants(person).await?).await
            }
            ExportSection::SignInPlaces => {
                write_whole(file, sources.sign_in_places(person).await?).await
            }
            ExportSection::SupportAccess => {
                write_whole(file, sources.support_access(person).await?).await
            }
            ExportSection::Profile => write_whole(file, sources.profile(person).await?).await,
            ExportSection::Attributes => write_whole(file, sources.attributes(person).await?).await,
            ExportSection::Consents => write_whole(file, sources.consents(person).await?).await,
            ExportSection::AppGrants => write_whole(file, sources.app_grants(person).await?).await,
            ExportSection::LinkedIdentities => {
                write_whole(file, sources.linked_identities(person).await?).await
            }
            ExportSection::RolesAndGroups => {
                write_whole(file, sources.roles_and_groups(person).await?).await
            }
            ExportSection::Sessions => write_whole(file, sources.sessions(person).await?).await,
            ExportSection::Devices => write_whole(file, sources.devices(person).await?).await,
        }
    }

    /// The filter of the person's sign-ins, as the person-facing list
    /// reads them: those they made, the lockouts of their account, and the
    /// failed attempts at each address while their account held it.
    async fn sign_ins_filter(&self, person: Person<'_>) -> Result<AuditLogFilter, DomainError> {
        let address = self.sources.address(person).await?;
        let of = sign_ins_of(
            self.sources.activity.as_ref(),
            person.tenant,
            person.user,
            &address,
        )
        .await?;
        Ok(AuditLogFilter {
            sign_ins_of: Some(of),
            ..AuditLogFilter::default()
        })
    }

    /// Writes the person's audit records `filter` keeps as one array,
    /// newest first, a page at a time.
    async fn write_log(
        &self,
        file: &mut dyn FileUpload,
        person: Person<'_>,
        filter: &AuditLogFilter,
    ) -> Result<(), DomainError> {
        file.write(b"[").await?;
        let order = SortOrder::default();
        let mut page = PageRequest::first(Limit::internal(LOG_PAGE));
        let mut written: u64 = 0;
        loop {
            let read = self
                .sources
                .activity
                .query(person.tenant, filter, &order, &page)
                .await?;
            file.write(json_items(&read.items, written)?.as_bytes())
                .await?;
            written = written.saturating_add(counted(read.items.len()));
            let Some(next) = read.next else {
                return file.write(b"\n]").await;
            };
            page = PageRequest::new(Some(next), Limit::internal(LOG_PAGE));
        }
    }

    /// Writes how the person chose to be told, and the notices sent to
    /// them about their own account, newest first, a page at a time.
    ///
    /// Only those notices are theirs: a notice shown to them for a right
    /// they hold tells of the tenant or of someone else, so it is asked for
    /// with no right at all.
    async fn write_notifications(
        &self,
        file: &mut dyn FileUpload,
        person: Person<'_>,
    ) -> Result<(), DomainError> {
        let choices = self.sources.notification_choices(person).await?;
        let choices = serde_json::to_string(&choices).map_err(DomainError::infra)?;
        file.write(format!("{{\"choices\": {choices}, \"inbox\": [").as_bytes())
            .await?;
        self.write_inbox(file, person).await?;
        file.write(b"\n]}").await
    }

    /// Writes the notices sent to the person about their own account into
    /// an open array, newest first, a page at a time.
    async fn write_inbox(
        &self,
        file: &mut dyn FileUpload,
        person: Person<'_>,
    ) -> Result<(), DomainError> {
        let filter = TenantNotificationFilter {
            permissions: &[],
            reads: ReadFilter::All,
        };
        let order = SortOrder::default();
        let mut page = PageRequest::first(Limit::internal(LOG_PAGE));
        let mut written: u64 = 0;
        loop {
            let listing = Listing {
                filter: &filter,
                sort: &order,
                page: &page,
            };
            let read = self
                .sources
                .notifications
                .list_for_user(person.tenant, person.user, listing)
                .await?;
            let items: Vec<Value> = (read.items.iter())
                .map(notice_item)
                .collect::<Result<_, _>>()?;
            file.write(array_items(&items, written)?.as_bytes()).await?;
            written = written.saturating_add(counted(items.len()));
            let Some(next) = read.next else {
                return Ok(());
            };
            page = PageRequest::new(Some(next), Limit::internal(LOG_PAGE));
        }
    }
}

/// `count` items as a running total adds them.
fn counted(count: usize) -> u64 {
    u64::try_from(count).unwrap_or(u64::MAX)
}

/// `items` as JSON, each after a comma unless it is the first of the
/// array, `already` being how many the array holds before them.
fn array_items(items: &[Value], already: u64) -> Result<String, DomainError> {
    let mut text = String::new();
    for (at, item) in items.iter().enumerate() {
        if already > 0 || at > 0 {
            text.push(',');
        }
        text.push('\n');
        text.push_str(&serde_json::to_string(item).map_err(DomainError::infra)?);
    }
    Ok(text)
}

#[async_trait]
impl DataExportBuilder for FileDataExportBuilder {
    async fn build(
        &self,
        tenant_id: &ScopedTenant,
        request: &DataExportRequest<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        tokio::time::timeout(BUILD_TIMEOUT, self.write_export(tenant_id, request))
            .await
            .map_err(DomainError::infra)?
    }
}

/// Writes `value` whole as JSON.
async fn write_whole(file: &mut dyn FileUpload, value: Value) -> Result<(), DomainError> {
    let bytes = serde_json::to_vec(&value).map_err(DomainError::infra)?;
    file.write(&bytes).await
}

/// The start of the file: the opening brace and the export's own details.
fn heading(request: &DataExportRequest<ResolvedTenant>) -> Result<String, DomainError> {
    let details = json!({
        "id": request.id().to_string(),
        "scope": request.scope().as_str(),
        "requested_at": moment(request.requested_at())?,
    });
    let details = serde_json::to_string(&details).map_err(DomainError::infra)?;
    Ok(format!("{{\n\"export\": {details}"))
}

/// The member name a section is written under, after the comma that
/// separates it from the member before.
fn member_name(section: ExportSection) -> Result<String, DomainError> {
    let name = serde_json::to_string(section.as_str()).map_err(DomainError::infra)?;
    Ok(format!(",\n{name}: "))
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::authentication::{
        BreakGlassStore, CountedAccount, ResetRequestStore, SignInAttemptCounts, SignInHistoryStore,
    };
    use ianua_app::ports::authorization::RoleStore;
    use ianua_app::ports::identity::{
        ConsentStore, InvitationStore, SupportImpersonationStore, UserStore,
    };
    use ianua_app::ports::notifications::{NotificationPreferenceStore, TenantNotificationStore};
    use ianua_app::ports::shared::SessionStore;
    use ianua_domain::domains::audit::builder::AuditContext;
    use ianua_domain::domains::authentication::recovery::reset::PasswordResetRequest;
    use ianua_domain::domains::authentication::risk_engine::assessment::IpGeolocation;
    use ianua_domain::domains::authentication::risk_engine::origin::AttemptOrigin;
    use ianua_domain::domains::authentication::risk_engine::rate_limit::RateLimitPolicy;
    use ianua_domain::domains::authentication::sessions::session::{Session, SessionRow};
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;
    use ianua_domain::domains::authorization::break_glass::BreakGlassGrant;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::domains::identity::impersonation::SupportImpersonation;
    use ianua_domain::domains::identity::invitations::invitation::Invitation;
    use ianua_domain::domains::identity::privacy::consent::{ConsentRecord, ConsentType};
    use ianua_domain::domains::identity::privacy::export::ExportScope;
    use ianua_domain::domains::notifications::category::NotificationCategory;
    use ianua_domain::domains::notifications::channel::NotificationChannel;
    use ianua_domain::domains::notifications::preference::NotificationPreference;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::test_support::events::{sample_account_locked_out, sample_login_succeeded};
    use ianua_domain::types::{CountryCode, Email, Fact, OperatorId};
    use tokio::io::AsyncReadExt as _;

    use super::*;
    use crate::cache::{CacheSignInAttemptCounts, MemoryState};
    use crate::files::disk::DiskFileStore;
    use crate::postgres::audit::PgTenantAuditLogStore;
    use crate::postgres::authentication::{
        PgBreakGlassStore, PgMfaEnrollmentStore, PgPasskeyStore, PgResetRequestStore,
        PgSignInHistoryStore, PgTrustedDeviceStore,
    };
    use crate::postgres::authorization::{PgGroupMembershipStore, PgGroupStore, PgRoleStore};
    use crate::postgres::federation::PgFederatedLinkStore;
    use crate::postgres::identity::{
        PgConsentStore, PgInvitationStore, PgMetadataStore, PgSupportImpersonationStore,
        PgUserStore,
    };
    use crate::postgres::notifications::{
        PgNotificationPreferenceStore, PgTenantNotificationStore,
    };
    use crate::postgres::oauth::PgOAuthConsentStore;
    use crate::postgres::shared::PgSessionStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::audit::{
        failed_sign_in, recorded, recorded_as, saved_organization, saved_tenant_of,
    };
    use crate::test_support::rows::authentication::{grant_row, hash, reset_row, session_row};
    use crate::test_support::rows::authorization::role;
    use crate::test_support::rows::identity::{
        InvitationSeed, consent_row, export_row, impersonation_row, invitation_row, user_row,
    };
    use crate::test_support::rows::notifications::{notice, own_account_notice, user_registered};

    struct Fixture {
        db: TestDb,
        dir: tempfile::TempDir,
        tenant: ScopedTenant,
        ann: UserId,
        bob: UserId,
        counts: Arc<CacheSignInAttemptCounts>,
        builder: FileDataExportBuilder,
    }

    /// The account of `email` kept in `tenant`.
    async fn saved_user(db: &TestDb, tenant: &ScopedTenant, email: &str) -> UserId {
        let user = User::reconstitute(user_row(email)).unwrap();
        PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(tenant, &user)
            .await
            .unwrap();
        *user.id()
    }

    /// Ann's and Bob's accounts in Acme's tenant, Ann with one consent,
    /// and a builder reading every section from the real stores into a
    /// fresh directory.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let tenant = saved_tenant_of(&db.databases, organization).await;
        let ann = saved_user(&db, &tenant, "ann@acme.test").await;
        let bob = saved_user(&db, &tenant, "bob@acme.test").await;
        let databases = &db.databases;
        let consent =
            ConsentRecord::reconstitute(consent_row(ann, ConsentType::TermsOfService, 1)).unwrap();
        PgConsentStore::new(Arc::clone(databases))
            .save(&tenant, &consent)
            .await
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let counts = Arc::new(CacheSignInAttemptCounts::new(Arc::new(MemoryState::new(
            1_000,
        ))));
        let sources = sources(&db, &counts);
        let builder = FileDataExportBuilder::new(Arc::new(DiskFileStore::new(dir.path())), sources);
        Fixture {
            ann,
            bob,
            db,
            dir,
            tenant,
            counts,
            builder,
        }
    }

    /// Wires every export source to the fixture database and its attempt counter.
    /// The flat field list keeps each port's concrete store visible in one place.
    #[allow(clippy::too_many_lines)]
    fn sources(db: &TestDb, counts: &Arc<CacheSignInAttemptCounts>) -> PersonalDataSources {
        let databases = &db.databases;
        PersonalDataSources {
            users: Arc::new(PgUserStore::new(
                Arc::clone(databases),
                DomainLimits::default(),
            )),
            metadata: Arc::new(PgMetadataStore::new(Arc::clone(databases))),
            consents: Arc::new(PgConsentStore::new(Arc::clone(databases))),
            app_grants: Arc::new(PgOAuthConsentStore::new(Arc::clone(databases))),
            linked_identities: Arc::new(PgFederatedLinkStore::new(Arc::clone(databases))),
            roles: Arc::new(PgRoleStore::new(Arc::clone(databases))),
            groups: Arc::new(PgGroupStore::new(Arc::clone(databases))),
            memberships: Arc::new(PgGroupMembershipStore::new(Arc::clone(databases))),
            sessions: Arc::new(PgSessionStore::new(Arc::clone(databases))),
            factors: Arc::new(PgMfaEnrollmentStore::new(Arc::clone(databases))),
            passkeys: Arc::new(PgPasskeyStore::new(Arc::clone(databases))),
            devices: Arc::new(PgTrustedDeviceStore::new(Arc::clone(databases))),
            sign_in_places: Arc::new(PgSignInHistoryStore::new(Arc::clone(databases))),
            notifications: Arc::new(PgTenantNotificationStore::new(Arc::clone(databases))),
            notification_choices: Arc::new(PgNotificationPreferenceStore::new(Arc::clone(
                databases,
            ))),
            impersonations: Arc::new(PgSupportImpersonationStore::new(Arc::clone(databases))),
            sign_in_counts: counts.clone(),
            resets: Arc::new(PgResetRequestStore::new(Arc::clone(databases))),
            invitations: Arc::new(PgInvitationStore::new(Arc::clone(databases))),
            break_glass: Arc::new(PgBreakGlassStore::new(Arc::clone(databases))),
            activity: Arc::new(PgTenantAuditLogStore::new(
                Arc::clone(databases),
                DomainLimits::default(),
            )),
        }
    }

    /// Every member name anywhere in `value`.
    fn member_names(value: &Value) -> Vec<String> {
        match value {
            Value::Object(members) => members
                .iter()
                .flat_map(|(name, inner)| std::iter::once(name.clone()).chain(member_names(inner)))
                .collect(),
            Value::Array(items) => items.iter().flat_map(member_names).collect(),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Vec::new(),
        }
    }

    fn request(user: UserId, scope: ExportScope) -> DataExportRequest<ResolvedTenant> {
        let mut row = export_row(user, 0);
        row.scope = scope;
        DataExportRequest::reconstitute(row).unwrap()
    }

    async fn built(fixture: &Fixture, request: &DataExportRequest<ResolvedTenant>) -> String {
        fixture
            .builder
            .build(&fixture.tenant, request)
            .await
            .unwrap();
        let store = DiskFileStore::new(fixture.dir.path());
        let file = store
            .open(&FileName::data_export(&fixture.tenant, request.id()))
            .await
            .unwrap()
            .unwrap();
        let mut text = String::new();
        file.into_reader().read_to_string(&mut text).await.unwrap();
        text
    }

    /// Ann asks for everything kept about her. The file holds every
    /// section: her account, her consent, and her own activity from the
    /// audit trail, never another's.
    #[tokio::test]
    async fn an_access_export_holds_every_section() {
        let fixture = fixture().await;
        let tenant = *fixture.tenant;
        let hers = ActorRef::User(fixture.ann);
        recorded(
            &fixture.db.databases,
            vec![
                failed_sign_in(tenant, 1).with_actor(hers.clone()),
                sample_login_succeeded(tenant, 30, at(2)).with_actor(hers),
                failed_sign_in(tenant, 3).with_actor(ActorRef::User(fixture.bob)),
            ],
        )
        .await;
        let request = request(fixture.ann, ExportScope::Access);

        let file: Value = serde_json::from_str(&built(&fixture, &request).await).unwrap();

        for section in ExportScope::Access.sections() {
            assert!(file.get(section.as_str()).is_some(), "{}", section.as_str());
        }
        assert_eq!(file["export"]["id"], request.id().to_string());
        assert_eq!(file["profile"]["email"], "ann@acme.test");
        assert_eq!(file["consents"][0]["consent"], "terms_of_service");
        assert_eq!(file["activity"].as_array().unwrap().len(), 2);
    }

    /// Ann's exported sign-in history includes her own attempts, platform-recorded
    /// failures at her address and her lockout, while excluding Bob's lockout.
    #[tokio::test]
    async fn the_sign_in_history_holds_the_failed_attempts_at_her_address() {
        let fixture = fixture().await;
        record_sign_in_history(&fixture).await;
        let request = request(fixture.ann, ExportScope::Access);

        let file: Value = serde_json::from_str(&built(&fixture, &request).await).unwrap();

        let kinds: Vec<&str> = file["sign_in_history"]
            .as_array()
            .unwrap()
            .iter()
            .map(|record| record["event_type"].as_str().unwrap())
            .collect();
        assert_eq!(
            kinds,
            [
                "authentication.account_locked_out",
                "authentication.login_failed",
                "authentication.login_succeeded",
                "authentication.login_failed",
            ]
        );
    }

    /// Records Ann's attempts and both accounts' lockouts for export filtering.
    async fn record_sign_in_history(fixture: &Fixture) {
        let tenant = *fixture.tenant;
        let hers = ActorRef::User(fixture.ann);
        recorded(
            &fixture.db.databases,
            vec![
                failed_sign_in(tenant, 1).with_actor(hers.clone()),
                sample_login_succeeded(tenant, 30, at(2)).with_actor(hers),
                failed_sign_in(tenant, 3),
                sample_account_locked_out(tenant, fixture.ann, at(4)),
                sample_account_locked_out(tenant, fixture.bob, at(5)),
            ],
        )
        .await;
    }

    /// Ann's export includes reset and invitation statuses, her emergency grant,
    /// failed sign-in count and impersonated activity. It excludes the reset
    /// hash and invitation link, and keeps impersonated activity out of her own.
    #[tokio::test]
    async fn the_account_records_hold_resets_invitations_grants_and_acting() {
        let fixture = fixture().await;
        save_reset_and_invitation(&fixture).await;
        record_emergency_access(&fixture).await;
        let request = request(fixture.ann, ExportScope::Access);

        let text = built(&fixture, &request).await;

        let file: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(file["password_resets"][0]["status"], "pending");
        assert_eq!(file["invitations"][0]["status"], "pending");
        assert_eq!(file["break_glass_grants"][0]["reason"], "incident 42");
        assert_eq!(file["failed_sign_in_count"]["failed_count"], 1);
        assert_eq!(file["acted_as_them"].as_array().unwrap().len(), 1);
        assert!(file["activity"].as_array().unwrap().is_empty());
        assert!(!text.contains(hash("reset-link").as_str()));
        assert!(!text.contains("invite-link"));
    }

    /// Saves Ann's pending reset and invitation under a persisted member role.
    async fn save_reset_and_invitation(fixture: &Fixture) {
        let databases = &fixture.db.databases;
        let (tenant, ann) = (&fixture.tenant, fixture.ann);
        let reset = PasswordResetRequest::reconstitute(reset_row(ann, "reset-link", 0)).unwrap();
        PgResetRequestStore::new(Arc::clone(databases))
            .save(tenant, &reset)
            .await
            .unwrap();
        let member = role("member");
        PgRoleStore::new(Arc::clone(databases))
            .save(tenant, &member)
            .await
            .unwrap();
        let invited: Invitation<ResolvedTenant> =
            Invitation::reconstitute(invitation_row(InvitationSeed {
                user_id: ann,
                role_id: *member.id(),
                email: "ann@acme.test",
                hash: "invite-link",
                seconds: 0,
            }))
            .unwrap();
        PgInvitationStore::new(Arc::clone(databases))
            .save(tenant, &invited)
            .await
            .unwrap();
    }

    /// Records Ann's emergency grant, failed sign-in count and impersonated activity.
    async fn record_emergency_access(fixture: &Fixture) {
        let databases = &fixture.db.databases;
        let (tenant, ann) = (&fixture.tenant, fixture.ann);
        let grant = BreakGlassGrant::reconstitute(grant_row(**tenant, ann, 0)).unwrap();
        PgBreakGlassStore::new(Arc::clone(databases))
            .save(tenant, &grant)
            .await
            .unwrap();
        let address = Email::new("ann@acme.test").unwrap();
        let account = CountedAccount::Tenant {
            tenant,
            email: &address,
        };
        let from_somewhere = AttemptOrigin::of(Fact::Unknown);
        fixture
            .counts
            .count_failure(account, &from_somewhere, RateLimitPolicy::DEFAULT.window())
            .await
            .unwrap();
        let as_ann = AuditContext::system()
            .with_tenant(**tenant)
            .impersonating(OperatorId::new(), ann);
        recorded_as(databases, vec![failed_sign_in(**tenant, 2)], &as_ann).await;
    }

    /// Ann's export lists both active and ended sessions without either refresh
    /// token's hash.
    #[tokio::test]
    async fn the_sessions_hold_ended_ones_and_no_token() {
        let fixture = fixture().await;
        let sessions = PgSessionStore::new(Arc::clone(&fixture.db.databases));
        for row in [
            SessionRow {
                status: SessionStatus::Revoked,
                ..session_row(fixture.ann, "refresh-ended")
            },
            session_row(fixture.ann, "refresh-open"),
        ] {
            let session: Session<ResolvedTenant> = Session::reconstitute(row).unwrap();
            sessions.save(&fixture.tenant, &session).await.unwrap();
        }
        let request = request(fixture.ann, ExportScope::Access);

        let text = built(&fixture, &request).await;

        let file: Value = serde_json::from_str(&text).unwrap();
        let mut statuses: Vec<&str> = file["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|session| session["status"].as_str().unwrap())
            .collect();
        statuses.sort_unstable();
        assert_eq!(statuses, ["active", "ended"]);
        for token in ["refresh-ended", "refresh-open"] {
            assert!(!text.contains(hash(token).as_str()), "{token}");
        }
    }

    /// An export containing a session has no JSON member named for a hash,
    /// secret, token, password, seed, recovery code or link.
    #[tokio::test]
    async fn no_member_of_an_export_names_a_secret() {
        let fixture = fixture().await;
        let session: Session<ResolvedTenant> =
            Session::reconstitute(session_row(fixture.ann, "refresh-1")).unwrap();
        PgSessionStore::new(Arc::clone(&fixture.db.databases))
            .save(&fixture.tenant, &session)
            .await
            .unwrap();
        let request = request(fixture.ann, ExportScope::Access);

        let file: Value = serde_json::from_str(&built(&fixture, &request).await).unwrap();

        let names = member_names(&file);
        let secret = ["hash", "secret", "token", "seed", "recovery"];
        for name in &names {
            let a_link = name == "link" || name.ends_with("_link");
            assert!(
                !secret.iter().any(|word| name.contains(word)) && name != "password" && !a_link,
                "{name} names a secret"
            );
        }
    }

    /// Ann's copy holds how she chose to be told and the notice about her
    /// own account, but not a notice she sees only for a right she holds,
    /// which tells of someone else.
    #[tokio::test]
    async fn the_notifications_hold_her_own_notices_and_choices() {
        let fixture = fixture().await;
        let databases = &fixture.db.databases;
        let inbox = PgTenantNotificationStore::new(Arc::clone(databases));
        for each in [own_account_notice(1), notice(user_registered(), 2)] {
            inbox
                .save(&fixture.tenant, &fixture.ann, &each)
                .await
                .unwrap();
        }
        PgNotificationPreferenceStore::new(Arc::clone(databases))
            .save(
                &fixture.tenant,
                &fixture.ann,
                &[NotificationPreference::new(
                    NotificationCategory::Authentication,
                    NotificationChannel::InAppAndEmail,
                )],
            )
            .await
            .unwrap();
        let request = request(fixture.ann, ExportScope::Access);

        let file: Value = serde_json::from_str(&built(&fixture, &request).await).unwrap();

        let notices = file["notifications"]["inbox"].as_array().unwrap();
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0]["body"], "Ann did it");
        assert_eq!(
            file["notifications"]["choices"][0]["channel"],
            NotificationChannel::InAppAndEmail.as_str()
        );
    }

    /// Ann's copy holds the countries she signed in from, and where she
    /// last did.
    #[tokio::test]
    async fn the_sign_in_places_hold_her_countries() {
        let fixture = fixture().await;
        let berlin = IpGeolocation::new(52.5, 13.4, CountryCode::new("DE").unwrap(), None).unwrap();
        PgSignInHistoryStore::new(Arc::clone(&fixture.db.databases))
            .record(&fixture.tenant, &fixture.ann, &berlin, at(1))
            .await
            .unwrap();
        let request = request(fixture.ann, ExportScope::Access);

        let file: Value = serde_json::from_str(&built(&fixture, &request).await).unwrap();

        assert_eq!(file["sign_in_places"]["countries"][0], "DE");
        assert_eq!(file["sign_in_places"]["latest"]["country"], "DE");
    }

    /// Ann's export names Bob and his reason for requesting support access to
    /// her account, while excluding her request to act as Bob.
    #[tokio::test]
    async fn the_support_access_holds_who_asked_to_act_as_her() {
        let fixture = fixture().await;
        let impersonations = PgSupportImpersonationStore::new(Arc::clone(&fixture.db.databases));
        for row in [
            impersonation_row(fixture.bob, fixture.ann, 1),
            impersonation_row(fixture.ann, fixture.bob, 2),
        ] {
            let asked: SupportImpersonation<ResolvedTenant> =
                SupportImpersonation::reconstitute(row).unwrap();
            impersonations.save(&fixture.tenant, &asked).await.unwrap();
        }
        let request = request(fixture.ann, ExportScope::Access);

        let file: Value = serde_json::from_str(&built(&fixture, &request).await).unwrap();

        let asked = file["support_access"].as_array().unwrap();
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0]["admin_id"], fixture.bob.to_string());
        assert_eq!(asked[0]["reason"], "ticket 4711");
    }

    /// Ann asks to take her data elsewhere. The file holds only what she
    /// gave the service: her account, attributes and consents.
    #[tokio::test]
    async fn a_portability_export_holds_what_she_gave() {
        let fixture = fixture().await;
        let request = request(fixture.ann, ExportScope::Portability);

        let file: Value = serde_json::from_str(&built(&fixture, &request).await).unwrap();

        let members: Vec<&str> = file
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(members.len(), 4);
        assert!(file.get("activity").is_none());
        assert!(file.get("sessions").is_none());
    }

    /// Building an export for an absent account fails and leaves no file.
    #[tokio::test]
    async fn an_export_of_a_gone_account_is_not_built() {
        let fixture = fixture().await;
        let request = request(UserId::new(), ExportScope::Access);

        let result = fixture.builder.build(&fixture.tenant, &request).await;

        let store = DiskFileStore::new(fixture.dir.path());
        let kept = store
            .open(&FileName::data_export(&fixture.tenant, request.id()))
            .await
            .unwrap();
        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
        assert!(kept.is_none());
    }
}
