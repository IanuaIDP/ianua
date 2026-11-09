//! The people a fan-out tells on each plane, each with the channel they
//! hear of it through.
//!
//! Inside a tenant, that is who runs it: the tenant users who administer
//! it, the organization's members with access to it, and the person the
//! event is about. Never the tenant's users at large: an admin action in a
//! tenant of thousands tells its admins, not thousands of customers. A
//! tenant user is told only what they may see in the app, so a category
//! they cannot read is never mailed to them either. The one exception is
//! what changes how safe their own account is, which they are always told,
//! and which shows in their feed whatever they hold.
//!
//! A security alert goes to fewer people or to others: on the
//! organization's side only its admins and owners, and inside the tenant,
//! for an alert the domain ties to a right, everyone holding that right
//! rather than the administrators, such as whoever manages the mail.
//!
//! A workflow run that fails also reaches the people who wrote the version
//! it ran, when that version asked for it, as they may see it.

use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::notifications::alert::AlertAudience;
use ianua_domain::domains::notifications::category::NotificationCategory;
use ianua_domain::domains::notifications::channel::NotificationChannel;
use ianua_domain::domains::notifications::preference::NotificationPreference;
use ianua_domain::domains::notifications::reach::{MailAddress, NotificationReach, ToldAs};
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::domains::organization::members::tenant_authority::members_with_access;
use ianua_domain::domains::workflows::events::failed_run_telling_authors;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::types::{
    EventType, HumanAccount, OrganizationId, PrincipalRef, TenantId, UserId,
};

use crate::listing::SortOrder;
use crate::ports::authorization::{AccessRecords, HeldRecords, Holder, Holders};
use crate::ports::operator::OperatorFilter;
use crate::ports::organization::OrgUserFilter;
use crate::tenancy::ScopedTenant;
use crate::use_cases::notifications::delivery::audience::Audience;
use crate::use_cases::notifications::delivery::fan_out::FanOutUseCase;
use crate::use_cases::notifications::delivery::notice::Notice;
use crate::use_cases::notifications::delivery::recipients::{Inbox, Member, channel_of};

impl FanOutUseCase {
    /// The people `audience` reaches about an event of `event_type`, each
    /// with the channel they hear of it through: those who run the plane,
    /// and the tenant user it happened to. Told as `notice`, an alert
    /// reaches only the organization's admins and owners among its members.
    pub(in crate::use_cases::notifications::delivery) async fn members(
        &self,
        audience: &Audience,
        event_type: EventType,
        notice: Notice,
    ) -> Result<Vec<Member>, DomainError> {
        let topic = Topic {
            category: NotificationCategory::from_event_type(&event_type),
            notice,
        };
        let mut people = match *audience {
            Audience::Platform { .. } => self.operators(topic.category).await?,
            Audience::Organization {
                organization_id, ..
            } => self.org_users(organization_id, topic).await?,
            Audience::Tenant {
                tenant_id, subject, ..
            } => self.tenant_people(tenant_id, subject, topic).await?,
        };
        people.extend(self.subject_told(audience.subject(), event_type).await?);
        Ok(people)
    }

    /// The platform's operators, up to the cap.
    async fn operators(&self, category: NotificationCategory) -> Result<Vec<Member>, DomainError> {
        let operators = self
            .ports
            .audience
            .operator_store
            .list(
                &OperatorFilter::all(),
                &SortOrder::default(),
                &self.max_recipients,
            )
            .await?
            .items;
        let chosen = self
            .ports
            .preferences
            .operator_preferences
            .chosen_channels(category)
            .await?;
        Ok(operators
            .iter()
            .map(|operator| Member {
                id: *operator.id().as_uuid(),
                name: operator.email().as_str().to_owned(),
                email: operator.email().clone(),
                inbox: Inbox::Operator(*operator.id()),
                channel: channel_of(&chosen, operator.id()),
                told_as: ToldAs::Overseer,
            })
            .collect())
    }

    /// The organization's users the notice reaches, up to the cap.
    async fn org_users(
        &self,
        organization_id: OrganizationId,
        topic: Topic,
    ) -> Result<Vec<Member>, DomainError> {
        let users = self
            .ports
            .audience
            .org_user_store
            .list_by_org(
                &organization_id,
                &OrgUserFilter::all(),
                &SortOrder::default(),
                &self.max_recipients,
            )
            .await?;
        self.as_org_members(organization_id, &users.items, topic)
            .await
    }

    /// `users` of `organization_id` the notice reaches by their role in the
    /// organization, each with the channel they chose.
    async fn as_org_members<'u>(
        &self,
        organization_id: OrganizationId,
        users: impl IntoIterator<Item = &'u OrgUser>,
        topic: Topic,
    ) -> Result<Vec<Member>, DomainError> {
        let chosen = self
            .ports
            .preferences
            .member_preferences
            .chosen_channels(&organization_id, topic.category)
            .await?;
        Ok(users
            .into_iter()
            .filter(|user| topic.notice.reaches(user.role()))
            .map(|user| Member {
                id: *user.id().as_uuid(),
                name: user.display_name().as_str().to_owned(),
                email: user.email().clone(),
                inbox: Inbox::OrgUser(organization_id, *user.id()),
                channel: channel_of(&chosen, user.id()),
                told_as: ToldAs::Overseer,
            })
            .collect())
    }

    /// The people who run `tenant_id`, leaving out `subject`, the user the
    /// event is about, who is told as its subject instead.
    async fn tenant_people(
        &self,
        tenant_id: TenantId,
        subject: Option<UserId>,
        topic: Topic,
    ) -> Result<Vec<Member>, DomainError> {
        let mut people = self.tenant_overseers(tenant_id, subject, topic).await?;
        people.extend(self.members_reaching(tenant_id, topic).await?);
        Ok(people)
    }

    /// The tenant users who oversee what the notice is about, up to the
    /// cap, but `subject`: its administrators, or for an alert told by a
    /// right, everyone holding it. Each is kept only while they may sign
    /// in and may see the category in the app.
    async fn tenant_overseers(
        &self,
        tenant_id: TenantId,
        subject: Option<UserId>,
        topic: Topic,
    ) -> Result<Vec<Member>, DomainError> {
        let tenant = ScopedTenant::for_background(tenant_id);
        let category = topic.category;
        let mut ids = self.overseer_ids(&tenant, topic.notice).await?;
        ids.retain(|overseer| Some(*overseer) != subject);
        let users = self
            .ports
            .audience
            .user_store
            .find_by_ids(&tenant, &ids)
            .await?;
        let chosen = self
            .ports
            .preferences
            .preference_store
            .chosen_channels(&tenant, category)
            .await?;
        let held = self.overseer_holdings(&tenant, &users).await?;
        let access = held.access(tenant_id);
        let now = clock::now();
        let mut people = Vec::new();
        for user in users.iter().filter(|user| user.can_authenticate()) {
            let holdings = access.permissions_held_by(PrincipalRef::User(*user.id()), now)?;
            if holdings.holds(category.required_permission()) {
                let channel = channel_of(&chosen, user.id());
                people.push(tenant_member(tenant, user, channel, ToldAs::Overseer));
            }
        }
        Ok(people)
    }

    /// Loads active overseers' holdings together, without reading storage
    /// when none of the selected users can authenticate.
    async fn overseer_holdings(
        &self,
        tenant: &ScopedTenant,
        users: &[User<ResolvedTenant>],
    ) -> Result<HeldRecords, DomainError> {
        let principals: Vec<_> = users
            .iter()
            .filter(|user| user.can_authenticate())
            .map(|user| PrincipalRef::User(*user.id()))
            .collect();
        if principals.is_empty() {
            return Ok(HeldRecords::new(AccessRecords::default()));
        }
        self.ports
            .audience
            .access_records
            .load_held_by_all(
                tenant,
                Holders {
                    principals: &principals,
                    groups: &[],
                    roles: &[],
                },
            )
            .await
    }

    /// The ids of the tenant's users `notice` is told to, up to the cap.
    async fn overseer_ids(
        &self,
        tenant: &ScopedTenant,
        notice: Notice,
    ) -> Result<Vec<UserId>, DomainError> {
        let records = self.ports.audience.access_records.as_ref();
        let listed = match notice.tenant_audience() {
            AlertAudience::Administrators => {
                records
                    .list_administrators(tenant, &self.max_recipients)
                    .await?
            }
            AlertAudience::HoldersOf(right) => {
                records
                    .list_holders_of(tenant, right, &self.max_recipients)
                    .await?
            }
        };
        Ok(listed.items)
    }

    /// The tenant user an event of `event_type` happened to, as `subject`
    /// names them with their tenant, when they are told of it.
    ///
    /// Of what changes how safe their own account is, they are always
    /// told, whatever they hold and even while they cannot sign in: a
    /// locked or switched-off account is the one that most needs to hear.
    /// Of anything else, only as anyone is: while they may sign in and may
    /// see its category.
    async fn subject_told(
        &self,
        subject: Option<(TenantId, UserId)>,
        event_type: EventType,
    ) -> Result<Option<Member>, DomainError> {
        let Some((tenant_id, user_id)) = subject else {
            return Ok(None);
        };
        let tenant = ScopedTenant::for_background(tenant_id);
        let Some(user) = self
            .ports
            .audience
            .user_store
            .find_by_id(&tenant, &user_id)
            .await?
        else {
            return Ok(None);
        };
        let category = NotificationCategory::from_event_type(&event_type);
        let reach = NotificationReach::of(&event_type, ToldAs::Subject);
        if !self.subject_hears(&tenant, &user, reach, category).await? {
            return Ok(None);
        }
        let chose = self.chosen_by(&tenant, &user_id, category).await?;
        let channel = reach.channel(chose, MailAddress::from(user.email_verified()));
        Ok(Some(tenant_member(tenant, &user, channel, ToldAs::Subject)))
    }

    /// Whether `user`, reached as `reach`, hears of an event in `category`.
    async fn subject_hears(
        &self,
        tenant: &ScopedTenant,
        user: &User<ResolvedTenant>,
        reach: NotificationReach,
        category: NotificationCategory,
    ) -> Result<bool, DomainError> {
        match reach {
            NotificationReach::OwnAccount | NotificationReach::Addressed => Ok(true),
            NotificationReach::ByRights if !user.can_authenticate() => Ok(false),
            NotificationReach::ByRights => self.may_see(tenant, user.id(), category).await,
        }
    }

    /// The channel `user_id` chose for `category`, or in the app when they
    /// chose none.
    async fn chosen_by(
        &self,
        tenant: &ScopedTenant,
        user_id: &UserId,
        category: NotificationCategory,
    ) -> Result<NotificationChannel, DomainError> {
        let chosen = self
            .ports
            .preferences
            .preference_store
            .get(tenant, user_id)
            .await?;
        Ok(chosen
            .iter()
            .find(|preference| preference.category() == category)
            .map(NotificationPreference::channel)
            .unwrap_or_default())
    }

    /// Whether `user` may see `category` in the app now: the same check
    /// their notification feed makes.
    async fn may_see(
        &self,
        tenant: &ScopedTenant,
        user: &UserId,
        category: NotificationCategory,
    ) -> Result<bool, DomainError> {
        let held = self
            .ports
            .audience
            .access_records
            .load_held_by(tenant, Holder::user(*user))
            .await?;
        let holdings = held
            .access(**tenant)
            .permissions_held_by(PrincipalRef::User(*user), clock::now())?;
        Ok(holdings.holds(category.required_permission()))
    }

    /// The authors of a failed run whose version asked to tell them, who
    /// are not among `told` already, each as they chose to be reached.
    ///
    /// They are told as people who run it: only while they may sign in and
    /// may see its category, as an administrator is. An author who is a
    /// member of the organization hears as one already, so only the tenant
    /// users among the authors are looked up here.
    pub(in crate::use_cases::notifications::delivery) async fn authors_told(
        &self,
        event: &DomainEvent,
        told: &[Member],
    ) -> Result<Vec<Member>, DomainError> {
        let Some((tenant_id, execution_id)) = failed_run_telling_authors(event) else {
            return Ok(Vec::new());
        };
        let tenant = ScopedTenant::for_background(tenant_id);
        let Some(execution) = self
            .ports
            .audience
            .executions
            .find_by_id(&tenant, &execution_id)
            .await?
        else {
            return Ok(Vec::new());
        };
        let category = NotificationCategory::from_event_type(&event.event_type());
        let mut people = Vec::new();
        for author in execution.authors().as_slice() {
            let HumanAccount::User(user_id) = author.account() else {
                continue;
            };
            if told.iter().any(|member| member.id == *user_id.as_uuid()) {
                continue;
            }
            people.extend(self.author_told(tenant, &user_id, category).await?);
        }
        Ok(people)
    }

    /// The tenant user `user_id`, told of a failed run they wrote, when
    /// they may sign in and see `category`.
    async fn author_told(
        &self,
        tenant: ScopedTenant,
        user_id: &UserId,
        category: NotificationCategory,
    ) -> Result<Option<Member>, DomainError> {
        let Some(user) = self
            .ports
            .audience
            .user_store
            .find_by_id(&tenant, user_id)
            .await?
        else {
            return Ok(None);
        };
        let reach = NotificationReach::ByRights;
        if !self.subject_hears(&tenant, &user, reach, category).await? {
            return Ok(None);
        }
        let chose = self.chosen_by(&tenant, user_id, category).await?;
        let channel = reach.channel(chose, MailAddress::from(user.email_verified()));
        Ok(Some(tenant_member(
            tenant,
            &user,
            channel,
            ToldAs::Overseer,
        )))
    }

    /// The organization's members with access to `tenant_id` the notice
    /// reaches, up to the cap. None when the tenant or its organization is
    /// gone.
    async fn members_reaching(
        &self,
        tenant_id: TenantId,
        topic: Topic,
    ) -> Result<Vec<Member>, DomainError> {
        let Some(tenant) = self.ports.tenants.find_by_id(&tenant_id).await? else {
            return Ok(Vec::new());
        };
        let organization_id = *tenant.organization_id();
        let Some(organization) = self
            .ports
            .audience
            .organizations
            .find_by_id(&organization_id)
            .await?
        else {
            return Ok(Vec::new());
        };
        let roster = self
            .ports
            .audience
            .member_roster
            .members_in(&organization_id, &tenant_id)
            .await?;
        let reaching =
            members_with_access(&organization, &tenant_id, &roster.members, &roster.grants);
        let cap = self.max_recipients.limit().as_usize();
        self.as_org_members(organization_id, reaching.into_iter().take(cap), topic)
            .await
    }
}

/// What one fan-out tells: the category its event shows under, and how it
/// is told.
#[derive(Debug, Clone, Copy)]
struct Topic {
    category: NotificationCategory,
    notice: Notice,
}

/// `user` of `tenant`, told as `told_as` through `channel`.
fn tenant_member(
    tenant: ScopedTenant,
    user: &User<ResolvedTenant>,
    channel: NotificationChannel,
    told_as: ToldAs,
) -> Member {
    Member {
        id: *user.id().as_uuid(),
        name: user.display_name().as_str().to_owned(),
        email: user.email().clone(),
        inbox: Inbox::TenantUser(tenant, *user.id()),
        channel,
        told_as,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::identity::account::user_status::UserStatus;

    use super::*;
    use crate::ports::authorization::AccessRecords;
    use crate::test_support::authorization::{
        FakeAccessRecordStore, stored_assignment, stored_role,
    };
    use crate::test_support::identity::{FakeUserStore, stored_user};
    use crate::test_support::{block_on, test_ctx};
    use crate::use_cases::notifications::delivery::fan_out::{AudiencePorts, FanOutPorts};

    /// Gives each named user the same administrator role in the test tenant.
    fn administrator_records(users: &[UserId]) -> Arc<FakeAccessRecordStore> {
        let admin = stored_role("admin", SystemPermission::all().to_vec(), vec![]);
        Arc::new(FakeAccessRecordStore::holding(
            test_ctx().tenant_id(),
            AccessRecords {
                assignments: users
                    .iter()
                    .map(|id| stored_assignment(PrincipalRef::User(*id), *admin.id()))
                    .collect(),
                roles: vec![admin],
                ..AccessRecords::default()
            },
        ))
    }

    /// Two active administrators hear the notice through one shared holding
    /// read. A locked administrator remains excluded from this audience.
    #[test]
    fn recipients_share_one_holding_read() {
        let (ann, bob, locked) = (UserId::new(), UserId::new(), UserId::new());
        let users = FakeUserStore::with_user(ann, "ann@acme.com");
        users.add_active_user(bob, "bob@acme.com");
        users.add(stored_user(locked, "locked@acme.com", UserStatus::Locked));
        let records = administrator_records(&[ann, bob, locked]);
        let use_case = FanOutUseCase::new(
            FanOutPorts {
                audience: AudiencePorts {
                    user_store: Arc::new(users),
                    access_records: records.clone(),
                    ..AudiencePorts::fakes()
                },
                ..FanOutPorts::fakes()
            },
            100,
        );

        let members = block_on(use_case.tenant_overseers(
            test_ctx().tenant_id(),
            None,
            Topic {
                category: NotificationCategory::Identity,
                notice: Notice::Feed,
            },
        ))
        .unwrap();

        assert_eq!(members.len(), 2);
        assert!(members.iter().any(|member| member.id == *ann.as_uuid()));
        assert!(members.iter().any(|member| member.id == *bob.as_uuid()));
        assert_eq!(records.holder_reads(), 1);
        assert_eq!(records.whole_reads(), 0);
    }
}
