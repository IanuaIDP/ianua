//! A rule on admin roles. A refusing rule stops an admin role with a 403
//! naming a company rule, while a role holding no built-in permission is
//! not the rule's to decide. An allowing rule lets the role through, and
//! with no rule the change happens as before. A rule that would wait for
//! a person or for time is refused at publish. The rule is asked on every
//! road an admin role takes, not only the direct one: an invitation, a
//! group's role, joining a group that carries one, and a role people hold
//! gaining a built-in permission.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{Request, people, policies, roles, workflows};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::policies::{GroupRole, NewGroupMember};
use ianua_scenarios::wire::roles::{AssignRole, Holder, NewRole, RoleChange, SystemPermission};
use ianua_scenarios::wire::workflows::{Edge, Graph, Node, Publication, Step, Workflow};
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;

use super::{
    REFUSED_BY_A_RULE, VERDICT_STEP, before, group, only_run, refused_by_the_rule, rule_on, verdict,
};
use crate::support::{drafted, pat};

/// The change these rules decide.
const ADMIN_GIVEN: &str = "admin_given";

/// Tess drafts and Ann publishes a rule run before an admin role is
/// given, deciding it with `operation`; the published rule.
async fn rule_deciding(world: &World<'_>, operation: &str) -> Workflow {
    rule_on(world, ADMIN_GIVEN, operation).await
}

/// Tess makes a role named `name` carrying `rights`, each a resource and
/// an action; the role's id.
async fn role(world: &World<'_>, name: &str, rights: &[(&str, &str)]) -> String {
    let made = NewRole {
        name: name.to_owned(),
        system_permissions: rights
            .iter()
            .map(|(resource, action)| SystemPermission::new(resource, action))
            .collect(),
    };
    roles::create(world.tenant(), &made)
        .send(world.admin().client())
        .await
        .ok()
        .id
}

/// Giving a role to `person`, as Tess does by hand.
fn to(person: &Person) -> AssignRole {
    AssignRole {
        user_id: person.id().to_owned(),
    }
}

/// Whether `person` holds the role `role_id` directly.
async fn holds(world: &World<'_>, role_id: &str, person: &Person) -> bool {
    roles::holders(world.tenant(), role_id)
        .send(world.admin().client())
        .await
        .ok()
        .items
        .iter()
        .any(|holder| matches!(holder, Holder::Direct { principal } if principal.id == person.id()))
}

/// Ann publishes a rule that refuses every admin role. Tess gives Pat the
/// role "Support admin", which may view people: refused with a 403 saying
/// a company rule refused it, and Pat does not hold it. Tess gives Pat
/// "Newsletter reader", which holds no built-in permission: the rule is
/// not asked, and Pat holds it.
#[tokio::test]
async fn a_rule_refusing_admin_roles_stops_them_and_lets_other_roles_through() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = pat(&world).await;
    let admin = role(&world, "Support admin", &[("Users", "View")]).await;
    let reader = role(&world, "Newsletter reader", &[]).await;
    rule_deciding(&world, "refuse").await;

    let problem = roles::assign(world.tenant(), &admin, &to(&pat))
        .send(world.admin().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    roles::assign(world.tenant(), &reader, &to(&pat))
        .send(world.admin().client())
        .await
        .ok();

    assert!(
        problem.message().to_lowercase().contains(REFUSED_BY_A_RULE),
        "{}",
        problem.message()
    );
    assert!(!holds(&world, &admin, &pat).await, "Pat is no admin");
    assert!(
        holds(&world, &reader, &pat).await,
        "Pat reads the newsletter"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// With no rule, Tess gives Pat "Support admin" and Pat holds it, as
/// before rules existed. Ann then publishes a rule that allows admin
/// roles. Tess gives Pat "Billing admin": the rule runs once, handed the
/// role and Pat as its holder, succeeds, and Pat holds the role.
#[tokio::test]
async fn an_allowing_rule_lets_the_admin_role_through() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = pat(&world).await;
    let support = role(&world, "Support admin", &[("Users", "View")]).await;
    let billing = role(&world, "Billing admin", &[("Roles", "View")]).await;

    roles::assign(world.tenant(), &support, &to(&pat))
        .send(world.admin().client())
        .await
        .ok();
    let rule = rule_deciding(&world, "allow").await;
    roles::assign(world.tenant(), &billing, &to(&pat))
        .send(world.admin().client())
        .await
        .ok();

    assert!(holds(&world, &support, &pat).await, "no rule, no change");
    assert!(holds(&world, &billing, &pat).await, "the rule allowed it");
    let run = only_run(&world, &rule, "succeeded").await;
    assert_eq!(run.input["role"], billing.as_str(), "the rule saw the role");
    assert_eq!(run.input["role_name"], "Billing admin");
    assert!(
        run.input["holder"]
            .as_str()
            .is_some_and(|holder| holder.contains(pat.id())),
        "the rule saw who would hold it: {}",
        run.input
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess drafts two rules run before an admin role is given: one waits
/// for Ann's approval, the other a minute, before allowing it. A change
/// cannot wait for either, so Ann's publication of each is refused,
/// naming the step that would wait.
#[tokio::test]
async fn a_before_rule_that_would_wait_is_refused_at_publish() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let approving = Node {
        key: "ask".to_owned(),
        name: "Ask Ann".to_owned(),
        step: Step::Approval {
            summary: "Make this person an admin".to_owned(),
            action_class: "read".to_owned(),
            window_seconds: 120,
        },
    };
    let waiting = Node {
        key: "later".to_owned(),
        name: "Wait a minute".to_owned(),
        step: Step::Wait {
            duration_seconds: Some(60),
            working_hours: None,
        },
    };

    refused_at_publish(&world, approving).await;
    refused_at_publish(&world, waiting).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess drafts a rule where `slow` comes before Allow; Ann's publication
/// is refused, naming `slow`.
async fn refused_at_publish(world: &World<'_>, slow: Node) {
    let key = slow.key.clone();
    let trigger = before(ADMIN_GIVEN);
    let graph = Graph {
        nodes: vec![slow, verdict("allow")],
        edges: vec![Edge {
            from: key.clone(),
            to: VERDICT_STEP.to_owned(),
        }],
    };
    let draft = drafted(world, trigger, graph).await;
    let publication = Publication {
        revision: draft.revision,
    };
    let refused = workflows::publish(world.tenant(), &draft.id, &publication)
        .send(world.owner().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    assert!(
        refused.message().to_lowercase().contains(&key),
        "the refusal names {key}: {}",
        refused.message()
    );
}

/// Before any rule, Tess makes the group "Admins" carrying "Support admin",
/// which may view people, and gives Pat "Newsletter reader". Ann then
/// publishes a rule refusing every admin role. Every other road to admin
/// work is refused with the rule's 403: inviting Lee as a support admin,
/// giving the group "Helpdesk" that role, putting Pat into "Admins", and
/// letting "Newsletter reader" view people. Pat is in no group and his
/// role is as it was.
#[tokio::test]
async fn a_rule_refusing_admin_roles_is_asked_on_every_road_to_one() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = pat(&world).await;
    let roads = Roads::laid(&world, &pat).await;
    rule_deciding(&world, "refuse").await;

    refused_by_the_rule(&world, people::invite(world.tenant(), &roads.lee_invited())).await;
    refused_by_the_rule(&world, roads.helpdesk_given_admin(&world)).await;
    refused_by_the_rule(&world, roads.pat_joining_admins(&world, &pat)).await;
    refused_by_the_rule(&world, roads.reader_viewing_people(&world)).await;

    let members = policies::members(world.tenant(), &roads.admins)
        .send(world.admin().client())
        .await
        .ok()
        .items;
    let kept = roles::get(world.tenant(), &roads.reader)
        .send(world.admin().client())
        .await
        .ok();
    assert!(members.is_empty(), "Pat is not in Admins");
    assert!(
        kept.system_permissions.is_empty(),
        "the reader role is as it was"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// What Tess set up before Ann's rule: the role "Support admin", which
/// may view people, the group "Admins" carrying it, the empty group
/// "Helpdesk", and "Newsletter reader", which holds nothing, given to Pat.
struct Roads {
    admin: String,
    reader: String,
    admins: String,
    helpdesk: String,
}

impl Roads {
    /// Tess sets them up, giving Pat "Newsletter reader".
    async fn laid(world: &World<'_>, pat: &Person) -> Self {
        let admin = role(world, "Support admin", &[("Users", "View")]).await;
        let reader = role(world, "Newsletter reader", &[]).await;
        let admins = group_holding(world, "Admins", &admin).await;
        let helpdesk = group(world, "Helpdesk").await;
        roles::assign(world.tenant(), &reader, &to(pat))
            .send(world.admin().client())
            .await
            .ok();
        Self {
            admin,
            reader,
            admins,
            helpdesk,
        }
    }

    /// Lee invited as a support admin.
    fn lee_invited(&self) -> InviteUser {
        InviteUser {
            email: "lee@corp.test".to_owned(),
            display_name: "Lee".to_owned(),
            role_id: self.admin.clone(),
        }
    }

    /// "Helpdesk" given "Support admin".
    fn helpdesk_given_admin(&self, world: &World<'_>) -> Request<()> {
        let role = GroupRole {
            role_id: self.admin.clone(),
        };
        policies::grant_group_role(world.tenant(), &self.helpdesk, &role)
    }

    /// Pat put into "Admins".
    fn pat_joining_admins(&self, world: &World<'_>, pat: &Person) -> Request<IgnoredAny> {
        let member = NewGroupMember {
            kind: "user".to_owned(),
            id: pat.id().to_owned(),
        };
        policies::add_member(world.tenant(), &self.admins, &member)
    }

    /// "Newsletter reader" let view people, which Pat holds.
    fn reader_viewing_people(&self, world: &World<'_>) -> Request<()> {
        let change = RoleChange {
            name: None,
            system_permissions: Some(vec![SystemPermission::new("Users", "View")]),
        };
        roles::change(world.tenant(), &self.reader, &change)
    }
}

/// Tess makes a group named `name` carrying the role `role_id`; its id.
async fn group_holding(world: &World<'_>, name: &str, role_id: &str) -> String {
    let id = group(world, name).await;
    let role = GroupRole {
        role_id: role_id.to_owned(),
    };
    policies::grant_group_role(world.tenant(), &id, &role)
        .send(world.admin().client())
        .await
        .ok();
    id
}
