//! Tess puts Pat and Uma in a group that holds the reader role: each
//! reads the users from the moment they join, Pat loses the read the
//! moment she leaves, and Uma the moment the group loses its role. Max,
//! Sam and nobody signed in take Pat out of no group, nor does a removal
//! the trail cannot record.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{Request, people, policies};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{AuditWrites, Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::policies::{GroupRole, NewGroup, NewGroupMember};
use ianua_scenarios::world::World;

use crate::support::{person, reader, reads_the_users, refused_the_users};

/// The audit record a member taken out of a group leaves.
const MEMBER_REMOVED: &str = "authorization.group_member_removed";

/// The kind of group member a tenant user is.
const USER: &str = "user";

/// The group `group` holds the role `role`.
fn bind(world: &World<'_>, group: &str, role: &str) -> Request<()> {
    let role = GroupRole {
        role_id: role.to_owned(),
    };
    policies::grant_group_role(world.tenant(), group, &role)
}

/// Tenant user `user` taken out of the group `group`.
fn remove(world: &World<'_>, group: &str, user: &str) -> Request<()> {
    policies::remove_member(world.tenant(), group, USER, user)
}

/// Readers and the role whose permissions reach its members.
struct Readers {
    group: String,
    role: String,
}

impl Readers {
    /// Creates Readers and grants it the user-reading role.
    async fn create(world: &World<'_>) -> Self {
        let role = reader(world).await;
        let group = policies::create_group(
            world.tenant(),
            &NewGroup {
                name: "Readers".to_owned(),
            },
        )
        .send(world.admin().client())
        .await
        .ok();
        bind(world, &group.id, &role)
            .send(world.admin().client())
            .await
            .ok();
        Self {
            group: group.id,
            role,
        }
    }

    /// Adds a user to Readers through Tess's administrative session.
    async fn enroll(&self, world: &World<'_>, person: &Person) {
        policies::add_member(
            world.tenant(),
            &self.group,
            &NewGroupMember {
                kind: USER.to_owned(),
                id: person.id().to_owned(),
            },
        )
        .send(world.admin().client())
        .await
        .ok();
    }

    /// Removing Pat cuts off only her group-derived access.
    async fn remove_pat(&self, world: &World<'_>, pat: &Person, uma: &Person) {
        remove(world, &self.group, pat.id())
            .send(world.admin().client())
            .await
            .ok();
        refused_the_users(world, pat).await;
        reads_the_users(world, uma).await;
    }

    /// Withdrawing the group's role cuts off Uma but preserves both own reads.
    async fn withdraw_role(&self, world: &World<'_>, pat: &Person, uma: &Person) {
        policies::withdraw_group_role(world.tenant(), &self.group, &self.role)
            .send(world.admin().client())
            .await
            .ok();
        refused_the_users(world, uma).await;
        for holder in [pat, uma] {
            people::me(world.tenant()).send(holder.client()).await.ok();
        }
        assert_eq!(
            world.trail().count(MEMBER_REMOVED).await,
            1,
            "Pat leaving the group is recorded once"
        );
        assert_eq!(
            world
                .trail()
                .count("authorization.group_role_unassigned")
                .await,
            1,
            "the group losing its role is recorded once"
        );
    }
}

/// Tess makes the Readers group hold the reader role. Pat and Uma, each
/// signed in and refused the users, read them from the moment Tess puts
/// them in the group. Tess takes Pat out: Pat is refused at once, Uma
/// still reads. Tess takes the role from the group: Uma is refused at
/// once. Both still read their own record; the removal and the unbinding
/// are each recorded once.
#[tokio::test]
async fn leaving_a_group_cuts_off_the_leaver_and_unbinding_its_role_cuts_off_the_rest() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    let readers = Readers::create(&world).await;

    for holder in [&pat, &uma] {
        refused_the_users(&world, holder).await;
        readers.enroll(&world, holder).await;
        reads_the_users(&world, holder).await;
    }

    readers.remove_pat(&world, &pat, &uma).await;
    readers.withdraw_role(&world, &pat, &uma).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Max, Sam and an anonymous caller cannot remove Pat from Readers, nor
/// can Tess when audit writes fail. Pat still reads the users afterward,
/// no removal is recorded, and only Tess's retry
/// with the trail back takes her out, refused at once and recorded once.
#[tokio::test]
async fn nobody_without_the_right_and_no_failed_removal_takes_pat_out_of_the_group() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let readers = Readers::create(&world).await;
    readers.enroll(&world, &pat).await;
    reads_the_users(&world, &pat).await;

    refuse_removal(&world, &readers.group, &pat).await;
    fail_removal(&world, &readers.group, &pat).await;
    retry_removal(&world, &readers.group, &pat).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Every caller lacking membership-management rights is refused.
async fn refuse_removal(world: &World<'_>, group: &str, pat: &Person) {
    Matrix::new(
        "taking someone out of a group",
        remove(world, group, pat.id()).call(),
    )
    .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
}

/// A failed audit write leaves Pat's group-derived read intact without a removal event.
async fn fail_removal(world: &World<'_>, group: &str, pat: &Person) {
    world.stack().audit_writes(AuditWrites::Refuse).await;
    let failed = remove(world, group, pat.id())
        .send(world.admin().client())
        .await;
    assert_eq!(
        failed.status(),
        Status::INTERNAL_SERVER_ERROR,
        "a removal the trail cannot record fails: {}",
        failed.summary()
    );
    world.stack().audit_writes(AuditWrites::Allow).await;
    reads_the_users(world, pat).await;
    assert_eq!(
        world.trail().count(MEMBER_REMOVED).await,
        0,
        "no refused or failed removal is recorded"
    );
}

/// The retry removes Pat's access and records exactly one removal.
async fn retry_removal(world: &World<'_>, group: &str, pat: &Person) {
    remove(world, group, pat.id())
        .send(world.admin().client())
        .await
        .ok();
    refused_the_users(world, pat).await;
    assert_eq!(
        world.trail().count(MEMBER_REMOVED).await,
        1,
        "the retried removal is recorded once"
    );
}
