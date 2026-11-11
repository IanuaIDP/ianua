//! A workflow's next version. While Tess drafts and edits version 2, runs
//! still use version 1. Each edit makes a new revision, so Ann cannot
//! publish a revision she did not review. Publishing version 2 archives
//! version 1, and from then on runs use version 2. Only one draft exists at
//! a time, and only a draft is edited.

use ianua_scenarios::api::{Request, workflows};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::workflows::{DraftEdit, Publication, Trigger, Workflow};
use ianua_scenarios::world::World;

use crate::service::Service;
use crate::support::{connected_account, delivery_graph, drafted, ended, published, started};

/// Version 1 delivers to the old service. Tess drafts version 2 and a run
/// still delivers to the old service; a second draft is refused while the
/// first is open. Tess points version 2 at the new service, which makes a
/// new revision: Ann's publication of the revision she saw before the edit
/// is refused, and her publication of the edited one succeeds. Version 1
/// is archived, the next run delivers to the new service, and editing the
/// published version is refused.
#[tokio::test]
async fn a_new_version_takes_over_only_once_its_reviewed_revision_is_published() {
    let old = Service::start().await;
    let new = Service::start().await;
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let old_account = connected_account(&world, &old).await;
    let new_account = connected_account(&world, &new).await;
    let first = drafted(&world, Trigger::Manual, delivery_graph(&old, &old_account)).await;
    let first = published(&world, &first).await;
    let next = workflows::next_draft(world.tenant(), &first.id)
        .send(world.admin().client())
        .await
        .ok();

    delivered_once(&world, &first).await;
    workflows::next_draft(world.tenant(), &first.id)
        .send(world.admin().client())
        .await
        .refused(Status::CONFLICT, "conflict");
    let edit = DraftEdit::ReplaceSteps {
        graph: delivery_graph(&new, &new_account),
    };
    let edited = workflows::edit_draft(world.tenant(), &first.id, &edit)
        .send(world.admin().client())
        .await
        .ok();
    publishing(&world, &next)
        .send(world.owner().client())
        .await
        .refused(Status::CONFLICT, "conflict");
    let second = publishing(&world, &edited)
        .send(world.owner().client())
        .await
        .ok();
    delivered_once(&world, &second).await;
    workflows::edit_draft(world.tenant(), &first.id, &edit)
        .send(world.admin().client())
        .await
        .refused(Status::CONFLICT, "conflict");

    assert_eq!((next.version, next.status.as_str()), (2, "draft"));
    assert_ne!(edited.revision, next.revision, "the edit made a revision");
    assert_eq!((second.version, second.status.as_str()), (2, "published"));
    let archived = workflows::version(world.tenant(), &first.id, 1)
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(archived.status, "archived", "version 1 is out of service");
    assert_eq!(
        old.calls(),
        1,
        "only the run before publishing used version 1"
    );
    assert_eq!(new.calls(), 1, "the run after publishing used version 2");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann publishing the revision of `draft` she saw.
fn publishing(world: &World<'_>, draft: &Workflow) -> Request<Workflow> {
    let publication = Publication {
        revision: draft.revision.clone(),
    };
    workflows::publish(world.tenant(), &draft.id, &publication)
}

/// Tess starts `workflow` and the run succeeds.
async fn delivered_once(world: &World<'_>, workflow: &Workflow) {
    let run = started(world, workflow).await;
    ended(world, &run.execution_id, "succeeded").await;
}
