//! A company's tenants as Ann sees them, and as Max and Sam try to reach
//! them: Ann's company and Sam's may both call a tenant "production",
//! one company may not have two, and neither a plain member nor a
//! stranger makes or reads one they have no business with.

use ianua_scenarios::api::tenants;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::tenants::{NewTenant, TenantStatus};
use ianua_scenarios::world::World;

/// Ann and Sam each founded their company with a tenant called
/// "production", and each sees exactly their own, set up. Ann making a
/// second "production" in her company is refused, and so is Max making
/// any tenant. Sam reading Ann's tenants, or her tenant by its path, is
/// refused.
#[tokio::test]
async fn each_company_has_its_own_production_and_only_its_own() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    assert_own_tenant(&world).await;
    tenants::create(world.org(), &new_tenant(&world, "production"))
        .send(world.owner().client())
        .await
        .refused(Status::CONFLICT, "conflict");
    tenants::create(world.org(), &new_tenant(&world, "maxs-own"))
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    tenants::list(world.org())
        .send(world.stranger().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    tenants::get(world.tenant())
        .send(world.stranger().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann reads only her active production tenant with completed setup.
async fn assert_own_tenant(world: &World<'_>) {
    let anns = tenants::list(world.org())
        .send(world.owner().client())
        .await
        .ok();
    let names: Vec<&str> = anns
        .items
        .iter()
        .map(|tenant| tenant.slug.as_str())
        .collect();
    assert_eq!(names, ["production"], "Ann sees her one tenant");
    assert_eq!(
        anns.items[0].status,
        TenantStatus::Active,
        "her tenant is active"
    );
    assert_eq!(anns.items[0].setup.state, "over", "its setup is over");
}

/// A tenant called `slug` in the world's company.
fn new_tenant(world: &World<'_>, slug: &str) -> NewTenant {
    NewTenant {
        slug: slug.to_owned(),
        display_name: slug.to_owned(),
        contact_email: world.address("contact"),
        timezone: "Europe/Berlin".to_owned(),
        locale: "en-US".to_owned(),
    }
}
