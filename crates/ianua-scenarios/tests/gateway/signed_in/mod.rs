//! People signed in to a tenant's apps: on the app's own host by the
//! gateway's sign-in, and at the app's API by the short-lived tokens its
//! pages fetch. The app sees a signed assertion naming them and none of
//! their credentials; everyone and everything else is refused before the
//! app sees anything.
//!
//! - `cookies`: Pat signed in on the shop's own host reaches it until she
//!   signs out; a page from another site can neither sign her out nor
//!   fetch a token with her cookie; a sign-in owing a code is finished
//!   only by her own browser with her phone.
//! - `tokens`: a token the shop's page fetches for the shop's API reaches
//!   the API and nothing else does; an expired token is refused and a
//!   fresh one works.
//! - `registration`: Pat registers at the shop and gets in once the mailed
//!   link is followed there; the form refuses while the tenant keeps
//!   registration closed.

mod cookies;
mod registration;
mod tokens;

use ianua_scenarios::upstreams::{Arrival, AssertionCheck, Echo};
use ianua_scenarios::world::World;

use crate::support::{Shop, ShopOwner, word};

/// Opens the shop under the tenant administrator's authority.
async fn open_shop(world: &World<'_>) -> Shop {
    Shop::opened(
        world.stack(),
        &ShopOwner {
            tenant: world.tenant(),
            admin: world.admin().client(),
            word: &word(),
        },
    )
    .await
}

/// Opens another company's shop with its own administrator and host.
async fn open_twin_shop(world: &World<'_>) -> Shop {
    Shop::opened(
        world.stack(),
        &ShopOwner {
            tenant: world.twin(),
            admin: world.stranger().client(),
            word: &word(),
        },
    )
    .await
}

/// Fails unless the last request `app` got was asserted as `user_id`, a
/// person of the tenant, and carried none of the caller's credentials.
fn asserted_as(app: &Echo, user_id: &str) -> Arrival {
    let arrived = app.arrivals();
    let Some(last) = arrived.last() else {
        panic!("nothing reached the app");
    };
    let AssertionCheck::Verified { caller } = &last.assertion else {
        panic!("the app could not check the gateway's assertion: {last:?}");
    };
    assert_eq!(caller.sub, user_id, "the assertion names the person");
    assert_eq!(caller.kind, "user", "the assertion names a tenant user");
    for credential in ["authorization", "cookie"] {
        assert!(
            !last.has_header(credential),
            "the caller's {credential} reached the app"
        );
    }
    last.clone()
}
