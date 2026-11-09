//! A tenant sign-in vouches for tenant records only: it cannot remember a
//! device for an organization member.

use ianua_domain::domains::authentication::device_trust::{TrustDeviceParams, TrustedDevice};
use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::domains::authentication::sessions::account_check::SessionCheck;

fn remember(session: &Session<ResolvedTenant>, params: TrustDeviceParams, check: &SessionCheck<'_, ResolvedTenant>) {
    let Some(signed_in) = session.signed_in(check) else {
        return;
    };
    let _ = TrustedDevice::<ResolvedOrganization>::trust(params, &signed_in);
}

fn main() {}
