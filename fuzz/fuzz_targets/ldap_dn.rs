//! Arbitrary strings at the DN parser, which is an authorization boundary.
//!
//! `within` is what keeps one tenant's LDAP subtree out of another's, so the
//! invariant worth hunting is not a panic but a DN that lands inside two
//! sibling tenants at once. `normalize` has to be idempotent for that check to
//! mean anything: it is applied to both sides of every comparison, and a
//! second pass that changes the answer would let one caller's spelling of a DN
//! disagree with another's.

#![no_main]

use libfuzzer_sys::fuzz_target;

use ianua_ldap::dit::dn::{TenantPath, is_child_of, normalize, parse_bind_dn, tenant_of, within};

fuzz_target!(|data: &[u8]| {
    let Ok(dn) = std::str::from_utf8(data) else {
        return;
    };

    let once = normalize(dn);
    assert_eq!(normalize(&once), once, "normalize is not idempotent");

    let tenant = |slug: &str| TenantPath {
        org_slug: "acme".to_owned(),
        tenant_slug: slug.to_owned(),
    };
    let alpha = tenant("alpha").base();
    let beta = tenant("beta").base();
    assert!(
        !(within(dn, &alpha) && within(dn, &beta)),
        "dn lies inside two tenants at once"
    );

    assert!(!is_child_of(dn, &alpha) || within(dn, &alpha));

    let _ = parse_bind_dn(dn);
    let _ = tenant_of(dn);
});
