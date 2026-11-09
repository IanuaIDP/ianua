//! Arbitrary bytes at the nameserver's packet parser.
//!
//! Two things must hold for every input, however malformed. The parser must
//! not panic — a nameserver answers the open internet, and a panic there is a
//! remote crash. And a UDP answer must never exceed [`MAX_UDP_RESPONSE`],
//! because the gap between a short query and a long reply is the whole of a
//! reflection attack.

#![no_main]

use libfuzzer_sys::fuzz_target;

use ianua_dns::wire::{MAX_UDP_RESPONSE, Transport, answer_query};
use ianua_domain::domains::tenant::custom_domains::dns_zone::{Authority, RecordName, ZoneCatalog};

fuzz_target!(|data: &[u8]| {
    let Ok(hostmaster) = RecordName::new("hostmaster.ianua.test") else {
        return;
    };
    let catalog = ZoneCatalog::empty(Authority::new(hostmaster));

    if let Some(response) = answer_query(&catalog, data, Transport::Udp) {
        assert!(
            response.len() <= MAX_UDP_RESPONSE,
            "udp answer of {} bytes exceeds the {MAX_UDP_RESPONSE}-byte cap",
            response.len()
        );
    }

    let _ = answer_query(&catalog, data, Transport::Tcp);
});
