//! Where an address is, for the sign-in risk checks: read from a local
//! city database the server names, with no call out, or never known when
//! it names none.

mod mmdb;
mod none;

pub use mmdb::MmdbGeolocator;
pub use none::NoGeolocator;
