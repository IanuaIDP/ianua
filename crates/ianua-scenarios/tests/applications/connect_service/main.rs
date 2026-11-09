//! Letting programs in: a partner's program registered as a consumer of
//! the tenant, its key shown once, limited, cleared, rotated with an
//! overlap, switched off and on and deleted; and the keys the tenant signs
//! its tokens with, moved to another algorithm without breaking anyone.
//!
//! - `algorithm`: Tess moves token signing from RSA to elliptic-curve
//!   keys, both published while the move runs, the old one gone at its
//!   end; a plan cancelled and a move rolled back; nobody else plans one.
//! - `consumers`: Tess runs the partner's program from registration to
//!   deletion and rotates its key with an overlap she ends early; nobody
//!   without the right touches it. Whether the gateway takes or refuses
//!   the key is proved with the gateway's own scenarios.
//! - `expiry`: Tess writes what the program is for and when its key
//!   stops; once it stops the gateway refuses it.

#![cfg(test)]

mod algorithm;
mod consumers;
mod expiry;
mod support;
