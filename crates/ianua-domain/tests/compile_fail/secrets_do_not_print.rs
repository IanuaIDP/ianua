//! A secret, or a digest of one, has no text form to reach a log through.

use ianua_domain::types::{DeviceUserCode, TokenHash};

fn print(code: &DeviceUserCode, digest: &TokenHash) {
    println!("{code} {digest}");
}

fn main() {}
