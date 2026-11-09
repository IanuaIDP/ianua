//! Only a link's own state says why it was refused, so a caller cannot report
//! a link as spent when it was not.

use ianua_domain::types::TokenRefused;

fn main() {
    let _refused = TokenRefused::spent();
}
