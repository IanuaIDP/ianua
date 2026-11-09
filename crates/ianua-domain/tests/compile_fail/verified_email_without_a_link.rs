//! An address is only verified by spending a link, accepting an invitation or
//! a trusted provider's word; a caller cannot declare it so.

use ianua_domain::domains::identity::account::verified_email::VerifiedEmail;
use ianua_domain::types::Email;

fn main() {
    let email = Email::new("someone@example.com").unwrap();
    let _verified = VerifiedEmail::proven(email);
}
