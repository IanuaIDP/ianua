//! Named sets of rules, one file per kind of text.
//!
//! A value type picks the set that describes it, such as an identifier, a
//! token, a URL path or free text, instead of assembling its own chain of
//! checks. A rule is then written once, and every type of that kind keeps it.
//! Each set adds methods to [`Validator`](crate::shared::validation::Validator), so a type can
//! still add a check of its own after the set.

mod device_code;
mod email;
mod free_text;
mod header_value;
mod identifier;
mod listed;
mod password;
mod path;
mod pem;
mod slug;
mod token;
/// URLs, read with the parser the HTTP clients use.
pub mod url;
mod xml_id;
