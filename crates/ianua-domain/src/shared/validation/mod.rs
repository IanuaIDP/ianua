mod boundary;
mod charset;
/// Lists that must not name the same thing twice.
pub mod distinct;
mod error;
mod host_check;
/// Invisible characters: text that renders differently from what it says.
pub mod invisible;
/// Range checks for numeric values.
pub mod numeric;
mod rule;
/// Named sets of rules, one file per kind of text.
pub mod rules;
/// How text from outside is made safe to store, log and show.
pub(crate) mod safe_text;
mod text_value;
mod validator;

pub use boundary::Boundary;
pub use charset::{Charset, CharsetUnion};
pub use error::ValidationError;
pub use rule::Rule;
pub use rules::url::UrlHost;
pub(crate) use text_value::{TextValue, text_value};
pub use validator::Validator;
