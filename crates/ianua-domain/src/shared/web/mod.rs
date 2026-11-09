//! How the web spells things: percent-encoding, request parameter names and the headers a proxy owns.

/// How a request parameter's name is compared, in every spelling servers read.
pub(crate) mod parameter_key;
/// Percent-encoding for paths and query strings.
pub(crate) mod percent;
/// The headers a proxy vouches for itself, which no client and no tenant may set.
pub mod proxy_headers;
