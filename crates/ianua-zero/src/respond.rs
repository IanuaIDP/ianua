//! What the gateway answers with when it refuses a request or cannot carry
//! it: a page a person can read for a browser, a small JSON body for a
//! script, a gRPC status for a gRPC or gRPC-web call, the same meaning
//! every way. The answer says what kind of trouble it was and the
//! request's reference, never the reason behind it, and carries the
//! headers the pipeline set for its client, such as `Retry-After` on a 429.

pub mod error_page;
pub mod grpc;
pub mod key_set;
