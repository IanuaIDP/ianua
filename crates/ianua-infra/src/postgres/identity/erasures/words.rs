//! The words an erasure request's status is stored as.

use ianua_domain::domains::identity::privacy::erasure_status::ErasureStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    ErasureStatus as "erasure status" {
        Pending => "pending",
        Processing => "processing",
        Completed => "completed",
        Cancelled => "cancelled",
        Held => "held",
        Failed => "failed",
    }
}
