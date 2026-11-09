//! The words a job's status is stored as. A failed job goes back to
//! pending or ends dead within one step, so `failed` is never kept; the
//! table refuses it.

use ianua_domain::domains::scheduling::job_key::KeyHold;
use ianua_domain::domains::scheduling::job_status::JobStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    JobStatus as "job status" {
        Pending => "pending",
        Running => "running",
        Completed => "completed",
        Failed => "failed",
        Dead => "dead",
        Superseded => "superseded",
    }
}

stored_words! {
    KeyHold as "key hold" {
        WhileLive => "live",
        WhileKept => "kept",
    }
}
