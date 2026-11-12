//! What the platform's workers share through the platform database: the
//! announcements that wake their loops when work waits, and the leases that
//! keep one worker on a run or an exchange at a time.

pub mod announcements;
pub(crate) mod leases;
