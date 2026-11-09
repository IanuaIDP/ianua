//! What ships inside the build: the public suffix list the site rules
//! read, the common passwords a new password may not be, and the files the
//! platform publishes.
//!
//! Each answers from memory, so a check makes no call out and cannot hang.
//! A newer list or file arrives with a newer build.

mod passwords;
mod published;
mod sites;

pub use passwords::BundledCommonPasswordList;
pub use published::BundledPublishedFiles;
pub use sites::BundledSiteRules;
