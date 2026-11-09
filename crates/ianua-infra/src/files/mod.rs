//! Files the platform keeps: tenants' logos, the audit log exports and
//! people's data exports.
//!
//! Every adapter writes through one [`FileStore`]: a directory of the node
//! ([`DiskFileStore`]), or an S3-compatible bucket ([`ObjectFileStore`])
//! when the platform runs on more than one node. Names are made by the platform from ids, never
//! from what a person typed. Exports are written a page at a time and
//! appear whole or not at all; they are downloaded through links the
//! platform signs ([`FileLinks`]), each working for a few minutes and
//! once, and opened by the download route through [`FileLinkedFiles`].
//! Logos are served by the logo route through [`FilePublicLogos`].
//! A deleted tenant's files are removed by [`FileTenantFilePurger`].

mod audit;
mod builder;
mod disk;
mod links;
mod logos;
mod objects;
mod personal;
mod records;
mod sections;
mod store;
mod tenants;

pub use audit::FileAuditExportFiles;
pub use builder::FileDataExportBuilder;
pub use disk::DiskFileStore;
pub use links::{Download, FileLinkedFiles, FileLinks};
pub use logos::{FileLogoStore, FilePublicLogos};
pub use objects::{BucketAddressing, ObjectFileStore, ObjectStoreSettings};
pub use personal::FileDataExportFiles;
pub use sections::PersonalDataSources;
pub use store::{FileName, FileStore, FileUpload, StoredFile};
pub use tenants::FileTenantFilePurger;
