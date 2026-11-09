//! The use cases handing out files by address: export downloads through
//! their links, tenants' logos, the files the platform publishes, and the
//! pictures installed integrations carry.

use std::sync::Arc;

use ianua_app::use_cases::files::{
    DownloadPorts, DownloadUseCase, ServeLogoPorts, ServeLogoUseCase, ServePublishedPorts,
    ServePublishedUseCase,
};
use ianua_app::use_cases::workflows::catalog::{
    IntegrationPicturePorts, IntegrationPictureUseCase,
};

use crate::deps::Adapters;

/// The use cases handing out files by address.
#[derive(Clone)]
pub struct FilesState {
    pub download: Arc<DownloadUseCase>,
    pub logo: Arc<ServeLogoUseCase>,
    pub published: Arc<ServePublishedUseCase>,
    pub integration_picture: Arc<IntegrationPictureUseCase>,
}

/// Builds the use cases handing out files over `a`.
pub fn build(a: &Adapters) -> FilesState {
    FilesState {
        download: Arc::new(DownloadUseCase::new(DownloadPorts {
            files: a.linked_files.clone(),
        })),
        logo: Arc::new(ServeLogoUseCase::new(ServeLogoPorts {
            logos: a.public_logos.clone(),
        })),
        published: Arc::new(ServePublishedUseCase::new(ServePublishedPorts {
            files: a.published_files.clone(),
        })),
        integration_picture: Arc::new(IntegrationPictureUseCase::new(IntegrationPicturePorts {
            catalog: a.integration_catalog.clone(),
        })),
    }
}
