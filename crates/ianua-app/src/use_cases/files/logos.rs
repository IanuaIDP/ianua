//! A mail client or a sign-in page fetches a tenant's logo from the public
//! address its branding gave out.

use std::sync::Arc;

use ianua_domain::domains::branding::logo::LogoImage;
use ianua_domain::message;

use crate::error::{AppError, OrInternal};
use crate::ports::files::PublicLogos;
use crate::use_case::Query;

/// The ports [`ServeLogoUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ServeLogoPorts {
    /// The logos, by the key their address ends in.
    pub logos: Arc<dyn PublicLogos>,
}

/// Serves a tenant's logo.
pub struct ServeLogoUseCase {
    ports: ServeLogoPorts,
}

impl ServeLogoUseCase {
    /// A use case reading logos through `ports`.
    #[must_use]
    pub fn new(ports: ServeLogoPorts) -> Self {
        Self { ports }
    }
}

impl Query for ServeLogoUseCase {
    type Caller = ();
    type Input = String;
    type Output = Result<LogoImage, AppError>;

    /// The logo kept under `key`. Public: a logo is shown to anyone who
    /// sees the tenant's mail or sign-in page.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when `key` names no tenant's logo.
    /// - `AppError::Internal` when the logo cannot be read.
    async fn execute(&self, (): &(), key: String) -> Result<LogoImage, AppError> {
        self.ports
            .logos
            .logo_at(&key)
            .await
            .or_internal()?
            .ok_or_else(|| {
                AppError::NotFound(message!(
                    "files-no-logo-at-this-address",
                    "no logo at this address"
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::files::FakePublicLogos;

    /// An unknown logo address answers not found rather than returning an
    /// empty image.
    #[tokio::test]
    async fn an_address_naming_no_logo_answers_not_found() {
        let use_case = ServeLogoUseCase::new(ServeLogoPorts {
            logos: Arc::new(FakePublicLogos::default()),
        });

        let served = use_case.execute(&(), "unknown".to_owned()).await;

        assert!(matches!(served, Err(AppError::NotFound(_))));
    }
}
