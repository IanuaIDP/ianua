//! Handlers handing out files by address: an export through its download
//! link, a tenant's logo, and the files the platform publishes.

use axum::extract::{Path, State};
use ianua_app::ports::files::PublishedFile;
use ianua_app::use_case::Query as _;
use ianua_assembly::files::FilesState;

use crate::error::{ApiError, ErrorBody};
use crate::extractors::paths::files::{DownloadPath, IntegrationPicturePath, LogoPath};
use crate::response::files::{FileDownload, LogoAnswer, PictureAnswer, PublishedAnswer};

#[utoipa::path(
    get,
    path = "/api/v1/files/download/{token}",
    tag = "Files",
    params(("token" = String, Path, description = "The sealed ticket the download link carries")),
    responses(
        (status = 200, description = "The file, as an attachment", content_type = "application/octet-stream"),
        (status = 404, description = "The link opens nothing: forged, changed, run out, used before, or its file is gone", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Download an export file
///
/// Follows a download link the platform made for an audit log export or a
/// personal data export, and streams the file as an attachment under a name
/// the platform chose. A link works for a few minutes and opens its file
/// once; every reason it opens nothing answers the same `404`. Public: the
/// link is the whole proof, and it names no person.
pub(crate) async fn download(
    State(files): State<FilesState>,
    Path(path): Path<DownloadPath>,
) -> Result<FileDownload, ApiError> {
    let file = files.download.execute(&(), path.into_token()).await?;
    Ok(FileDownload(file))
}

#[utoipa::path(
    get,
    path = "/api/v1/files/logos/{key}",
    tag = "Files",
    params(("key" = String, Path, description = "The tenant the logo address names")),
    responses(
        (status = 200, description = "The logo, as a PNG or a JPEG", content_type = "image/png"),
        (status = 404, description = "No logo at this address", body = ErrorBody)
    )
)]
/// Fetch a tenant's logo
///
/// The logo a tenant uploaded, at the address its branding gave out. The
/// address changes with every new logo, so the answer is cached for good.
/// Public: mail clients and sign-in pages fetch it with no credentials.
pub(crate) async fn logo(
    State(files): State<FilesState>,
    Path(path): Path<LogoPath>,
) -> Result<LogoAnswer, ApiError> {
    let logo = files.logo.execute(&(), path.into_key()).await?;
    Ok(LogoAnswer(logo))
}

#[utoipa::path(
    get,
    path = "/email-logo.png",
    tag = "Files",
    responses(
        (status = 200, description = "The platform's mail logo, kept for a week", content_type = "image/png")
    )
)]
/// Fetch the platform's mail logo
///
/// The logo at the top of the platform's own mail. Mail clients strip
/// embedded images, so they fetch it by address. Public and cached for a
/// week: it changes only with a new build.
pub(crate) async fn email_logo(State(files): State<FilesState>) -> PublishedAnswer {
    PublishedAnswer(files.published.execute(&(), PublishedFile::EmailLogo).await)
}

#[utoipa::path(
    get,
    path = "/.well-known/ianua/aws-connect.yaml",
    tag = "Files",
    responses(
        (status = 200, description = "The CloudFormation template, shown inline as `ianua-connect.yaml` and kept for an hour", content_type = "application/x-yaml")
    )
)]
/// Fetch the AWS connect template
///
/// The CloudFormation template a customer runs in their AWS account to
/// make the one role the platform assumes, trusting only the platform's
/// account and only with the external id they were given. Public on
/// purpose: it holds no secret, since the account id and external id are
/// parameters the customer fills in, and someone about to make a role in
/// their own account may read exactly what it will do first. Served by the
/// deployment that will assume the role, so a self-hosted install never
/// points customers at a template made for another platform.
pub(crate) async fn aws_trust_template(State(files): State<FilesState>) -> PublishedAnswer {
    PublishedAnswer(
        files
            .published
            .execute(&(), PublishedFile::AwsTrustTemplate)
            .await,
    )
}

#[utoipa::path(
    get,
    path = "/api/v1/files/integrations/{integration}/picture.svg",
    tag = "Files",
    params(("integration" = String, Path, description = "The integration, such as `github`")),
    responses(
        (status = 200, description = "The integration's picture, SVG of shapes only", content_type = "image/svg+xml"),
        (status = 404, description = "No integration is installed under this name", body = ErrorBody),
        (status = 422, description = "Not an integration's name", body = ErrorBody)
    )
)]
/// Fetch an integration's picture
///
/// The picture an installed integration carries, drawn on a 24 by 24 grid.
/// It holds only shapes, checked when the integration was built, and is
/// served so a browser never runs anything in it. Public: it is the same on
/// every deployment and names no tenant.
pub(crate) async fn integration_picture(
    State(files): State<FilesState>,
    Path(path): Path<IntegrationPicturePath>,
) -> Result<PictureAnswer, ApiError> {
    let picture = files
        .integration_picture
        .execute(&(), path.integration()?)
        .await?;
    Ok(PictureAnswer(picture))
}
