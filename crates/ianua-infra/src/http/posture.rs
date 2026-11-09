//! Device posture from the device service the deployment names: an MDM or
//! an endpoint agent's server, asked over HTTP about one device.
//!
//! The gateway asks while a request waits, so the call is held to a couple
//! of seconds and its answer to a few kilobytes. The service is asked
//! `POST <endpoint>` with the tenant, the person and what names the device,
//! under the deployment's bearer token: the trusted device the person's
//! session was signed in from (`device_id`), or the fingerprint of the
//! device certificate the connection presented
//! (`certificate_fingerprint`, `sha256:` and hex). It answers `404` when it
//! knows nothing of the device, or `200` with its report:
//!
//! ```json
//! { "device_id": "…", "os": { "family": "mac_os", "version": "14.4.1" },
//!   "protections": { "disk_encryption": true, "firewall": false },
//!   "reported_at": "2026-10-26T09:00:00Z" }
//! ```
//!
//! The report is never trusted to name the device on its own. Asked about
//! a session's device, a report naming another is refused. Asked about a
//! certificate, the `device_id` it names is the trusted device the
//! certificate's device is enrolled as, which the application still holds
//! to the person's own records. A device nothing names is never asked
//! about. A protection or a system the service names that this side does
//! not know is left unreported, which no rule passes.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::proxy::{DeviceInQuestion, PostureProvider};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::proxy::request::device::RequestDevice;
use ianua_domain::domains::proxy::stages::posture::{
    DevicePosture, DevicePostureParams, OperatingSystem, OsFamily, OsVersion, Protection,
    ProtectionState, ReportedDevice,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificateFingerprint, Fact, TrustedDeviceId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::http::client::{body_within, fixed};

/// The longest the gateway waits for the device service.
const LONGEST_WAIT: Duration = Duration::from_secs(2);

/// The most of an answer read: a report is a few hundred bytes.
const LARGEST_REPORT: usize = 16 * 1024;

/// Asks the deployment's device service what it last heard about a device.
pub struct HttpPostureProvider {
    client: reqwest::Client,
    endpoint: url::Url,
    token: Secret,
}

impl fmt::Debug for HttpPostureProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpPostureProvider")
            .field("endpoint", &self.endpoint.as_str())
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl TenantScoped for HttpPostureProvider {}

impl HttpPostureProvider {
    /// A provider asking `endpoint` under `token`, giving up after
    /// `timeout`, and never later than two seconds.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be
    /// built.
    pub fn new(endpoint: url::Url, token: Secret, timeout: Duration) -> Result<Self, DomainError> {
        Ok(Self {
            client: fixed(timeout.min(LONGEST_WAIT))?,
            endpoint,
            token,
        })
    }

    /// The service's answer about `device`, as it sent it.
    async fn asked(
        &self,
        tenant_id: &ScopedTenant,
        device: &DeviceInQuestion,
    ) -> Result<Option<Report>, DomainError> {
        let question = Question {
            tenant_id: *tenant_id.as_uuid(),
            user_id: *device.person.as_uuid(),
            device_id: session_device(device.device).map(|id| *id.as_uuid()),
            certificate_fingerprint: certificate_of(device.device).map(|fp| fp.to_string()),
        };
        let response = self
            .client
            .post(self.endpoint.clone())
            .bearer_auth(self.token.expose())
            .json(&question)
            .send()
            .await
            .map_err(DomainError::infra)?;
        match response.status().as_u16() {
            200 => {
                let body = body_within(response, LARGEST_REPORT).await?;
                serde_json::from_slice(&body)
                    .map(Some)
                    .map_err(DomainError::infra)
            }
            404 => Ok(None),
            status => Err(DomainError::infra_msg(format!(
                "the device service answered {status}"
            ))),
        }
    }
}

#[async_trait]
impl PostureProvider for HttpPostureProvider {
    async fn posture_of(
        &self,
        tenant_id: &ScopedTenant,
        device: &DeviceInQuestion,
    ) -> Result<Fact<DevicePosture>, DomainError> {
        if !device.device.is_known() {
            return Ok(Fact::Unknown);
        }
        let Some(report) = self.asked(tenant_id, device).await? else {
            return Ok(Fact::Unknown);
        };
        report.into_posture(device.device).map(Fact::Known)
    }
}

/// The device service of a deployment that names none: every question is
/// an error, so a route asking for a device's posture is answered
/// unavailable, never let through on a posture nobody reported.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPostureProvider;

impl TenantScoped for NoPostureProvider {}

#[async_trait]
impl PostureProvider for NoPostureProvider {
    async fn posture_of(
        &self,
        _tenant_id: &ScopedTenant,
        _device: &DeviceInQuestion,
    ) -> Result<Fact<DevicePosture>, DomainError> {
        Err(DomainError::infra_msg(
            "no device service is set up, so no device's posture can be asked",
        ))
    }
}

/// What the service is asked.
#[derive(Serialize)]
struct Question {
    tenant_id: Uuid,
    user_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate_fingerprint: Option<String>,
}

/// A report as the service sends it.
#[derive(Deserialize)]
struct Report {
    device_id: Option<Uuid>,
    os: Option<ReportedSystem>,
    #[serde(default)]
    protections: BTreeMap<String, bool>,
    reported_at: String,
}

/// An operating system as the service names it.
#[derive(Deserialize)]
struct ReportedSystem {
    family: String,
    version: String,
}

impl Report {
    /// The report as the domain reads it, about the device the request
    /// named.
    fn into_posture(self, asked: RequestDevice) -> Result<DevicePosture, DomainError> {
        let device = reported_device(asked, self.device_id)?;
        let system = self.os.map(ReportedSystem::into_system).transpose()?;
        let reported_at =
            OffsetDateTime::parse(&self.reported_at, &Rfc3339).map_err(DomainError::infra)?;
        Ok(DevicePosture::new(DevicePostureParams {
            device,
            system: Fact::from_option(system.flatten()),
            protections: known_protections(self.protections),
            reported_at,
        }))
    }
}

impl ReportedSystem {
    /// The system, or nothing for a family this side does not know.
    fn into_system(self) -> Result<Option<OperatingSystem>, DomainError> {
        let Some(family) = family_named(&self.family) else {
            return Ok(None);
        };
        Ok(Some(OperatingSystem::new(
            family,
            version_of(&self.version)?,
        )))
    }
}

/// The trusted device the session names, when that is what names the
/// device.
fn session_device(device: RequestDevice) -> Option<TrustedDeviceId> {
    match device.session_device() {
        Fact::Known(id) => Some(id),
        Fact::Unknown => None,
    }
}

/// The fingerprint of the device certificate, when that is what names the
/// device.
fn certificate_of(device: RequestDevice) -> Option<CertificateFingerprint> {
    match device {
        RequestDevice::Certified(fingerprint) => Some(fingerprint),
        RequestDevice::SessionTrusted(_) | RequestDevice::Unknown => None,
    }
}

/// Which device the report is about. Asked about a session's device, only
/// that device can be a trusted one and a report naming another is
/// refused; asked about a certificate, the device the service names for it.
fn reported_device(
    asked: RequestDevice,
    answered: Option<Uuid>,
) -> Result<ReportedDevice, DomainError> {
    let Some(answered) = answered else {
        return Ok(ReportedDevice::Unenrolled);
    };
    match asked {
        RequestDevice::SessionTrusted(session) if answered == *session.as_uuid() => {
            Ok(ReportedDevice::Trusted(session))
        }
        RequestDevice::Certified(_) => Ok(ReportedDevice::Trusted(TrustedDeviceId::from_uuid(
            answered,
        ))),
        RequestDevice::SessionTrusted(_) | RequestDevice::Unknown => Err(DomainError::infra_msg(
            "the device service reported on another device",
        )),
    }
}

/// The family a service's word names.
fn family_named(word: &str) -> Option<OsFamily> {
    match word {
        "windows" => Some(OsFamily::Windows),
        "mac_os" => Some(OsFamily::MacOs),
        "linux" => Some(OsFamily::Linux),
        "ios" => Some(OsFamily::Ios),
        "android" => Some(OsFamily::Android),
        "chrome_os" => Some(OsFamily::ChromeOs),
        _ => None,
    }
}

/// The protection a service's word names.
fn protection_named(word: &str) -> Option<Protection> {
    match word {
        "disk_encryption" => Some(Protection::DiskEncryption),
        "screen_lock" => Some(Protection::ScreenLock),
        "firewall" => Some(Protection::Firewall),
        "managed" => Some(Protection::Managed),
        _ => None,
    }
}

/// The protections this side knows, each on or off.
fn known_protections(reported: BTreeMap<String, bool>) -> BTreeMap<Protection, ProtectionState> {
    reported
        .into_iter()
        .filter_map(|(word, on)| {
            let state = if on {
                ProtectionState::On
            } else {
                ProtectionState::Off
            };
            protection_named(&word).map(|protection| (protection, state))
        })
        .collect()
}

/// A version written `major[.minor[.patch[...]]]`; parts past the third are
/// left out, as no rule compares them.
fn version_of(text: &str) -> Result<OsVersion, DomainError> {
    let mut parts = text.trim().split('.').map(str::parse::<u16>);
    let major = parts
        .next()
        .ok_or_else(|| DomainError::infra_msg("the device service sent no version"))?
        .map_err(DomainError::infra)?;
    let minor = parts.next().transpose().map_err(DomainError::infra)?;
    let patch = parts.next().transpose().map_err(DomainError::infra)?;
    Ok(OsVersion::new(
        major,
        minor.unwrap_or(0),
        patch.unwrap_or(0),
    ))
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{TenantId, UserId};
    use wiremock::matchers::{body_partial_json, header, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const TOKEN: &str = "posture-token-distinctive";

    async fn service(response: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }

    fn provider(server: &MockServer) -> HttpPostureProvider {
        HttpPostureProvider::new(
            url::Url::parse(&server.uri()).unwrap(),
            Secret::new(TOKEN),
            Duration::from_millis(500),
        )
        .unwrap()
    }

    fn tenant() -> ScopedTenant {
        ScopedTenant::for_background(TenantId::new())
    }

    fn device(named: RequestDevice) -> DeviceInQuestion {
        DeviceInQuestion {
            person: UserId::new(),
            device: named,
        }
    }

    fn certificate() -> CertificateFingerprint {
        CertificateFingerprint::from_digest([7; 32])
    }

    fn certified() -> DeviceInQuestion {
        device(RequestDevice::Certified(certificate()))
    }

    fn report(device_id: Option<Uuid>) -> serde_json::Value {
        serde_json::json!({
            "device_id": device_id,
            "os": { "family": "mac_os", "version": "14.10.2" },
            "protections": { "disk_encryption": true, "firewall": false, "telepathy": true },
            "reported_at": "2026-10-26T09:00:00Z",
        })
    }

    /// Without a device service, asking about a certified device returns an
    /// error.
    #[tokio::test]
    async fn with_no_device_service_every_question_is_an_error() {
        let asked = NoPostureProvider.posture_of(&tenant(), &certified()).await;

        assert!(asked.is_err());
    }

    /// A report about the device the session names reads back whole: the
    /// trusted device, its system and version, and each protection.
    #[tokio::test]
    async fn a_report_on_the_session_device_is_read_back() {
        let id = TrustedDeviceId::new();
        let server =
            service(ResponseTemplate::new(200).set_body_json(report(Some(*id.as_uuid())))).await;

        let posture = provider(&server)
            .posture_of(&tenant(), &device(RequestDevice::SessionTrusted(id)))
            .await
            .unwrap();

        let Fact::Known(posture) = posture else {
            panic!("a report was sent");
        };
        assert_eq!(posture.device(), ReportedDevice::Trusted(id));
        assert_eq!(
            posture.system(),
            Fact::Known(OperatingSystem::new(
                OsFamily::MacOs,
                OsVersion::new(14, 10, 2)
            ))
        );
        assert_eq!(
            posture.protection(Protection::DiskEncryption),
            Fact::Known(ProtectionState::On)
        );
        assert_eq!(
            posture.protection(Protection::Firewall),
            Fact::Known(ProtectionState::Off)
        );
        assert_eq!(posture.protection(Protection::ScreenLock), Fact::Unknown);
    }

    /// A device the service knows nothing of is unreported, which no rule
    /// passes.
    #[tokio::test]
    async fn a_device_the_service_does_not_know_is_unreported() {
        let server = service(ResponseTemplate::new(404)).await;

        let posture = provider(&server)
            .posture_of(
                &tenant(),
                &device(RequestDevice::SessionTrusted(TrustedDeviceId::new())),
            )
            .await
            .unwrap();

        assert_eq!(posture, Fact::Unknown);
    }

    /// Ann's laptop presents its device certificate. The service is asked
    /// by the certificate's fingerprint, and the device it names is read as
    /// the one the certificate's device is enrolled as.
    #[tokio::test]
    async fn a_certified_device_is_asked_by_its_fingerprint() {
        let laptop = Uuid::new_v4();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(serde_json::json!({
                "certificate_fingerprint": certificate().to_string(),
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(report(Some(laptop))))
            .mount(&server)
            .await;

        let posture = provider(&server)
            .posture_of(&tenant(), &certified())
            .await
            .unwrap();

        let Fact::Known(posture) = posture else {
            panic!("a report was sent");
        };
        assert_eq!(
            posture.device(),
            ReportedDevice::Trusted(TrustedDeviceId::from_uuid(laptop))
        );
    }

    /// A report naming no device, about a certificate, is about a device
    /// nobody enrolled.
    #[tokio::test]
    async fn a_report_naming_no_device_is_unenrolled() {
        let server = service(ResponseTemplate::new(200).set_body_json(report(None))).await;

        let posture = provider(&server)
            .posture_of(&tenant(), &certified())
            .await
            .unwrap();

        let Fact::Known(posture) = posture else {
            panic!("a report was sent");
        };
        assert_eq!(posture.device(), ReportedDevice::Unenrolled);
    }

    /// An unknown request device produces unknown posture without sending
    /// a request to the device service.
    #[tokio::test]
    async fn a_device_nothing_names_is_never_asked_about() {
        let server = service(ResponseTemplate::new(200).set_body_json(report(None))).await;

        let posture = provider(&server)
            .posture_of(&tenant(), &device(RequestDevice::Unknown))
            .await
            .unwrap();

        assert_eq!(posture, Fact::Unknown);
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// A report naming a different device from the session returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_report_on_another_device_is_refused() {
        let server =
            service(ResponseTemplate::new(200).set_body_json(report(Some(Uuid::new_v4())))).await;

        let result = provider(&server)
            .posture_of(
                &tenant(),
                &device(RequestDevice::SessionTrusted(TrustedDeviceId::new())),
            )
            .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// A device-service response delayed beyond the timeout returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_slow_service_is_given_up() {
        let server = service(ResponseTemplate::new(404).set_delay(Duration::from_secs(3))).await;

        let result = provider(&server).posture_of(&tenant(), &certified()).await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// HTTP 500, malformed JSON and a report exceeding the byte limit each
    /// return an infrastructure error.
    #[tokio::test]
    async fn a_failure_or_an_unreadable_answer_is_an_error() {
        let failing = service(ResponseTemplate::new(500)).await;
        let garbled = service(ResponseTemplate::new(200).set_body_string("{\"os\": 1")).await;
        let endless =
            service(ResponseTemplate::new(200).set_body_bytes(vec![b' '; LARGEST_REPORT + 1]))
                .await;
        let asked = certified();

        for server in [&failing, &garbled, &endless] {
            let result = provider(server).posture_of(&tenant(), &asked).await;

            assert!(matches!(result, Err(DomainError::Infrastructure(_))));
        }
    }

    /// Empty or nonnumeric versions fail parsing; a Windows build uses its
    /// first three parts, and a lone major version fills minor and patch with zero.
    #[test]
    fn a_version_is_read_by_its_parts_or_refused() {
        assert_eq!(
            version_of("10.0.19045.1234").unwrap(),
            OsVersion::new(10, 0, 19045)
        );
        assert_eq!(version_of("17").unwrap(), OsVersion::new(17, 0, 0));
        assert!(version_of("").is_err());
        assert!(version_of("fourteen").is_err());
    }

    /// The deployment's token reaches the service and never a log line.
    #[tokio::test]
    async fn the_token_is_sent_but_never_shown() {
        let server = service(ResponseTemplate::new(404)).await;
        let provider = provider(&server);

        provider.posture_of(&tenant(), &certified()).await.unwrap();

        assert!(!format!("{provider:?}").contains(TOKEN));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}
