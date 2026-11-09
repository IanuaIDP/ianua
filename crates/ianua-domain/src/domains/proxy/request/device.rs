//! The device a request comes from, as a device posture check reads it.
//!
//! Two sources, in this order. A device certificate the connection's
//! mutual TLS handshake verified names the device the connection was made
//! from, whatever the request carries. Without one, the trusted device
//! recorded on the session when the person signed in, carried in its
//! token, names it. With neither the device is unknown, and a posture rule
//! asking for a device refuses: a request that names no device cannot show
//! that its device passes.

use crate::types::{CertificateFingerprint, Fact, TrustedDeviceId};

/// The device a request comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RequestDevice {
    /// The device certificate with this fingerprint, verified by the
    /// connection's mutual TLS handshake.
    Certified(CertificateFingerprint),
    /// The trusted device recorded on the session at sign-in.
    SessionTrusted(TrustedDeviceId),
    /// Neither: the request names no device.
    #[default]
    Unknown,
}

impl RequestDevice {
    /// The device a request names: the verified device certificate when
    /// the connection presented one, else the session's trusted device.
    ///
    /// Only a certificate the handshake verified against the tenant's
    /// device authorities may be passed as `certificate`; one that was not
    /// asked for, not sent or could not be checked is unknown.
    #[must_use]
    pub fn named_by(
        certificate: Fact<CertificateFingerprint>,
        session_device: Fact<TrustedDeviceId>,
    ) -> Self {
        if let Fact::Known(fingerprint) = certificate {
            return Self::Certified(fingerprint);
        }
        match session_device {
            Fact::Known(device) => Self::SessionTrusted(device),
            Fact::Unknown => Self::Unknown,
        }
    }

    /// The trusted device the session recorded, when that is what names the
    /// device. A certified device is named by its certificate instead, and
    /// a provider is asked about it by that.
    #[must_use]
    pub fn session_device(self) -> Fact<TrustedDeviceId> {
        match self {
            Self::SessionTrusted(device) => Fact::Known(device),
            Self::Certified(_) | Self::Unknown => Fact::Unknown,
        }
    }

    /// Whether anything names the device.
    #[must_use]
    pub fn is_known(self) -> bool {
        self != Self::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate() -> CertificateFingerprint {
        CertificateFingerprint::from_digest([7; 32])
    }

    /// Ann's laptop presents its device certificate and her session also
    /// names her trusted phone. The certificate names the device the
    /// connection really came from, so it wins.
    #[test]
    fn a_verified_device_certificate_names_the_device() {
        let device = RequestDevice::named_by(
            Fact::Known(certificate()),
            Fact::Known(TrustedDeviceId::new()),
        );

        assert_eq!(device, RequestDevice::Certified(certificate()));
        assert_eq!(device.session_device(), Fact::Unknown);
    }

    #[test]
    fn without_a_certificate_the_sessions_trusted_device_names_it() {
        let phone = TrustedDeviceId::new();

        let device = RequestDevice::named_by(Fact::Unknown, Fact::Known(phone));

        assert_eq!(device, RequestDevice::SessionTrusted(phone));
        assert_eq!(device.session_device(), Fact::Known(phone));
    }

    /// With neither a certificate nor a session device, the request's device
    /// is unknown and does not satisfy the known-device predicate.
    #[test]
    fn with_neither_the_device_is_unknown() {
        let device = RequestDevice::named_by(Fact::Unknown, Fact::Unknown);

        assert_eq!(device, RequestDevice::Unknown);
        assert!(!device.is_known());
    }
}
