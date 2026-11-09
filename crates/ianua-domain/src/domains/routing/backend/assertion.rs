//! Whom the gateway's signed identity assertion is made out to.
//!
//! The gateway tells an upstream who is calling in a signed assertion. Every
//! service of a tenant checks it against the same tenant key. So an
//! assertion made out to no one in particular, sent to one app, is just as
//! good at another. Each service's assertions name it as their audience, and
//! an upstream accepts only those made out to it.

use std::fmt;

use crate::types::{Audience, ServiceId};

/// The audience a service's assertions name.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum AssertionAudience {
    /// The service's own id, so no two services share an audience. The
    /// upstream checks for `urn:ianua:service:<id>`.
    #[default]
    ServiceId,
    /// A name the upstream already checks for, such as its own URL.
    Named(Audience),
}

/// The `aud` claim one service's assertions carry, worked out from its
/// [`AssertionAudience`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssertionAudienceClaim<'a> {
    /// The service's own id, written `urn:ianua:service:<id>`.
    Service(&'a ServiceId),
    /// The name set for the service.
    Named(&'a Audience),
}

impl<'a> AssertionAudienceClaim<'a> {
    /// The claim for the service `service`, whose assertions are set to
    /// name `audience`.
    #[must_use]
    pub fn of(service: &'a ServiceId, audience: &'a AssertionAudience) -> Self {
        match audience {
            AssertionAudience::ServiceId => Self::Service(service),
            AssertionAudience::Named(name) => Self::Named(name),
        }
    }
}

impl fmt::Display for AssertionAudienceClaim<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Service(id) => write!(f, "urn:ianua:service:{id}"),
            Self::Named(name) => f.write_str(name.as_str()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two service IDs produce distinct default audiences, with the reports
    /// audience containing its service ID in the expected URN.
    #[test]
    fn two_services_never_share_an_audience_by_default() {
        let (reports, billing) = (ServiceId::new(), ServiceId::new());
        let default = AssertionAudience::default();

        let to_reports = AssertionAudienceClaim::of(&reports, &default).to_string();
        let to_billing = AssertionAudienceClaim::of(&billing, &default).to_string();

        assert_ne!(to_reports, to_billing);
        assert_eq!(to_reports, format!("urn:ianua:service:{reports}"));
    }

    /// Ann names her service's audience `https://billing.example.com`. Its
    /// assertions carry exactly that.
    #[test]
    fn a_named_audience_is_written_as_given() {
        let named = AssertionAudience::Named(Audience::new("https://billing.example.com").unwrap());

        assert_eq!(
            AssertionAudienceClaim::of(&ServiceId::new(), &named).to_string(),
            "https://billing.example.com"
        );
    }
}
