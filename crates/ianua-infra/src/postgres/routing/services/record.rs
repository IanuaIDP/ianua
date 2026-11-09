//! A service as its row holds it: read back into the aggregate, and written
//! out from it.

use ianua_domain::domains::routing::service::{Service, ServiceRow};
use ianua_domain::domains::routing::sign_in::accepted::AcceptedSignIn;
use ianua_domain::domains::routing::sign_in::app::AppSignIn;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Label, ServiceId, Setting};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const SERVICE: Stored = Stored("service");

const UPSTREAM: Kept = Kept {
    entity: SERVICE.0,
    column: "upstream",
    shape: 1,
};

const HEALTH_CHECK: Kept = Kept {
    entity: SERVICE.0,
    column: "health_check",
    shape: 1,
};

const APP_SIGN_IN: Kept = Kept {
    entity: SERVICE.0,
    column: "app_sign_in",
    shape: 1,
};

const SIGN_IN_DELIVERY: Kept = Kept {
    entity: SERVICE.0,
    column: "sign_in_delivery",
    shape: 1,
};

/// A service as it is read. The store's checked queries fill it.
pub(super) struct ServiceRecord {
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) upstream: Value,
    pub(super) health_check: Value,
    pub(super) app_sign_in: Option<Value>,
    pub(super) accepts_sign_in_of: Option<Uuid>,
    pub(super) sign_in_delivery: Option<Value>,
    pub(super) status: String,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl ServiceRecord {
    /// The service the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the service
    /// keeps.
    pub(super) fn into_service(self) -> Result<Service<ResolvedTenant>, DomainError> {
        let app_sign_in = self
            .app_sign_in
            .map(|stored| APP_SIGN_IN.open::<AppSignIn>(stored))
            .transpose()?;
        Service::reconstitute(ServiceRow {
            id: ServiceId::from_uuid(self.id),
            name: SERVICE.value("name", Label::new("name", self.name))?,
            upstream: UPSTREAM.open(self.upstream)?,
            health_check: HEALTH_CHECK.open(self.health_check)?,
            app_sign_in: Setting::from_stored(app_sign_in),
            accepted_sign_in: Setting::from_stored(accepted_from(
                self.accepts_sign_in_of,
                self.sign_in_delivery,
            )?),
            status: SERVICE.choice(&self.status)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// The sign-in a stored service accepts, from its two columns.
fn accepted_from(
    owner: Option<Uuid>,
    delivery: Option<Value>,
) -> Result<Option<AcceptedSignIn>, DomainError> {
    match (owner, delivery) {
        (None, None) => Ok(None),
        (Some(owner), Some(delivery)) => Ok(Some(AcceptedSignIn::new(
            ServiceId::from_uuid(owner),
            SIGN_IN_DELIVERY.open(delivery)?,
        ))),
        (Some(_), None) | (None, Some(_)) => Err(DomainError::corrupt_row(
            SERVICE.0,
            "an accepted sign-in without its owner or its delivery",
        )),
    }
}

/// A service's columns, as they are written, with the hosts its sign-in
/// holds.
pub(super) struct ServiceColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) name: &'a str,
    pub(super) upstream: Value,
    pub(super) health_check: Value,
    pub(super) app_sign_in: Option<Value>,
    pub(super) accepts_sign_in_of: Option<Uuid>,
    pub(super) sign_in_delivery: Option<Value>,
    pub(super) status: &'static str,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
    pub(super) sign_in_hosts: Vec<String>,
}

impl<'a> ServiceColumns<'a> {
    /// The columns `service` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value cannot be written
    /// out as JSON.
    pub(super) fn of(service: &'a Service<ResolvedTenant>) -> Result<Self, DomainError> {
        let accepted = service.accepted_sign_in();
        Ok(Self {
            id: service.id().as_uuid(),
            name: service.name().as_str(),
            upstream: UPSTREAM.seal(service.upstream())?,
            health_check: HEALTH_CHECK.seal(service.health_check())?,
            app_sign_in: service
                .app_sign_in()
                .map(|sign_in| APP_SIGN_IN.seal(sign_in))
                .transpose()?,
            accepts_sign_in_of: accepted.map(|sign_in| *sign_in.owner().as_uuid()),
            sign_in_delivery: accepted
                .map(|sign_in| SIGN_IN_DELIVERY.seal(sign_in.delivery()))
                .transpose()?,
            status: service.status().word(),
            created_at: service.created_at(),
            updated_at: service.updated_at(),
            sign_in_hosts: sign_in_hosts_of(service),
        })
    }
}

/// The hosts `service` answers sign-in on, or sets its own cookie on.
fn sign_in_hosts_of(service: &Service<ResolvedTenant>) -> Vec<String> {
    let own = service.app_sign_in().map_or(&[][..], AppSignIn::hosts);
    let cookie = service
        .accepted_sign_in()
        .map_or(&[][..], AcceptedSignIn::cookie_hosts);
    own.iter()
        .chain(cookie)
        .map(|host| host.as_str().to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use std::collections::BTreeMap;

    use ianua_domain::domains::routing::backend::health_check::HealthCheckPolicy;
    use ianua_domain::domains::routing::backend::upstream::{
        HostHeader, Upstream, UpstreamTimeout,
    };
    use ianua_domain::domains::routing::sign_in::accepted::{CookieHosts, SignInDelivery};
    use ianua_domain::domains::routing::sign_in::app::{AppSignInParams, SignedOutBrowsers};
    use ianua_domain::types::{DomainName, HttpUrl};
    use serde_json::json;

    use super::*;

    /// The upstream is written in the shape pinned here, and a row in that
    /// shape reads back.
    #[test]
    fn the_upstream_is_stored_in_its_pinned_shape() {
        let upstream = Upstream::new(
            HttpUrl::new("https://payroll.example.com").unwrap(),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
        );
        let stored = json!({"v": 1, "value": {
            "url": "https://payroll.example.com",
            "timeout_secs": 30,
            "preserve_host": false,
            "expected_audience": "no_token_accepted",
            "identity": "token",
            "plaintext_http2": false,
            "balancing": "round_robin",
            "circuit_breaker": {"on": {"failure_threshold": 5, "cooldown_secs": 30}},
            "assertion_audience": "service_id",
            "reach": "direct"
        }});

        assert_eq!(UPSTREAM.seal(&upstream).unwrap(), stored);
        assert_eq!(UPSTREAM.open::<Upstream>(stored).unwrap(), upstream);
    }

    /// The health check is written in the shape pinned here, and a row in
    /// that shape reads back.
    #[test]
    fn the_health_check_is_stored_in_its_pinned_shape() {
        let check = HealthCheckPolicy::default();
        let stored = json!({"v": 1, "value": {"Active": {
            "path": "/healthz",
            "interval_secs": 10,
            "timeout_secs": 5,
            "healthy_threshold": 2,
            "unhealthy_threshold": 3,
            "panic_threshold_percent": 50
        }}});

        assert_eq!(HEALTH_CHECK.seal(&check).unwrap(), stored);
        assert_eq!(
            HEALTH_CHECK.open::<HealthCheckPolicy>(stored).unwrap(),
            check
        );
    }

    /// App sign-in is written in the shape pinned here, and a row in that
    /// shape reads back.
    #[test]
    fn the_app_sign_in_is_stored_in_its_pinned_shape() {
        let sign_in = AppSignIn::new(AppSignInParams {
            hosts: vec![DomainName::new("shop.example.com").unwrap()],
            prefix: Setting::Unset,
            moved: BTreeMap::new(),
            after_sign_in: Setting::Unset,
            signed_out_browsers: SignedOutBrowsers::Refuse,
        })
        .unwrap();
        let stored = json!({"v": 1, "value": {
            "hosts": ["shop.example.com"],
            "prefix": "/.ianua",
            "moved": {},
            "after_sign_in": "/",
            "signed_out_browsers": "Refuse"
        }});

        assert_eq!(APP_SIGN_IN.seal(&sign_in).unwrap(), stored);
        assert_eq!(APP_SIGN_IN.open::<AppSignIn>(stored).unwrap(), sign_in);
    }

    /// How an accepted sign-in reaches the service is written in the shape
    /// pinned here, and a row in that shape reads back.
    #[test]
    fn the_sign_in_delivery_is_stored_in_its_pinned_shape() {
        let delivery = SignInDelivery::OwnCookie(
            CookieHosts::new(vec![DomainName::new("api.example.com").unwrap()]).unwrap(),
        );
        let stored = json!({"v": 1, "value": {"own_cookie": ["api.example.com"]}});

        assert_eq!(SIGN_IN_DELIVERY.seal(&delivery).unwrap(), stored);
        assert_eq!(
            SIGN_IN_DELIVERY.open::<SignInDelivery>(stored).unwrap(),
            delivery
        );
    }
}
