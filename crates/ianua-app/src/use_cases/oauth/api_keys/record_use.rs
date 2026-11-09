//! Stamping a tenant API key with the request it just signed in, and
//! noting the country it came from on every request.

use std::sync::Arc;

use ianua_domain::domains::oauth::clients::api_key::CountryNoted;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, ApiKeyId, CountryCode, Fact, IpAddress};

use crate::auditor::RequestAuditor;
use crate::context::{CallerContext, Credential};
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::Geolocator;
use crate::ports::oauth::{ApiKeyStore, UseRecorded};
use crate::use_case::Command;
use crate::use_cases::oauth::lookup::existing_api_key;

/// Whether the key's last use is due to be written down again. Writing it
/// on every request would cost a write per request of a busy key, so the
/// caller spaces the stamps out; a new country is written whatever this
/// says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UseStamp {
    /// The last stamp is old enough: write when and from where.
    Due,
    /// The key was stamped a moment ago: write only a new country.
    Recent,
}

/// The ports [`RecordUseUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RecordUsePorts {
    /// Where keys are kept.
    pub key_store: Arc<dyn ApiKeyStore>,
    /// Places the request's address in a country.
    pub geolocator: Arc<dyn Geolocator>,
}

/// Records that the tenant API key a request came with was just used, and
/// from where.
///
/// The request middleware calls it on every request a bearer token
/// resolved to a tenant key, so the key's owners can see when and from
/// where it last worked and spot one that leaked or sits unused. The
/// country is checked every time: a stolen copy used from Brazil thirty
/// seconds after the key worked in Germany is noted on that first request,
/// not a minute later. A caller who came with anything else has no key to
/// stamp.
pub struct RecordUseUseCase {
    ports: RecordUsePorts,
}

impl RecordUseUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RecordUsePorts) -> Self {
        Self { ports }
    }

    /// Notes the country of the request on the key `key_id` of `caller`'s
    /// tenant, and writes the key back when the country is new to it or
    /// the stamp is due, with when and from where it was used. A request
    /// that changes nothing and comes a moment after the last stamp costs
    /// one read and no write.
    async fn stamp(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        key_id: &ApiKeyId,
        stamp: UseStamp,
    ) -> Result<(), AppError> {
        let store = self.ports.key_store.as_ref();
        let tenant = caller.tenant();
        let mut key = existing_api_key(store, &tenant, key_id).await?;
        let read_countries = key.seen_countries().to_vec();
        let context = caller.audit_context();
        let ip = context.ip_address();
        let noted = key.note_country(self.country_of(ip).await);
        if (noted, stamp) == (CountryNoted::Unchanged, UseStamp::Recent) {
            return Ok(());
        }
        key.record_usage(ip);
        let written = store
            .record_use(&tenant, &key, &read_countries)
            .await
            .or_internal()?;
        if !ensure_still_kept(written)? {
            return Ok(());
        }
        auditor
            .dispatch_by(&ActorRef::System, key.take_events(&tenant))
            .await
            .or_internal()
    }

    /// The country `ip` is in, when it is known and could be placed. A
    /// lookup that fails is a country nobody knows, never a refusal.
    async fn country_of(&self, ip: &Fact<IpAddress>) -> Fact<CountryCode> {
        let Fact::Known(ip) = ip else {
            return Fact::Unknown;
        };
        match self.ports.geolocator.locate(ip).await {
            Ok(Some(place)) => Fact::Known(place.country_code().clone()),
            Ok(None) | Err(_) => Fact::Unknown,
        }
    }
}

impl Command for RecordUseUseCase {
    type Caller = CallerContext;
    type Input = UseStamp;
    type Output = Result<(), AppError>;

    /// Notes the country of the key `caller` came with, and stamps it used
    /// now when `stamp` is due or the country is new to it. A caller who
    /// came with no tenant key changes nothing. The stamp is bookkeeping,
    /// not an action anyone took, so it is not recorded; a country the key
    /// never signed in from before is, by the system, once.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the key is gone.
    /// - `AppError::Internal` when the key cannot be read or saved, or a
    ///   new country cannot be recorded.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        stamp: UseStamp,
    ) -> Result<(), AppError> {
        let Credential::TenantApiKey(key_id) = caller.credential() else {
            return Ok(());
        };
        self.stamp(caller, auditor, key_id, stamp).await
    }
}

/// Whether the write landed: `false` when another use of the key noted a
/// country first, which then recorded it, so this one records nothing.
///
/// # Errors
///
/// - `AppError::NotFound` when the key was revoked since it was read.
fn ensure_still_kept(written: UseRecorded) -> Result<bool, AppError> {
    match written {
        UseRecorded::Written => Ok(true),
        UseRecorded::Overtaken => Ok(false),
        UseRecorded::Gone => Err(AppError::NotFound(message!(
            "oauth-api-key-not-found",
            "API key not found"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::risk_engine::assessment::IpGeolocation;
    use ianua_domain::domains::oauth::clients::api_key::ApiKey;
    use ianua_domain::domains::organization::billing::plan::OrganizationPlan;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::{ActorRef, IpAddress, UserId};

    use super::*;
    use crate::context::CallerIdentity;
    use crate::test_support::authentication::FakeGeolocator;
    use crate::test_support::oauth::{FakeApiKeyStore, stored_api_key};
    use crate::test_support::{
        FakeEventDispatcher, ReadBeforeWrite, block_on, test_auditor, test_ctx, test_session_id,
    };

    /// The event a key's first use from another country raises.
    const NEW_COUNTRY: &str = "oauth.api_key_used_from_new_country";

    struct Fixture {
        maker: UserId,
        key_id: ApiKeyId,
        keys: Arc<FakeApiKeyStore>,
        events: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn new() -> Self {
            let maker = UserId::new();
            let key = stored_api_key("ci", ActorRef::User(maker));
            Self {
                maker,
                key_id: *key.id(),
                keys: Arc::new(FakeApiKeyStore::holding(&test_ctx().tenant(), key)),
                events: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn came_with(&self, credential: Credential) -> CallerContext {
            let base = test_ctx();
            CallerContext::new(
                CallerIdentity::TenantUser(self.maker),
                credential,
                base.organization_id(),
                base.tenant_id(),
                OrganizationPlan::Free.default_limits(),
            )
            .unwrap()
            .with_request_metadata(Some(IpAddress::new("203.0.113.7").unwrap()), None)
        }

        fn with_key(&self) -> CallerContext {
            self.came_with(Credential::TenantApiKey(self.key_id))
        }

        fn record(&self, caller: &CallerContext) -> Result<(), AppError> {
            self.record_from(caller, None, UseStamp::Due)
        }

        /// Records a use by `caller` placed in `country`, or nowhere, with
        /// the stamp `stamp`.
        fn record_from(
            &self,
            caller: &CallerContext,
            country: Option<&str>,
            stamp: UseStamp,
        ) -> Result<(), AppError> {
            let use_case = RecordUseUseCase::new(RecordUsePorts {
                key_store: self.keys.clone(),
                geolocator: placing_in(country),
            });
            let auditor = test_auditor(self.events.clone());
            block_on(use_case.execute(caller, &auditor, stamp))
        }

        fn key(&self) -> ApiKey<ResolvedTenant> {
            block_on(self.keys.find_by_id(&test_ctx().tenant(), &self.key_id))
                .unwrap()
                .unwrap()
        }

        fn countries(&self) -> Vec<String> {
            self.key()
                .seen_countries()
                .iter()
                .map(ToString::to_string)
                .collect()
        }

        fn raised(&self) -> usize {
            self.events
                .payloads
                .lock()
                .unwrap()
                .iter()
                .filter(|(kind, _)| kind == NEW_COUNTRY)
                .count()
        }
    }

    /// A geolocator placing every address in `country`, or nowhere.
    fn placing_in(country: Option<&str>) -> Arc<dyn Geolocator> {
        let location = country.map(|code| {
            IpGeolocation::new(10.0, 10.0, CountryCode::new(code).unwrap(), None).unwrap()
        });
        Arc::new(FakeGeolocator { location })
    }

    /// Ann's CI job signs in with her key from 203.0.113.7. The key now
    /// shows it was used just now, from that address.
    #[test]
    fn a_key_request_stamps_the_key_used_from_its_address() {
        let fixture = Fixture::new();
        let caller = fixture.with_key();

        fixture.record(&caller).unwrap();

        let key = fixture.key();
        assert!(key.last_used_at().is_some());
        assert_eq!(
            key.last_used_ip().map(IpAddress::as_str),
            Some("203.0.113.7")
        );
    }

    /// Ann signs in to the dashboard with her session. No key came with the
    /// request, so her key keeps showing it was never used.
    #[test]
    fn a_session_request_stamps_no_key() {
        let fixture = Fixture::new();
        let caller = fixture.came_with(Credential::TenantSession(test_session_id()));

        fixture.record(&caller).unwrap();

        assert!(fixture.key().last_used_at().is_none());
    }

    /// Recording usage for an unknown API-key credential returns not found.
    #[test]
    fn a_key_gone_is_not_found() {
        let fixture = Fixture::new();
        let caller = fixture.came_with(Credential::TenantApiKey(ApiKeyId::new()));

        let result = fixture.record(&caller);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann's deploy key works from Germany, and thirty seconds later a
    /// stolen copy is used from Brazil, while the last stamp is still
    /// recent. Brazil is noted on that first request, and recorded once.
    #[test]
    fn a_new_country_thirty_seconds_after_the_last_stamp_is_recorded_at_once() {
        let fixture = Fixture::new();
        let caller = fixture.with_key();
        fixture
            .record_from(&caller, Some("DE"), UseStamp::Due)
            .unwrap();

        fixture
            .record_from(&caller, Some("BR"), UseStamp::Recent)
            .unwrap();

        assert_eq!(fixture.countries(), ["DE", "BR"]);
        assert_eq!(fixture.raised(), 1);
        assert_eq!(
            fixture.events.payload_of(NEW_COUNTRY).get("country"),
            Some("BR")
        );
    }

    /// The key's first placed use, from Germany, comes while its last
    /// stamp is still recent. Germany is written down anyway, as where the
    /// key lives, and nothing is recorded.
    #[test]
    fn a_key_s_first_country_is_written_even_between_stamps() {
        let fixture = Fixture::new();
        let caller = fixture.with_key();

        fixture
            .record_from(&caller, Some("DE"), UseStamp::Recent)
            .unwrap();

        assert_eq!(fixture.countries(), ["DE"]);
        assert_eq!(fixture.raised(), 0);
    }

    /// The key works from Germany again a moment after its last stamp.
    /// Nothing changed and the stamp is not due, so nothing is written:
    /// the key still shows the time and address of its last stamp.
    #[test]
    fn a_known_country_between_stamps_writes_nothing() {
        let fixture = Fixture::new();
        let caller = fixture.with_key();
        fixture
            .record_from(&caller, Some("DE"), UseStamp::Due)
            .unwrap();
        let stamped = fixture.key().last_used_at();
        let later = fixture
            .came_with(Credential::TenantApiKey(fixture.key_id))
            .with_request_metadata(Some(IpAddress::new("203.0.113.9").unwrap()), None);

        fixture
            .record_from(&later, Some("DE"), UseStamp::Recent)
            .unwrap();

        assert_eq!(fixture.key().last_used_at(), stamped);
        assert_eq!(
            fixture.key().last_used_ip().map(IpAddress::as_str),
            Some("203.0.113.7")
        );
        assert_eq!(fixture.raised(), 0);
    }

    /// Two requests with the stolen copy arrive from Brazil in the same
    /// instant; both read the key knowing only Germany. The first notes
    /// Brazil; the second finds the key changed since it read it, writes
    /// nothing and records nothing, so Brazil is recorded once.
    #[test]
    fn two_uses_from_one_new_country_at_once_record_it_once() {
        let fixture = Fixture::new();
        let caller = fixture.with_key();
        fixture
            .record_from(&caller, Some("DE"), UseStamp::Due)
            .unwrap();
        let as_both_read = FakeApiKeyStore::holding(&test_ctx().tenant(), fixture.key());
        let racing = RecordUseUseCase::new(RecordUsePorts {
            key_store: Arc::new(ReadBeforeWrite::new(as_both_read, fixture.keys.clone())),
            geolocator: placing_in(Some("BR")),
        });
        let auditor = test_auditor(fixture.events.clone());

        let first = block_on(racing.execute(&caller, &auditor, UseStamp::Recent));
        let second = block_on(racing.execute(&caller, &auditor, UseStamp::Recent));

        assert!(first.is_ok() && second.is_ok());
        assert_eq!(fixture.countries(), ["DE", "BR"]);
        assert_eq!(fixture.raised(), 1);
    }

    /// A usage stamp that reads a stale key snapshot but writes after
    /// deletion returns not found and leaves the key absent.
    #[test]
    fn a_stamp_racing_a_revocation_does_not_bring_the_key_back() {
        let fixture = Fixture::new();
        let caller = fixture.with_key();
        let revoked = Arc::new(FakeApiKeyStore::empty());
        let use_case = RecordUseUseCase::new(RecordUsePorts {
            key_store: Arc::new(ReadBeforeWrite::new(
                FakeApiKeyStore::holding(&test_ctx().tenant(), fixture.key()),
                revoked.clone(),
            )),
            geolocator: crate::test_support::Fake::fake(),
        });

        let result = block_on(use_case.execute(
            &caller,
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            UseStamp::Due,
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(revoked.count(), 0);
    }
}
