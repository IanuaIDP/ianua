//! Where a person signed in from, as its rows hold it: one row per country,
//! read back into the history through each value's own constructor.

use ianua_domain::domains::authentication::risk_engine::assessment::IpGeolocation;
use ianua_domain::domains::authentication::risk_engine::history::SignInHistory;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{CountryCode, Fact};
use time::OffsetDateTime;

use crate::postgres::foundation::stored::Stored;

const SIGN_IN: Stored = Stored("sign-in place");

/// One country signed in from, as it is read. The store's checked query
/// fills it.
pub(super) struct CountryRecord {
    pub(super) country_code: String,
    pub(super) latitude: f64,
    pub(super) longitude: f64,
    pub(super) city: Option<String>,
    pub(super) signed_in_at: OffsetDateTime,
}

impl CountryRecord {
    /// The place and time of the latest sign-in from the country.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the code is no country,
    /// or the place is not on the globe.
    fn into_place(self) -> Result<(IpGeolocation, OffsetDateTime), DomainError> {
        let country = SIGN_IN.value("country code", CountryCode::new(self.country_code))?;
        let place = IpGeolocation::new(self.latitude, self.longitude, country, self.city)
            .map_err(|_| DomainError::corrupt_row(SIGN_IN.0, "a place not on the globe"))?;
        Ok((place, self.signed_in_at))
    }
}

/// The history `records`, the latest sign-in first, hold.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` for the first row that does not
/// read back.
pub(super) fn history_from(records: Vec<CountryRecord>) -> Result<SignInHistory, DomainError> {
    let places = records
        .into_iter()
        .map(CountryRecord::into_place)
        .collect::<Result<Vec<_>, _>>()?;
    let countries = places
        .iter()
        .map(|(place, _)| place.country_code().clone())
        .collect();
    let last = places.into_iter().next();
    Ok(SignInHistory::new(countries, Fact::from_option(last)))
}
