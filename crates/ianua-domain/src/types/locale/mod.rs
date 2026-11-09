/// Supported BCP 47 locale tags.
pub mod code;
/// ISO 3166-1 alpha-2 country codes.
pub mod country_code;
/// Supported IANA timezone names.
pub mod timezone;

pub use code::Locale;
pub use country_code::CountryCode;
pub use timezone::Timezone;
