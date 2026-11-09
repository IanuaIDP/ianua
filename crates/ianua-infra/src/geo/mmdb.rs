//! Where an address is, read from a city database in the MaxMind DB
//! format (GeoLite2 City, GeoIP2 City, or any database of that shape) that
//! the server names. Nothing goes out over the network: the whole file is
//! read into memory once and every lookup is a walk of its tree.
//!
//! An address the database does not place, places without coordinates,
//! or places in no country the standard lists is answered as unknown,
//! never as a guess: a made-up location at the equator would read as a
//! journey across the globe to the risk checks.

use std::net::IpAddr;
use std::path::Path;

use async_trait::async_trait;
use ianua_app::ports::authentication::Geolocator;
use ianua_domain::domains::authentication::risk_engine::assessment::IpGeolocation;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{CountryCode, IpAddress};
use maxminddb::Reader;
use maxminddb::geoip2::City;

/// A geolocator over a city database file.
pub struct MmdbGeolocator {
    reader: Reader<Vec<u8>>,
}

impl MmdbGeolocator {
    /// Reads the database at `path` into memory.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the file cannot be read
    /// or is not a database of this format.
    pub fn open(path: &Path) -> Result<Self, DomainError> {
        let reader = Reader::open_readfile(path).map_err(DomainError::infra)?;
        Ok(Self { reader })
    }

    /// Whether this database cannot hold `address` at all: an IPv6
    /// address asked of a database of IPv4 addresses only.
    fn cannot_hold(&self, address: IpAddr) -> bool {
        address.is_ipv6() && self.reader.metadata.ip_version == 4
    }
}

impl std::fmt::Debug for MmdbGeolocator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MmdbGeolocator")
            .field("database", &self.reader.metadata.database_type)
            .finish_non_exhaustive()
    }
}

/// The location `record` gives, or none when it lacks coordinates or a
/// listed country.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when its coordinates lie off the
/// globe, which only a broken database holds.
fn located(record: &City<'_>) -> Result<Option<IpGeolocation>, DomainError> {
    let (Some(latitude), Some(longitude)) = (record.location.latitude, record.location.longitude)
    else {
        return Ok(None);
    };
    let Some(country) = record
        .country
        .iso_code
        .and_then(|code| CountryCode::new(code).ok())
    else {
        return Ok(None);
    };
    let city = record.city.names.english.map(str::to_owned);
    IpGeolocation::new(latitude, longitude, country, city)
        .map(Some)
        .map_err(DomainError::infra)
}

#[async_trait]
impl Geolocator for MmdbGeolocator {
    async fn locate(&self, ip: &IpAddress) -> Result<Option<IpGeolocation>, DomainError> {
        let address: IpAddr = ip.as_str().parse().map_err(DomainError::infra)?;
        if self.cannot_hold(address) {
            return Ok(None);
        }
        let found = self.reader.lookup(address).map_err(DomainError::infra)?;
        let Some(record) = found.decode::<City<'_>>().map_err(DomainError::infra)? else {
            return Ok(None);
        };
        located(&record)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    /// A string, as the database format writes one shorter than 29 bytes.
    fn text(value: &str) -> Vec<u8> {
        let mut out = vec![0x40 | u8::try_from(value.len()).unwrap()];
        out.extend_from_slice(value.as_bytes());
        out
    }

    fn double(value: f64) -> Vec<u8> {
        let mut out = vec![0x68];
        out.extend_from_slice(&value.to_be_bytes());
        out
    }

    fn short(value: u16) -> Vec<u8> {
        let mut out = vec![0xA2];
        out.extend_from_slice(&value.to_be_bytes());
        out
    }

    fn long(value: u32) -> Vec<u8> {
        let mut out = vec![0xC4];
        out.extend_from_slice(&value.to_be_bytes());
        out
    }

    fn longest(value: u64) -> Vec<u8> {
        let mut out = vec![0x08, 0x02];
        out.extend_from_slice(&value.to_be_bytes());
        out
    }

    fn map(pairs: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
        let mut out = vec![0xE0 | u8::try_from(pairs.len()).unwrap()];
        for (key, value) in pairs {
            out.extend(text(key));
            out.extend(value);
        }
        out
    }

    fn empty_list() -> Vec<u8> {
        vec![0x00, 0x04]
    }

    fn record(at: u32) -> [u8; 3] {
        let bytes = at.to_be_bytes();
        [bytes[1], bytes[2], bytes[3]]
    }

    /// Tokyo, in Japan, with its coordinates.
    fn tokyo() -> Vec<u8> {
        map(vec![
            (
                "city",
                map(vec![("names", map(vec![("en", text("Tokyo"))]))]),
            ),
            ("country", map(vec![("iso_code", text("JP"))])),
            (
                "location",
                map(vec![
                    ("latitude", double(35.6895)),
                    ("longitude", double(139.6917)),
                ]),
            ),
        ])
    }

    /// A country with no coordinates.
    fn germany_without_coordinates() -> Vec<u8> {
        map(vec![("country", map(vec![("iso_code", text("DE"))]))])
    }

    /// A tiny IPv4 city database: `0.0.0.0/2` is Tokyo, `64.0.0.0/2` is
    /// Germany without coordinates, and `128.0.0.0/1` is not in it.
    fn tiny_database() -> Vec<u8> {
        let first = tokyo();
        let second = germany_without_coordinates();
        let node_count: u32 = 2;
        let data_start = node_count + 16;
        let mut file = Vec::new();
        file.extend(record(1));
        file.extend(record(node_count));
        file.extend(record(data_start));
        file.extend(record(data_start + u32::try_from(first.len()).unwrap()));
        file.extend([0_u8; 16]);
        file.extend(first);
        file.extend(second);
        file.extend(b"\xab\xcd\xefMaxMind.com");
        file.extend(map(vec![
            ("binary_format_major_version", short(2)),
            ("binary_format_minor_version", short(0)),
            ("build_epoch", longest(1_700_000_000)),
            ("database_type", text("Test-City")),
            ("description", map(Vec::new())),
            ("ip_version", short(4)),
            ("languages", empty_list()),
            ("node_count", long(node_count)),
            ("record_size", short(24)),
        ]));
        file
    }

    fn geolocator() -> MmdbGeolocator {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&tiny_database()).unwrap();
        MmdbGeolocator::open(file.path()).unwrap()
    }

    fn address(text: &str) -> IpAddress {
        IpAddress::new(text).unwrap()
    }

    /// An address the database places in Tokyo is located there, with the
    /// city's name and coordinates.
    #[tokio::test]
    async fn an_address_in_the_database_is_located() {
        let geolocator = geolocator();

        let found = geolocator
            .locate(&address("1.2.3.4"))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(found.country_code().as_str(), "JP");
        assert_eq!(found.city(), Some("Tokyo"));
        assert!((found.latitude() - 35.6895).abs() < 1e-9);
        assert!((found.longitude() - 139.6917).abs() < 1e-9);
    }

    /// An address mapped to a country without coordinates returns no location.
    #[tokio::test]
    async fn an_address_without_coordinates_is_unknown() {
        let geolocator = geolocator();

        let found = geolocator.locate(&address("100.1.1.1")).await.unwrap();

        assert!(found.is_none());
    }

    /// An address the database does not hold is unknown.
    #[tokio::test]
    async fn an_address_not_in_the_database_is_unknown() {
        let geolocator = geolocator();

        let found = geolocator.locate(&address("200.1.1.1")).await.unwrap();

        assert!(found.is_none());
    }

    /// An IPv6 address asked of a database of IPv4 addresses is unknown,
    /// not an error.
    #[tokio::test]
    async fn an_ipv6_address_in_an_ipv4_database_is_unknown() {
        let geolocator = geolocator();

        let found = geolocator.locate(&address("2001:db8::1")).await.unwrap();

        assert!(found.is_none());
    }

    /// A file that is not a database is refused when it is opened, not at
    /// the first sign-in.
    #[test]
    fn a_file_that_is_not_a_database_is_refused() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"not a database").unwrap();

        let opened = MmdbGeolocator::open(file.path());

        assert!(matches!(opened, Err(DomainError::Infrastructure(_))));
    }
}
