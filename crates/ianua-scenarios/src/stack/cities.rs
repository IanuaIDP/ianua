//! A small city database in the MaxMind DB format, written by the stack
//! itself for a profile that places its callers, as GeoLite2 City would
//! place real ones.
//!
//! It places three networks from the range set aside for benchmarking
//! (RFC 2544), one in each of [`BERLIN`], [`POZNAN`] and [`SAO_PAULO`], and
//! nothing else. A client standing for an address of one of them arrives
//! from that city; every other address, the documentation addresses
//! clients get by default among them, stays as unknown as with no
//! database at all.

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use super::StackError;
use super::settings::Settings;

/// How many leading bits of an address name a city's network: a `/24`.
const NETWORK_BITS: u32 = 24;

/// The zero bytes between the search tree and the data section.
const SEPARATOR: usize = 16;

/// The bytes that open the metadata at the end of the file.
const METADATA_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";

/// The largest value a 24-bit record holds, plus one.
const RECORD_LIMIT: u32 = 1 << 24;

/// The control byte of a string, its length in the low five bits.
const TEXT: u8 = 0x40;

/// The control byte of a map, its count of entries in the low five bits.
const MAP: u8 = 0xE0;

/// The longest string or map the control byte alone can size.
const SHORT: u8 = 29;

/// A city the database places one network in.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct City {
    name: &'static str,
    country: &'static str,
    latitude: f64,
    longitude: f64,
    network: [u8; 3],
}

impl City {
    /// The address `host` of this city's network, for a client that
    /// stands for someone signing in there.
    #[must_use]
    pub fn address(&self, host: u8) -> IpAddr {
        let [a, b, c] = self.network;
        IpAddr::V4(Ipv4Addr::new(a, b, c, host))
    }

    /// The country it is in, as its ISO code, such as `DE`.
    #[must_use]
    pub fn country(&self) -> &'static str {
        self.country
    }

    /// The first address of its network, as the tree reads it.
    fn network(&self) -> u32 {
        let [a, b, c] = self.network;
        u32::from_be_bytes([a, b, c, 0])
    }
}

/// Berlin, Germany: `198.18.0.0/24`.
pub const BERLIN: City = City {
    name: "Berlin",
    country: "DE",
    latitude: 52.52,
    longitude: 13.405,
    network: [198, 18, 0],
};

/// Poznań, Poland, 240 km east of Berlin: `198.18.1.0/24`. Twenty
/// minutes after a sign-in in Berlin, one here is a journey of about
/// 720 km/h: possible, by plane, but worth a look.
pub const POZNAN: City = City {
    name: "Poznań",
    country: "PL",
    latitude: 52.4064,
    longitude: 16.9252,
    network: [198, 18, 1],
};

/// São Paulo, Brazil: `198.18.2.0/24`.
pub const SAO_PAULO: City = City {
    name: "São Paulo",
    country: "BR",
    latitude: -23.5505,
    longitude: -46.6333,
    network: [198, 18, 2],
};

/// Every city the database places.
const CITIES: [City; 3] = [BERLIN, POZNAN, SAO_PAULO];

/// Writes the database under `files` and points `settings` at it, for the
/// platform and the gateway alike.
///
/// # Errors
///
/// [`StackError::Io`] when the database cannot be written.
pub(crate) fn configure(settings: &mut Settings, files: &Path) -> Result<(), StackError> {
    let path = files.join("cities.mmdb");
    database()
        .and_then(|bytes| std::fs::write(&path, bytes))
        .map_err(|cause| StackError::Io {
            what: "city database",
            cause,
        })?;
    settings.set("GEOIP_DB_PATH", &path.to_string_lossy());
    Ok(())
}

/// The whole database: the search tree, the separator, each city's record
/// and the metadata.
fn database() -> io::Result<Vec<u8>> {
    let mut data = Encoder::default();
    let mut tree = Tree::rooted();
    for city in CITIES {
        tree.insert(city.network(), data.bytes.len());
        data.city(&city)?;
    }
    let mut file = tree.records()?;
    file.extend([0_u8; SEPARATOR]);
    file.extend(data.bytes);
    file.extend_from_slice(METADATA_MARKER);
    file.extend(metadata(tree.nodes.len())?.bytes);
    Ok(file)
}

/// The metadata describing a database of IPv4 addresses with 24-bit
/// records and `node_count` nodes.
fn metadata(node_count: usize) -> io::Result<Encoder> {
    let node_count = u32::try_from(node_count).map_err(io::Error::other)?;
    let mut out = Encoder::default();
    out.map(9)?;
    out.text("binary_format_major_version")?;
    out.uint16(2);
    out.text("binary_format_minor_version")?;
    out.uint16(0);
    out.text("build_epoch")?;
    out.uint64(1_700_000_000);
    out.text("database_type")?;
    out.text("Scenario-City")?;
    out.text("description")?;
    out.map(0)?;
    out.text("ip_version")?;
    out.uint16(4);
    out.text("languages")?;
    out.bytes.extend_from_slice(&[0x00, 0x04]);
    out.text("node_count")?;
    out.uint32(node_count);
    out.text("record_size")?;
    out.uint16(24);
    Ok(out)
}

/// What one side of a node points at.
#[derive(Debug, Clone, Copy)]
enum Branch {
    /// No address below it is placed.
    Empty,
    /// The node at this index.
    Node(usize),
    /// The record at this offset of the data section.
    Data(usize),
}

/// The search tree: from the root, each bit of an address picks a side.
struct Tree {
    nodes: Vec<[Branch; 2]>,
}

impl Tree {
    /// A tree of its root alone, placing nothing.
    fn rooted() -> Self {
        Self {
            nodes: vec![[Branch::Empty; 2]],
        }
    }

    /// Places the `/24` starting at `network` in the record at `data`.
    fn insert(&mut self, network: u32, data: usize) {
        let mut node = 0;
        for depth in 0..NETWORK_BITS - 1 {
            node = self.child(node, side(network, depth));
        }
        self.nodes[node][side(network, NETWORK_BITS - 1)] = Branch::Data(data);
    }

    /// The node on `side` of `node`, made when there is none yet.
    fn child(&mut self, node: usize, side: usize) -> usize {
        if let Branch::Node(next) = self.nodes[node][side] {
            return next;
        }
        let next = self.nodes.len();
        self.nodes.push([Branch::Empty; 2]);
        self.nodes[node][side] = Branch::Node(next);
        next
    }

    /// Every node as two 24-bit records: a node's index, the node count
    /// for nothing, or past it for a record of the data section.
    fn records(&self) -> io::Result<Vec<u8>> {
        let count = self.nodes.len();
        let mut out = Vec::with_capacity(count * 6);
        for branch in self.nodes.iter().flatten() {
            let value = match *branch {
                Branch::Empty => count,
                Branch::Node(next) => next,
                Branch::Data(offset) => count + SEPARATOR + offset,
            };
            out.extend_from_slice(&record(value)?);
        }
        Ok(out)
    }
}

/// The side the bit at `depth` of `network` picks: 0 or 1.
fn side(network: u32, depth: u32) -> usize {
    usize::from((network >> (31 - depth)) & 1 == 1)
}

/// `value` as a 24-bit record, refused when it does not fit.
fn record(value: usize) -> io::Result<[u8; 3]> {
    let value = u32::try_from(value)
        .ok()
        .filter(|value| *value < RECORD_LIMIT)
        .ok_or_else(|| io::Error::other("a record past 24 bits"))?;
    let [_, a, b, c] = value.to_be_bytes();
    Ok([a, b, c])
}

/// Values written one after another in the format's own encoding.
#[derive(Default)]
struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    /// A city's record, shaped as GeoIP2 City shapes one: its English
    /// name, its country's code and its coordinates.
    fn city(&mut self, city: &City) -> io::Result<()> {
        self.map(3)?;
        self.text("city")?;
        self.map(1)?;
        self.text("names")?;
        self.map(1)?;
        self.text("en")?;
        self.text(city.name)?;
        self.text("country")?;
        self.map(1)?;
        self.text("iso_code")?;
        self.text(city.country)?;
        self.text("location")?;
        self.map(2)?;
        self.text("latitude")?;
        self.double(city.latitude);
        self.text("longitude")?;
        self.double(city.longitude);
        Ok(())
    }

    fn text(&mut self, value: &str) -> io::Result<()> {
        self.bytes.push(TEXT | short(value.len())?);
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn map(&mut self, entries: usize) -> io::Result<()> {
        self.bytes.push(MAP | short(entries)?);
        Ok(())
    }

    fn double(&mut self, value: f64) {
        self.bytes.push(0x68);
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn uint16(&mut self, value: u16) {
        self.bytes.push(0xA2);
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn uint32(&mut self, value: u32) {
        self.bytes.push(0xC4);
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn uint64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&[0x08, 0x02]);
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }
}

/// `size` as the low five bits of a control byte, refused when it needs
/// the longer forms this writer does not write.
fn short(size: usize) -> io::Result<u8> {
    u8::try_from(size)
        .ok()
        .filter(|size| *size < SHORT)
        .ok_or_else(|| io::Error::other("a value too long for the short form"))
}

#[cfg(test)]
mod tests {
    use ianua_infra::geo::MmdbGeolocator;

    use super::*;

    /// Where the search for `address` ends in `tree`: the branch it stops
    /// at once no node is left to walk into.
    fn walked(tree: &Tree, address: Ipv4Addr) -> Branch {
        let bits = u32::from(address);
        let mut node = 0;
        for depth in 0..32 {
            let Branch::Node(next) = tree.nodes[node][side(bits, depth)] else {
                return tree.nodes[node][side(bits, depth)];
            };
            node = next;
        }
        Branch::Empty
    }

    /// The written file opens as a city database in the platform's own
    /// geolocator, which refuses any file that is not one.
    #[test]
    fn the_written_file_opens_as_a_city_database() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("cities.mmdb");
        std::fs::write(&path, database().unwrap()).unwrap();

        let opened = MmdbGeolocator::open(&path);

        assert!(opened.is_ok(), "{opened:?}");
    }

    /// An address in Berlin's network walks to Berlin's record, one in
    /// Poznań's to the next, and a documentation address or the network
    /// beside the cities' to nothing.
    #[test]
    fn each_network_walks_to_its_own_record_and_no_other_address_does() {
        let mut tree = Tree::rooted();
        tree.insert(BERLIN.network(), 0);
        tree.insert(POZNAN.network(), 40);

        let berlin = walked(&tree, Ipv4Addr::new(198, 18, 0, 7));
        let poznan = walked(&tree, Ipv4Addr::new(198, 18, 1, 200));
        let beside = walked(&tree, Ipv4Addr::new(198, 18, 3, 1));
        let documentation = walked(&tree, Ipv4Addr::new(192, 0, 2, 10));

        assert!(matches!(berlin, Branch::Data(0)), "{berlin:?}");
        assert!(matches!(poznan, Branch::Data(40)), "{poznan:?}");
        assert!(matches!(beside, Branch::Empty), "{beside:?}");
        assert!(matches!(documentation, Branch::Empty), "{documentation:?}");
    }
}
