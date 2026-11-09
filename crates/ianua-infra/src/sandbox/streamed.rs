//! A run streamed into a sandbox that knows nothing of it beforehand: a
//! pod on Kubernetes, or a container the gate starts.
//!
//! The sandbox is sent one line saying how many bytes of bundle and of the
//! run's own files follow and how long the code may run, then the bundle,
//! then the files: the version's code, the entry script that calls it, and
//! the input. Its start-up script reads that line, then exactly those
//! bytes, so it never waits on an end of input that may not be passed on,
//! unpacks them into `/sandbox`, and runs the code there under `timeout`.

use flate2::Compression;
use flate2::write::GzEncoder;

use crate::sandbox::entry::{ENTRY_FOLDER, Entry, MOUNTED_AT};

/// The file the run's input is written to, beside the entry script.
const INPUT_FILE: &str = "input.json";

/// The most bytes of a run's own files: its code, its entry and its input,
/// packed, with room to spare.
pub(super) const MAX_RUN_FILES_BYTES: u64 = 8 * 1024 * 1024;

/// The code, its entry and `input`, as one gzipped tar laid out as the
/// sandbox's `/sandbox` holds them.
///
/// # Errors
///
/// When the archive cannot be written, which in memory it always can.
pub(super) fn run_files(entry: &Entry, code: &str, input: &str) -> std::io::Result<Vec<u8>> {
    let mut archive = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
    for (path, body) in [
        (entry.code_file.to_owned(), code),
        (format!("{ENTRY_FOLDER}/{}", entry.entry_file), entry.script),
        (format!("{ENTRY_FOLDER}/{INPUT_FILE}"), input),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(u64::try_from(body.len()).unwrap_or(u64::MAX));
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_entry_type(tar::EntryType::Regular);
        archive.append_data(&mut header, path, body.as_bytes())?;
    }
    archive.into_inner()?.finish()
}

/// The word a header line holds for a run that reaches no network.
const NO_PROXY: &str = "-";

/// What a header line tells a sandbox about its run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Header {
    /// How many bytes of bundle follow.
    pub(super) bundle_bytes: u64,
    /// How many bytes of the run's own files follow them.
    pub(super) files_bytes: u64,
    /// How long the code may run.
    pub(super) seconds: u32,
    /// The network filter the code reaches its hosts through, its ticket
    /// in it; `None` when it reaches no network.
    pub(super) proxy: Option<String>,
}

impl Header {
    /// The first line a sandbox is sent.
    pub(super) fn line(&self) -> String {
        format!(
            "{} {} {} {}\n",
            self.bundle_bytes,
            self.files_bytes,
            self.seconds,
            self.proxy.as_deref().unwrap_or(NO_PROXY)
        )
    }

    /// The header `line` names, without its end: a proxy is only ever an
    /// `http` address, so the line holds nothing the script would run.
    pub(super) fn read(line: &str) -> Option<Self> {
        let mut words = line.split(' ');
        let bundle_bytes = words.next()?.parse().ok()?;
        let files_bytes = words.next()?.parse().ok()?;
        let seconds = words.next()?.parse().ok()?;
        let proxy = match words.next()? {
            NO_PROXY => None,
            proxy if is_proxy_address(proxy) => Some(proxy.to_owned()),
            _ => return None,
        };
        words.next().is_none().then_some(Self {
            bundle_bytes,
            files_bytes,
            seconds,
            proxy,
        })
    }
}

/// Whether `proxy` is an `http` address of letters, digits and the few
/// marks a ticket and an address hold, so the script reads it as one word.
pub(super) fn is_proxy_address(proxy: &str) -> bool {
    proxy.starts_with("http://")
        && proxy.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b':' | b'/' | b'@' | b'.' | b'-' | b'_' | b'[' | b']')
        })
}

/// The exit status of a sandbox sent no header line: nothing ran, as a
/// container command reports a container it could not start.
const NO_HEADER: u8 = 125;

/// The script a sandbox starts with: the header line, then the bundle and
/// the run's files, each read to its exact length and unpacked, then the
/// code run on its input under `timeout`. Each step runs only when the one
/// before it succeeded.
pub(super) fn start_script(entry: &Entry) -> String {
    let steps = [
        read_header_step(),
        proxy_step(),
        unpack_step("$bundle"),
        unpack_step("$files"),
        run_step(entry),
    ];
    steps.join(" && ")
}

/// Reads the header line into `bundle`, `files`, `seconds` and `proxy`, or
/// ends the sandbox as not started.
fn read_header_step() -> String {
    format!("read -r bundle files seconds proxy || exit {NO_HEADER}")
}

/// Makes the network filter the code's proxy, when the run reaches the
/// network; Node uses it only when told to.
fn proxy_step() -> String {
    format!(
        "{{ [ \"$proxy\" = \"{NO_PROXY}\" ] || export HTTPS_PROXY=\"$proxy\" https_proxy=\"$proxy\" NODE_USE_ENV_PROXY=1; }}"
    )
}

/// Reads exactly `length` bytes, a gzipped tar, and unpacks them into the
/// sandbox's folder.
fn unpack_step(length: &str) -> String {
    format!("head -c \"{length}\" | tar -xzf - -C {MOUNTED_AT}")
}

/// Runs the entry script on the input file, stopped at `seconds` and
/// killed two seconds after.
fn run_step(entry: &Entry) -> String {
    let folder = format!("{MOUNTED_AT}/{ENTRY_FOLDER}");
    let script = format!("{folder}/{}", entry.entry_file);
    let input = format!("{folder}/{INPUT_FILE}");
    format!(
        "exec timeout -k 2 \"$seconds\" {} {script} < {input}",
        entry.interpreter
    )
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;

    use ianua_domain::domains::workflows::sandbox::runtime::Runtime;

    use super::*;
    use crate::sandbox::entry::entry_of;

    /// The archive holds the code, the entry script and the input at the
    /// paths the start-up script runs them from.
    #[test]
    fn the_files_sit_where_the_sandbox_runs_them() {
        let entry = entry_of(Runtime::Python313);

        let packed = run_files(&entry, "def main(i):\n\treturn i\n", r#"{"a":1}"#).unwrap();

        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(packed.as_slice()));
        let mut found = Vec::new();
        for file in archive.entries().unwrap() {
            let mut file = file.unwrap();
            let path = file.path().unwrap().display().to_string();
            let mut body = String::new();
            file.read_to_string(&mut body).unwrap();
            found.push((path, body));
        }
        assert_eq!(
            found[0],
            (
                "main.py".to_owned(),
                "def main(i):\n\treturn i\n".to_owned()
            )
        );
        assert_eq!(found[1].0, ".ianua/run.py");
        assert_eq!(
            found[2],
            (".ianua/input.json".to_owned(), r#"{"a":1}"#.to_owned())
        );
    }

    /// The sandbox knows nothing of its run: its script reads the sizes
    /// and the time from its first line, then each archive to its exact
    /// length, then runs the code, each step only after the one before.
    #[test]
    fn the_script_runs_its_steps_in_order() {
        let entry = entry_of(Runtime::Python313);

        let script = start_script(&entry);

        assert_eq!(
            script,
            [
                read_header_step(),
                proxy_step(),
                unpack_step("$bundle"),
                unpack_step("$files"),
                run_step(&entry),
            ]
            .join(" && ")
        );
    }

    /// With no header line the sandbox ends as not started, before it
    /// reads anything else.
    #[test]
    fn no_header_ends_the_sandbox_as_not_started() {
        assert_eq!(
            read_header_step(),
            "read -r bundle files seconds proxy || exit 125"
        );
    }

    /// The filter becomes the code's proxy only when the run has one, and
    /// the step succeeds either way, so the run goes on.
    #[test]
    fn the_proxy_is_set_only_for_a_run_reaching_the_network() {
        assert_eq!(
            proxy_step(),
            "{ [ \"$proxy\" = \"-\" ] || export HTTPS_PROXY=\"$proxy\" https_proxy=\"$proxy\" NODE_USE_ENV_PROXY=1; }"
        );
    }

    /// A header reads back as it was written, with or without a proxy.
    #[test]
    fn a_header_reads_back() {
        let closed = Header {
            bundle_bytes: 4096,
            files_bytes: 512,
            seconds: 30,
            proxy: None,
        };
        let proxied = Header {
            proxy: Some("http://run:abc.def_-1@172.31.0.2:3128".to_owned()),
            ..closed.clone()
        };

        assert_eq!(closed.line(), "4096 512 30 -\n");
        assert_eq!(Header::read(closed.line().trim_end()), Some(closed));
        assert_eq!(Header::read(proxied.line().trim_end()), Some(proxied));
    }

    /// Header parsing rejects missing or extra fields, negative lengths and
    /// proxy values with an unsupported scheme or shell syntax.
    #[test]
    fn only_a_whole_header_reads_back() {
        for refused in [
            "4096 512 30",
            "4096 512 30 - 1",
            "4096 -512 30 -",
            "4096 512 30 ftp://x",
            "4096 512 30 http://x;reboot",
            "4096 512 30 http://$(id)",
        ] {
            assert_eq!(Header::read(refused), None, "{refused} was read");
        }
    }

    /// Each archive is read to the length its header named and unpacked
    /// into the sandbox.
    #[test]
    fn an_archive_is_read_to_its_length() {
        assert_eq!(
            unpack_step("$bundle"),
            "head -c \"$bundle\" | tar -xzf - -C /sandbox"
        );
    }

    /// The code runs on its input under `timeout`, killed two seconds past
    /// its limit.
    #[test]
    fn the_code_runs_on_its_input_under_its_limit() {
        assert_eq!(
            run_step(&entry_of(Runtime::Python313)),
            "exec timeout -k 2 \"$seconds\" python3 /sandbox/.ianua/run.py < /sandbox/.ianua/input.json"
        );
    }
}
