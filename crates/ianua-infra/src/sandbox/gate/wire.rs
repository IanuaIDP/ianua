//! What the worker and the gate say to each other over the gate's socket.
//!
//! The worker asks with one line naming the runtime, the exact image and
//! the run's limits, then sends the run as a pod would get it: the header
//! line, the bundle and the run's own files. For a company's image it asks
//! with a line naming the image and the limits, then a line with the
//! input's length and the proxy, a line with the registry login the gate
//! pulls with, and the input itself. The gate answers once, after the run:
//! how the code exited, its answer and the end of its errors, why no
//! container ran, or why the image could not be pulled.

use ianua_domain::domains::workflows::data::MAX_SIZE;
use ianua_domain::domains::workflows::sandbox::image::PinnedImage;
use ianua_domain::domains::workflows::sandbox::recipe::RunBudget;
use ianua_domain::domains::workflows::sandbox::runtime::{Runtime, RuntimeImage};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWrite,
    AsyncWriteExt as _,
};

use crate::sandbox::output::{ERRORS_HELD, Exit, Memory};
use crate::sandbox::streamed::is_proxy_address;

/// The most bytes of one line either side reads.
pub(super) const MAX_LINE: usize = 512;

/// The most bytes of a reason no container ran.
const MAX_REASON: usize = 4096;

/// The word an ask starts with.
const ASK: &str = "ask";

/// The word an ask for a company's image starts with.
pub(super) const IMAGE: &str = "image";

/// The most bytes of the line holding a registry login.
pub(super) const MAX_LOGIN_LINE: usize = 4096;

/// Whether the run asked for reaches the network filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Reach {
    /// No network at all.
    Closed,
    /// The network filter alone.
    Proxied,
}

/// The word a line holds for no proxy or no login.
pub(super) const NONE: &str = "-";

impl Reach {
    /// The word an ask holds for it.
    fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Proxied => "proxied",
        }
    }

    /// The reach `word` names.
    fn parse(word: &str) -> Option<Self> {
        match word {
            "closed" => Some(Self::Closed),
            "proxied" => Some(Self::Proxied),
            _ => None,
        }
    }
}

/// What the worker asks the gate to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Ask {
    /// The runtime that starts the code.
    pub(super) runtime: Runtime,
    /// The exact image it runs in.
    pub(super) image: RuntimeImage,
    /// How long it may run and the memory it is given.
    pub(super) budget: RunBudget,
    /// Whether it reaches the network filter.
    pub(super) reach: Reach,
}

impl Ask {
    /// The line that asks for this run.
    pub(super) fn line(&self) -> String {
        format!(
            "{ASK} {} {} {} {} {}\n",
            self.runtime.as_str(),
            self.image.as_str(),
            self.budget.seconds(),
            self.budget.memory_mib(),
            self.reach.as_str()
        )
    }

    /// The run `line` asks for, without its end, each part checked as a
    /// version's is.
    ///
    /// # Errors
    ///
    /// Why the line asks for no run the gate may start.
    pub(super) fn read(line: &str) -> Result<Self, String> {
        let words: Vec<&str> = line.split(' ').collect();
        let [ASK, runtime, image, seconds, memory, reach] = words.as_slice() else {
            return Err("the ask is not one".to_owned());
        };
        let reach = Reach::parse(reach).ok_or("the network asked for is not one")?;
        let runtime = Runtime::parse(runtime).map_err(|_| "the runtime is not one".to_owned())?;
        let image = RuntimeImage::new(*image)
            .map_err(|_| "the image is not named by its content".to_owned())?;
        let seconds = seconds.parse().map_err(|_| "the time limit is no number")?;
        let memory = memory.parse().map_err(|_| "the memory is no number")?;
        let budget = RunBudget::new(seconds, memory)
            .map_err(|_| "the limits are outside what a version may have".to_owned())?;
        Ok(Self {
            runtime,
            image,
            budget,
            reach,
        })
    }
}

/// What the worker asks the gate to run of a company's image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ImageAsk {
    /// The image, pinned to its digest.
    pub(super) image: PinnedImage,
    /// How long it may run and the memory it is given.
    pub(super) budget: RunBudget,
    /// Whether it reaches the network filter.
    pub(super) reach: Reach,
}

impl ImageAsk {
    /// The line that asks for this run.
    pub(super) fn line(&self) -> String {
        format!(
            "{IMAGE} {} {} {} {}\n",
            self.image.as_str(),
            self.budget.seconds(),
            self.budget.memory_mib(),
            self.reach.as_str()
        )
    }

    /// The run `line` asks for, without its end, each part checked as a
    /// version's is.
    ///
    /// # Errors
    ///
    /// Why the line asks for no run the gate may start.
    pub(super) fn read(line: &str) -> Result<Self, String> {
        let words: Vec<&str> = line.split(' ').collect();
        let [IMAGE, image, seconds, memory, reach] = words.as_slice() else {
            return Err("the ask is not one".to_owned());
        };
        let reach = Reach::parse(reach).ok_or("the network asked for is not one")?;
        let image = PinnedImage::parse(image)
            .map_err(|_| "the image is not pinned to its digest".to_owned())?;
        let seconds = seconds.parse().map_err(|_| "the time limit is no number")?;
        let memory = memory.parse().map_err(|_| "the memory is no number")?;
        let budget = RunBudget::new(seconds, memory)
            .map_err(|_| "the limits are outside what a version may have".to_owned())?;
        Ok(Self {
            image,
            budget,
            reach,
        })
    }
}

/// What follows an image's ask: the input's length and the proxy, then the
/// registry login the gate pulls with, as Docker's `X-Registry-Auth` value.
/// The login is never printed.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct ImageRun {
    /// How many bytes of input follow.
    pub(super) input_bytes: u64,
    /// The network filter, its ticket in it; `None` for no network.
    pub(super) proxy: Option<String>,
    /// The registry login, encoded for the engine; `None` for none.
    pub(super) login: Option<String>,
}

impl ImageRun {
    /// The two lines that follow the ask.
    pub(super) fn lines(&self) -> String {
        format!(
            "{} {}\n{}\n",
            self.input_bytes,
            self.proxy.as_deref().unwrap_or(NONE),
            self.login.as_deref().unwrap_or(NONE)
        )
    }

    /// The run `sizes` and `login`, the two lines after the ask without
    /// their ends, name: a proxy only ever an `http` address, a login only
    /// URL-safe base64, so neither reaches the engine as anything else.
    ///
    /// # Errors
    ///
    /// Why the lines name no run.
    pub(super) fn read(sizes: &str, login: &str) -> Result<Self, String> {
        let (bytes, proxy) = sizes
            .split_once(' ')
            .ok_or("the run's sizes are not given")?;
        let input_bytes: u64 = bytes
            .parse()
            .map_err(|_| "the input's length is no number")?;
        if input_bytes > u64::try_from(MAX_SIZE).unwrap_or(u64::MAX) {
            return Err("the input is larger than workflow data may be".to_owned());
        }
        let proxy = match proxy {
            NONE => None,
            proxy if is_proxy_address(proxy) => Some(proxy.to_owned()),
            _ => return Err("the proxy is not one".to_owned()),
        };
        let login = match login {
            NONE => None,
            login if is_url_safe_base64(login) => Some(login.to_owned()),
            _ => return Err("the registry login is not one".to_owned()),
        };
        Ok(Self {
            input_bytes,
            proxy,
            login,
        })
    }
}

impl std::fmt::Debug for ImageRun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageRun")
            .field("input_bytes", &self.input_bytes)
            .field("proxy", &self.proxy.as_ref().map(|_| "<redacted>"))
            .field("login", &self.login.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Whether `text` holds only URL-safe base64.
fn is_url_safe_base64(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'='))
}

/// What the gate answers.
pub(super) enum Answer {
    /// The container ran, and exited so.
    Ran(Exit),
    /// No container ran, for this reason.
    NotStarted(String),
    /// The company's image could not be pulled, for this reason; it is not
    /// tried again.
    Unpulled(String),
}

/// The next line of `reader`, without its end, read a byte at a time so
/// nothing after it is taken; `None` when it is longer than `most` bytes,
/// is not text, or the stream ends first.
pub(super) async fn line_of(
    reader: &mut (impl AsyncBufRead + Unpin),
    most: usize,
) -> std::io::Result<Option<String>> {
    let mut line = Vec::new();
    let read = (&mut *reader)
        .take(u64::try_from(most).unwrap_or(u64::MAX).saturating_add(1))
        .read_until(b'\n', &mut line)
        .await?;
    if read == 0 || line.pop() != Some(b'\n') {
        return Ok(None);
    }
    Ok(String::from_utf8(line).ok())
}

/// Writes `answer` to `writer`.
pub(super) async fn write_answer(
    writer: &mut (impl AsyncWrite + Unpin),
    answer: &Answer,
) -> std::io::Result<()> {
    match answer {
        Answer::Ran(exit) => write_exit(writer, exit).await?,
        Answer::NotStarted(why) => write_reason(writer, b'N', why).await?,
        Answer::Unpulled(why) => write_reason(writer, b'P', why).await?,
    }
    writer.flush().await
}

/// Writes how a run ended: `R`, its status when it has one, whether it ran
/// out of memory, and what it wrote.
async fn write_exit(writer: &mut (impl AsyncWrite + Unpin), exit: &Exit) -> std::io::Result<()> {
    writer.write_u8(b'R').await?;
    writer.write_u8(u8::from(exit.status.is_some())).await?;
    writer.write_i32(exit.status.unwrap_or(0)).await?;
    writer
        .write_u8(u8::from(exit.memory == Memory::OverItsLimit))
        .await?;
    write_part(writer, &exit.answer).await?;
    write_part(writer, &exit.errors).await
}

/// Writes an answer with no run: its `tag` and why.
async fn write_reason(
    writer: &mut (impl AsyncWrite + Unpin),
    tag: u8,
    why: &str,
) -> std::io::Result<()> {
    writer.write_u8(tag).await?;
    write_part(writer, why.as_bytes()).await
}

/// How a run ended, as `write_exit` wrote it after its `R`.
async fn read_exit(reader: &mut (impl AsyncRead + Unpin)) -> std::io::Result<Exit> {
    let has_status = reader.read_u8().await? == 1;
    let status = reader.read_i32().await?;
    let memory = match reader.read_u8().await? {
        1 => Memory::OverItsLimit,
        _ => Memory::WithinItsLimit,
    };
    let answer = read_part(reader, MAX_SIZE.saturating_add(1)).await?;
    let errors = read_part(reader, ERRORS_HELD).await?;
    Ok(Exit {
        status: has_status.then_some(status),
        answer,
        errors,
        memory,
    })
}

/// Why no run happened, as `write_reason` wrote it after its tag.
async fn read_reason(reader: &mut (impl AsyncRead + Unpin)) -> std::io::Result<String> {
    let why = read_part(reader, MAX_REASON).await?;
    Ok(String::from_utf8_lossy(&why).into_owned())
}

/// The answer `reader` holds, each part within what it may be, read
/// without taking anything after it.
///
/// # Errors
///
/// When the stream ends early, or holds no answer or a part too long.
pub(super) async fn read_answer(mut reader: impl AsyncRead + Unpin) -> std::io::Result<Answer> {
    match reader.read_u8().await? {
        b'R' => Ok(Answer::Ran(read_exit(&mut reader).await?)),
        b'N' => Ok(Answer::NotStarted(read_reason(&mut reader).await?)),
        b'P' => Ok(Answer::Unpulled(read_reason(&mut reader).await?)),
        _ => Err(unreadable("the gate gave no answer")),
    }
}

/// Writes `part` after its length.
async fn write_part(writer: &mut (impl AsyncWrite + Unpin), part: &[u8]) -> std::io::Result<()> {
    let length = u32::try_from(part.len()).map_err(|_| unreadable("a part is too long"))?;
    writer.write_u32(length).await?;
    writer.write_all(part).await
}

/// The part `reader` holds next, refused when longer than `most`.
async fn read_part(reader: &mut (impl AsyncRead + Unpin), most: usize) -> std::io::Result<Vec<u8>> {
    let length = usize::try_from(reader.read_u32().await?).unwrap_or(usize::MAX);
    if length > most {
        return Err(unreadable("a part of the gate's answer is too long"));
    }
    let mut part = vec![0; length];
    reader.read_exact(&mut part).await?;
    Ok(part)
}

/// An answer that cannot be read, for `why`.
fn unreadable(why: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, why)
}

#[cfg(test)]
mod tests {
    use tokio::io::BufReader;

    use super::*;

    const IMAGE: &str =
        "python:3.13-slim@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1";

    fn ask() -> Ask {
        Ask {
            runtime: Runtime::Python313,
            image: RuntimeImage::new(IMAGE).unwrap(),
            budget: RunBudget::new(20, 128).unwrap(),
            reach: Reach::Proxied,
        }
    }

    /// An ask reads back as it was written.
    #[test]
    fn an_ask_reads_back() {
        let line = ask().line();

        assert_eq!(Ask::read(line.trim_end()).unwrap(), ask());
    }

    /// Run requests reject unpinned images, unknown runtimes or network modes,
    /// excessive time limits and extra arguments.
    #[test]
    fn an_ask_outside_what_a_version_may_have_is_refused() {
        for refused in [
            "ask python-3.13 python:3.13-slim 20 128 closed".to_owned(),
            format!("ask ruby-3.3 {IMAGE} 20 128 closed"),
            format!("ask python-3.13 {IMAGE} 3600 128 closed"),
            format!("ask python-3.13 {IMAGE} 20 128 host"),
            format!("ask python-3.13 {IMAGE} 20 128 closed --privileged"),
        ] {
            assert!(Ask::read(&refused).is_err(), "{refused} was taken");
        }
    }

    /// A line longer than allowed reads as none, and what follows a line is
    /// left in the stream.
    #[tokio::test]
    async fn a_line_is_read_within_its_bound() {
        let mut short = BufReader::new(&b"4096 512 30\nrest"[..]);
        let mut long = BufReader::new(&b"0123456789\n"[..]);

        let line = line_of(&mut short, 64).await.unwrap();
        let mut rest = String::new();
        short.read_to_string(&mut rest).await.unwrap();

        assert_eq!(line.as_deref(), Some("4096 512 30"));
        assert_eq!(rest, "rest");
        assert_eq!(line_of(&mut long, 4).await.unwrap(), None);
    }

    /// An answer reads back as it was written: a run's exit, and a reason
    /// no container ran.
    #[tokio::test]
    async fn an_answer_reads_back() {
        let ran = Answer::Ran(Exit {
            status: Some(137),
            answer: b"{}".to_vec(),
            errors: b"Killed".to_vec(),
            memory: Memory::OverItsLimit,
        });
        let mut written = Vec::new();
        write_answer(&mut written, &ran).await.unwrap();
        write_answer(&mut written, &Answer::NotStarted("no image".to_owned()))
            .await
            .unwrap();
        let mut reader = written.as_slice();

        let Answer::Ran(exit) = read_answer(&mut reader).await.unwrap() else {
            panic!("no run was read");
        };
        let Answer::NotStarted(why) = read_answer(&mut reader).await.unwrap() else {
            panic!("no refusal was read");
        };

        assert_eq!(exit.status, Some(137));
        assert_eq!(exit.memory, Memory::OverItsLimit);
        assert_eq!(
            (exit.answer, exit.errors),
            (b"{}".to_vec(), b"Killed".to_vec())
        );
        assert_eq!(why, "no image");
    }

    fn image_ask() -> ImageAsk {
        ImageAsk {
            image: PinnedImage::parse(&format!(
                "registry.acme.example/codegen@sha256:{}",
                "ab".repeat(32)
            ))
            .unwrap(),
            budget: RunBudget::new(60, 512).unwrap(),
            reach: Reach::Closed,
        }
    }

    /// An image's ask and the lines after it read back as written.
    #[test]
    fn an_image_ask_reads_back() {
        let run = ImageRun {
            input_bytes: 17,
            proxy: Some("http://run:t@10.0.0.2:3128".to_owned()),
            login: Some("eyJ1c2VybmFtZSI6InJvYm90In0=".to_owned()),
        };
        let lines = run.lines();
        let (sizes, login) = lines.trim_end().split_once('\n').unwrap();

        assert_eq!(
            ImageAsk::read(image_ask().line().trim_end()).unwrap(),
            image_ask()
        );
        assert_eq!(ImageRun::read(sizes, login).unwrap(), run);
    }

    /// An image named by a tag, a login that is not base64, a proxy that
    /// is not an address, and input past workflow data's size are refused.
    #[test]
    fn an_image_run_outside_its_bounds_is_refused() {
        let too_large = format!("{} -", MAX_SIZE + 1);

        assert!(ImageAsk::read("image registry.acme.example/codegen:1.4 60 512 closed").is_err());
        assert!(ImageRun::read("17 -", "a\r\nX-Evil: 1").is_err());
        assert!(ImageRun::read("17 file:///etc", "-").is_err());
        assert!(ImageRun::read(&too_large, "-").is_err());
    }

    /// A pull that failed is answered apart from a run that did not start.
    #[tokio::test]
    async fn an_unpulled_image_reads_back() {
        let mut written = Vec::new();
        write_answer(
            &mut written,
            &Answer::Unpulled("manifest unknown".to_owned()),
        )
        .await
        .unwrap();

        let read = read_answer(written.as_slice()).await.unwrap();

        assert!(matches!(read, Answer::Unpulled(why) if why == "manifest unknown"));
    }
}
