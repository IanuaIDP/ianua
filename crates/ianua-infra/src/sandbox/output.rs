//! What a run writes and how it exits, read the same way whichever sandbox
//! ran it: its answer within what workflow data holds, the end of its error
//! stream, and its exit read as an outcome.

use ianua_domain::domains::workflows::data::MAX_SIZE;
use ianua_domain::domains::workflows::execution::step::{CodeFailure, CodeOutcome};
use ianua_domain::types::{MAX_UNTRUSTED_CHARS, UntrustedText};
use ianua_integration::answer::flow_of;
use tokio::io::{AsyncRead, AsyncReadExt as _};

/// The exit status `timeout` gives when it stopped the code.
pub(super) const STOPPED_AT_LIMIT: i32 = 124;

/// The exit status of a process killed outright, as the kernel kills one
/// out of memory.
pub(super) const KILLED: i32 = 137;

/// The exit statuses that mean the container itself could not be made or
/// its command not started, so the code never ran.
pub(super) const NOT_STARTED: [i32; 3] = [125, 126, 127];

/// The most of the end of what the code writes to standard error that is
/// held while it runs, in bytes: room for a failure's reason, however long
/// the report before it.
pub(super) const ERRORS_HELD: usize = 16 * 1024;

/// What came of asking a sandbox for a run.
pub(super) enum Ended {
    /// The code ran, and this is how it went.
    Ran(CodeOutcome),
    /// The sandbox could not run it, as this says.
    NotStarted(String),
}

/// How a run's process exited, with what it wrote.
pub(super) struct Exit {
    /// Its exit status, when it had one.
    pub(super) status: Option<i32>,
    /// What it wrote to standard output: its answer.
    pub(super) answer: Vec<u8>,
    /// The end of what it wrote to standard error.
    pub(super) errors: Vec<u8>,
    /// Whether the kernel killed it for its memory.
    pub(super) memory: Memory,
}

/// Whether a run kept to its memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Memory {
    /// It did, or it was not killed for it.
    WithinItsLimit,
    /// The kernel killed it for using more than it was given.
    OverItsLimit,
}

/// How the code's exit reads, once its sandbox started it.
pub(super) fn code_outcome(exit: &Exit) -> CodeOutcome {
    match (exit.status, exit.memory) {
        (Some(0), _) => answer_of(&exit.answer),
        (Some(STOPPED_AT_LIMIT), _) => CodeOutcome::Failed(CodeFailure::TimedOut),
        (Some(KILLED), Memory::OverItsLimit) => CodeOutcome::Failed(CodeFailure::OutOfMemory),
        (Some(KILLED), Memory::WithinItsLimit) => CodeOutcome::Failed(CodeFailure::TimedOut),
        (Some(_) | None, _) => CodeOutcome::Failed(CodeFailure::Raised(UntrustedText::record(
            &tail(&exit.errors),
        ))),
    }
}

/// What the code gave back, read as workflow data.
fn answer_of(answer: &[u8]) -> CodeOutcome {
    if answer.len() > MAX_SIZE {
        return CodeOutcome::Failed(CodeFailure::Unreadable);
    }
    let read = serde_json::from_slice::<serde_json::Value>(answer)
        .ok()
        .and_then(|json| flow_of(&json).ok());
    match read {
        Some(data) => CodeOutcome::Succeeded(data),
        None => CodeOutcome::Failed(CodeFailure::Unreadable),
    }
}

/// At most `most` bytes of `reader`, and one more to show there was more;
/// the rest is read and dropped, so the process never blocks on a full
/// pipe.
pub(super) async fn bounded(
    mut reader: impl AsyncRead + Unpin,
    most: usize,
) -> std::io::Result<Vec<u8>> {
    let mut kept = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let read = reader.read(&mut chunk).await?;
        if read == 0 {
            return Ok(kept);
        }
        let room = most.saturating_add(1).saturating_sub(kept.len());
        kept.extend_from_slice(chunk.get(..read.min(room)).unwrap_or_default());
    }
}

/// The last `most` bytes of `reader`; everything before is read and
/// dropped, so the process never blocks on a full pipe.
pub(super) async fn last_of(
    mut reader: impl AsyncRead + Unpin,
    most: usize,
) -> std::io::Result<Vec<u8>> {
    let mut kept = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let read = reader.read(&mut chunk).await?;
        if read == 0 {
            return Ok(kept);
        }
        kept.extend_from_slice(chunk.get(..read).unwrap_or_default());
        let over = kept.len().saturating_sub(most);
        kept.drain(..over);
    }
}

/// The last of `errors` that a failure's reason keeps, as text: the end
/// of an error report, where Python and Node name what went wrong.
pub(super) fn tail(errors: &[u8]) -> String {
    let text = String::from_utf8_lossy(errors);
    let text = text.trim();
    let skipped = text.chars().count().saturating_sub(MAX_UNTRUSTED_CHARS);
    text.chars().skip(skipped).collect()
}

/// A code that stopped before reading its input closed the pipe; that is
/// no failure of the run.
pub(super) fn ignore_closed_input(error: std::io::Error) -> std::io::Result<()> {
    if error.kind() == std::io::ErrorKind::BrokenPipe {
        return Ok(());
    }
    Err(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exited(status: i32, answer: &[u8]) -> Exit {
        Exit {
            status: Some(status),
            answer: answer.to_vec(),
            errors: b"Traceback: ValueError: no title".to_vec(),
            memory: Memory::WithinItsLimit,
        }
    }

    /// A JSON answer reads as the code's output, a list and numbers among
    /// it, its fields in name order as every service's answer reads; anything
    /// else reads as an unreadable answer, never as a success.
    #[test]
    fn only_json_reads_as_an_answer() {
        let read = answer_of(br#"{"title":"Fix login","python":[3,13]}"#);
        let broken = answer_of(b"Fix login");

        let CodeOutcome::Succeeded(data) = read else {
            panic!("JSON was not read");
        };
        assert_eq!(data.render(), r#"{"python":[3,13],"title":"Fix login"}"#);
        assert_eq!(broken, CodeOutcome::Failed(CodeFailure::Unreadable));
    }

    /// A clean exit is the answer, `timeout`'s status is a time out, a kill
    /// for memory is out of memory, and any other exit raised the end of
    /// what the code wrote.
    #[test]
    fn each_exit_reads_as_its_outcome() {
        let over_memory = Exit {
            memory: Memory::OverItsLimit,
            ..exited(KILLED, b"")
        };

        assert!(matches!(
            code_outcome(&exited(0, b"1")),
            CodeOutcome::Succeeded(_)
        ));
        assert_eq!(
            code_outcome(&exited(STOPPED_AT_LIMIT, b"")),
            CodeOutcome::Failed(CodeFailure::TimedOut)
        );
        assert_eq!(
            code_outcome(&over_memory),
            CodeOutcome::Failed(CodeFailure::OutOfMemory)
        );
        assert_eq!(
            code_outcome(&exited(1, b"")),
            CodeOutcome::Failed(CodeFailure::Raised(UntrustedText::record(
                "Traceback: ValueError: no title"
            )))
        );
    }

    /// A long error report keeps its end, where the error is named, within
    /// what a reason holds, whole characters only.
    #[test]
    fn the_end_of_an_error_is_kept() {
        let long = format!(
            "Traceback:\n{}Ä\nurllib.error.URLError: <urlopen error>",
            "  File line\n".repeat(400)
        );

        let kept = tail(long.as_bytes());

        assert!(kept.ends_with("URLError: <urlopen error>"));
        assert_eq!(kept.chars().count(), MAX_UNTRUSTED_CHARS);
    }

    /// Of a stream longer than it holds, the reader keeps the last bytes.
    #[tokio::test]
    async fn the_last_of_a_long_stream_is_held() {
        let stream = format!("{}the end", "x".repeat(40_000));

        let held = last_of(stream.as_bytes(), 16).await.unwrap();

        assert_eq!(held, b"xxxxxxxxxthe end");
    }
}
