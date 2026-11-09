//! The bus server the bus adapters' tests run against, started once for
//! the run by the `bus` setup script, and the sweep of the streams earlier
//! runs left on it.

use std::time::Duration;

use async_nats::jetstream;
use futures_util::TryStreamExt as _;

use crate::bus::ServerBus;
use crate::namespace::Namespace;

/// The bus on the test bus server, under the default namespace.
///
/// # Panics
///
/// When the setup script did not run or the server does not answer: no
/// bus test can go on without it.
pub async fn test_server() -> ServerBus {
    test_server_in(&Namespace::default()).await
}

/// The bus on the test bus server, every name under `namespace`.
///
/// # Panics
///
/// When the setup script did not run or the server does not answer: no
/// bus test can go on without it.
pub async fn test_server_in(namespace: &Namespace) -> ServerBus {
    let port = std::env::var("IANUA_TEST_BUS_PORT")
        .expect("the bus setup script names the test bus's port");
    ServerBus::connect(
        &format!("127.0.0.1:{port}"),
        namespace,
        Duration::from_secs(5),
    )
    .await
    .expect("the test bus answers")
}

/// Whether `stream` belongs to a namespace a test made for itself: `s` and
/// hex digits for a scenario stack, `t` and hex digits for a bus test,
/// then a dash and the stream's role. The default `ianua-*` streams, and
/// any namespace a person chose, never match.
#[must_use]
pub fn left_by_a_test_namespace(stream: &str) -> bool {
    let Some((namespace, role)) = stream.split_once('-') else {
        return false;
    };
    let Some(digits) = namespace
        .strip_prefix('s')
        .or_else(|| namespace.strip_prefix('t'))
    else {
        return false;
    };
    !role.is_empty()
        && !digits.is_empty()
        && digits
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Deletes every stream on the server `streams` reaches that `left`
/// picks, with the consumers kept inside it, and answers their names.
///
/// # Errors
///
/// [`async_nats::Error`] when the streams cannot be listed or one cannot
/// be deleted.
pub async fn clear_streams(
    streams: &jetstream::Context,
    left: impl Fn(&str) -> bool,
) -> Result<Vec<String>, async_nats::Error> {
    let names: Vec<String> = streams.stream_names().try_collect().await?;
    let mut cleared = Vec::new();
    for name in names.into_iter().filter(|name| left(name)) {
        streams.delete_stream(&name).await?;
        cleared.push(name);
    }
    Ok(cleared)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The streams of the test bus server, reached directly.
    async fn test_streams() -> jetstream::Context {
        let port = std::env::var("IANUA_TEST_BUS_PORT")
            .expect("the bus setup script names the test bus's port");
        let client = async_nats::connect(format!("127.0.0.1:{port}"))
            .await
            .expect("the test bus answers");
        jetstream::new(client)
    }

    /// Scenario stacks' and bus tests' streams are picked, whatever their
    /// role.
    #[test]
    fn streams_of_test_namespaces_are_picked() {
        for stream in [
            "s1a2b3c4d-events",
            "s0f-messages",
            "t9e8d7c6b5a4f-dead-letters",
        ] {
            assert!(left_by_a_test_namespace(stream), "{stream}");
        }
    }

    /// Default deployment streams, ordinary names and malformed test names are
    /// excluded from the test-namespace sweep.
    #[test]
    fn other_streams_are_never_picked() {
        for stream in [
            "ianua-events",
            "ianua-messages",
            "staging-events",
            "test-events",
            "s-events",
            "s1a2b-",
            "s1A2B-events",
            "s1a2b",
        ] {
            assert!(!left_by_a_test_namespace(stream), "{stream}");
        }
    }

    /// Sweeping the fixture's scenario namespace deletes its stream while
    /// retaining its ordinary namespace and the default deployment's stream.
    #[tokio::test]
    async fn the_sweep_deletes_a_left_stream_and_keeps_the_others() {
        let id = uuid::Uuid::now_v7().simple().to_string();
        let end = &id[20..];
        let scenario = Namespace::new(&format!("s{end}")).unwrap();
        let other = Namespace::new(&format!("x{end}")).unwrap();
        test_server_in(&scenario).await;
        test_server_in(&other).await;
        test_server().await;
        let streams = test_streams().await;
        let ours = |name: &str| name.contains(end) && left_by_a_test_namespace(name);

        let cleared = clear_streams(&streams, ours).await.unwrap();
        let left: Vec<String> = streams.stream_names().try_collect().await.unwrap();
        streams
            .delete_stream(format!("{other}-events"))
            .await
            .unwrap();

        assert_eq!(cleared, [format!("{scenario}-events")]);
        assert!(!left.contains(&format!("{scenario}-events")));
        assert!(left.contains(&format!("{other}-events")));
        assert!(left.iter().any(|name| name == "ianua-events"));
    }
}
