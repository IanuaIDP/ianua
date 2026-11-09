//! A local ACME authority that validates DNS-01 through the real bundled
//! nameserver and signs the gateway's CSR with the stack's trusted authority.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use http::{Request, Response};
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use ianua_boot::env::Env;
use ianua_boot::shutdown::Shutdown;
use ianua_infra::test_support::{NAMESERVER_ROLE, NAMESERVER_ROLE_PASSWORD, TestDb};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::net::{TcpListener, UdpSocket};

use crate::stack::StackError;
use crate::stack::authority::Authority;
use crate::wire::Status;

/// The two services the nested-address profile uses.
pub(crate) struct Issuer {
    pub(crate) directory: String,
    pub(crate) resolver: SocketAddr,
}

/// Starts real authoritative DNS and a local authority under the stack's stop.
pub(crate) async fn open(
    db: &TestDb,
    authority: Arc<Authority>,
    shutdown: &Shutdown,
) -> Result<Issuer, StackError> {
    let login = db.address(NAMESERVER_ROLE, NAMESERVER_ROLE_PASSWORD);
    let vars = Env::of([
        ("APP_ENV", "development"),
        ("NAMESERVER_DATABASE_URL", login.as_str()),
        ("DNS_BIND", "127.0.0.1:0"),
        ("DNS_HOSTMASTER", "hostmaster.example.com"),
        ("DNS_REFRESH_SECONDS", "1"),
    ]);
    let resolver = ianua_dns::serving(&vars, shutdown)
        .await
        .map_err(StackError::Nameserver)?
        .address;
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(io_error)?;
    let base = format!("http://{}", listener.local_addr().map_err(io_error)?);
    let state = Arc::new(State {
        base: base.clone(),
        resolver,
        authority,
        accounts: Mutex::new(HashMap::new()),
        orders: Mutex::new(HashMap::new()),
    });
    serving(listener, state, shutdown);
    Ok(Issuer {
        directory: format!("{base}/directory"),
        resolver,
    })
}

/// Converts a listener failure while preserving its cause.
fn io_error(cause: std::io::Error) -> StackError {
    StackError::Io {
        what: "ACME authority",
        cause,
    }
}

/// Pending orders and account thumbprints, isolated to one scenario.
struct State {
    base: String,
    resolver: SocketAddr,
    authority: Arc<Authority>,
    accounts: Mutex<HashMap<String, String>>,
    orders: Mutex<HashMap<String, Order>>,
}

/// One order's actual identifiers, proofs and resulting certificate chain.
struct Order {
    names: Vec<String>,
    thumbprint: String,
    proven: Vec<bool>,
    chain: Option<String>,
}

/// Accepts local requests until the same shutdown that stops the platform.
fn serving(listener: TcpListener, state: Arc<State>, shutdown: &Shutdown) {
    let tasks = shutdown.clone();
    shutdown.spawn_until_stopped(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let state = state.clone();
            tasks.spawn_until_stopped(async move {
                let service = service_fn(move |request| answer(request, state.clone()));
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
}

/// Reads a bounded JWS envelope and dispatches the ACME resource it names.
async fn answer(
    request: Request<Incoming>,
    state: Arc<State>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = request.uri().path().to_owned();
    if path == "/directory" {
        return Ok(json_answer(
            &json!({ "newNonce": format!("{}/nonce", state.base), "newAccount": format!("{}/account", state.base), "newOrder": format!("{}/order", state.base) }),
        ));
    }
    if path == "/nonce" {
        return Ok(json_answer(&json!({})));
    }
    let bytes = Limited::new(request.into_body(), 65536).collect().await;
    let Some(envelope) = bytes
        .ok()
        .and_then(|body| serde_json::from_slice::<Value>(&body.to_bytes()).ok())
    else {
        return Ok(refused());
    };
    let protected = decoded(&envelope, "protected").unwrap_or(Value::Null);
    let payload = decoded(&envelope, "payload").unwrap_or(Value::Null);
    let response = dispatch(&state, &path, &protected, &payload)
        .await
        .unwrap_or_else(refused);
    Ok(response)
}

/// Decodes one base64url JSON member of the client's JWS envelope.
fn decoded(envelope: &Value, key: &str) -> Option<Value> {
    let bytes = URL_SAFE_NO_PAD.decode(envelope.get(key)?.as_str()?).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Implements only the account and order resources used by these scenarios.
async fn dispatch(
    state: &State,
    path: &str,
    protected: &Value,
    payload: &Value,
) -> Option<Response<Full<Bytes>>> {
    if path == "/account" {
        return account(state, protected);
    }
    if path == "/order" {
        return new_order(state, protected, payload);
    }
    let parts: Vec<_> = path.trim_start_matches('/').split('/').collect();
    let [kind, id, rest @ ..] = parts.as_slice() else {
        return None;
    };
    match *kind {
        "order" => Some(json_answer(&order_state(state, id)?)),
        "authz" => authorization(state, id, rest.first()?.parse().ok()?),
        "challenge" => validate(state, id, rest.first()?.parse().ok()?).await,
        "finalize" => finalize(state, id, payload),
        "cert" => certificate(state, id),
        _ => None,
    }
}

/// Reads the issued chain only from order state unaffected by an earlier fixture panic.
#[allow(clippy::expect_used)]
fn certificate(state: &State, id: &str) -> Option<Response<Full<Bytes>>> {
    let orders = state
        .orders
        .lock()
        .expect("the ACME order state is not poisoned");
    Some(response(orders.get(id)?.chain.clone()?))
}

/// Registers an account under its own thumbprint, allowing concurrent orders.
/// A poisoned account lock means another fixture operation failed and must abort this task.
#[allow(clippy::expect_used)]
fn account(state: &State, protected: &Value) -> Option<Response<Full<Bytes>>> {
    let jwk = protected.get("jwk")?;
    let thumbprint = thumbprint(jwk)?;
    let location = format!("{}/accounts/{}", state.base, uuid::Uuid::now_v7());
    state
        .accounts
        .lock()
        .expect("the ACME account state is not poisoned")
        .insert(location.clone(), thumbprint);
    Some(created(location, &json!({"status": "valid"})))
}

/// Hashes only the required public EC members, in their canonical key order.
fn thumbprint(jwk: &Value) -> Option<String> {
    let canonical = json!({
        "crv": jwk.get("crv")?.as_str()?,
        "kty": jwk.get("kty")?.as_str()?,
        "x": jwk.get("x")?.as_str()?,
        "y": jwk.get("y")?.as_str()?,
    });
    let bytes = serde_json::to_vec(&canonical).ok()?;
    Some(URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)))
}

/// Keeps the exact requested names and the ordering account's proof key.
/// Poisoned account or order state cannot safely establish the scenario's authorization proof.
#[allow(clippy::expect_used)]
fn new_order(state: &State, protected: &Value, payload: &Value) -> Option<Response<Full<Bytes>>> {
    let thumbprint = account_thumbprint(state, protected)?;
    let names = requested_names(payload)?;
    let id = uuid::Uuid::now_v7().to_string();
    let proven = vec![false; names.len()];
    state
        .orders
        .lock()
        .expect("the ACME order state is not poisoned")
        .insert(
            id.clone(),
            Order {
                names,
                thumbprint,
                proven,
                chain: None,
            },
        );
    Some(created(
        format!("{}/order/{id}", state.base),
        &order_state(state, &id)?,
    ))
}

/// Resolves the signing account before accepting its requested names.
/// A poisoned account map must fail the fixture instead of authorizing an order.
#[allow(clippy::expect_used)]
fn account_thumbprint(state: &State, protected: &Value) -> Option<String> {
    let account = protected.get("kid")?.as_str()?;
    state
        .accounts
        .lock()
        .expect("the ACME account state is not poisoned")
        .get(account)
        .cloned()
}

/// Reads every requested identifier in order, refusing an incomplete identifier list.
fn requested_names(payload: &Value) -> Option<Vec<String>> {
    payload
        .get("identifiers")?
        .as_array()?
        .iter()
        .map(|identifier| identifier.get("value")?.as_str().map(str::to_owned))
        .collect()
}

/// Reports ready only after every requested name passed its DNS authorization.
/// An earlier panic while mutating an order invalidates this fixture's state.
#[allow(clippy::expect_used)]
fn order_state(state: &State, id: &str) -> Option<Value> {
    let orders = state
        .orders
        .lock()
        .expect("the ACME order state is not poisoned");
    let order = orders.get(id)?;
    let status = match (&order.chain, order.proven.iter().all(|proof| *proof)) {
        (Some(_), _) => "valid",
        (None, true) => "ready",
        (None, false) => "pending",
    };
    Some(json!({ "status": status,
        "authorizations": (0..order.names.len()).map(|at| format!("{}/authz/{id}/{at}", state.base)).collect::<Vec<_>>(),
        "finalize": format!("{}/finalize/{id}", state.base), "certificate": format!("{}/cert/{id}", state.base),
    }))
}

/// Offers a distinct DNS-01 token for each root and wildcard authorization.
/// A poisoned order lock must fail the fixture rather than conceal the earlier panic.
#[allow(clippy::expect_used)]
fn authorization(state: &State, id: &str, at: usize) -> Option<Response<Full<Bytes>>> {
    let orders = state
        .orders
        .lock()
        .expect("the ACME order state is not poisoned");
    let order = orders.get(id)?;
    let name = order.names.get(at)?;
    Some(json_answer(
        &json!({ "status": "pending", "identifier": {"type": "dns", "value": name.strip_prefix("*.").unwrap_or(name)},
            "wildcard": name.starts_with("*."),
            "challenges": [{"type": "dns-01", "url": format!("{}/challenge/{id}/{at}", state.base), "token": format!("token-{id}-{at}"), "status": "pending"}],
        }),
    ))
}

/// Checks the published TXT value over UDP before accepting an authorization.
/// Authorization cannot continue from order state poisoned by another fixture failure.
#[allow(clippy::expect_used)]
async fn validate(state: &State, id: &str, at: usize) -> Option<Response<Full<Bytes>>> {
    let (name, expected) = expected_proof(state, id, at)?;
    if !texts(state.resolver, &name).await?.contains(&expected) {
        return None;
    }
    *state
        .orders
        .lock()
        .expect("the ACME order state is not poisoned")
        .get_mut(id)?
        .proven
        .get_mut(at)? = true;
    Some(json_answer(
        &json!({"type": "dns-01", "status": "valid", "url": format!("{}/challenge/{id}/{at}", state.base), "token": format!("token-{id}-{at}")}),
    ))
}

/// Computes the account-bound TXT proof without holding the order lock during DNS I/O.
/// Poisoned state cannot provide a trustworthy authorization proof for the fixture.
#[allow(clippy::expect_used)]
fn expected_proof(state: &State, id: &str, at: usize) -> Option<(String, String)> {
    let orders = state
        .orders
        .lock()
        .expect("the ACME order state is not poisoned");
    let order = orders.get(id)?;
    let name = order.names.get(at)?;
    let proof = format!("token-{id}-{at}.{}", order.thumbprint);
    Some((
        format!(
            "_acme-challenge.{}",
            name.strip_prefix("*.").unwrap_or(name)
        ),
        URL_SAFE_NO_PAD.encode(Sha256::digest(proof)),
    ))
}

/// Signs only a CSR whose names exactly match the now-proved order.
/// A poisoned order cannot be trusted to authorize issuance and must fail the fixture.
#[allow(clippy::expect_used)]
fn finalize(state: &State, id: &str, payload: &Value) -> Option<Response<Full<Bytes>>> {
    let csr = URL_SAFE_NO_PAD.decode(payload.get("csr")?.as_str()?).ok()?;
    {
        let mut orders = state
            .orders
            .lock()
            .expect("the ACME order state is not poisoned");
        let order = orders.get_mut(id)?;
        if !order.proven.iter().all(|proof| *proof) {
            return None;
        }
        order.chain = Some(state.authority.sign_request(&csr, &order.names).ok()?);
    }
    Some(json_answer(&order_state(state, id)?))
}

/// Reads authoritative TXT answers with a bounded real-network exchange.
async fn texts(server: SocketAddr, name: &str) -> Option<Vec<String>> {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).await.ok()?;
    let mut question = Message::new(7, MessageType::Query, OpCode::Query);
    question.add_query(Query::query(Name::from_ascii(name).ok()?, RecordType::TXT));
    socket.connect(server).await.ok()?;
    socket.send(&question.to_vec().ok()?).await.ok()?;
    let mut bytes = [0; 4096];
    let length = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut bytes))
        .await
        .ok()?
        .ok()?;
    let answer = Message::from_vec(&bytes[..length]).ok()?;
    Some(
        answer
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::TXT(txt) => Some(txt.to_string()),
                _ => None,
            })
            .collect(),
    )
}

/// A successful JSON response with a fresh replay nonce.
fn json_answer(value: &Value) -> Response<Full<Bytes>> {
    response(value.to_string())
}

/// A response body with the nonce required by the ACME client.
/// UUID nonce text contains only characters allowed in an HTTP header.
#[allow(clippy::expect_used)]
fn response(body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .header("Replay-Nonce", uuid::Uuid::now_v7().to_string())
        .body(Full::new(Bytes::from(body)))
        .expect("valid ACME response")
}

/// A newly created resource's canonical location.
/// Resource locations contain the fixture's numeric loopback URL and generated UUIDs.
#[allow(clippy::expect_used)]
fn created(location: String, value: &Value) -> Response<Full<Bytes>> {
    let mut answer = json_answer(value);
    *answer.status_mut() = Status::CREATED;
    answer.headers_mut().insert(
        "Location",
        http::HeaderValue::try_from(location).expect("local resource URL"),
    );
    answer
}

/// A failed authorization or malformed request, without echoing its secrets.
fn refused() -> Response<Full<Bytes>> {
    let mut answer = json_answer(
        &json!({"type": "urn:ietf:params:acme:error:unauthorized", "detail": "the requested proof was not accepted", "status": Status::FORBIDDEN.as_u16()}),
    );
    *answer.status_mut() = Status::FORBIDDEN;
    answer
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Adding optional algorithm and use metadata leaves the account
    /// thumbprint equal to the hash of the required public key fields.
    #[test]
    fn account_thumbprints_ignore_optional_key_metadata() {
        let required = json!({"crv": "P-256", "kty": "EC", "x": "public-x", "y": "public-y"});
        let mut advertised = required.clone();
        advertised["alg"] = json!("ES256");
        advertised["use"] = json!("sig");
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(
            br#"{"crv":"P-256","kty":"EC","x":"public-x","y":"public-y"}"#,
        ));

        assert_eq!(thumbprint(&required), Some(expected.clone()));
        assert_eq!(thumbprint(&advertised), Some(expected));
    }
}
