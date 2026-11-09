import type { StreamPolicy, StreamProtocol } from '@/types/stream-route';

/// Which of the two kinds the Routes card is showing. It lives in the URL so
/// that returning from a form, reloading, or going back lands on the kind the
/// operator was actually looking at.
export const ROUTE_KIND_PARAM = 'kind';
export const STREAM_ROUTE_KIND = 'stream';

/// The data plane does not run as root, so a privileged port is one it could
/// never bind — refused at configuration time rather than at start-up.
export const MIN_STREAM_LISTEN_PORT = 1024;
export const MAX_STREAM_LISTEN_PORT = 65535;

/// Below a minute, a healthy long-lived connection is closed the moment it
/// pauses — and pausing is most of what layer 4 carries.
export const MIN_STREAM_IDLE_SECS = 60;

/// Twelve hours. Past this a connection is not idle, it is leaked — and each
/// one still open rests on a decision taken so long ago the grant behind it
/// may since have been revoked.
export const MAX_STREAM_IDLE_SECS = 43_200;

export const DEFAULT_STREAM_CONNECT_SECS = '10';
export const DEFAULT_STREAM_IDLE_SECS = '3600';

/// Ids of the protocols; the wording is `dashboard.ports.protocols.<id>`, `.protocolLabels.<id>`
/// and `.protocolHints.<id>`.
export const STREAM_PROTOCOLS: StreamProtocol[] = [
  'tcp',
  'tls_terminate',
  'tls_passthrough',
  'udp',
];

/// Ids of the policies; the wording is `dashboard.ports.policies.<id>`.
export const STREAM_POLICIES: StreamPolicy[] = ['public', 'mutual_tls'];

/// Whether this protocol completes a handshake the proxy can read a client
/// certificate from.
export function terminatesTls(protocol: StreamProtocol) {
  return protocol === 'tls_terminate';
}

/// Whether a handshake on this protocol carries a server name to match on.
export function carriesSni(protocol: StreamProtocol) {
  return protocol === 'tls_terminate' || protocol === 'tls_passthrough';
}
