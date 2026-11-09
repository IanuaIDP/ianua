/**
 * How the proxy speaks on a listening port.
 *
 * Not a detail: each one fixes what the proxy can learn about the caller, and
 * therefore which policies are even possible. Only `tls_terminate` completes
 * the handshake, so only it can verify a client certificate — on passthrough
 * the certificate is inside the tunnel, and raw TCP and UDP carry none.
 */
export type StreamProtocol = 'tcp' | 'tls_terminate' | 'tls_passthrough' | 'udp';

/**
 * Who is allowed through a port.
 *
 * `public` is spelled out rather than implied: a port with no way to identify
 * its caller is a hole in the perimeter, and opening one should take a
 * deliberate word.
 */
export type StreamPolicy = 'mutual_tls' | 'public' | 'tunnel';

export type StreamRouteStatus = 'Active' | 'Disabled';

export type StreamRouteAction =
  'Enable' | 'Disable' | 'Edit' | 'Delete' | 'OpenToWorkflows' | 'CloseToWorkflows';

export type StreamBackend = {
  host: string;
  port: number;
  weight: number;
};

/// Which handshakes a port answers. `Any` means every one arriving on it.
export type StreamSni = { mode: 'any' } | { mode: 'only'; names: string[] };

export type StreamTimeouts = {
  connectSecs: number;
  idleSecs: number;
};

/**
 * A port the proxy listens on below HTTP.
 *
 * Unlike an HTTP route, this carries its own backends rather than pointing at
 * a service — a service's upstream is an HTTP URL, which means nothing at
 * layer 4.
 */
export type StreamRoute = {
  /** The access rule the API attached; sent back as it came. */
  access: Record<string, unknown> | null;
  backends: StreamBackend[];
  created: string;
  id: string;
  listenPort: number;
  name: string;
  policy: StreamPolicy;
  protocol: StreamProtocol;
  sni: StreamSni;
  workflowUse: string | null;
  status: StreamRouteStatus;
  timeouts: StreamTimeouts;
};

export type StreamRouteList = {
  items: StreamRoute[];
  limit: number;
  nextCursor: string | null;
};

export type StreamRouteSortField = 'listen_port' | 'name' | 'created_at' | 'updated_at';

export type StreamRouteSortDirection = 'asc' | 'desc';
