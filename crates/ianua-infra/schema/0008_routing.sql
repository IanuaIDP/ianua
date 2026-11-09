-- Routing: a tenant's services, the routes that forward to them, its stream
-- routes, its private-network connectors and its egress policies.
--
-- Every table is a tenant table, under row-level security, and lives in a
-- tenant's own database too. That database has no tenants table, so no
-- table here points at one; foreign keys run only between routing tables,
-- each through `tenant_id`, so a row never points into another tenant.
--
-- The checks repeat the rules the domain keeps between columns, so a row
-- written past the domain is refused here too.

CREATE TABLE services (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    upstream jsonb NOT NULL,
    health_check jsonb NOT NULL,
    app_sign_in jsonb,
    -- The service whose app sign-in this one accepts, and how it reaches it.
    accepts_sign_in_of uuid,
    sign_in_delivery jsonb,
    status text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT services_tenant_id_key UNIQUE (tenant_id, id),
    CONSTRAINT services_name_key UNIQUE (tenant_id, name),
    CONSTRAINT services_status_known
        CHECK (status IN ('active', 'disabled')),
    CONSTRAINT services_acceptance_whole
        CHECK ((accepts_sign_in_of IS NULL) = (sign_in_delivery IS NULL)),
    CONSTRAINT services_owns_or_accepts_sign_in
        CHECK (app_sign_in IS NULL OR accepts_sign_in_of IS NULL),
    CONSTRAINT services_accepts_another
        CHECK (accepts_sign_in_of <> id),
    CONSTRAINT services_changed_after_created
        CHECK (updated_at >= created_at),
    -- A service whose sign-in another still accepts may not be deleted, as
    -- the domain refuses it: those sessions would have no one to end them.
    CONSTRAINT services_accepted_sign_in_fkey
        FOREIGN KEY (tenant_id, accepts_sign_in_of) REFERENCES services (tenant_id, id)
        ON DELETE RESTRICT
);

ALTER TABLE services ENABLE ROW LEVEL SECURITY;
ALTER TABLE services FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON services
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- One index per order a list can ask for, the id last to break ties.
CREATE INDEX services_by_created ON services (tenant_id, created_at, id);
CREATE INDEX services_by_updated ON services (tenant_id, updated_at, id);
CREATE INDEX services_by_name ON services (tenant_id, name, id);

-- The services accepting one service's sign-in, for its foreign key.
CREATE INDEX services_accepting_sign_in ON services (tenant_id, accepts_sign_in_of);

-- The hosts a service's app sign-in answers on, or its own session cookie
-- is set on. One host belongs to one service of the tenant, so two
-- services never both answer sign-in or set a cookie there. A save
-- replaces the service's hosts in the same statement as the service.
CREATE TABLE service_sign_in_hosts (
    tenant_id uuid NOT NULL,
    host text NOT NULL,
    service_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, host),
    -- A deleted service's hosts go with it: they are part of its settings.
    CONSTRAINT service_sign_in_hosts_service_fkey
        FOREIGN KEY (tenant_id, service_id) REFERENCES services (tenant_id, id)
        ON DELETE CASCADE
);

ALTER TABLE service_sign_in_hosts ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_sign_in_hosts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON service_sign_in_hosts
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX service_sign_in_hosts_of_service ON service_sign_in_hosts (tenant_id, service_id);

CREATE TABLE routes (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    path_pattern text NOT NULL,
    -- The methods matched, as sent on the wire; none for every method.
    methods text[] NOT NULL,
    service_id uuid NOT NULL,
    policy jsonb NOT NULL,
    -- The domains the route answers on, or NULL for every one.
    hosts text[],
    conditions jsonb NOT NULL,
    -- no foreign key: pipelines belong to the proxy context, linked in its wave
    pipeline_id uuid NOT NULL,
    path_rewrite jsonb NOT NULL,
    status text NOT NULL,
    priority integer NOT NULL,
    data_class text NOT NULL,
    -- The action class declared, or NULL when none was.
    action_class text,
    reach text NOT NULL,
    parameter_rules jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    -- Whether the tenant's workflows may call it, as the person a run acts
    -- for. Every route starts closed until someone who may change routing
    -- opens it.
    workflow_use text NOT NULL DEFAULT 'closed',
    -- Until when the route is in attack mode, every request to it checked
    -- harder before its pipeline; NULL when it is not. It ends on its own.
    attack_mode_until timestamptz,
    -- Tables that name a route link to it with its tenant.
    CONSTRAINT routes_tenant_id_key UNIQUE (tenant_id, id),
    CONSTRAINT routes_name_key UNIQUE (tenant_id, name),
    CONSTRAINT routes_methods_known
        CHECK (methods <@ ARRAY['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', '*']),
    CONSTRAINT routes_hosts_named
        CHECK (hosts IS NULL OR cardinality(hosts) > 0),
    CONSTRAINT routes_status_known
        CHECK (status IN ('active', 'disabled')),
    CONSTRAINT routes_priority_in_range
        CHECK (priority BETWEEN 0 AND 65535),
    CONSTRAINT routes_data_class_known
        CHECK (data_class IN ('public', 'internal', 'confidential', 'restricted')),
    CONSTRAINT routes_action_class_known
        CHECK (action_class IN
            ('read', 'write', 'delete', 'configure', 'communicate', 'financial', 'admin')),
    CONSTRAINT routes_reach_known
        CHECK (reach IN ('fixed', 'open_ended')),
    CONSTRAINT routes_changed_after_created
        CHECK (updated_at >= created_at),
    CONSTRAINT routes_workflow_use_known CHECK (workflow_use IN ('closed', 'open')),
    -- Attack mode ends after the route was made.
    CONSTRAINT routes_attack_mode_after_created CHECK (attack_mode_until > created_at),
    -- A service a route still forwards to may not be deleted, as the domain
    -- refuses it: the route would be left with no backend.
    CONSTRAINT routes_service_fkey
        FOREIGN KEY (tenant_id, service_id) REFERENCES services (tenant_id, id)
        ON DELETE RESTRICT
);

ALTER TABLE routes ENABLE ROW LEVEL SECURITY;
ALTER TABLE routes FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON routes
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- One index per order a list can ask for, the id last to break ties, and
-- the default order narrowed to one status.
CREATE INDEX routes_by_priority ON routes (tenant_id, priority, id);
CREATE INDEX routes_by_created ON routes (tenant_id, created_at, id);
CREATE INDEX routes_by_updated ON routes (tenant_id, updated_at, id);
CREATE INDEX routes_by_name ON routes (tenant_id, name, id);
CREATE INDEX routes_by_status ON routes (tenant_id, status, id);
CREATE INDEX routes_in_status_by_priority ON routes (tenant_id, status, priority, id);

-- The routes running one pipeline, in priority order.
CREATE INDEX routes_on_pipeline ON routes (tenant_id, pipeline_id, priority, id);

-- The routes forwarding to one service, for its foreign key and its count.
CREATE INDEX routes_to_service ON routes (tenant_id, service_id);

CREATE TABLE stream_routes (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    protocol text NOT NULL,
    listen_port integer NOT NULL,
    -- The server names the route answers, or NULL for every one.
    sni text[],
    policy text NOT NULL,
    access jsonb NOT NULL,
    backends jsonb NOT NULL,
    connect_timeout_secs integer NOT NULL,
    idle_timeout_secs integer NOT NULL,
    status text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    -- Whether the tenant's workflows may reach the system behind it, with
    -- the login kept in stream_route_logins. Every stream route starts
    -- closed until someone who may change routing opens it with a login.
    workflow_use text NOT NULL DEFAULT 'closed',
    -- Tables that name a stream route link to it with its tenant.
    CONSTRAINT stream_routes_tenant_id_key UNIQUE (tenant_id, id),
    CONSTRAINT stream_routes_name_key UNIQUE (tenant_id, name),
    CONSTRAINT stream_routes_protocol_known
        CHECK (protocol IN ('tcp', 'tls_terminate', 'tls_passthrough', 'udp')),
    CONSTRAINT stream_routes_policy_known
        CHECK (policy IN ('mutual_tls', 'tunnel', 'public')),
    CONSTRAINT stream_routes_status_known
        CHECK (status IN ('active', 'disabled')),
    CONSTRAINT stream_routes_port_in_range
        CHECK (listen_port BETWEEN 1024 AND 65535),
    CONSTRAINT stream_routes_sni_named
        CHECK (sni IS NULL OR cardinality(sni) > 0),
    CONSTRAINT stream_routes_timeouts_positive
        CHECK (connect_timeout_secs > 0 AND idle_timeout_secs > 0),
    CONSTRAINT stream_routes_changed_after_created
        CHECK (updated_at >= created_at),
    CONSTRAINT stream_routes_workflow_use_known CHECK (workflow_use IN ('closed', 'open'))
);

ALTER TABLE stream_routes ENABLE ROW LEVEL SECURITY;
ALTER TABLE stream_routes FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON stream_routes
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- One index per order a list can ask for, the id last to break ties.
CREATE INDEX stream_routes_by_created ON stream_routes (tenant_id, created_at, id);
CREATE INDEX stream_routes_by_updated ON stream_routes (tenant_id, updated_at, id);
CREATE INDEX stream_routes_by_name ON stream_routes (tenant_id, name, id);
CREATE INDEX stream_routes_by_port ON stream_routes (tenant_id, listen_port, id);

-- Every tenant's active stream routes, which the gateway binds at start.
CREATE INDEX stream_routes_active ON stream_routes (tenant_id, id) WHERE status = 'active';

-- The login a Protected data step signs in with behind a stream route,
-- and how its connection is protected: TLS from the worker to the system
-- itself, the system's certificate checked for tls_server_name and
-- chaining to tls_authority, or the public roots when it is empty; or
-- none, chosen by name. Kept in a table of its own, which the gateway's
-- role is never granted: the gateway reads every stream route, and needs
-- to know only whether one is open. The password is kept sealed for its
-- route.
CREATE TABLE stream_route_logins (
    tenant_id uuid NOT NULL,
    stream_route_id uuid NOT NULL,
    login_user text NOT NULL,
    login_password text NOT NULL,
    tls text NOT NULL,
    tls_authority text,
    tls_server_name text,
    PRIMARY KEY (tenant_id, stream_route_id),
    FOREIGN KEY (tenant_id, stream_route_id)
        REFERENCES stream_routes (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT stream_route_logins_tls_known CHECK (
        (tls = 'required' AND tls_server_name IS NOT NULL)
        OR (tls = 'off' AND tls_authority IS NULL AND tls_server_name IS NULL)
    )
);

ALTER TABLE stream_route_logins ENABLE ROW LEVEL SECURITY;
ALTER TABLE stream_route_logins FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON stream_route_logins
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE TABLE connectors (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    scope jsonb NOT NULL,
    -- Awaiting enrollment: the keyed hash of the one-time code, and when
    -- it expires.
    code_hash text,
    code_expires_at timestamptz,
    -- Enrolled: the key the connector pinned, which every certificate the
    -- platform's connector authority signs for it carries, and when.
    public_key text,
    enrolled_at timestamptz,
    status text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    -- Enrolled: when the certificate signed last for the pinned key ends;
    -- it is renewed every day.
    certificate_expires_at timestamptz,
    -- When the gateway last saw a link of the connector open. The gateway
    -- writes this column and no other.
    last_seen_at timestamptz,
    CONSTRAINT connectors_name_key UNIQUE (tenant_id, name),
    CONSTRAINT connectors_status_known
        CHECK (status IN ('active', 'revoked')),
    CONSTRAINT connectors_awaiting_whole
        CHECK ((code_hash IS NULL) = (code_expires_at IS NULL)),
    CONSTRAINT connectors_enrolled_whole
        CHECK ((public_key IS NULL) = (enrolled_at IS NULL)
               AND (public_key IS NULL) = (certificate_expires_at IS NULL)),
    CONSTRAINT connectors_awaiting_or_enrolled
        CHECK ((code_hash IS NULL) <> (public_key IS NULL)),
    CONSTRAINT connectors_certificate_ends_after_enrollment
        CHECK (certificate_expires_at > enrolled_at),
    CONSTRAINT connectors_seen_once_enrolled
        CHECK (last_seen_at IS NULL
               OR (enrolled_at IS NOT NULL AND last_seen_at >= enrolled_at)),
    CONSTRAINT connectors_changed_after_created
        CHECK (updated_at >= created_at)
);

ALTER TABLE connectors ENABLE ROW LEVEL SECURITY;
ALTER TABLE connectors FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON connectors
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The connector a presented enrollment code is for.
CREATE INDEX connectors_by_code ON connectors (tenant_id, code_hash);

-- The enrolled connectors of a tenant, which the gateway reads.
CREATE INDEX connectors_enrolled ON connectors (tenant_id, id)
    WHERE public_key IS NOT NULL;

CREATE TABLE egress_policies (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    -- The workload identity of the service the policy is for.
    service text NOT NULL,
    destinations jsonb NOT NULL,
    max_data_class text NOT NULL,
    -- The person who made it: a tenant user or an organization member.
    created_by_kind text NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT egress_policies_service_key UNIQUE (tenant_id, service),
    CONSTRAINT egress_policies_data_class_known
        CHECK (max_data_class IN ('public', 'internal', 'confidential', 'restricted')),
    CONSTRAINT egress_policies_made_by_a_person
        CHECK (created_by_kind IN ('tenant_user', 'org_user')),
    CONSTRAINT egress_policies_changed_after_created
        CHECK (updated_at >= created_at)
);

ALTER TABLE egress_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE egress_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON egress_policies
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The tenant's policies by name.
CREATE INDEX egress_policies_by_name ON egress_policies (tenant_id, name, id);

-- The egress gateway knows a calling service only by the name its client
-- certificate carries, so it finds the policies written for that name
-- across every tenant before it knows whose the service is: a service two
-- tenants claim reaches nothing.
CREATE INDEX egress_policies_by_service ON egress_policies (service);
