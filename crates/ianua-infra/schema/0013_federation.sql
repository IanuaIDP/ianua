-- The federation context: a tenant's connections to outside identity
-- providers, the accounts linked through them and what their group
-- mappings gave each person; the sign-ins and logouts in flight with them;
-- the tenant's own SAML apps, with this platform as their identity
-- provider; and the tenant's SCIM endpoint.
--
-- Every table is a tenant table: it lives in the platform database and in
-- a tenant's own, so it names no platform table. Row-level security keeps
-- each row to its tenant, and every foreign key carries the tenant too, so
-- a row can never point at another tenant's.
--
-- Secrets are kept only as the domain hands them over, hashed or sealed:
-- an OIDC state is kept as its digest, a PKCE verifier sealed by the
-- platform, a SCIM token as its hash.
--
-- The checks repeat the rules the domain keeps between columns, so a row
-- written past the domain is refused here too.

CREATE TABLE federation_connections (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    provider_name text NOT NULL,
    status text NOT NULL,
    -- The settings of its protocol, the other left empty. The OIDC client
    -- secret in them is sealed by the platform.
    saml jsonb,
    oidc jsonb,
    jit_provisioning text NOT NULL,
    jit_default_role_id uuid,
    email_trust text NOT NULL,
    assurance_trust text NOT NULL,
    domain_hint text,
    allowed_domains text[] NOT NULL,
    -- Which provider claim fills which profile field, paired by position.
    mapped_claims text[] NOT NULL,
    mapped_fields text[] NOT NULL,
    -- The claim the provider sends groups in, while groups are mapped; the
    -- rules are in connection_group_rules.
    group_claim text,
    created_at timestamptz NOT NULL,
    keyed_at timestamptz NOT NULL,
    -- Whether the SAML settings name an address the metadata is read from
    -- again, for the refresh that walks every tenant's.
    follows_metadata boolean GENERATED ALWAYS AS (saml #>> '{value,metadata_url}' IS NOT NULL) STORED,
    CONSTRAINT federation_connections_tenant_id_key UNIQUE (tenant_id, id),
    -- A role new accounts are given is never deleted from under the
    -- connection: people made after would get a role that is gone.
    CONSTRAINT federation_connections_default_role_fkey FOREIGN KEY (tenant_id, jit_default_role_id)
        REFERENCES roles (tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT federation_connections_one_protocol CHECK (num_nonnulls(saml, oidc) = 1),
    CONSTRAINT federation_connections_status_known CHECK (status IN ('active', 'disabled')),
    CONSTRAINT federation_connections_jit_known CHECK (jit_provisioning IN ('enabled', 'disabled')),
    CONSTRAINT federation_connections_email_trust_known
        CHECK (email_trust IN ('unverified', 'authoritative')),
    CONSTRAINT federation_connections_assurance_trust_known
        CHECK (assurance_trust IN ('untrusted', 'trusted')),
    CONSTRAINT federation_connections_role_while_provisioning
        CHECK (jit_provisioning = 'enabled' OR jit_default_role_id IS NULL),
    CONSTRAINT federation_connections_mapping_paired
        CHECK (cardinality(mapped_claims) = cardinality(mapped_fields)),
    CONSTRAINT federation_connections_keyed_after_created CHECK (keyed_at >= created_at)
);

ALTER TABLE federation_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE federation_connections FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON federation_connections
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- One index per order a connection list can ask for, the id last.
CREATE INDEX federation_connections_by_created ON federation_connections (tenant_id, created_at, id);
CREATE INDEX federation_connections_by_name ON federation_connections (tenant_id, provider_name, id);
CREATE INDEX federation_connections_by_status ON federation_connections (tenant_id, status, id);
CREATE INDEX federation_connections_default_role
    ON federation_connections (tenant_id, jit_default_role_id);
-- The connections following a metadata address, by tenant then id.
CREATE INDEX federation_connections_following ON federation_connections (tenant_id, id)
    WHERE follows_metadata;

-- A connection's group mapping: members of a provider's group get one
-- role or one group here, each rule in the order the admin gave them.
CREATE TABLE connection_group_rules (
    tenant_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    position integer NOT NULL,
    provider_group text NOT NULL,
    role_id uuid,
    group_id uuid,
    PRIMARY KEY (tenant_id, connection_id, position),
    -- The rules are part of the connection, and go with it.
    FOREIGN KEY (tenant_id, connection_id)
        REFERENCES federation_connections (tenant_id, id) ON DELETE CASCADE,
    -- A role or group a connection maps is never deleted from under it:
    -- the mapping would go on handing out something that is gone, and a
    -- mapping is never left without its rules.
    FOREIGN KEY (tenant_id, role_id) REFERENCES roles (tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, group_id) REFERENCES groups (tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT connection_group_rules_one_grant CHECK (num_nonnulls(role_id, group_id) = 1)
);

ALTER TABLE connection_group_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE connection_group_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON connection_group_rules
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX connection_group_rules_giving_role ON connection_group_rules (tenant_id, role_id);
CREATE INDEX connection_group_rules_giving_group ON connection_group_rules (tenant_id, group_id);

-- Who a local account's owner is at a connection's provider: one link per
-- subject and one per account on each connection.
CREATE TABLE federated_links (
    tenant_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    subject text NOT NULL,
    user_id uuid NOT NULL,
    linked_at timestamptz NOT NULL,
    confirmed_at timestamptz NOT NULL,
    CONSTRAINT federated_links_pkey PRIMARY KEY (tenant_id, connection_id, user_id),
    CONSTRAINT federated_links_subject_key UNIQUE (tenant_id, connection_id, subject),
    -- A link through a connection that is gone signs nobody in.
    FOREIGN KEY (tenant_id, connection_id)
        REFERENCES federation_connections (tenant_id, id) ON DELETE CASCADE,
    -- Nor does one to an account that is gone.
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT federated_links_confirmed_after_linked CHECK (confirmed_at >= linked_at)
);

ALTER TABLE federated_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE federated_links FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON federated_links
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- An account's links, oldest first.
CREATE INDEX federated_links_of_user ON federated_links (tenant_id, user_id, linked_at);

-- What one connection's group mapping gave one person, so a later sign-in
-- takes back what the provider no longer vouches for. The roles and
-- groups are in the two tables below it.
CREATE TABLE mapped_holdings (
    tenant_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    user_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, connection_id, user_id),
    -- Without the connection nothing is mapped any more, so nothing is
    -- taken back through it.
    FOREIGN KEY (tenant_id, connection_id)
        REFERENCES federation_connections (tenant_id, id) ON DELETE CASCADE,
    -- The record is about one account, and goes with it.
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE mapped_holdings ENABLE ROW LEVEL SECURITY;
ALTER TABLE mapped_holdings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON mapped_holdings
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX mapped_holdings_of_user ON mapped_holdings (tenant_id, user_id);

CREATE TABLE mapped_holding_roles (
    tenant_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role_id uuid NOT NULL,
    position integer NOT NULL,
    PRIMARY KEY (tenant_id, connection_id, user_id, role_id),
    -- The roles are part of the record, and go with it.
    FOREIGN KEY (tenant_id, connection_id, user_id)
        REFERENCES mapped_holdings (tenant_id, connection_id, user_id) ON DELETE CASCADE,
    -- A role that is gone is held by nobody, so there is nothing to take
    -- back.
    FOREIGN KEY (tenant_id, role_id) REFERENCES roles (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE mapped_holding_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE mapped_holding_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON mapped_holding_roles
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX mapped_holding_roles_of_role ON mapped_holding_roles (tenant_id, role_id);

CREATE TABLE mapped_holding_groups (
    tenant_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    user_id uuid NOT NULL,
    group_id uuid NOT NULL,
    position integer NOT NULL,
    PRIMARY KEY (tenant_id, connection_id, user_id, group_id),
    -- The groups are part of the record, and go with it.
    FOREIGN KEY (tenant_id, connection_id, user_id)
        REFERENCES mapped_holdings (tenant_id, connection_id, user_id) ON DELETE CASCADE,
    -- A group that is gone has nobody in it, so there is nothing to take
    -- back.
    FOREIGN KEY (tenant_id, group_id) REFERENCES groups (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE mapped_holding_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE mapped_holding_groups FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON mapped_holding_groups
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX mapped_holding_groups_of_group ON mapped_holding_groups (tenant_id, group_id);

-- OIDC sign-ins between the redirect to the provider and its callback.
-- Each is kept under a digest of its state, never the state itself: the
-- state is a secret the browser holds, and a reader of this table cannot
-- answer a sign-in with it. The PKCE verifier is sealed.
CREATE TABLE oidc_flows (
    tenant_id uuid NOT NULL,
    state_hash bytea NOT NULL,
    connection_id uuid NOT NULL,
    nonce text NOT NULL,
    sealed_pkce_verifier text NOT NULL,
    redirect_uri text NOT NULL,
    binding_hash text NOT NULL,
    dashboard_hash text NOT NULL,
    lapses_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, state_hash),
    -- A sign-in through a connection that is gone can never finish.
    FOREIGN KEY (tenant_id, connection_id)
        REFERENCES federation_connections (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE oidc_flows ENABLE ROW LEVEL SECURITY;
ALTER TABLE oidc_flows FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON oidc_flows
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX oidc_flows_of_connection ON oidc_flows (tenant_id, connection_id);
-- The flows whose time ran out, cleared as new ones are kept.
CREATE INDEX oidc_flows_lapsing ON oidc_flows (tenant_id, lapses_at);

-- SAML sign-in requests sent to a connection's provider and awaiting its
-- answer, each kept under the request's ID.
CREATE TABLE saml_requests (
    tenant_id uuid NOT NULL,
    request_id text NOT NULL,
    connection_id uuid NOT NULL,
    binding_hash text NOT NULL,
    dashboard_hash text NOT NULL,
    lapses_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, request_id),
    -- A request sent through a connection that is gone can never finish.
    FOREIGN KEY (tenant_id, connection_id)
        REFERENCES federation_connections (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE saml_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON saml_requests
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX saml_requests_of_connection ON saml_requests (tenant_id, connection_id);
CREATE INDEX saml_requests_lapsing ON saml_requests (tenant_id, lapses_at);

-- The SAML assertions a tenant's connections sent that were spent, each
-- kept until it would have expired anyway.
CREATE TABLE saml_assertions (
    tenant_id uuid NOT NULL,
    assertion_id text NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, assertion_id)
);

ALTER TABLE saml_assertions ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_assertions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON saml_assertions
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX saml_assertions_expiring ON saml_assertions (tenant_id, expires_at);

-- The SAML logout requests this platform sent a peer, kept until their
-- answer comes back or they lapse. A peer is a connection's provider or
-- one of the tenant's SAML apps, named by its entity id.
CREATE TABLE sent_logout_requests (
    tenant_id uuid NOT NULL,
    id text NOT NULL,
    peer text NOT NULL,
    destination text NOT NULL,
    name_id_format text NOT NULL,
    name_id text NOT NULL,
    session_index text NOT NULL,
    sent_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT sent_logout_requests_expires_after_sent CHECK (expires_at >= sent_at)
);

ALTER TABLE sent_logout_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE sent_logout_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON sent_logout_requests
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX sent_logout_requests_expiring ON sent_logout_requests (tenant_id, expires_at);

-- The session a connection's provider keeps behind a session here, so a
-- logout from either side reaches the other.
CREATE TABLE provider_sessions (
    tenant_id uuid NOT NULL,
    -- Our session behind the provider's, linked to sessions in 0018.
    session_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    subject text NOT NULL,
    session_index text NOT NULL,
    PRIMARY KEY (tenant_id, session_id),
    -- A provider session behind a connection that is gone is reached by
    -- no logout any more.
    FOREIGN KEY (tenant_id, connection_id)
        REFERENCES federation_connections (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE provider_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON provider_sessions
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX provider_sessions_of_connection ON provider_sessions (tenant_id, connection_id);

-- The tenant's SAML apps, signed in to with this platform as their
-- identity provider. An app's entity id is unique within its tenant.
CREATE TABLE saml_service_providers (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    entity_id text NOT NULL,
    status text NOT NULL,
    -- How it is answered: its addresses, NameID format, attributes,
    -- signing, sealing and the rule for its requests.
    settings jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT saml_service_providers_tenant_id_key UNIQUE (tenant_id, id),
    CONSTRAINT saml_service_providers_entity_id_key UNIQUE (tenant_id, entity_id),
    CONSTRAINT saml_service_providers_status_known CHECK (status IN ('active', 'disabled')),
    CONSTRAINT saml_service_providers_changed_after_created CHECK (updated_at >= created_at)
);

ALTER TABLE saml_service_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_service_providers FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON saml_service_providers
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX saml_service_providers_by_created
    ON saml_service_providers (tenant_id, created_at, id);

-- The SAML apps each session here signed in to, each sign-in once, so a
-- logout reaches every one of them.
CREATE TABLE saml_app_sessions (
    tenant_id uuid NOT NULL,
    -- Our session the app's sign-in stands on, linked to sessions in 0018.
    session_id uuid NOT NULL,
    provider_id uuid NOT NULL,
    name_id text NOT NULL,
    session_index text NOT NULL,
    PRIMARY KEY (tenant_id, session_id, provider_id, session_index),
    -- An app that is gone is sent no logout.
    FOREIGN KEY (tenant_id, provider_id)
        REFERENCES saml_service_providers (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE saml_app_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_app_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON saml_app_sessions
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX saml_app_sessions_of_provider ON saml_app_sessions (tenant_id, provider_id);

-- An app's sign-in request, held as it reached this platform until the
-- person it is for has signed in and it is answered. The time it arrived
-- is set here, never by the browser.
CREATE TABLE held_saml_sign_ins (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    binding text NOT NULL,
    -- The signature the HTTP-Redirect binding carried beside the message,
    -- all three or none, and none for a posted message.
    signature_algorithm text,
    signature text,
    signed_query text,
    message text NOT NULL,
    relay_state text,
    arrived_at timestamptz NOT NULL,
    CONSTRAINT held_saml_sign_ins_binding_known CHECK (binding IN ('post', 'redirect')),
    CONSTRAINT held_saml_sign_ins_signature_whole
        CHECK (num_nonnulls(signature_algorithm, signature, signed_query) IN (0, 3)),
    CONSTRAINT held_saml_sign_ins_signed_only_redirected
        CHECK (binding = 'redirect' OR signature IS NULL)
);

ALTER TABLE held_saml_sign_ins ENABLE ROW LEVEL SECURITY;
ALTER TABLE held_saml_sign_ins FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON held_saml_sign_ins
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The requests held past their ten minutes, cleared as new ones arrive.
CREATE INDEX held_saml_sign_ins_by_arrival ON held_saml_sign_ins (tenant_id, arrived_at);

-- The tenant's SCIM endpoint, at most one, its bearer token kept as a hash.
CREATE TABLE scim_endpoints (
    tenant_id uuid PRIMARY KEY,
    bearer_token_hash text NOT NULL,
    enabled boolean NOT NULL,
    default_role_id uuid,
    -- Whether a provisioned user may sign in at once, or once they
    -- confirm their address.
    auto_activate boolean NOT NULL,
    -- Whether removing a user switches the account off, or deletes it.
    deactivate_on_remove boolean NOT NULL,
    last_sync_at timestamptz,
    created_at timestamptz NOT NULL,
    -- A role provisioned users are given is never deleted from under the
    -- endpoint: people provisioned after would get a role that is gone.
    CONSTRAINT scim_endpoints_default_role_fkey FOREIGN KEY (tenant_id, default_role_id)
        REFERENCES roles (tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT scim_endpoints_synced_after_created
        CHECK (last_sync_at IS NULL OR last_sync_at >= created_at)
);

ALTER TABLE scim_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_endpoints FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON scim_endpoints
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX scim_endpoints_default_role ON scim_endpoints (tenant_id, default_role_id);

-- What a SCIM directory looks people and groups up by. An address is kept
-- in lower case already and is found through users_by_email; a display
-- name or group name keeps its case, so it is found by its lower case.
CREATE INDEX users_scim_display_name ON users (tenant_id, lower(display_name));
CREATE INDEX users_scim_external_id ON users (tenant_id, external_id);
CREATE INDEX groups_scim_name ON groups (tenant_id, lower(name)) WHERE origin = 'directory';

-- The logout requests a tenant's peers sent that were taken, by the peer
-- that issued each and its ID, kept until each is too old to be taken
-- anyway. A signed logout request ends a person's sessions whenever it
-- arrives, so each is taken once.
CREATE TABLE taken_logout_requests (
    tenant_id uuid NOT NULL,
    -- The peer that issued the request, its entity id.
    issuer text NOT NULL,
    -- The request's own ID.
    request_id text NOT NULL,
    -- When the request stops being taken, and can be forgotten.
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, issuer, request_id),
    CONSTRAINT taken_logout_requests_issuer_named CHECK (issuer <> ''),
    CONSTRAINT taken_logout_requests_id_named CHECK (request_id <> '')
);

ALTER TABLE taken_logout_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE taken_logout_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON taken_logout_requests
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A tenant's taken requests by when they can be forgotten.
CREATE INDEX taken_logout_requests_expiring ON taken_logout_requests (tenant_id, expires_at);
