-- The OAuth context: a tenant's clients and the initial access tokens apps
-- register themselves with, the codes, consents, pushed requests, access
-- and refresh tokens and device grants the flows leave behind, the client
-- assertions and DPoP proofs already used, and the tenant's API keys.
--
-- Every table is a tenant table: it lives in the platform database and in
-- a tenant's own, so it names no platform table. Row-level security keeps
-- each row to its tenant, and every foreign key carries the tenant too, so
-- a row can never point at another tenant's.
--
-- No secret is kept as it was handed out. Codes, tokens, keys and client
-- secrets are kept as their hashes; a device's user code, which the person
-- who approves it reads back, as its keyed hash to find it by and sealed to
-- show it.
--
-- The checks repeat the rules the domain keeps between columns, so a row
-- written past the domain is refused here too.

-- The tokens a tenant hands out so apps may register themselves as
-- clients, a set number of times.
CREATE TABLE oauth_initial_access_tokens (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    token_hash text NOT NULL,
    uses_left integer NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CONSTRAINT oauth_initial_access_tokens_tenant_id_key UNIQUE (tenant_id, id),
    CONSTRAINT oauth_initial_access_tokens_token_key UNIQUE (tenant_id, token_hash),
    CONSTRAINT oauth_initial_access_tokens_uses_in_range
        CHECK (uses_left BETWEEN 0 AND 1000),
    CONSTRAINT oauth_initial_access_tokens_expires_after_created
        CHECK (expires_at > created_at),
    CONSTRAINT oauth_initial_access_tokens_revoked_after_created
        CHECK (revoked_at >= created_at)
);

ALTER TABLE oauth_initial_access_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_initial_access_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON oauth_initial_access_tokens
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The tenant's tokens, newest first.
CREATE INDEX oauth_initial_access_tokens_by_created
    ON oauth_initial_access_tokens (tenant_id, created_at, id);

CREATE TABLE oauth_clients (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    -- The public client id sent in OAuth requests.
    client_id_value text NOT NULL,
    -- How the client proves itself: a secret's hashes, its keys, its
    -- certificate's subject, or nothing for a public client.
    credential jsonb NOT NULL,
    name text NOT NULL,
    redirect_uris text[] NOT NULL,
    post_logout_redirect_uris text[] NOT NULL,
    grant_types text[] NOT NULL,
    scopes text[] NOT NULL,
    settings jsonb NOT NULL,
    -- A client that registered itself: the hash of its registration access
    -- token, and the initial access token it was admitted with. Both NULL
    -- for one the tenant's admins manage alone.
    registration_token_hash text,
    admitted_with_id uuid,
    status text NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT oauth_clients_tenant_id_key UNIQUE (tenant_id, id),
    CONSTRAINT oauth_clients_client_id_key UNIQUE (tenant_id, client_id_value),
    CONSTRAINT oauth_clients_grant_types_known
        CHECK (cardinality(grant_types) > 0 AND grant_types <@ ARRAY['authorization_code',
            'client_credentials', 'refresh_token', 'device_code', 'token_exchange']),
    CONSTRAINT oauth_clients_status_known
        CHECK (status IN ('active', 'revoked')),
    CONSTRAINT oauth_clients_self_management_whole
        CHECK ((registration_token_hash IS NULL) = (admitted_with_id IS NULL)),
    -- The initial access token a client registered with stays on record,
    -- revoked or spent, so the clients a leaked one let in can be found.
    CONSTRAINT oauth_clients_admitted_with_fkey
        FOREIGN KEY (tenant_id, admitted_with_id)
        REFERENCES oauth_initial_access_tokens (tenant_id, id) ON DELETE RESTRICT
);

ALTER TABLE oauth_clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_clients FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON oauth_clients
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- One index per order a client list can ask for, the id last, alone and
-- narrowed to one status.
CREATE INDEX oauth_clients_by_created ON oauth_clients (tenant_id, created_at, id);
CREATE INDEX oauth_clients_by_name ON oauth_clients (tenant_id, name, id);
CREATE INDEX oauth_clients_by_status ON oauth_clients (tenant_id, status, id);
CREATE INDEX oauth_clients_in_status_by_created
    ON oauth_clients (tenant_id, status, created_at, id);
CREATE INDEX oauth_clients_in_status_by_name ON oauth_clients (tenant_id, status, name, id);

-- The clients one initial access token let in, for its foreign key.
CREATE INDEX oauth_clients_admitted_with ON oauth_clients (tenant_id, admitted_with_id);

-- Authorization codes, each found by its hash.
CREATE TABLE oauth_codes (
    tenant_id uuid NOT NULL,
    code_hash text NOT NULL,
    client_id uuid NOT NULL,
    user_id uuid NOT NULL,
    redirect_uri text NOT NULL,
    scopes text[] NOT NULL,
    code_challenge text NOT NULL,
    code_challenge_method text NOT NULL,
    -- The OIDC nonce the request carried, or NULL when it sent none.
    nonce text,
    -- The session the code was consented in, linked to sessions in 0018.
    session_id uuid NOT NULL,
    auth_method text NOT NULL,
    -- The second factor the consenting session proved, or NULL for none.
    second_factor text,
    authenticated_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    PRIMARY KEY (tenant_id, code_hash),
    -- A code is worth nothing without the client it was issued to.
    CONSTRAINT oauth_codes_client_fkey FOREIGN KEY (tenant_id, client_id)
        REFERENCES oauth_clients (tenant_id, id) ON DELETE CASCADE,
    -- A code hands out tokens for its person, so it goes with their account.
    CONSTRAINT oauth_codes_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT oauth_codes_challenge_method_known
        CHECK (code_challenge_method IN ('s256')),
    CONSTRAINT oauth_codes_auth_method_known
        CHECK (auth_method IN ('password', 'magic_link', 'passkey', 'saml', 'oidc')),
    CONSTRAINT oauth_codes_second_factor_known
        CHECK (second_factor IN ('totp', 'email_code', 'sms_code', 'recovery_code',
            'hardware_key', 'passkey', 'email_confirmation', 'provider_multi_factor',
            'provider_hardware_key')),
    CONSTRAINT oauth_codes_signed_in_before_issued
        CHECK (authenticated_at <= created_at),
    CONSTRAINT oauth_codes_expires_after_created
        CHECK (expires_at > created_at),
    CONSTRAINT oauth_codes_consumed_after_created
        CHECK (consumed_at >= created_at)
);

ALTER TABLE oauth_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON oauth_codes
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The codes of one client, for its foreign key.
CREATE INDEX oauth_codes_of_client ON oauth_codes (tenant_id, client_id);
-- The clients and sessions a person consented in, told of a sign-out.
CREATE INDEX oauth_codes_of_user ON oauth_codes (tenant_id, user_id, client_id, session_id);

-- The scopes one person gave one client.
CREATE TABLE oauth_consents (
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    client_id uuid NOT NULL,
    scopes text[] NOT NULL,
    granted_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, user_id, client_id),
    -- A consent is the person's own word and goes with their account.
    CONSTRAINT oauth_consents_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    -- A consent given to a client means nothing without it.
    CONSTRAINT oauth_consents_client_fkey FOREIGN KEY (tenant_id, client_id)
        REFERENCES oauth_clients (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE oauth_consents ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_consents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON oauth_consents
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A person's consents, newest first.
CREATE INDEX oauth_consents_of_user ON oauth_consents (tenant_id, user_id, granted_at, client_id);
-- The consents given to one client, for its foreign key.
CREATE INDEX oauth_consents_to_client ON oauth_consents (tenant_id, client_id);

-- Authorization requests clients pushed (RFC 9126), each living sixty
-- seconds.
CREATE TABLE oauth_pushed_requests (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    client_id uuid NOT NULL,
    parameters jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    -- A request only the client that pushed it may use goes with it.
    CONSTRAINT oauth_pushed_requests_client_fkey FOREIGN KEY (tenant_id, client_id)
        REFERENCES oauth_clients (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT oauth_pushed_requests_expires_after_created
        CHECK (expires_at > created_at),
    CONSTRAINT oauth_pushed_requests_live_a_minute
        CHECK (expires_at <= created_at + interval '60 seconds'),
    CONSTRAINT oauth_pushed_requests_used_after_created
        CHECK (used_at >= created_at)
);

ALTER TABLE oauth_pushed_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_pushed_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON oauth_pushed_requests
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The requests of one client, for its foreign key.
CREATE INDEX oauth_pushed_requests_of_client ON oauth_pushed_requests (tenant_id, client_id);
-- The tenant's requests by expiry, dropped once it passed.
CREATE INDEX oauth_pushed_requests_expiring ON oauth_pushed_requests (tenant_id, expires_at);

-- Issued access tokens, each found by its hash.
CREATE TABLE oauth_access_tokens (
    tenant_id uuid NOT NULL,
    token_hash text NOT NULL,
    client_id uuid NOT NULL,
    -- The person it acts for, or NULL for a client acting as itself.
    user_id uuid,
    scopes text[] NOT NULL,
    -- The client it was exchanged for, or NULL when meant for its holder.
    audience_client_id uuid,
    -- Who acts for its subject, outermost first, as the token was issued
    -- with them: its `act` claim, a record that stays as it was written,
    -- not a link to keep.
    delegation jsonb NOT NULL,
    -- What it must be presented with, and the thumbprint of the key or
    -- certificate it is bound to.
    binding text NOT NULL,
    binding_thumbprint text,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    -- The stream route whose signed-in tunnel a resource indicator asked
    -- the token for (RFC 8707), or NULL for any other token. It names the
    -- route the way an exchanged token names its client, and at most one
    -- of the two.
    audience_stream_route_id uuid,
    PRIMARY KEY (tenant_id, token_hash),
    -- A token is worth nothing without the client holding it.
    CONSTRAINT oauth_access_tokens_client_fkey FOREIGN KEY (tenant_id, client_id)
        REFERENCES oauth_clients (tenant_id, id) ON DELETE CASCADE,
    -- A token meant for a tunnel is worth nothing without its route.
    CONSTRAINT oauth_access_tokens_audience_stream_route_fkey
        FOREIGN KEY (tenant_id, audience_stream_route_id)
        REFERENCES stream_routes (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT oauth_access_tokens_one_audience
        CHECK (audience_client_id IS NULL OR audience_stream_route_id IS NULL),
    -- Only a person's grant asks for a tunnel.
    CONSTRAINT oauth_access_tokens_tunnel_for_a_person
        CHECK (audience_stream_route_id IS NULL OR user_id IS NOT NULL),
    -- A token acting for a person goes with their account.
    CONSTRAINT oauth_access_tokens_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    -- A token meant for a client is worth nothing without it.
    CONSTRAINT oauth_access_tokens_audience_fkey FOREIGN KEY (tenant_id, audience_client_id)
        REFERENCES oauth_clients (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT oauth_access_tokens_binding_known
        CHECK (binding IN ('bearer', 'dpop', 'certificate')),
    CONSTRAINT oauth_access_tokens_binding_whole
        CHECK ((binding = 'bearer') = (binding_thumbprint IS NULL)),
    CONSTRAINT oauth_access_tokens_expires_after_created
        CHECK (expires_at > created_at),
    CONSTRAINT oauth_access_tokens_revoked_after_created
        CHECK (revoked_at >= created_at)
);

ALTER TABLE oauth_access_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_access_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON oauth_access_tokens
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The tokens of one client, and of the client they are meant for, for
-- their foreign keys.
CREATE INDEX oauth_access_tokens_of_client ON oauth_access_tokens (tenant_id, client_id);
CREATE INDEX oauth_access_tokens_for_audience
    ON oauth_access_tokens (tenant_id, audience_client_id);
-- The tokens one client holds for one person, revoked with their consent.
CREATE INDEX oauth_access_tokens_of_grant ON oauth_access_tokens (tenant_id, user_id, client_id);
-- The tokens meant for one stream route, for its foreign key.
CREATE INDEX oauth_access_tokens_for_stream_route
    ON oauth_access_tokens (tenant_id, audience_stream_route_id);

-- Refresh tokens, each found by its hash, rotated within their family.
CREATE TABLE oauth_refresh_tokens (
    tenant_id uuid NOT NULL,
    token_hash text NOT NULL,
    -- no foreign key: a family is no row of its own, only the id its
    -- tokens share.
    family_id uuid NOT NULL,
    client_id uuid NOT NULL,
    user_id uuid NOT NULL,
    scopes text[] NOT NULL,
    -- The session the grant was given in, linked to sessions in 0018;
    -- NULL for a grant given on a second screen, approving a device.
    session_id uuid,
    binding text NOT NULL,
    binding_thumbprint text,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    family_expires_at timestamptz NOT NULL,
    state text NOT NULL,
    -- When it was rotated or revoked, or NULL while it is active.
    ended_at timestamptz,
    PRIMARY KEY (tenant_id, token_hash),
    -- A token is worth nothing without the client holding it.
    CONSTRAINT oauth_refresh_tokens_client_fkey FOREIGN KEY (tenant_id, client_id)
        REFERENCES oauth_clients (tenant_id, id) ON DELETE CASCADE,
    -- A token acts for its person, so it goes with their account.
    CONSTRAINT oauth_refresh_tokens_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT oauth_refresh_tokens_binding_known
        CHECK (binding IN ('bearer', 'dpop', 'certificate')),
    CONSTRAINT oauth_refresh_tokens_binding_whole
        CHECK ((binding = 'bearer') = (binding_thumbprint IS NULL)),
    CONSTRAINT oauth_refresh_tokens_state_known
        CHECK (state IN ('active', 'rotated', 'revoked')),
    CONSTRAINT oauth_refresh_tokens_ended_fits_state
        CHECK ((state = 'active') = (ended_at IS NULL)),
    CONSTRAINT oauth_refresh_tokens_expires_after_issued
        CHECK (expires_at > issued_at),
    CONSTRAINT oauth_refresh_tokens_within_family
        CHECK (expires_at <= family_expires_at),
    CONSTRAINT oauth_refresh_tokens_ended_after_issued
        CHECK (ended_at >= issued_at)
);

ALTER TABLE oauth_refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_refresh_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON oauth_refresh_tokens
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The tokens of one client, for its foreign key.
CREATE INDEX oauth_refresh_tokens_of_client ON oauth_refresh_tokens (tenant_id, client_id);
-- The tokens one client holds for one person, revoked with their consent.
CREATE INDEX oauth_refresh_tokens_of_grant
    ON oauth_refresh_tokens (tenant_id, user_id, client_id);
-- The tokens of one family, revoked when one of it is used twice.
CREATE INDEX oauth_refresh_tokens_of_family ON oauth_refresh_tokens (tenant_id, family_id);
-- The tokens granted in one session, revoked when the person signs out.
CREATE INDEX oauth_refresh_tokens_of_session ON oauth_refresh_tokens (tenant_id, session_id);

-- Device authorization requests (RFC 8628), each found by the hash of its
-- device code or of its user code.
CREATE TABLE oauth_device_authorizations (
    tenant_id uuid NOT NULL,
    device_code_hash text NOT NULL,
    -- The user code's keyed hash, which a typed code is found by, and the
    -- code sealed, which the approval page shows.
    user_code_hash text NOT NULL,
    user_code_sealed text NOT NULL,
    client_id uuid NOT NULL,
    scopes text[] NOT NULL,
    status text NOT NULL,
    -- Who approved it, once someone did.
    approved_by uuid,
    interval_secs integer NOT NULL,
    last_polled_at timestamptz,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, device_code_hash),
    CONSTRAINT oauth_device_authorizations_user_code_key UNIQUE (tenant_id, user_code_hash),
    -- A request started by a client is worth nothing without it.
    CONSTRAINT oauth_device_authorizations_client_fkey FOREIGN KEY (tenant_id, client_id)
        REFERENCES oauth_clients (tenant_id, id) ON DELETE CASCADE,
    -- An approval hands out tokens for its approver, so it goes with their
    -- account.
    CONSTRAINT oauth_device_authorizations_approver_fkey FOREIGN KEY (tenant_id, approved_by)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT oauth_device_authorizations_status_known
        CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'redeemed')),
    CONSTRAINT oauth_device_authorizations_approver_fits_status
        CHECK ((status IN ('approved', 'redeemed')) = (approved_by IS NOT NULL)),
    CONSTRAINT oauth_device_authorizations_interval_in_range
        CHECK (interval_secs BETWEEN 1 AND 65535),
    CONSTRAINT oauth_device_authorizations_expires_after_created
        CHECK (expires_at > created_at),
    CONSTRAINT oauth_device_authorizations_polled_after_created
        CHECK (last_polled_at >= created_at)
);

ALTER TABLE oauth_device_authorizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_device_authorizations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON oauth_device_authorizations
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The requests of one client and the approvals of one person, for their
-- foreign keys.
CREATE INDEX oauth_device_authorizations_of_client
    ON oauth_device_authorizations (tenant_id, client_id);
CREATE INDEX oauth_device_authorizations_of_approver
    ON oauth_device_authorizations (tenant_id, approved_by);
-- The requests still waiting, by expiry: the sweep reads each tenant
-- through its current database route.
CREATE INDEX oauth_device_authorizations_lapsing_of_tenant
    ON oauth_device_authorizations (tenant_id, expires_at)
    WHERE status = 'pending';

-- The client assertions already used (RFC 7523 3), each kept until it
-- would have expired anyway.
CREATE TABLE oauth_client_assertions (
    tenant_id uuid NOT NULL,
    client_id uuid NOT NULL,
    jti text NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, client_id, jti),
    -- An assertion proves only its client, so it goes with it.
    CONSTRAINT oauth_client_assertions_client_fkey FOREIGN KEY (tenant_id, client_id)
        REFERENCES oauth_clients (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE oauth_client_assertions ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_client_assertions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON oauth_client_assertions
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The tenant's used assertions by expiry, forgotten once it passed.
CREATE INDEX oauth_client_assertions_expiring ON oauth_client_assertions (tenant_id, expires_at);

-- The DPoP proofs already used (RFC 9449 11.1), each kept until it would
-- have been refused as too old anyway.
CREATE TABLE oauth_dpop_proofs (
    tenant_id uuid NOT NULL,
    thumbprint text NOT NULL,
    jti text NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, thumbprint, jti)
);

ALTER TABLE oauth_dpop_proofs ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_dpop_proofs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON oauth_dpop_proofs
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The tenant's used proofs by expiry, forgotten once it passed.
CREATE INDEX oauth_dpop_proofs_expiring ON oauth_dpop_proofs (tenant_id, expires_at);

-- A tenant's API keys. A revoked key is deleted, not flagged.
CREATE TABLE api_keys (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    key_prefix text NOT NULL,
    key_hash text NOT NULL,
    scopes text[] NOT NULL,
    -- Who made it: a tenant user or an organization member.
    created_by jsonb NOT NULL,
    -- When it stops working, or NULL when it never does.
    expires_at timestamptz,
    last_used_at timestamptz,
    last_used_ip text,
    created_at timestamptz NOT NULL,
    -- When it was paused, or NULL while it works: a paused key signs in
    -- nothing until resumed, and nothing about it is lost.
    paused_at timestamptz,
    -- The countries the key signed in from, oldest first, at most sixteen:
    -- a sign-in from one not here is recorded as news.
    seen_countries text[] NOT NULL DEFAULT '{}',
    -- A presented key is found by its prefix, so one prefix is one key.
    CONSTRAINT api_keys_key_prefix_key UNIQUE (tenant_id, key_prefix),
    CONSTRAINT api_keys_grants_something
        CHECK (cardinality(scopes) > 0),
    CONSTRAINT api_keys_address_of_a_use
        CHECK (last_used_ip IS NULL OR last_used_at IS NOT NULL),
    CONSTRAINT api_keys_used_after_created
        CHECK (last_used_at >= created_at),
    CONSTRAINT api_keys_expires_after_created
        CHECK (expires_at > created_at),
    CONSTRAINT api_keys_paused_after_created
        CHECK (paused_at IS NULL OR paused_at >= created_at),
    CONSTRAINT api_keys_seen_countries_bounded
        CHECK (cardinality(seen_countries) <= 16)
);

ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON api_keys
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- One index per order a key list can ask for, the id last.
CREATE INDEX api_keys_by_created ON api_keys (tenant_id, created_at, id);
CREATE INDEX api_keys_by_name ON api_keys (tenant_id, name, id);
CREATE INDEX api_keys_by_expiry ON api_keys (tenant_id, expires_at, id);
CREATE INDEX api_keys_by_last_used ON api_keys (tenant_id, last_used_at, id);
-- The keys that expire, for the sweep across every tenant in the platform
-- database; a tenant's own database is swept through the index by expiry.
CREATE INDEX api_keys_expiring ON api_keys (expires_at) WHERE expires_at IS NOT NULL;
-- A presented key is found by its digest alone, before the tenant it
-- belongs to is known, so the lookup needs a key of its own.
CREATE INDEX api_keys_by_hash ON api_keys (key_hash);
