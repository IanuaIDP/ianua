-- A tenant's own configuration records: the keys it signs tokens with and
-- the algorithm migration moving them, the consumers it lets through, the
-- LDAP client certificates and directory service accounts its directory
-- accepts, and the rules it classifies response fields by.
--
-- Every table is a tenant table: it lives in the platform database and in
-- a tenant's own, so it names no platform table. Row-level security keeps
-- each row to its tenant, and every foreign key carries the tenant too, so
-- a row can never point at another tenant's.
--
-- The checks repeat the rules the domain keeps between columns, so a row
-- written past the domain is refused here too.

-- A tenant's signing keys. A key set only grows: a key leaves service by
-- rotation and revocation, never by being removed.
CREATE TABLE signing_keys (
    tenant_id uuid NOT NULL,
    kid text NOT NULL,
    algorithm text NOT NULL,
    public_key text NOT NULL,
    -- The private key, sealed by the platform's secret sealer before it is
    -- written. It is never kept in clear.
    private_key_sealed text NOT NULL,
    status text NOT NULL,
    -- When the key stopped signing, kept after a revocation that followed.
    rotated_at timestamptz,
    -- When the key stops signing, or NULL for never.
    expires_at timestamptz,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, kid),
    CONSTRAINT signing_keys_algorithm_known
        CHECK (algorithm IN ('RS256', 'ES256', 'EdDSA')),
    CONSTRAINT signing_keys_status_known
        CHECK (status IN ('active', 'rotated', 'revoked')),
    CONSTRAINT signing_keys_rotation_fits_status
        CHECK ((status = 'active' AND rotated_at IS NULL)
            OR (status = 'rotated' AND rotated_at IS NOT NULL)
            OR status = 'revoked'),
    CONSTRAINT signing_keys_rotated_after_created
        CHECK (rotated_at IS NULL OR rotated_at >= created_at)
);

ALTER TABLE signing_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE signing_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON signing_keys
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The tenants holding a rotated key, for the sweep that revokes it once
-- its grace is over.
CREATE INDEX signing_keys_rotated ON signing_keys (tenant_id) WHERE status = 'rotated';

-- The active keys by age, for the sweep that rotates the old ones.
CREATE INDEX signing_keys_active_by_age ON signing_keys (created_at, tenant_id)
    WHERE status = 'active';

-- The latest algorithm migration of each tenant. A new one is planned only
-- once the last has finished, and replaces it; the audit log keeps every
-- step of the one before.
CREATE TABLE algorithm_migrations (
    tenant_id uuid PRIMARY KEY,
    source_algorithm text NOT NULL,
    target_algorithm text NOT NULL,
    source_kid text NOT NULL,
    status text NOT NULL,
    -- The key the migration moves onto, from the moment it is started.
    target_kid text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    -- The key a migration moves away from stays while the migration names
    -- it.
    CONSTRAINT algorithm_migrations_source_fkey FOREIGN KEY (tenant_id, source_kid)
        REFERENCES signing_keys (tenant_id, kid) ON DELETE RESTRICT,
    -- The key a migration moves onto stays while the migration names it.
    CONSTRAINT algorithm_migrations_target_fkey FOREIGN KEY (tenant_id, target_kid)
        REFERENCES signing_keys (tenant_id, kid) ON DELETE RESTRICT,
    CONSTRAINT algorithm_migrations_algorithms_known
        CHECK (source_algorithm IN ('RS256', 'ES256', 'EdDSA')
            AND target_algorithm IN ('RS256', 'ES256', 'EdDSA')),
    CONSTRAINT algorithm_migrations_moves
        CHECK (source_algorithm <> target_algorithm),
    CONSTRAINT algorithm_migrations_status_known
        CHECK (status IN ('planned', 'in_progress', 'validating', 'completed', 'rolled_back', 'cancelled')),
    CONSTRAINT algorithm_migrations_target_fits_status
        CHECK ((status IN ('planned', 'cancelled')) = (target_kid IS NULL)),
    CONSTRAINT algorithm_migrations_onto_another_key
        CHECK (target_kid IS NULL OR target_kid <> source_kid),
    CONSTRAINT algorithm_migrations_changed_after_created
        CHECK (updated_at >= created_at)
);

ALTER TABLE algorithm_migrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE algorithm_migrations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON algorithm_migrations
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The keys a migration names, for their foreign keys.
CREATE INDEX algorithm_migrations_from_key ON algorithm_migrations (tenant_id, source_kid);
CREATE INDEX algorithm_migrations_onto_key ON algorithm_migrations (tenant_id, target_kid);

-- The consumers a tenant lets through the gateway: the credential each
-- signs in with now, and the one a rotation keeps working for a while.
-- Each credential fills the columns of its kind and leaves the others
-- empty.
CREATE TABLE consumers (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    description text,
    credential_kind text NOT NULL,
    key_prefix text,
    key_hash text,
    cert_fingerprint text,
    jwt_issuer text,
    jwt_subject text,
    jwks_uri text,
    -- When the credential stops working, or NULL for never.
    credential_expires_at timestamptz,
    -- The credential a rotation replaced, kept working until
    -- previous_until, or NULL in every column once none is kept.
    previous_kind text,
    previous_key_prefix text,
    previous_key_hash text,
    previous_cert_fingerprint text,
    previous_jwt_issuer text,
    previous_jwt_subject text,
    previous_jwks_uri text,
    previous_expires_at timestamptz,
    previous_until timestamptz,
    -- The allowance, or NULL in both for an unlimited consumer.
    quota_requests bigint,
    quota_period text,
    status text NOT NULL,
    clearance text NOT NULL,
    created_by jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    -- What a gateway finds a consumer by: the kind of credential and what
    -- names it, apart by a character no credential holds.
    current_credential text GENERATED ALWAYS AS (
        credential_kind || chr(31)
            || coalesce(key_prefix, cert_fingerprint, jwt_issuer || chr(31) || jwt_subject)
    ) STORED,
    previous_credential text GENERATED ALWAYS AS (
        previous_kind || chr(31)
            || coalesce(previous_key_prefix, previous_cert_fingerprint,
                        previous_jwt_issuer || chr(31) || previous_jwt_subject)
    ) STORED,
    CONSTRAINT consumers_tenant_id_key UNIQUE (tenant_id, id),
    -- One credential in use names one consumer, so a gateway never has
    -- to pick between two.
    CONSTRAINT consumers_credential_key UNIQUE (tenant_id, current_credential),
    CONSTRAINT consumers_credential_fits_kind
        CHECK ((credential_kind = 'api_key' AND num_nonnulls(key_prefix, key_hash) = 2
                AND num_nonnulls(cert_fingerprint, jwt_issuer, jwt_subject, jwks_uri) = 0)
            OR (credential_kind = 'client_cert' AND cert_fingerprint IS NOT NULL
                AND num_nonnulls(key_prefix, key_hash, jwt_issuer, jwt_subject, jwks_uri) = 0)
            OR (credential_kind = 'jwt_bearer' AND num_nonnulls(jwt_issuer, jwt_subject, jwks_uri) = 3
                AND num_nonnulls(key_prefix, key_hash, cert_fingerprint) = 0)),
    CONSTRAINT consumers_previous_fits_kind
        CHECK ((previous_kind IS NULL
                AND num_nonnulls(previous_key_prefix, previous_key_hash, previous_cert_fingerprint,
                                 previous_jwt_issuer, previous_jwt_subject, previous_jwks_uri,
                                 previous_expires_at, previous_until) = 0)
            OR (previous_kind = 'api_key' AND previous_until IS NOT NULL
                AND num_nonnulls(previous_key_prefix, previous_key_hash) = 2
                AND num_nonnulls(previous_cert_fingerprint, previous_jwt_issuer,
                                 previous_jwt_subject, previous_jwks_uri) = 0)
            OR (previous_kind = 'client_cert' AND previous_until IS NOT NULL
                AND previous_cert_fingerprint IS NOT NULL
                AND num_nonnulls(previous_key_prefix, previous_key_hash, previous_jwt_issuer,
                                 previous_jwt_subject, previous_jwks_uri) = 0)
            OR (previous_kind = 'jwt_bearer' AND previous_until IS NOT NULL
                AND num_nonnulls(previous_jwt_issuer, previous_jwt_subject, previous_jwks_uri) = 3
                AND num_nonnulls(previous_key_prefix, previous_key_hash,
                                 previous_cert_fingerprint) = 0)),
    CONSTRAINT consumers_quota_whole
        CHECK (num_nulls(quota_requests, quota_period) IN (0, 2)),
    CONSTRAINT consumers_quota_period_known
        CHECK (quota_period IN ('minute', 'hour', 'day', 'month')),
    CONSTRAINT consumers_quota_positive
        CHECK (quota_requests > 0),
    CONSTRAINT consumers_status_known
        CHECK (status IN ('active', 'disabled')),
    CONSTRAINT consumers_clearance_known
        CHECK (clearance IN ('public', 'internal', 'confidential', 'restricted')),
    CONSTRAINT consumers_changed_after_created
        CHECK (updated_at >= created_at)
);

ALTER TABLE consumers ENABLE ROW LEVEL SECURITY;
ALTER TABLE consumers FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON consumers
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- One index per order a consumer list can ask for, the id last.
CREATE INDEX consumers_by_created ON consumers (tenant_id, created_at, id);
CREATE INDEX consumers_by_updated ON consumers (tenant_id, updated_at, id);
CREATE INDEX consumers_by_name ON consumers (tenant_id, name, id);
CREATE INDEX consumers_by_status ON consumers (tenant_id, status, id);

-- The consumer a replaced credential still names during its overlap.
CREATE INDEX consumers_by_previous_credential ON consumers (tenant_id, previous_credential);

-- The client certificates a tenant's people bind to its LDAP directory
-- with.
CREATE TABLE ldap_certificates (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    fingerprint text NOT NULL,
    device_label text NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    -- A certificate presented names one record, so a bind never has to
    -- pick between two.
    CONSTRAINT ldap_certificates_fingerprint_key UNIQUE (tenant_id, fingerprint),
    -- A certificate proves nothing without the account it was issued to,
    -- so it goes with the account. That it was issued is in the audit log.
    CONSTRAINT ldap_certificates_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT ldap_certificates_expire_after_issued
        CHECK (expires_at > issued_at),
    CONSTRAINT ldap_certificates_revoked_after_issued
        CHECK (revoked_at IS NULL OR revoked_at >= issued_at)
);

ALTER TABLE ldap_certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE ldap_certificates FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON ldap_certificates
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A person's certificates in the order they were issued, and the foreign
-- key to the account.
CREATE INDEX ldap_certificates_of_user ON ldap_certificates (tenant_id, user_id, issued_at, id);

-- The accounts applications bind to a tenant's directory as.
CREATE TABLE directory_service_accounts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    secret_hash text NOT NULL,
    access text NOT NULL,
    base_dns text[] NOT NULL,
    status text NOT NULL,
    created_at timestamptz NOT NULL,
    secret_changed_at timestamptz NOT NULL,
    -- The bind DN names the account by its name.
    CONSTRAINT directory_service_accounts_name_key UNIQUE (tenant_id, name),
    CONSTRAINT directory_service_accounts_access_known
        CHECK (access IN ('read_only', 'read_write')),
    CONSTRAINT directory_service_accounts_status_known
        CHECK (status IN ('active', 'disabled')),
    CONSTRAINT directory_service_accounts_base_dns_counted
        CHECK (cardinality(base_dns) BETWEEN 1 AND 16),
    CONSTRAINT directory_service_accounts_secret_after_created
        CHECK (secret_changed_at >= created_at)
);

ALTER TABLE directory_service_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE directory_service_accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON directory_service_accounts
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- Each tenant's one set of rules its response fields are classified by,
-- kept whole in the order they are evaluated.
CREATE TABLE classification_rule_sets (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    rules jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT classification_rule_sets_tenant_key UNIQUE (tenant_id),
    CONSTRAINT classification_rule_sets_changed_after_created
        CHECK (updated_at >= created_at)
);

ALTER TABLE classification_rule_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE classification_rule_sets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON classification_rule_sets
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A tenant's assertion keys: the key pairs the gateway signs the identity
-- it hands upstreams (X-Ianua-Assertion) with. Kept apart from the
-- tenant's signing keys: the gateway's role reads this table whole,
-- private halves included, and never the private half of a signing key,
-- so a gateway broken into cannot mint the tenant's tokens. The app's role
-- makes, rotates and retires the keys; the gateway's only reads them.
CREATE TABLE assertion_keys (
    tenant_id uuid NOT NULL,
    kid text NOT NULL,
    algorithm text NOT NULL,
    public_key text NOT NULL,
    -- The private half, sealed for its row by the platform's secret
    -- sealer before it is written. It is never kept in clear.
    private_key_sealed text NOT NULL,
    status text NOT NULL,
    -- When the key stopped signing, kept after the retirement that
    -- followed.
    rotated_at timestamptz,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, kid),
    CONSTRAINT assertion_keys_algorithm_known
        CHECK (algorithm IN ('RS256', 'ES256', 'EdDSA')),
    CONSTRAINT assertion_keys_status_known
        CHECK (status IN ('active', 'rotated', 'revoked')),
    CONSTRAINT assertion_keys_rotation_fits_status
        CHECK ((status = 'active' AND rotated_at IS NULL)
            OR (status = 'rotated' AND rotated_at IS NOT NULL)
            OR status = 'revoked'),
    CONSTRAINT assertion_keys_rotated_after_created
        CHECK (rotated_at IS NULL OR rotated_at >= created_at)
);

ALTER TABLE assertion_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE assertion_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON assertion_keys
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- One key of a tenant signs at a time, so which one signs is never a guess.
CREATE UNIQUE INDEX assertion_keys_one_active ON assertion_keys (tenant_id)
    WHERE status = 'active';

-- The tenants holding a rotated key, for the sweep that retires it once
-- its overlap is over.
CREATE INDEX assertion_keys_rotated ON assertion_keys (tenant_id) WHERE status = 'rotated';

-- The active keys by age, for the sweep that rotates the old ones.
CREATE INDEX assertion_keys_active_by_age ON assertion_keys (created_at, tenant_id)
    WHERE status = 'active';
