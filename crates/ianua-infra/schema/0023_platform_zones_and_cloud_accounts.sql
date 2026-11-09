-- The DNS zones tenants delegated to us and the records we answer from
-- them, and the connections organizations made to their own cloud
-- accounts.
--
-- Platform tables, in the platform database only. A zone answers for a
-- hostname of the whole deployment, so it is kept beside the claim on that
-- name, which is kept here whichever database the tenant's registration
-- lives in; the nameservers read every zone with no tenant in hand. A
-- cloud connection is an organization's, and it is what is read to reach a
-- tenant's own database, so it can never live inside one.
--
-- A table that carries a tenant's id is under row-level security like
-- every tenant table.

-- A zone a tenant delegated to us: one hostname, the nameservers its
-- delegation names, and when what it answers last changed.
CREATE TABLE dns_zones (
    hostname text PRIMARY KEY,
    tenant_id uuid NOT NULL,
    -- The registration's own nameserver names, worked out from its label
    -- when the zone was opened, and kept, since the tenant's delegation
    -- names them.
    nameservers text[] NOT NULL,
    -- What the zone's serial is read from.
    changed_at timestamptz NOT NULL,
    CONSTRAINT dns_zones_tenant_hostname_key UNIQUE (tenant_id, hostname),
    -- A zone answers for a name its tenant claims: releasing the claim
    -- closes the zone, and a handover moving the claim moves the zone.
    CONSTRAINT dns_zones_claim_fkey FOREIGN KEY (tenant_id, hostname)
        REFERENCES domain_claims (tenant_id, hostname) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT dns_zones_some_nameserver CHECK (cardinality(nameservers) > 0)
);

ALTER TABLE dns_zones ENABLE ROW LEVEL SECURITY;
ALTER TABLE dns_zones FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON dns_zones
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- Every answer a zone gives to one question: a name and a type, with its
-- values as a zone file spells them.
CREATE TABLE dns_records (
    tenant_id uuid NOT NULL,
    hostname text NOT NULL,
    name text NOT NULL,
    kind text NOT NULL,
    ttl integer NOT NULL,
    record_values text[] NOT NULL,
    PRIMARY KEY (hostname, name, kind),
    -- A record is part of its zone, and follows it to another tenant.
    CONSTRAINT dns_records_zone_fkey FOREIGN KEY (tenant_id, hostname)
        REFERENCES dns_zones (tenant_id, hostname) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT dns_records_kind_known
        CHECK (kind IN ('A', 'AAAA', 'CNAME', 'TXT', 'MX', 'SRV', 'CAA')),
    CONSTRAINT dns_records_ttl_in_range CHECK (ttl BETWEEN 60 AND 3600),
    CONSTRAINT dns_records_some_value CHECK (cardinality(record_values) > 0)
);

ALTER TABLE dns_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE dns_records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON dns_records
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A tenant's records of one zone, and the foreign key to it.
CREATE INDEX dns_records_of_zone ON dns_records (tenant_id, hostname, name, kind);

-- An organization's connection to one of its own cloud accounts, one per
-- cloud.
CREATE TABLE org_cloud_accounts (
    -- A connection goes with its organization.
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    provider text NOT NULL,
    -- The shared secret the customer places in their role's trust policy,
    -- sealed by the platform's secret sealer. It is made when the
    -- connection is begun and never replaced.
    external_id_sealed text NOT NULL,
    state text NOT NULL,
    -- The credential, sealed by the platform's secret sealer, or NULL while
    -- the connection waits for one.
    credential_sealed text,
    -- When the credential was last proved or refused.
    checked_at timestamptz,
    -- The account the credential opened, for a verified connection.
    verified_identity text,
    -- Why the cloud refused the credential, for a failed connection.
    failure_reason text,
    -- The account the connection is tied to since it was first verified.
    bound_identity text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id, provider),
    CONSTRAINT org_cloud_accounts_provider_known
        CHECK (provider IN ('aws', 'gcp', 'azure', 'digitalocean', 'kubernetes')),
    CONSTRAINT org_cloud_accounts_state_known
        CHECK (state IN ('awaiting_credential', 'awaiting_verification', 'verified', 'failed')),
    CONSTRAINT org_cloud_accounts_credential_fits_state
        CHECK ((state = 'awaiting_credential') = (credential_sealed IS NULL)),
    CONSTRAINT org_cloud_accounts_check_fits_state
        CHECK ((state IN ('verified', 'failed')) = (checked_at IS NOT NULL)),
    CONSTRAINT org_cloud_accounts_identity_fits_state
        CHECK ((state = 'verified') = (verified_identity IS NOT NULL)),
    CONSTRAINT org_cloud_accounts_reason_fits_state
        CHECK ((state = 'failed') = (failure_reason IS NOT NULL)),
    CONSTRAINT org_cloud_accounts_verified_where_bound
        CHECK (state <> 'verified' OR bound_identity = verified_identity),
    CONSTRAINT org_cloud_accounts_checked_after_begun CHECK (checked_at >= created_at),
    CONSTRAINT org_cloud_accounts_changed_after_begun CHECK (updated_at >= created_at)
);
