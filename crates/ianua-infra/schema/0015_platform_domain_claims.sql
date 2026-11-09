-- What the domain context keeps for the whole platform: the claims on
-- hostnames, the certificates that serve them, the ACME challenges a
-- certificate authority reads, and the offers that hand a domain between
-- two tenants. Beside them, the address changes organization members and
-- operators asked for, the platform's accounts with certificate
-- authorities, and the certificates of each tenant's platform addresses.
--
-- Platform tables, in the platform database only. A hostname belongs to
-- the whole deployment: registering it stops every other tenant from
-- registering it, and the proxy and the sweeps find it with no tenant in
-- hand. A unique index on the tenants' registrations could not keep that,
-- since a tenant with a database of its own keeps them there. So the claim
-- is kept here, whichever database the registration lives in, and its
-- primary key keeps each name to one registration across every tenant.
--
-- A table that carries a tenant's id is under row-level security like
-- every tenant table.

CREATE TABLE domain_claims (
    hostname text PRIMARY KEY,
    -- The name's labels in reverse, a leading `*.` set aside, so the names
    -- above and below one are found by an index: `login.acme.com` is
    -- `com.acme.login`. Compared byte by byte.
    overlap_key text COLLATE "C" NOT NULL,
    -- A claim goes with its tenant.
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    -- no foreign key: the registration lives in the tenant's own database,
    -- which may not be this one.
    domain_id uuid NOT NULL,
    -- When the registration was made, and when its proof was lost, or
    -- NULL while it was never lost: what a new claim judges whether this
    -- one still holds its name by, without reading the tenant's database.
    claimed_at timestamptz NOT NULL,
    failed_at timestamptz,
    -- Whether the registration behind the claim proved its name, so the
    -- nameservers answer only for names that were proved.
    verified boolean NOT NULL DEFAULT false,
    CONSTRAINT domain_claims_domain_id_key UNIQUE (domain_id),
    CONSTRAINT domain_claims_lost_after_claimed CHECK (failed_at >= claimed_at),
    CONSTRAINT domain_claims_registration_key UNIQUE (tenant_id, domain_id),
    -- A proof standing now is not one that was lost.
    CONSTRAINT domain_claims_proved_or_lost CHECK (NOT (verified AND failed_at IS NOT NULL)),
    -- A delegated zone points at the claim it answers for by tenant and
    -- hostname.
    CONSTRAINT domain_claims_tenant_hostname_key UNIQUE (tenant_id, hostname)
);

ALTER TABLE domain_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE domain_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON domain_claims
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The names at, above and below one, whichever tenant holds them.
CREATE INDEX domain_claims_by_overlap ON domain_claims (overlap_key);

-- The certificates a registered domain serves, issued by the platform or
-- uploaded by its tenant, the newest saved last. They are kept beside the
-- claim, not with the registration, so the proxy and the renewal sweep
-- read them by domain with no tenant in hand, and a certificate stays with
-- its domain when a handover moves the claim to another tenant. The
-- private key is sealed by the crypto adapter before it is written.
CREATE TABLE domain_certificates (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    certificate_pem text NOT NULL,
    private_key text NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    source text NOT NULL,
    -- What an uploaded certificate says about itself; NULL for one the
    -- platform issued.
    issuer text,
    subject_names text[],
    -- The order certificates were saved in, so the newest is the one a
    -- domain serves.
    saved_order bigint GENERATED ALWAYS AS IDENTITY,
    -- A certificate serves only its domain, so it goes with the claim, and
    -- follows the claim to the tenant a handover gives it to.
    CONSTRAINT domain_certificates_claim_fkey FOREIGN KEY (tenant_id, domain_id)
        REFERENCES domain_claims (tenant_id, domain_id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT domain_certificates_source_known
        CHECK (source IN ('acme', 'uploaded')),
    CONSTRAINT domain_certificates_upload_whole
        CHECK ((source = 'uploaded') = (issuer IS NOT NULL AND subject_names IS NOT NULL)
            AND num_nonnulls(issuer, subject_names) IN (0, 2)),
    CONSTRAINT domain_certificates_names_some_host
        CHECK (subject_names IS NULL OR cardinality(subject_names) > 0),
    CONSTRAINT domain_certificates_expires_after_issued
        CHECK (expires_at > issued_at)
);

ALTER TABLE domain_certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE domain_certificates FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON domain_certificates
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A tenant's certificates of one domain, newest last, and the foreign key.
CREATE INDEX domain_certificates_of_claim
    ON domain_certificates (tenant_id, domain_id, saved_order);
-- One domain's certificates, newest last, for the proxy and the sweeps.
CREATE INDEX domain_certificates_of_domain ON domain_certificates (domain_id, saved_order);
-- The certificates running out soonest, for the renewal sweep.
CREATE INDEX domain_certificates_by_expiry ON domain_certificates (expires_at);

-- HTTP-01 challenges, published by the control plane and read by the proxy.
-- The certificate authority arrives on a customer's hostname with no session
-- and no tenant, carrying only the token it issued, so the token is the key
-- and the row belongs to no tenant. Rows live an hour at most.
CREATE TABLE acme_challenges (
    token text PRIMARY KEY,
    key_authorization text NOT NULL,
    domain text NOT NULL,
    expires_at timestamptz NOT NULL
);

-- The challenges past their expiry, for the sweep that removes them.
CREATE INDEX acme_challenges_by_expiry ON acme_challenges (expires_at);

-- Domains one tenant offered to another of its organization. An offer is
-- known by the giving tenant and the domain, so a domain is offered to one
-- tenant at a time; an accepted one is kept, spent. Both tenants may see
-- it.
CREATE TABLE domain_handover_offers (
    -- The giving tenant. An offer means nothing once either tenant is gone.
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    domain text NOT NULL,
    -- The receiving tenant.
    to_tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    offered_at timestamptz NOT NULL,
    -- When the receiving tenant accepted it, or NULL while it waits.
    accepted_at timestamptz,
    PRIMARY KEY (tenant_id, domain),
    CONSTRAINT domain_handover_offers_between_two
        CHECK (to_tenant_id <> tenant_id),
    CONSTRAINT domain_handover_offers_accepted_after_offered
        CHECK (accepted_at >= offered_at),
    CONSTRAINT domain_handover_offers_accepted_in_time
        CHECK (accepted_at < offered_at + interval '7 days')
);

ALTER TABLE domain_handover_offers ENABLE ROW LEVEL SECURITY;
ALTER TABLE domain_handover_offers FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON domain_handover_offers
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on') OR (to_tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'))
    WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on') OR (to_tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The offers made to one tenant, and the foreign key to it.
CREATE INDEX domain_handover_offers_to_tenant ON domain_handover_offers (to_tenant_id);

-- The address changes organization members and platform operators asked
-- for, at most one per person. Only the hashes of the mailed links are
-- kept.
CREATE TABLE org_email_changes (
    -- no foreign key: the person is an organization member or a platform
    -- operator, kept in two tables; the port names them by principal alone.
    principal_id uuid PRIMARY KEY,
    from_email text NOT NULL,
    new_email text NOT NULL,
    token_hash text NOT NULL,
    cancel_token_hash text NOT NULL,
    state text NOT NULL,
    -- When it was confirmed or cancelled, or NULL while it waits.
    settled_at timestamptz,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT org_email_changes_token_key UNIQUE (token_hash),
    CONSTRAINT org_email_changes_cancel_token_key UNIQUE (cancel_token_hash),
    CONSTRAINT org_email_changes_state_known
        CHECK (state IN ('waiting', 'confirmed', 'cancelled')),
    CONSTRAINT org_email_changes_settled_fits_state
        CHECK ((state = 'waiting') = (settled_at IS NULL)),
    CONSTRAINT org_email_changes_to_another_address
        CHECK (new_email <> from_email),
    CONSTRAINT org_email_changes_expires_after_asked
        CHECK (expires_at > created_at),
    CONSTRAINT org_email_changes_settled_after_asked
        CHECK (settled_at >= created_at),
    CONSTRAINT org_email_changes_confirmed_in_time
        CHECK (state <> 'confirmed' OR settled_at < expires_at)
);

-- The accounts the platform holds with certificate authorities, one per
-- directory, so a staging account and a production one live side by side.
-- An authority rate-limits registration, so an account is made once and
-- kept. Its credentials hold the account's private key, sealed by the
-- platform's secret sealer; the database never holds them in clear.
CREATE TABLE acme_accounts (
    -- The authority's directory, the address the client starts from.
    directory_url text PRIMARY KEY,
    -- The account's credentials, sealed.
    credentials_sealed text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT acme_accounts_directory_is_https
        CHECK (directory_url LIKE 'https://%'
            OR directory_url LIKE 'http://127.0.0.1%'
            OR directory_url LIKE 'http://localhost%'
            OR directory_url LIKE 'http://[::1]%'),
    CONSTRAINT acme_accounts_credentials_held CHECK (credentials_sealed <> ''),
    CONSTRAINT acme_accounts_changed_after_made CHECK (updated_at >= created_at)
);

-- The certificates for each tenant's platform addresses, one per address
-- root, renewed by the certificate sweep under a lease, and the DNS-01
-- proofs it publishes while an order is open.
CREATE TABLE platform_certificates (
    root text PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    readable boolean NOT NULL,
    nameservers text[] NOT NULL,
    address text NOT NULL,
    changed_at timestamptz NOT NULL DEFAULT now(),
    -- no foreign key: an attempt is a transient lease, not an entity.
    attempt_id uuid,
    lease_until timestamptz,
    next_attempt timestamptz NOT NULL DEFAULT now(),
    -- no foreign key: the certificate is held in this row itself.
    certificate_id uuid UNIQUE,
    certificate_pem text,
    private_key text,
    issued_at timestamptz,
    expires_at timestamptz,
    CHECK ((attempt_id IS NULL) = (lease_until IS NULL)),
    CONSTRAINT platform_certificates_complete CHECK ((certificate_id IS NULL AND certificate_pem IS NULL AND private_key IS NULL
            AND issued_at IS NULL AND expires_at IS NULL)
        OR (certificate_id IS NOT NULL AND certificate_pem IS NOT NULL AND private_key IS NOT NULL
            AND issued_at IS NOT NULL AND expires_at IS NOT NULL AND expires_at > issued_at))
);

CREATE INDEX platform_certificates_due ON platform_certificates (next_attempt, root);
CREATE INDEX platform_certificates_tenant ON platform_certificates (tenant_id);

ALTER TABLE platform_certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_certificates FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON platform_certificates
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on');

CREATE TABLE platform_dns_proofs (
    root text NOT NULL REFERENCES platform_certificates(root) ON DELETE CASCADE,
    value text NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (root, value)
);

CREATE INDEX platform_dns_proofs_expiry ON platform_dns_proofs (expires_at);
