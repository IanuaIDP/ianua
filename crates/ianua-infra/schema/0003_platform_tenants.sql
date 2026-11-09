-- Tenants: each one an organization's isolated space of users, routes and
-- policies.
--
-- A platform table, so it has no row-level security: a tenant is found by
-- its slug before any tenant is in scope. Its own records live in the
-- tenant tables, under row-level security.
--
-- The checks repeat the rules the domain keeps between columns, so a row
-- written past the domain is refused here too.

CREATE TABLE tenants (
    id uuid PRIMARY KEY,
    -- An organization is never removed while it holds a tenant: it closes,
    -- and its tenants are deleted first.
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
    slug text NOT NULL,
    display_name text NOT NULL,
    primary_domain text,
    contact_email text NOT NULL,
    status text NOT NULL,
    held boolean NOT NULL,
    archived_at timestamptz,
    compliance jsonb NOT NULL,
    auth_config jsonb NOT NULL,
    mtls jsonb NOT NULL,
    timezone text NOT NULL,
    locale text NOT NULL,
    residency jsonb NOT NULL,
    -- The customer's own cloud the residency places the tenant in, if any,
    -- written beside it so a count by cloud reads an index.
    customer_cloud text,
    environment text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    -- The random label of the tenant's platform address, such as
    -- `k3x9q2m7`, unique on the platform.
    platform_label text NOT NULL,
    -- Whether the tenant also answers at its readable address,
    -- `{organization slug}-{tenant slug}`.
    readable_address boolean NOT NULL DEFAULT false,
    -- A tenant's slug is unique within its organization, not across the
    -- platform: every lookup by slug names the organization too, so two
    -- companies may each call a tenant "production".
    CONSTRAINT tenants_organization_slug_key UNIQUE (organization_id, slug),
    CONSTRAINT tenants_platform_label_unique UNIQUE (platform_label),
    CONSTRAINT tenants_platform_label_valid CHECK (platform_label ~ '^[a-z0-9]{6,16}$'),
    CONSTRAINT tenants_status_known
        CHECK (status IN ('provisioning', 'active', 'suspended', 'archived', 'deleted')),
    CONSTRAINT tenants_environment_known
        CHECK (environment IN ('production', 'staging', 'development')),
    CONSTRAINT tenants_customer_cloud_known
        CHECK (customer_cloud IN ('aws', 'gcp', 'azure', 'digitalocean', 'kubernetes')),
    CONSTRAINT tenants_archive_fits_status
        CHECK ((status IN ('archived', 'deleted')) = (archived_at IS NOT NULL)),
    CONSTRAINT tenants_held_only_out_of_service
        CHECK (NOT held OR status IN ('suspended', 'archived', 'deleted')),
    CONSTRAINT tenants_changed_after_created
        CHECK (updated_at >= created_at)
);

-- One index per order a list can ask for, the id last to break ties: for
-- one organization's tenants, and for every tenant.
CREATE INDEX tenants_in_organization_by_created ON tenants (organization_id, created_at, id);
CREATE INDEX tenants_in_organization_by_updated ON tenants (organization_id, updated_at, id);
CREATE INDEX tenants_in_organization_by_name ON tenants (organization_id, display_name, id);
CREATE INDEX tenants_by_created ON tenants (created_at, id);
CREATE INDEX tenants_by_updated ON tenants (updated_at, id);
CREATE INDEX tenants_by_name ON tenants (display_name, id);

-- The archived tenants, by the time they were archived, for the sweep
-- that deletes them once their grace has passed.
CREATE INDEX tenants_archived ON tenants (archived_at, id) WHERE status = 'archived';

-- The tenants still provisioning, by when they were made, and the deleted
-- tenants, by when they were deleted, the oldest first, for the reconcile
-- sweep that picks up a setup or a teardown that never began or stalled.
CREATE INDEX tenants_provisioning_since ON tenants (created_at, id) WHERE status = 'provisioning';
CREATE INDEX tenants_deleted_since ON tenants (updated_at, id) WHERE status = 'deleted';

-- The tenants in a customer's own cloud, counted per organization.
CREATE INDEX tenants_in_customer_cloud ON tenants (organization_id, customer_cloud)
    WHERE customer_cloud IS NOT NULL;
