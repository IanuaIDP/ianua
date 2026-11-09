-- Organizations: the customers of the platform, each owning its tenants.
--
-- A platform table, so it has no row-level security: an organization is
-- found by its slug before any tenant is known. Which tenants it owns is
-- read from the tenants table, never kept here, so the two cannot drift.
--
-- The checks repeat the rules the domain keeps between columns, so a row
-- written past the domain is refused here too.

CREATE TABLE organizations (
    id uuid PRIMARY KEY,
    slug text NOT NULL,
    name text NOT NULL,
    contact_email text NOT NULL,
    display_name text NOT NULL,
    plan text NOT NULL,
    -- The limits a Custom organization negotiated, or NULL for its plan's.
    negotiated_limits jsonb,
    status text NOT NULL,
    -- Who suspended it: one of its members, or the platform for a reason.
    suspended_by_member uuid,
    suspended_by_platform text,
    auth_config jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT organizations_slug_key UNIQUE (slug),
    CONSTRAINT organizations_plan_known
        CHECK (plan IN ('free', 'starter', 'business', 'custom', 'self_hosted')),
    CONSTRAINT organizations_status_known
        CHECK (status IN ('active', 'suspended', 'closed')),
    CONSTRAINT organizations_platform_reason_known
        CHECK (suspended_by_platform IN ('non_payment', 'operator')),
    CONSTRAINT organizations_suspension_fits_status
        CHECK ((status = 'suspended') = (num_nonnulls(suspended_by_member, suspended_by_platform) = 1)),
    CONSTRAINT organizations_negotiated_only_on_custom
        CHECK (negotiated_limits IS NULL OR plan = 'custom'),
    CONSTRAINT organizations_changed_after_created
        CHECK (updated_at >= created_at)
);

-- One index per order a list can ask for, the id last to break ties, and
-- the same led by status for a list narrowed to one status.
CREATE INDEX organizations_by_created ON organizations (created_at, id);
CREATE INDEX organizations_by_updated ON organizations (updated_at, id);
CREATE INDEX organizations_by_name ON organizations (name, id);
CREATE INDEX organizations_by_slug ON organizations (slug, id);
CREATE INDEX organizations_by_status ON organizations (status, id);
CREATE INDEX organizations_by_status_created ON organizations (status, created_at, id);

-- The payment provider's events the platform has acted on, by the
-- provider's own event id. A provider delivers an event again whenever an
-- answer is lost, so an event found here is acknowledged and acted on no
-- second time. Kept for a month, well past the days a provider retries.
CREATE TABLE payment_events (
    -- The provider's id for the event, the same on every delivery of it.
    event_id text PRIMARY KEY,
    -- An event belongs to the organization it is about and goes with it.
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    -- When the provider created the event.
    created_at timestamptz NOT NULL,
    -- When the platform first took it.
    received_at timestamptz NOT NULL,
    CONSTRAINT payment_events_id_named CHECK (event_id <> '')
);

-- An organization's events by when they arrived, for clearing the old.
CREATE INDEX payment_events_of_organization
    ON payment_events (organization_id, received_at);

-- The newest event applied to each organization, one per kind of change,
-- so a late event older than one already applied changes nothing: a
-- failed charge reported after the payment that settled it leaves the
-- organization paid up.
CREATE TABLE payment_event_marks (
    -- A mark belongs to the organization it is about and goes with it.
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    -- What the events change: the payment method, or whether payments are
    -- owed.
    stream text NOT NULL,
    -- When the provider created the newest event applied.
    newest_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id, stream),
    CONSTRAINT payment_event_marks_stream_known CHECK (stream IN ('method', 'payment'))
);
