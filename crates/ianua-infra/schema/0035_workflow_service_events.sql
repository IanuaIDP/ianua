-- Connecting an account by signing in at its service, and starting
-- workflows on what a service sends: the connections people began, the
-- registrations workflows keep at services, and the deliveries that
-- already started a run.
--
-- Every table is a tenant table, kept as the workflows context keeps its
-- own. A connection and a registration are found by what a service sends
-- before their tenant is known, by a state's digest or the id in an
-- address, in every database a tenant lives in, so each has a key of its
-- own for that read.

-- An account connection a person began by signing in at its service,
-- used once and gone ten minutes after it began. The browser's state is
-- kept as its digest; the PKCE verifier and the credential the service
-- issued are sealed by the app's secret sealer.
CREATE TABLE workflow_pending_connections (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    integration text NOT NULL,
    name text NOT NULL,
    sharing text NOT NULL,
    -- The operations the account may be used for, or NULL for every one.
    operations text[],
    -- The space at the service the account works in, such as an Azure
    -- DevOps organization, or NULL for a sign-in that asks for none.
    place text,
    started_by jsonb NOT NULL,
    state_hash text NOT NULL,
    verifier_sealed text NOT NULL,
    -- How far it got: waiting for the service, answered with a credential
    -- and the digest of the platform's one-time code, or spent.
    stage text NOT NULL,
    credential_sealed text,
    code_hash text,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT workflow_pending_connections_state_key UNIQUE (state_hash),
    CONSTRAINT workflow_pending_connections_sharing_known
        CHECK (sharing IN ('owner_only', 'tenant')),
    CONSTRAINT workflow_pending_connections_operations_some
        CHECK (operations IS NULL OR cardinality(operations) BETWEEN 1 AND 64),
    CONSTRAINT workflow_pending_connections_stage_known
        CHECK (stage IN ('awaiting_service', 'answered', 'spent')),
    CONSTRAINT workflow_pending_connections_answer_fits_stage
        CHECK ((stage = 'answered') = (credential_sealed IS NOT NULL)
            AND (stage = 'answered') = (code_hash IS NOT NULL)),
    CONSTRAINT workflow_pending_connections_expires_after_begun
        CHECK (expires_at >= created_at),
    CONSTRAINT workflow_pending_connections_changed_after_begun
        CHECK (updated_at >= created_at)
);

ALTER TABLE workflow_pending_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_pending_connections FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON workflow_pending_connections
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The connections the sweep removes, oldest first.
CREATE INDEX workflow_pending_connections_by_expiry
    ON workflow_pending_connections (expires_at);

-- A workflow version's registration at the service its trigger names. Its
-- id is in the address the service sends events to; the secret the
-- service signs with is sealed by the app's secret sealer. A service that
-- sends every event of the deployment's app to one address names the
-- registration by a key of its own, such as a Slack workspace's id.
CREATE TABLE workflow_service_subscriptions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    workflow_id uuid NOT NULL,
    version integer NOT NULL,
    integration text NOT NULL,
    trigger jsonb NOT NULL,
    secret_sealed text NOT NULL,
    status text NOT NULL,
    -- The service's name for it once it took it, and when it lapses unless
    -- renewed, for a service whose registrations do.
    remote text,
    lapses_at timestamptz,
    route_key text,
    label text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    -- When the service chose the secret itself, in a check of the address
    -- or in its answer. Only the first one is kept.
    secret_given_at timestamptz,
    CONSTRAINT workflow_service_subscriptions_tenant_id_key UNIQUE (tenant_id, id),
    -- A registration starts its version and nothing else, so it goes with
    -- an agent flow's version when that is deleted.
    FOREIGN KEY (tenant_id, workflow_id, version)
        REFERENCES workflow_versions (tenant_id, workflow_id, version) ON DELETE CASCADE,
    CONSTRAINT workflow_service_subscriptions_status_known
        CHECK (status IN ('registering', 'live', 'lapsed', 'removed')),
    CONSTRAINT workflow_service_subscriptions_live_was_taken
        CHECK (status <> 'live' OR remote IS NOT NULL),
    CONSTRAINT workflow_service_subscriptions_lapse_of_a_taken_one
        CHECK (lapses_at IS NULL OR remote IS NOT NULL),
    CONSTRAINT workflow_service_subscriptions_changed_after_opened
        CHECK (updated_at >= created_at)
);

ALTER TABLE workflow_service_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_service_subscriptions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON workflow_service_subscriptions
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A workflow's registrations, for publishing and archiving, and the
-- version each belongs to.
CREATE INDEX workflow_service_subscriptions_of_workflow
    ON workflow_service_subscriptions (tenant_id, workflow_id, version);

-- The live registrations an app's keyed delivery is for.
CREATE INDEX workflow_service_subscriptions_by_route
    ON workflow_service_subscriptions (integration, route_key)
    WHERE status = 'live' AND route_key IS NOT NULL;

-- The registrations the renewal sweep looks at: live ones that lapse, the
-- soonest first.
CREATE INDEX workflow_service_subscriptions_due
    ON workflow_service_subscriptions (lapses_at, id)
    WHERE status = 'live' AND lapses_at IS NOT NULL;

-- The registrations a sweep gives up on: waiting since long ago, the oldest
-- first.
CREATE INDEX workflow_service_subscriptions_waiting
    ON workflow_service_subscriptions (created_at, id)
    WHERE status = 'registering';

-- An account's one address for a service's events, for a service that takes
-- one per account rather than one per workflow. Its id is in the address;
-- what proves a delivery is sealed by the app's secret sealer.
CREATE TABLE workflow_account_channels (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    account_id uuid NOT NULL,
    integration text NOT NULL,
    secret_sealed text NOT NULL,
    setup text NOT NULL,
    status text NOT NULL,
    -- The service's name for it once it took it, when it lapses unless
    -- renewed, and how far its history has been read.
    remote text,
    lapses_at timestamptz,
    history_cursor text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT workflow_account_channels_one_per_account UNIQUE (tenant_id, account_id),
    CONSTRAINT workflow_account_channels_account_fkey FOREIGN KEY (tenant_id, account_id)
        REFERENCES integration_accounts (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT workflow_account_channels_setup_known
        CHECK (setup IN ('registered', 'pasted_key', 'token_from_service')),
    CONSTRAINT workflow_account_channels_status_known
        CHECK (status IN ('registering', 'awaiting_key', 'awaiting_token',
                          'awaiting_confirmation', 'live', 'lapsed')),
    CONSTRAINT workflow_account_channels_lapse_of_a_taken_one
        CHECK (lapses_at IS NULL OR remote IS NOT NULL),
    CONSTRAINT workflow_account_channels_changed_after_opened
        CHECK (updated_at >= created_at)
);

ALTER TABLE workflow_account_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_account_channels FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON workflow_account_channels
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The channels the renewal sweep looks at: live ones that lapse, the soonest
-- first.
CREATE INDEX workflow_account_channels_due
    ON workflow_account_channels (lapses_at, id)
    WHERE status = 'live' AND lapses_at IS NOT NULL;

-- The channels the idle sweep looks at: those the platform registered, the
-- longest unchanged first.
CREATE INDEX workflow_account_channels_idle
    ON workflow_account_channels (updated_at, id)
    WHERE setup = 'registered';

-- The deliveries that already started a run, by the service's own id for
-- each, so one the service sends again starts nothing twice. The sweep
-- forgets them once a service would no longer send them again.
CREATE TABLE workflow_service_deliveries (
    tenant_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    delivery text NOT NULL,
    noted_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, subscription_id, delivery),
    FOREIGN KEY (tenant_id, subscription_id)
        REFERENCES workflow_service_subscriptions (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE workflow_service_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_service_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON workflow_service_deliveries
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The deliveries the sweep forgets, oldest first.
CREATE INDEX workflow_service_deliveries_by_noted
    ON workflow_service_deliveries (noted_at);
