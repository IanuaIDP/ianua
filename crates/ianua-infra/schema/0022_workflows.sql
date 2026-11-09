-- The workflows context: the workflows a tenant designs or makes as agent
-- flows, every version of them, the runs of those versions and the agent
-- runs a run waits on, the secrets their webhooks are called with, the
-- accounts a tenant connected to integrations, and its raised views of
-- how risky an integration's operation is.
--
-- Every table is a tenant table: it lives in the platform database and in
-- a tenant's own, so it names no platform table. Row-level security keeps
-- each row to its tenant, and every foreign key carries the tenant too, so
-- a row can never point at another tenant's.
--
-- A designed workflow is archived, never deleted. Only an agent flow is
-- deleted, once its run has ended, and its version, its run and its
-- webhook secret go with it.
--
-- A value made of many parts, such as a graph of steps or the people who
-- wrote a version, is one jsonb column in the store's versioned envelope.
-- The checks repeat the rules the domain keeps between columns, so a row
-- written past the domain is refused here too.

-- A workflow, whichever version of it is current: what every version,
-- run and webhook secret of it belongs to.
CREATE TABLE workflows (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    -- Whether a person designed it version by version, or made it at once
    -- as an agent flow.
    origin text NOT NULL,
    -- What a flow's maker wrote about it, or NULL when they wrote nothing,
    -- and always for a designed workflow.
    flow_description text,
    CONSTRAINT workflows_tenant_id_key UNIQUE (tenant_id, id),
    CONSTRAINT workflows_origin_known CHECK (origin IN ('designed', 'flow')),
    CONSTRAINT workflows_description_of_a_flow
        CHECK (origin = 'flow' OR flow_description IS NULL)
);

ALTER TABLE workflows ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflows FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON workflows
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- One version of a workflow: its steps, what starts it and where it
-- stands. A workflow and version pair is kept once, so two drafts made from
-- the same version cannot both be kept.
CREATE TABLE workflow_versions (
    tenant_id uuid NOT NULL,
    workflow_id uuid NOT NULL,
    version integer NOT NULL,
    name text NOT NULL,
    graph jsonb NOT NULL,
    -- What starts it: a person, a schedule, its webhook, an event or a
    -- service's event, with the schedule, the event or the service's event
    -- when it is one of those.
    trigger_kind text NOT NULL,
    trigger_schedule text,
    trigger_event text,
    -- How long one run of it may go on, in seconds.
    run_limit_secs integer NOT NULL,
    status text NOT NULL,
    created_by jsonb NOT NULL,
    edited_by jsonb NOT NULL,
    authors jsonb NOT NULL,
    -- Who published it, or NULL for a version never published.
    published_by jsonb,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    -- A service's event that starts it: the integration, the event, the
    -- account it registers through and the trigger's filters.
    trigger_service jsonb,
    -- Why a version in service is held: an account it acts through can no
    -- longer be used for its publisher, where the version uses it and why,
    -- or NULL when nothing holds it. A draft is never held.
    hold jsonb,
    -- What it does, in the builder's words, where its steps sit on the
    -- canvas, and who is told when one of its runs fails.
    description text,
    layout jsonb NOT NULL DEFAULT '{"v": 1, "value": []}',
    failure_alert text NOT NULL DEFAULT 'administrators',
    -- The change a "before" version decides, or NULL for any other trigger.
    trigger_change text,
    PRIMARY KEY (tenant_id, workflow_id, version),
    -- A version is part of its workflow, and goes with an agent flow when
    -- that is deleted; a designed workflow is never deleted.
    FOREIGN KEY (tenant_id, workflow_id) REFERENCES workflows (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT workflow_versions_from_one CHECK (version >= 1),
    CONSTRAINT workflow_versions_trigger_known
        CHECK (trigger_kind IN ('manual', 'schedule', 'webhook', 'event', 'service', 'before')),
    CONSTRAINT workflow_versions_trigger_whole
        CHECK ((trigger_kind = 'schedule') = (trigger_schedule IS NOT NULL)
            AND (trigger_kind = 'event') = (trigger_event IS NOT NULL)
            AND (trigger_kind = 'service') = (trigger_service IS NOT NULL)
            AND (trigger_kind = 'before') = (trigger_change IS NOT NULL)),
    CONSTRAINT workflow_versions_trigger_change_known
        CHECK (trigger_change IN ('access_given', 'admin_given', 'app_opened_to_workflows',
                                  'audit_exported')),
    CONSTRAINT workflow_versions_draft_not_held CHECK (status <> 'draft' OR hold IS NULL),
    CONSTRAINT workflow_versions_description_length
        CHECK (char_length(description) BETWEEN 1 AND 500),
    CONSTRAINT workflow_versions_failure_alert_known
        CHECK (failure_alert IN ('administrators', 'also_authors')),
    CONSTRAINT workflow_versions_run_limit_positive CHECK (run_limit_secs > 0),
    CONSTRAINT workflow_versions_status_known
        CHECK (status IN ('draft', 'published', 'archived')),
    CONSTRAINT workflow_versions_publication_fits_status
        CHECK ((status <> 'draft' OR published_by IS NULL)
            AND (status <> 'published' OR published_by IS NOT NULL)),
    CONSTRAINT workflow_versions_changed_after_created CHECK (updated_at >= created_at)
);

ALTER TABLE workflow_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON workflow_versions
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- At most one version of a workflow is in service, so two versions
-- published at once cannot both be kept.
CREATE UNIQUE INDEX workflow_versions_published_key ON workflow_versions (tenant_id, workflow_id)
    WHERE status = 'published';

-- The orders a list of workflows can ask for, the workflow last.
CREATE INDEX workflow_versions_by_created ON workflow_versions (tenant_id, created_at, workflow_id);
CREATE INDEX workflow_versions_by_updated ON workflow_versions (tenant_id, updated_at, workflow_id);
CREATE INDEX workflow_versions_by_name ON workflow_versions (tenant_id, name, workflow_id);

-- The versions in service that start on an event, found by the event.
CREATE INDEX workflow_versions_published_on ON workflow_versions (tenant_id, trigger_event)
    WHERE status = 'published' AND trigger_kind = 'event';

-- The versions in service that decide a change before it happens, by the
-- change, which a guarded change looks up while it waits.
CREATE INDEX workflow_versions_published_before ON workflow_versions (tenant_id, trigger_change)
    WHERE status = 'published' AND trigger_kind = 'before';

-- The versions in service that start on a schedule, in the order the
-- scheduler reads them, and each by its workflow.
CREATE INDEX workflow_versions_scheduled ON workflow_versions (tenant_id, workflow_id)
    WHERE status = 'published' AND trigger_kind = 'schedule';
CREATE INDEX workflow_versions_scheduled_by_workflow ON workflow_versions (workflow_id)
    WHERE status = 'published' AND trigger_kind = 'schedule';

-- One run of a published version, with the graph it runs, so a later
-- version never changes a run already started.
CREATE TABLE workflow_executions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    workflow_id uuid NOT NULL,
    version integer NOT NULL,
    graph jsonb NOT NULL,
    acting_for jsonb NOT NULL,
    authors jsonb NOT NULL,
    -- What started it: a person, its schedule, its webhook, an event, or
    -- the person an earlier run acted for, starting that run again.
    cause text NOT NULL,
    cause_event text,
    -- How deep in a chain of runs the event that started it was raised, or
    -- NULL for an event from outside any run.
    cause_event_depth smallint,
    restarted_execution_id uuid,
    -- Where a run started again picks up: from the trigger, or from the
    -- steps that did not finish.
    restart_from text,
    chain_depth smallint NOT NULL,
    input jsonb NOT NULL,
    exposure text NOT NULL,
    -- Where each step stands, in the graph's order.
    steps jsonb NOT NULL,
    status text NOT NULL,
    -- Who stopped it, for a cancelled run only.
    cancelled_by jsonb,
    deadline timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    -- A loop's pass: the run whose loop started it, that loop step and the
    -- item, counted from zero. A pass stopped because its loop failed or
    -- its run ended first ends as 'loop_ended', which only a pass does.
    pass_of uuid,
    pass_step text,
    pass_index integer,
    -- Who is told when it fails, carried from its version; whether it is a
    -- real run or a test of a draft, and the steps a test stood in for.
    failure_alert text NOT NULL DEFAULT 'administrators',
    mode text NOT NULL DEFAULT 'live',
    stand_ins text[] NOT NULL DEFAULT '{}',
    -- The change a "before" run decides, or NULL for any other cause.
    cause_change text,
    CONSTRAINT workflow_executions_tenant_id_key UNIQUE (tenant_id, id),
    -- A run is of one version, and goes with an agent flow's version when
    -- that is deleted; a designed workflow's versions are never deleted.
    FOREIGN KEY (tenant_id, workflow_id, version)
        REFERENCES workflow_versions (tenant_id, workflow_id, version) ON DELETE CASCADE,
    -- A run started again is a run of the same version, so it goes when the
    -- run it picks up from goes with its agent flow.
    FOREIGN KEY (tenant_id, restarted_execution_id)
        REFERENCES workflow_executions (tenant_id, id) ON DELETE CASCADE,
    -- A pass goes when the run whose loop started it goes.
    CONSTRAINT workflow_executions_pass_of_run
        FOREIGN KEY (tenant_id, pass_of)
        REFERENCES workflow_executions (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT workflow_executions_from_one CHECK (version >= 1),
    CONSTRAINT workflow_executions_cause_known
        CHECK (cause IN ('manual', 'schedule', 'webhook', 'event', 'service', 'restart', 'before')),
    CONSTRAINT workflow_executions_before_whole
        CHECK ((cause = 'before') = (cause_change IS NOT NULL)),
    CONSTRAINT workflow_executions_event_whole
        CHECK ((cause = 'event') = (cause_event IS NOT NULL)
            AND (cause = 'event' OR cause_event_depth IS NULL)),
    CONSTRAINT workflow_executions_restart_whole
        CHECK ((cause = 'restart') = (restarted_execution_id IS NOT NULL)
            AND (cause = 'restart') = (restart_from IS NOT NULL)),
    CONSTRAINT workflow_executions_restart_from_known
        CHECK (restart_from IN ('rerun', 'retry')),
    CONSTRAINT workflow_executions_not_its_own_restart
        CHECK (restarted_execution_id <> id),
    CONSTRAINT workflow_executions_chain_depth_in_range CHECK (chain_depth BETWEEN 1 AND 3),
    CONSTRAINT workflow_executions_event_depth_in_range
        CHECK (cause_event_depth BETWEEN 1 AND 3),
    CONSTRAINT workflow_executions_exposure_known
        CHECK (exposure IN ('public', 'internal', 'confidential', 'restricted')),
    CONSTRAINT workflow_executions_status_known
        CHECK (status IN ('running', 'succeeded', 'failed', 'cancelled', 'timed_out',
            'loop_ended')),
    CONSTRAINT workflow_executions_cancelled_by_someone
        CHECK ((status = 'cancelled') = (cancelled_by IS NOT NULL)),
    CONSTRAINT workflow_executions_deadline_after_start CHECK (deadline > created_at),
    CONSTRAINT workflow_executions_changed_after_start CHECK (updated_at >= created_at),
    CONSTRAINT workflow_executions_pass_whole
        CHECK ((pass_of IS NULL) = (pass_step IS NULL)
            AND (pass_of IS NULL) = (pass_index IS NULL)),
    CONSTRAINT workflow_executions_pass_index_in_range CHECK (pass_index BETWEEN 0 AND 999),
    CONSTRAINT workflow_executions_not_its_own_pass CHECK (pass_of <> id),
    CONSTRAINT workflow_executions_loop_ended_is_a_pass
        CHECK (status <> 'loop_ended' OR pass_of IS NOT NULL),
    CONSTRAINT workflow_executions_failure_alert_known
        CHECK (failure_alert IN ('administrators', 'also_authors')),
    CONSTRAINT workflow_executions_mode_known CHECK (mode IN ('live', 'test')),
    CONSTRAINT workflow_executions_only_tests_stand_in
        CHECK (mode = 'test' OR cardinality(stand_ins) = 0)
);

ALTER TABLE workflow_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_executions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON workflow_executions
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The runs of one version, for its foreign key.
CREATE INDEX workflow_executions_of_version
    ON workflow_executions (tenant_id, workflow_id, version);
-- The runs or the tests of one workflow, newest first, and every run or
-- every test of the tenant: lists show the runs people started, never a
-- loop's passes, and real runs or tests, never both.
CREATE INDEX workflow_executions_of_workflow
    ON workflow_executions (tenant_id, workflow_id, mode, created_at, id)
    WHERE pass_of IS NULL;
CREATE INDEX workflow_executions_by_created
    ON workflow_executions (tenant_id, mode, created_at, id)
    WHERE pass_of IS NULL;
-- The passes of one run's loops, newest first, and for their foreign key.
CREATE INDEX workflow_executions_passes
    ON workflow_executions (tenant_id, pass_of, created_at, id);
-- The runs that ended, oldest first, for the sweep past their keeping.
CREATE INDEX workflow_executions_ended
    ON workflow_executions (tenant_id, updated_at)
    WHERE status <> 'running' AND pass_of IS NULL;
-- The runs started again from one, for its foreign key.
CREATE INDEX workflow_executions_restarts
    ON workflow_executions (tenant_id, restarted_execution_id);

-- The agent runs a run's steps wait on now, so the run is found when one
-- of them ends. A run's save keeps them as its steps hold them.
CREATE TABLE workflow_execution_runs (
    tenant_id uuid NOT NULL,
    -- Linked to its agent run in 0026.
    agent_run_id uuid NOT NULL,
    execution_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, agent_run_id),
    -- What a run waits on means nothing once the run is gone.
    FOREIGN KEY (tenant_id, execution_id)
        REFERENCES workflow_executions (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE workflow_execution_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_execution_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON workflow_execution_runs
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The agent runs one run waits on, and the foreign key to it.
CREATE INDEX workflow_execution_runs_of_execution
    ON workflow_execution_runs (tenant_id, execution_id);

-- The pages of a loop's items each person opened while the loop asked one
-- approval for every item. A yes counts only once every item was on a page
-- its approver opened. The opening names the approval a page belongs to,
-- so a page of a list since replaced counts for nothing; the same page
-- opened again keeps the first time.
CREATE TABLE workflow_approval_pages (
    tenant_id uuid NOT NULL,
    execution_id uuid NOT NULL,
    -- The loop step, by its key in the run's graph.
    step text NOT NULL,
    -- The person shown the page, across their accounts.
    person text NOT NULL,
    opening timestamptz NOT NULL,
    first_item integer NOT NULL,
    item_count integer NOT NULL,
    opened_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, execution_id, step, person, opening, first_item, item_count),
    -- What a person was shown means nothing once the run is gone.
    FOREIGN KEY (tenant_id, execution_id)
        REFERENCES workflow_executions (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT workflow_approval_pages_first_in_range CHECK (first_item BETWEEN 0 AND 999),
    CONSTRAINT workflow_approval_pages_count_in_range CHECK (item_count BETWEEN 1 AND 1000),
    CONSTRAINT workflow_approval_pages_opened_after_opening CHECK (opened_at >= opening)
);

ALTER TABLE workflow_approval_pages ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_approval_pages FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON workflow_approval_pages
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The secret a workflow's webhook is called with, at most one per
-- workflow. Only the keyed digest of the secret is kept, under a key the
-- server holds and the database does not.
CREATE TABLE workflow_trigger_secrets (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    workflow_id uuid NOT NULL,
    secret_hash text NOT NULL,
    issued_by jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    secret_changed_at timestamptz NOT NULL,
    CONSTRAINT workflow_trigger_secrets_workflow_key UNIQUE (tenant_id, workflow_id),
    -- A webhook secret starts its workflow and nothing else, so it goes
    -- with an agent flow when that is deleted.
    FOREIGN KEY (tenant_id, workflow_id) REFERENCES workflows (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT workflow_trigger_secrets_set_after_issued
        CHECK (secret_changed_at >= created_at)
);

ALTER TABLE workflow_trigger_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_trigger_secrets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON workflow_trigger_secrets
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The accounts a tenant connected to integrations. The credential is kept
-- in the sealed form the app's secret sealer gave it; the action runner
-- opens it for the one call that needs it.
CREATE TABLE integration_accounts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    integration text NOT NULL,
    name text NOT NULL,
    credential_sealed text NOT NULL,
    owner jsonb NOT NULL,
    sharing text NOT NULL,
    -- The operations it may be used for, or NULL for every one.
    operations text[],
    status text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT integration_accounts_tenant_id_key UNIQUE (tenant_id, id),
    CONSTRAINT integration_accounts_sharing_known CHECK (sharing IN ('owner_only', 'tenant')),
    CONSTRAINT integration_accounts_status_known CHECK (status IN ('active', 'disabled')),
    CONSTRAINT integration_accounts_operations_some
        CHECK (operations IS NULL OR cardinality(operations) BETWEEN 1 AND 64),
    CONSTRAINT integration_accounts_changed_after_connected CHECK (updated_at >= created_at)
);

ALTER TABLE integration_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON integration_accounts
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A tenant's accounts, oldest first.
CREATE INDEX integration_accounts_by_created ON integration_accounts (tenant_id, created_at, id);

-- A tenant's raised views of how risky an integration's operation is, at
-- most one per operation.
CREATE TABLE operation_risk_overrides (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    integration text NOT NULL,
    operation text NOT NULL,
    -- The class of action the tenant treats the operation as, or NULL when
    -- it treats it as undeclared.
    effect text,
    raised_by jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT operation_risk_overrides_operation_key UNIQUE (tenant_id, integration, operation),
    CONSTRAINT operation_risk_overrides_effect_known
        CHECK (effect IN ('read', 'write', 'delete', 'configure', 'communicate', 'financial', 'admin')),
    CONSTRAINT operation_risk_overrides_changed_after_set CHECK (updated_at >= created_at)
);

ALTER TABLE operation_risk_overrides ENABLE ROW LEVEL SECURITY;
ALTER TABLE operation_risk_overrides FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON operation_risk_overrides
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A tenant's overrides, oldest first.
CREATE INDEX operation_risk_overrides_by_created
    ON operation_risk_overrides (tenant_id, created_at, id);
