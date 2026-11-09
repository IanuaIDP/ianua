-- Each workflow's sample cases: the inputs its versions are tried against
-- and the checks their results must pass, kept across its versions, and
-- whether publishing a draft waits on its last evaluation passing. A set
-- goes with its workflow.
CREATE TABLE evaluation_sets (
    tenant_id uuid NOT NULL,
    workflow_id uuid NOT NULL,
    -- The cases, in the author's order, each its name, input, how
    -- sensitive the input is and its checks.
    cases jsonb NOT NULL,
    publish_gate text NOT NULL,
    edited_by jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, workflow_id),
    FOREIGN KEY (tenant_id, workflow_id) REFERENCES workflows (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT evaluation_sets_gate_known CHECK (publish_gate IN ('off', 'must_pass')),
    CONSTRAINT evaluation_sets_saved_after_made CHECK (updated_at >= created_at)
);

ALTER TABLE evaluation_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE evaluation_sets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON evaluation_sets
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- One evaluation: a workflow version, at one revision, tried against the
-- cases its set held when it started, each case as a test run. The test
-- runs are named inside the outcomes, not held by a foreign key: a test run
-- may be removed with its retention while the evaluation that read it is
-- still kept. An ended evaluation is removed thirty days after it ended.
CREATE TABLE evaluations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    workflow_id uuid NOT NULL,
    version integer NOT NULL,
    -- The revision of the version it tries: when the version last changed
    -- before it started.
    revision timestamptz NOT NULL,
    cases jsonb NOT NULL,
    -- What each case came to, in the cases' order: waiting, running with
    -- its test run, passed, failed with what differed, or not run with why.
    outcomes jsonb NOT NULL,
    state text NOT NULL,
    started_by jsonb NOT NULL,
    deadline timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, workflow_id, version)
        REFERENCES workflow_versions (tenant_id, workflow_id, version) ON DELETE CASCADE,
    CONSTRAINT evaluations_state_known CHECK (state IN ('running', 'passed', 'failed')),
    CONSTRAINT evaluations_changed_after_started CHECK (updated_at >= created_at),
    CONSTRAINT evaluations_due_after_started CHECK (deadline >= created_at)
);

ALTER TABLE evaluations ENABLE ROW LEVEL SECURITY;
ALTER TABLE evaluations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON evaluations
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A workflow's evaluations, newest first: the listing, and the last one a
-- publishing gate reads.
CREATE INDEX evaluations_of_workflow ON evaluations (tenant_id, workflow_id, created_at DESC);

-- The evaluations a tenant has running, counted against its plan and swept
-- once past their deadline.
CREATE INDEX evaluations_running ON evaluations (tenant_id, deadline) WHERE state = 'running';

-- The evaluations that ended, oldest first, for the daily purge.
CREATE INDEX evaluations_ended ON evaluations (tenant_id, updated_at) WHERE state <> 'running';

-- For the foreign key to the version.
CREATE INDEX evaluations_of_version ON evaluations (tenant_id, workflow_id, version);
