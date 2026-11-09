ALTER TABLE sandbox_versions DROP CONSTRAINT sandbox_versions_ready_whole;

-- Each workflow's sample cases: the inputs its versions are tried against
-- and the checks their results must pass, kept across its versions, and
-- whether publishing a draft waits on its last evaluation passing. A set
-- goes with its workflow.
CREATE TABLE evaluation_sets (
    tenant_id uuid NOT NULL,
    workflow_id uuid NOT NULL,
    cases jsonb NOT NULL,
    publish_gate text NOT NULL,
    edited_by jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);

-- One evaluation: a workflow version, at one revision, tried against the
-- cases its set held when it started, each case as a test run. The test
-- runs are named inside the outcomes, not held by a foreign key: a test run
-- may be removed with its retention while the evaluation that read it is
-- still kept. An ended evaluation is removed thirty days after it ended.
CREATE TABLE evaluations (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    workflow_id uuid NOT NULL,
    version integer NOT NULL,
    revision timestamp with time zone NOT NULL,
    cases jsonb NOT NULL,
    outcomes jsonb NOT NULL,
    state text NOT NULL,
    started_by jsonb NOT NULL,
    deadline timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);

-- The image registries a tenant's administrator allowed: the only places a
-- sandbox version takes the company's own image from. A host is on a
-- tenant's list once. Images are pulled anonymously, or as a user with a
-- password or token sealed for this row. Removing a row stops the versions
-- whose image it keeps from running; they name the registry by host, not by
-- row, so no foreign key holds them to it.
CREATE TABLE image_registries (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    host text NOT NULL,
    login text NOT NULL,
    username text,
    password text,
    allowed_by jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);

-- The pages of a loop's items each person opened while the loop asked one
-- approval for every item. A yes counts only once every item was on a page
-- its approver opened. The opening names the approval a page belongs to, so
-- a page of a list since replaced counts for nothing; the same page opened
-- again keeps the first time.
CREATE TABLE workflow_approval_pages (
    tenant_id uuid NOT NULL,
    execution_id uuid NOT NULL,
    step text NOT NULL,
    person text NOT NULL,
    opening timestamp with time zone NOT NULL,
    first_item integer NOT NULL,
    item_count integer NOT NULL,
    opened_at timestamp with time zone NOT NULL
);

-- The sandbox version whose code checks each of the run's answers, and how
-- many answers it may give; both NULL for a run that completes on its
-- model's answer.
ALTER TABLE agent_runs ADD COLUMN check_version_id uuid;

ALTER TABLE agent_runs ADD COLUMN check_tries smallint;

-- The agent the version holds and the rules it works under (its agent,
-- model provider, goal, purpose, tools, approvals, steps, spend and tries),
-- as the domain writes them; its code is then the check every answer of
-- that agent must pass. NULL when its code is the step's work. The agent
-- and provider named inside are history, like a run's: a version keeps them
-- after they are deleted, and its runs refuse.
ALTER TABLE sandbox_versions ADD COLUMN held_agent jsonb;

-- What it runs: code under a runtime, or the company's image.
ALTER TABLE sandbox_versions ADD COLUMN program text DEFAULT 'code'::text NOT NULL;

-- The company's image's size as its registry counts its layers.
ALTER TABLE sandbox_versions ADD COLUMN image_bytes bigint;

-- What scanning the company's image found below critical, once it was
-- cleared to run.
ALTER TABLE sandbox_versions ADD COLUMN scan_high integer;

ALTER TABLE sandbox_versions ADD COLUMN scan_medium integer;

ALTER TABLE sandbox_versions ADD COLUMN scan_low integer;

-- What its versions run: code in its language, or the company's image with
-- no language.
ALTER TABLE sandboxes ADD COLUMN kind text DEFAULT 'code'::text NOT NULL;

ALTER TABLE sandbox_versions ALTER COLUMN runtime DROP NOT NULL;

ALTER TABLE sandbox_versions ALTER COLUMN code DROP NOT NULL;

ALTER TABLE sandbox_versions ALTER COLUMN packages DROP NOT NULL;

ALTER TABLE sandboxes ALTER COLUMN language DROP NOT NULL;

ALTER TABLE evaluation_sets ADD CONSTRAINT evaluation_sets_pkey PRIMARY KEY (tenant_id, workflow_id);

ALTER TABLE evaluations ADD CONSTRAINT evaluations_pkey PRIMARY KEY (id);

ALTER TABLE image_registries ADD CONSTRAINT image_registries_host_once UNIQUE (tenant_id, host);

ALTER TABLE image_registries ADD CONSTRAINT image_registries_pkey PRIMARY KEY (id);

ALTER TABLE workflow_approval_pages ADD CONSTRAINT workflow_approval_pages_pkey PRIMARY KEY (tenant_id, execution_id, step, person, opening, first_item, item_count);

ALTER TABLE agent_runs ADD CONSTRAINT agent_runs_check_whole CHECK ((((check_version_id IS NULL) = (check_tries IS NULL)) AND ((check_tries >= 1) AND (check_tries <= 3)))) NOT VALID;
ALTER TABLE agent_runs VALIDATE CONSTRAINT agent_runs_check_whole;

ALTER TABLE evaluation_sets ADD CONSTRAINT evaluation_sets_gate_known CHECK ((publish_gate = ANY (ARRAY['off'::text, 'must_pass'::text])));

ALTER TABLE evaluation_sets ADD CONSTRAINT evaluation_sets_saved_after_made CHECK ((updated_at >= created_at));

ALTER TABLE evaluation_sets ADD CONSTRAINT evaluation_sets_tenant_id_workflow_id_fkey FOREIGN KEY (tenant_id, workflow_id) REFERENCES workflows(tenant_id, id) ON DELETE CASCADE;

ALTER TABLE evaluations ADD CONSTRAINT evaluations_changed_after_started CHECK ((updated_at >= created_at));

ALTER TABLE evaluations ADD CONSTRAINT evaluations_due_after_started CHECK ((deadline >= created_at));

ALTER TABLE evaluations ADD CONSTRAINT evaluations_state_known CHECK ((state = ANY (ARRAY['running'::text, 'passed'::text, 'failed'::text])));

ALTER TABLE evaluations ADD CONSTRAINT evaluations_tenant_id_workflow_id_version_fkey FOREIGN KEY (tenant_id, workflow_id, version) REFERENCES workflow_versions(tenant_id, workflow_id, version) ON DELETE CASCADE;

ALTER TABLE image_registries ADD CONSTRAINT image_registries_changed_after_allowed CHECK ((updated_at >= created_at));

ALTER TABLE image_registries ADD CONSTRAINT image_registries_login_known CHECK ((login = ANY (ARRAY['anonymous'::text, 'password'::text])));

ALTER TABLE image_registries ADD CONSTRAINT image_registries_login_whole CHECK ((((login = 'password'::text) = (username IS NOT NULL)) AND ((login = 'password'::text) = (password IS NOT NULL))));

ALTER TABLE sandbox_versions ADD CONSTRAINT sandbox_versions_code_whole CHECK ((((program = 'code'::text) = (runtime IS NOT NULL)) AND ((program = 'code'::text) = (code IS NOT NULL)) AND ((program = 'code'::text) = (packages IS NOT NULL)) AND ((program = 'image'::text) = (image_bytes IS NOT NULL)))) NOT VALID;
ALTER TABLE sandbox_versions VALIDATE CONSTRAINT sandbox_versions_code_whole;

ALTER TABLE sandbox_versions ADD CONSTRAINT sandbox_versions_image_bytes_bounded CHECK (((image_bytes >= 0) AND (image_bytes <= '2147483648'::bigint))) NOT VALID;
ALTER TABLE sandbox_versions VALIDATE CONSTRAINT sandbox_versions_image_bytes_bounded;

ALTER TABLE sandbox_versions ADD CONSTRAINT sandbox_versions_image_written CHECK (((program = 'code'::text) OR (source_integration IS NULL))) NOT VALID;
ALTER TABLE sandbox_versions VALIDATE CONSTRAINT sandbox_versions_image_written;

ALTER TABLE sandbox_versions ADD CONSTRAINT sandbox_versions_program_known CHECK ((program = ANY (ARRAY['code'::text, 'image'::text]))) NOT VALID;
ALTER TABLE sandbox_versions VALIDATE CONSTRAINT sandbox_versions_program_known;

ALTER TABLE sandbox_versions ADD CONSTRAINT sandbox_versions_ready_whole CHECK (((((build = 'ready'::text) AND (program = 'code'::text)) = (bundle_digest IS NOT NULL)) AND (((build = 'ready'::text) AND (program = 'code'::text)) = (bundle_bytes IS NOT NULL)) AND (((build = 'ready'::text) AND (program = 'code'::text)) = (unlisted IS NOT NULL)))) NOT VALID;
ALTER TABLE sandbox_versions VALIDATE CONSTRAINT sandbox_versions_ready_whole;

ALTER TABLE sandbox_versions ADD CONSTRAINT sandbox_versions_scanned_whole CHECK (((((build = 'ready'::text) AND (program = 'image'::text)) = (scan_high IS NOT NULL)) AND (((build = 'ready'::text) AND (program = 'image'::text)) = (scan_medium IS NOT NULL)) AND (((build = 'ready'::text) AND (program = 'image'::text)) = (scan_low IS NOT NULL)))) NOT VALID;
ALTER TABLE sandbox_versions VALIDATE CONSTRAINT sandbox_versions_scanned_whole;

ALTER TABLE sandboxes ADD CONSTRAINT sandboxes_kind_known CHECK ((kind = ANY (ARRAY['code'::text, 'image'::text]))) NOT VALID;
ALTER TABLE sandboxes VALIDATE CONSTRAINT sandboxes_kind_known;

ALTER TABLE sandboxes ADD CONSTRAINT sandboxes_language_of_code CHECK (((kind = 'code'::text) = (language IS NOT NULL))) NOT VALID;
ALTER TABLE sandboxes VALIDATE CONSTRAINT sandboxes_language_of_code;

ALTER TABLE workflow_approval_pages ADD CONSTRAINT workflow_approval_pages_count_in_range CHECK (((item_count >= 1) AND (item_count <= 1000)));

ALTER TABLE workflow_approval_pages ADD CONSTRAINT workflow_approval_pages_first_in_range CHECK (((first_item >= 0) AND (first_item <= 999)));

ALTER TABLE workflow_approval_pages ADD CONSTRAINT workflow_approval_pages_opened_after_opening CHECK ((opened_at >= opening));

ALTER TABLE workflow_approval_pages ADD CONSTRAINT workflow_approval_pages_tenant_id_execution_id_fkey FOREIGN KEY (tenant_id, execution_id) REFERENCES workflow_executions(tenant_id, id) ON DELETE CASCADE;

-- The evaluations that ended, oldest first, for the daily purge.
CREATE INDEX evaluations_ended ON evaluations USING btree (tenant_id, updated_at) WHERE (state <> 'running'::text);

-- For the foreign key to the version.
CREATE INDEX evaluations_of_version ON evaluations USING btree (tenant_id, workflow_id, version);

-- A workflow's evaluations, newest first: the listing, and the last one a
-- publishing gate reads.
CREATE INDEX evaluations_of_workflow ON evaluations USING btree (tenant_id, workflow_id, created_at DESC);

-- The evaluations a tenant has running, counted against its plan and swept
-- once past their deadline.
CREATE INDEX evaluations_running ON evaluations USING btree (tenant_id, deadline) WHERE (state = 'running'::text);

ALTER TABLE evaluation_sets ENABLE ROW LEVEL SECURITY;

ALTER TABLE evaluation_sets FORCE ROW LEVEL SECURITY;

ALTER TABLE evaluations ENABLE ROW LEVEL SECURITY;

ALTER TABLE evaluations FORCE ROW LEVEL SECURITY;

ALTER TABLE image_registries ENABLE ROW LEVEL SECURITY;

ALTER TABLE image_registries FORCE ROW LEVEL SECURITY;

ALTER TABLE workflow_approval_pages ENABLE ROW LEVEL SECURITY;

ALTER TABLE workflow_approval_pages FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_rows ON evaluation_sets AS PERMISSIVE FOR ALL TO public USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.platform_scope'::text, true) = 'on'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.platform_scope'::text, true) = 'on'::text)));

CREATE POLICY tenant_rows ON evaluations AS PERMISSIVE FOR ALL TO public USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.platform_scope'::text, true) = 'on'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.platform_scope'::text, true) = 'on'::text)));

CREATE POLICY tenant_rows ON image_registries AS PERMISSIVE FOR ALL TO public USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.platform_scope'::text, true) = 'on'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.platform_scope'::text, true) = 'on'::text)));

CREATE POLICY tenant_rows ON workflow_approval_pages AS PERMISSIVE FOR ALL TO public USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.platform_scope'::text, true) = 'on'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.platform_scope'::text, true) = 'on'::text)));
