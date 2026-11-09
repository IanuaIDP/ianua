-- Sandboxes: a tenant's named recipes of code, pinned packages and limits,
-- or of the company's own container image, and every saved version of
-- them with how far building its package bundle, or scanning its image,
-- got. The bundle itself is kept in the file store, named by the version,
-- beside the digest kept here.
--
-- Both are tenant tables, kept as the workflows context keeps its own:
-- row-level security keeps each row to its tenant, and the foreign key
-- carries the tenant too. A version never changes once saved but for its
-- build, which goes from building to ready or failed once.

CREATE TABLE sandboxes (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    language text,
    status text NOT NULL,
    -- The number of its latest version, or 0 before the first. A sandbox
    -- keeps at most 50, each with a bundle in storage.
    latest_version integer NOT NULL,
    created_by jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    -- What its versions run: code in its language, or the company's image
    -- with no language.
    kind text NOT NULL DEFAULT 'code',
    CONSTRAINT sandboxes_tenant_id_key UNIQUE (tenant_id, id),
    CONSTRAINT sandboxes_kind_known CHECK (kind IN ('code', 'image')),
    CONSTRAINT sandboxes_language_known CHECK (language IN ('python', 'javascript')),
    CONSTRAINT sandboxes_language_of_code CHECK ((kind = 'code') = (language IS NOT NULL)),
    CONSTRAINT sandboxes_status_known CHECK (status IN ('active', 'archived')),
    CONSTRAINT sandboxes_latest_in_range CHECK (latest_version BETWEEN 0 AND 50),
    CONSTRAINT sandboxes_changed_after_made CHECK (updated_at >= created_at)
);

ALTER TABLE sandboxes ENABLE ROW LEVEL SECURITY;
ALTER TABLE sandboxes FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON sandboxes
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The tenant's sandboxes by when they last changed, and by name.
CREATE INDEX sandboxes_by_updated ON sandboxes (tenant_id, updated_at, id);
CREATE INDEX sandboxes_by_name ON sandboxes (tenant_id, name, id);

-- One saved version: its runtime and the exact image of it, its code,
-- packages and limits, and its build; or the company's image pinned to its
-- digest, its size, and what scanning it found. A sandbox and number pair is kept once, so two saves made at once
-- cannot both become the same version.
CREATE TABLE sandbox_versions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    sandbox_id uuid NOT NULL,
    number integer NOT NULL,
    runtime text,
    -- The image it runs in, named by its content, for good: the runtime's,
    -- or the company's own, resolved from its tag when the version was
    -- saved.
    image text NOT NULL,
    code text,
    -- The packages it pins, as name and version pairs in the order given.
    packages jsonb,
    run_seconds integer NOT NULL,
    memory_mib integer NOT NULL,
    -- How far building its bundle got, with the bundle's digest, size and
    -- the packages a pinned one needs that are not pinned once ready, or
    -- why it failed.
    build text NOT NULL,
    bundle_digest text,
    bundle_bytes bigint,
    unlisted text[],
    failure text,
    failure_detail text,
    saved_by jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    -- The hosts its code may reach, by exact DNS name, through the
    -- platform's network filter. None reaches no network at all.
    allowed_hosts text[] NOT NULL DEFAULT '{}',
    -- Where its code came from: none for code written in the platform, or
    -- the file of a repository it was imported from, at the exact commit it
    -- was read at. The integration names the service keeping the
    -- repository; it is a key of the code, not a row.
    source_integration text,
    source_repository text,
    source_path text,
    source_commit text,
    -- The agent the version holds and the rules it works under (its agent,
    -- model provider, goal, purpose, tools, approvals, steps, spend and
    -- tries), as the domain writes them; its code is then the check every
    -- answer of that agent must pass. NULL when its code is the step's
    -- work. The agent and provider named inside are history, like a run's:
    -- a version keeps them after they are deleted, and its runs refuse.
    held_agent jsonb,
    -- What it runs: code under a runtime, or the company's image.
    program text NOT NULL DEFAULT 'code',
    -- The company's image's size as its registry counts its layers.
    image_bytes bigint,
    -- What scanning the company's image found below critical, once it was
    -- cleared to run.
    scan_high integer,
    scan_medium integer,
    scan_low integer,
    CONSTRAINT sandbox_versions_number_once UNIQUE (tenant_id, sandbox_id, number),
    -- Trials name the version they ran with its tenant.
    CONSTRAINT sandbox_versions_tenant_id_key UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, sandbox_id)
        REFERENCES sandboxes (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT sandbox_versions_in_range CHECK (number BETWEEN 1 AND 50),
    CONSTRAINT sandbox_versions_program_known CHECK (program IN ('code', 'image')),
    CONSTRAINT sandbox_versions_runtime_known CHECK (runtime IN (
        'python-3.11', 'python-3.12', 'python-3.13', 'node-20', 'node-22', 'node-24'
    )),
    CONSTRAINT sandbox_versions_code_whole
        CHECK ((program = 'code') = (runtime IS NOT NULL)
            AND (program = 'code') = (code IS NOT NULL)
            AND (program = 'code') = (packages IS NOT NULL)
            AND (program = 'image') = (image_bytes IS NOT NULL)),
    CONSTRAINT sandbox_versions_image_bytes_bounded
        CHECK (image_bytes BETWEEN 0 AND 2147483648),
    CONSTRAINT sandbox_versions_image_pinned CHECK (image LIKE '%@sha256:%'),
    CONSTRAINT sandbox_versions_build_known CHECK (build IN ('building', 'ready', 'failed')),
    CONSTRAINT sandbox_versions_ready_whole
        CHECK ((build = 'ready' AND program = 'code') = (bundle_digest IS NOT NULL)
            AND (build = 'ready' AND program = 'code') = (bundle_bytes IS NOT NULL)
            AND (build = 'ready' AND program = 'code') = (unlisted IS NOT NULL)),
    CONSTRAINT sandbox_versions_scanned_whole
        CHECK ((build = 'ready' AND program = 'image') = (scan_high IS NOT NULL)
            AND (build = 'ready' AND program = 'image') = (scan_medium IS NOT NULL)
            AND (build = 'ready' AND program = 'image') = (scan_low IS NOT NULL)),
    CONSTRAINT sandbox_versions_image_written
        CHECK (program = 'code' OR source_integration IS NULL),
    CONSTRAINT sandbox_versions_failed_whole
        CHECK ((build = 'failed') = (failure IS NOT NULL)
            AND (build = 'failed') = (failure_detail IS NOT NULL)),
    CONSTRAINT sandbox_versions_changed_after_saved CHECK (updated_at >= created_at),
    CONSTRAINT sandbox_versions_allowed_hosts_bounded
        CHECK (cardinality(allowed_hosts) <= 20),
    CONSTRAINT sandbox_versions_source_whole
        CHECK ((source_integration IS NULL) = (source_repository IS NULL)
            AND (source_integration IS NULL) = (source_path IS NULL)
            AND (source_integration IS NULL) = (source_commit IS NULL))
);

ALTER TABLE sandbox_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sandbox_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON sandbox_versions
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A sandbox's versions, newest first, and for their foreign key.
CREATE INDEX sandbox_versions_of_sandbox
    ON sandbox_versions (tenant_id, sandbox_id, created_at, id);

-- Trials of sandbox versions: a person hands a built version sample input,
-- a worker runs it, and they read back what it gave or why it failed. A
-- trial goes with its version, and an ended one is removed a day after it
-- ended.
CREATE TABLE sandbox_trials (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    sandbox_id uuid NOT NULL,
    version_id uuid NOT NULL,
    -- What the code is given.
    input jsonb NOT NULL,
    -- How far it got, with what the code gave back once it succeeded, or
    -- why it failed and the end of its error once it failed.
    state text NOT NULL,
    output jsonb,
    failure text,
    failure_detail text,
    started_by jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, sandbox_id)
        REFERENCES sandboxes (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, version_id)
        REFERENCES sandbox_versions (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT sandbox_trials_state_known CHECK (state IN ('running', 'succeeded', 'failed')),
    CONSTRAINT sandbox_trials_succeeded_whole CHECK ((state = 'succeeded') = (output IS NOT NULL)),
    CONSTRAINT sandbox_trials_failed_whole CHECK ((state = 'failed') = (failure IS NOT NULL)),
    CONSTRAINT sandbox_trials_detail_of_a_failure
        CHECK (failure_detail IS NULL OR failure IS NOT NULL),
    CONSTRAINT sandbox_trials_changed_after_started CHECK (updated_at >= created_at)
);

ALTER TABLE sandbox_trials ENABLE ROW LEVEL SECURITY;
ALTER TABLE sandbox_trials FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON sandbox_trials
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The trials a tenant has running, counted against its plan.
CREATE INDEX sandbox_trials_running ON sandbox_trials (tenant_id) WHERE state = 'running';

-- The trials that ended, oldest first, for the daily purge.
CREATE INDEX sandbox_trials_ended
    ON sandbox_trials (tenant_id, updated_at) WHERE state <> 'running';

-- For the foreign keys to the sandbox and the version.
CREATE INDEX sandbox_trials_of_sandbox ON sandbox_trials (tenant_id, sandbox_id);
CREATE INDEX sandbox_trials_of_version ON sandbox_trials (tenant_id, version_id);

-- The image registries a tenant's administrator allowed: the only places a
-- sandbox version takes the company's own image from. A host is on a
-- tenant's list once. Images are pulled anonymously, or as a user with a
-- password or token sealed for this row. Removing a row stops the versions
-- whose image it keeps from running; they name the registry by host, not
-- by row, so no foreign key holds them to it.
CREATE TABLE image_registries (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    host text NOT NULL,
    login text NOT NULL,
    username text,
    password text,
    allowed_by jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT image_registries_host_once UNIQUE (tenant_id, host),
    CONSTRAINT image_registries_login_known CHECK (login IN ('anonymous', 'password')),
    CONSTRAINT image_registries_login_whole
        CHECK ((login = 'password') = (username IS NOT NULL)
            AND (login = 'password') = (password IS NOT NULL)),
    CONSTRAINT image_registries_changed_after_allowed CHECK (updated_at >= created_at)
);

ALTER TABLE image_registries ENABLE ROW LEVEL SECURITY;
ALTER TABLE image_registries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON image_registries
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));
