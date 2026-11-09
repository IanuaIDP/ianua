-- The job queue: the work a change asked for, queued in the change's own
-- transaction, in the database the change was made in, so a change that
-- rolls back leaves no job and one that commits never loses its job. The
-- worker claims from every database.
CREATE TABLE scheduled_jobs (
    id uuid PRIMARY KEY,
    -- Empty for a job that belongs to no tenant, kept in the platform
    -- database and seen only by platform work.
    tenant_id uuid,
    job_type text NOT NULL,
    -- Two jobs with one key never wait or run at once.
    job_key text,
    payload text NOT NULL,
    run_at timestamptz NOT NULL,
    attempt integer NOT NULL,
    max_attempts integer NOT NULL,
    status text NOT NULL,
    error text,
    created_at timestamptz NOT NULL,
    last_attempted_at timestamptz,
    -- Until when the worker that claimed it holds it. A running job past
    -- it was left by a worker that stopped.
    leased_until timestamptz,
    -- How long the key holds: 'live' while the job waits or runs, 'kept'
    -- for as long as the row is kept, for work done once per event.
    key_hold text NOT NULL DEFAULT 'live',
    CONSTRAINT scheduled_jobs_status_known
        CHECK (status IN ('pending', 'running', 'completed', 'dead', 'superseded')),
    CONSTRAINT scheduled_jobs_key_hold_known
        CHECK (key_hold IN ('live', 'kept')),
    CONSTRAINT scheduled_jobs_kept_with_key
        CHECK (job_key IS NOT NULL OR key_hold = 'live'),
    CONSTRAINT scheduled_jobs_attempts_in_range
        CHECK (max_attempts >= 1 AND attempt BETWEEN 0 AND max_attempts),
    CONSTRAINT scheduled_jobs_attempt_recorded
        CHECK ((attempt = 0) = (last_attempted_at IS NULL)),
    CONSTRAINT scheduled_jobs_attempted_after_queued
        CHECK (last_attempted_at IS NULL OR last_attempted_at >= created_at),
    CONSTRAINT scheduled_jobs_error_after_attempt
        CHECK (attempt > 0 OR error IS NULL),
    CONSTRAINT scheduled_jobs_fits_status
        CHECK (CASE status
                   WHEN 'pending' THEN attempt < max_attempts
                   WHEN 'running' THEN attempt > 0
                   WHEN 'completed' THEN attempt > 0 AND error IS NULL
                   ELSE attempt = max_attempts AND error IS NOT NULL
               END),
    CONSTRAINT scheduled_jobs_held_while_running
        CHECK ((status = 'running') = (leased_until IS NOT NULL))
);

ALTER TABLE scheduled_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE scheduled_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON scheduled_jobs
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- One live job per key and tenant, the jobs of no tenant counted as one:
-- queueing a twin answers that it is already queued.
CREATE UNIQUE INDEX scheduled_jobs_one_live_per_key
    ON scheduled_jobs (tenant_id, job_key) NULLS NOT DISTINCT
    WHERE job_key IS NOT NULL AND status IN ('pending', 'running');
-- One job ever per key and tenant for work done once, whatever became of
-- it, for as long as the row is kept: an event delivered again after its
-- job ended queues nothing.
CREATE UNIQUE INDEX scheduled_jobs_once_per_kept_key
    ON scheduled_jobs (tenant_id, job_key) NULLS NOT DISTINCT
    WHERE key_hold = 'kept';
-- The due jobs of a lane, oldest first.
CREATE INDEX scheduled_jobs_due
    ON scheduled_jobs (job_type, run_at, id) WHERE status = 'pending';
-- The jobs whose holder stopped.
CREATE INDEX scheduled_jobs_held
    ON scheduled_jobs (leased_until, id) WHERE status = 'running';
-- The dead jobs operators look into, newest first, and the ended jobs the
-- cleanup removes, superseded ones among them.
CREATE INDEX scheduled_jobs_dead
    ON scheduled_jobs (created_at, id) WHERE status = 'dead';
CREATE INDEX scheduled_jobs_ended
    ON scheduled_jobs (created_at) WHERE status IN ('completed', 'dead', 'superseded');
