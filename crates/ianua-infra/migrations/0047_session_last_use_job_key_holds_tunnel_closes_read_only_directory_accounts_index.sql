-- no-transaction
-- Made concurrently, outside a transaction, so the table goes on taking
-- writes while it is built.

-- One job ever per key and tenant for work done once, whatever became of
-- it, for as long as the row is kept: an event delivered again after its
-- job ended queues nothing.
CREATE UNIQUE INDEX CONCURRENTLY scheduled_jobs_once_per_kept_key ON scheduled_jobs USING btree (tenant_id, job_key) NULLS NOT DISTINCT WHERE (key_hold = 'kept'::text);
