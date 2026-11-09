-- no-transaction
-- Made concurrently, outside a transaction, so the table goes on taking
-- writes while it is built.

CREATE INDEX CONCURRENTLY scheduled_jobs_ended ON scheduled_jobs USING btree (created_at) WHERE (status = ANY (ARRAY['completed'::text, 'dead'::text, 'superseded'::text]));
