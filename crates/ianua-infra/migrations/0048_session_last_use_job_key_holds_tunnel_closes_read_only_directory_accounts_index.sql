-- no-transaction
-- Made concurrently, outside a transaction, so the table goes on taking
-- writes while it is built.

-- The runs that ended, oldest first, for the sweep past their keeping.
CREATE INDEX CONCURRENTLY workflow_executions_ended ON workflow_executions USING btree (tenant_id, updated_at) WHERE ((status <> 'running'::text) AND (pass_of IS NULL));
