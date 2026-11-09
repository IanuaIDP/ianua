-- no-transaction
-- Made concurrently, outside a transaction, so the table goes on taking
-- writes while it is built.

-- The versions in service that decide a change before it happens, by the
-- change, which a guarded change looks up while it waits.
CREATE INDEX CONCURRENTLY workflow_versions_published_before ON workflow_versions USING btree (tenant_id, trigger_change) WHERE ((status = 'published'::text) AND (trigger_kind = 'before'::text));
