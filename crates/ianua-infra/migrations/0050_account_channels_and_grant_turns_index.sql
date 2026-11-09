-- no-transaction
-- Made concurrently, outside a transaction, so the table goes on taking
-- writes while it is built.

-- The registrations a sweep gives up on: waiting since long ago, the oldest
-- first.
CREATE INDEX CONCURRENTLY workflow_service_subscriptions_waiting ON workflow_service_subscriptions USING btree (created_at, id) WHERE (status = 'registering'::text);
