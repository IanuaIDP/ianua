-- Removes events from the gateway's inbox once they were appended to their
-- tenants' trails, or dropped.
DELETE FROM gateway_events
WHERE tenant_id = ANY($1) AND id = ANY($2)
