-- Tells the workers listening on the gateway event channel that events
-- the gateway kept wait for the trail, once the change that kept them
-- commits.
SELECT pg_notify('ianua_gateway_events', '')
