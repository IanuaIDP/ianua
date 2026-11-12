-- Tells the workers listening on the event channel that events wait for
-- the bus, once the change that recorded them commits; a change rolled
-- back tells nobody.
SELECT pg_notify('ianua_events', '')
