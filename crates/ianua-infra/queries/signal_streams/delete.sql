-- Removes a signal stream of the tenant for good, with the subjects it
-- lists, its delivery history and the tokens it held for polling.
DELETE FROM signal_streams
WHERE tenant_id = $1 AND id = $2
