-- Deletes every text of one memory.
DELETE FROM memory_entries WHERE tenant_id = $1 AND memory_id = $2
