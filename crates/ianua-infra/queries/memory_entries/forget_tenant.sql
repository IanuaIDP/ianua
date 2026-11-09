-- Deletes every text of a deleted tenant's memories.
DELETE FROM memory_entries WHERE tenant_id = $1
