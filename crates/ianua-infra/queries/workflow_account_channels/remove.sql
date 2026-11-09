-- Forgets one channel.
DELETE FROM workflow_account_channels
WHERE tenant_id = $1 AND id = $2
