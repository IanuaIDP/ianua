-- Where the channel a delivery's address names is kept, in whichever tenants
-- the read may see.
SELECT tenant_id, id
FROM workflow_account_channels
WHERE id = $1
