-- Takes off every named resource one delegation of a tenant was kept as
-- granting, before what it grants now is written.
DELETE FROM delegation_resources
WHERE tenant_id = $1 AND delegation_id = $2
