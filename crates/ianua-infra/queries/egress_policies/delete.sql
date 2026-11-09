-- Deletes one egress policy of one tenant.
DELETE FROM egress_policies
WHERE tenant_id = $1 AND id = $2
