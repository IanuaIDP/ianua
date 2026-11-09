-- Takes every role off the record of what a connection's mapping gave an
-- account of a tenant.
DELETE FROM mapped_holding_roles
WHERE tenant_id = $1 AND connection_id = $2 AND user_id = $3
