-- Removes the link an account of a tenant holds at a connection's
-- provider.
DELETE FROM federated_links
WHERE tenant_id = $1 AND connection_id = $2 AND user_id = $3
