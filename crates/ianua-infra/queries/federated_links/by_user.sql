-- The link an account of a tenant holds at a connection's provider.
SELECT connection_id, subject, user_id, linked_at, confirmed_at
FROM federated_links
WHERE tenant_id = $1 AND connection_id = $2 AND user_id = $3
