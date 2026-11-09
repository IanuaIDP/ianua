-- The link a subject at a connection's provider signs in by, in a tenant.
SELECT connection_id, subject, user_id, linked_at, confirmed_at
FROM federated_links
WHERE tenant_id = $1 AND connection_id = $2 AND subject = $3
